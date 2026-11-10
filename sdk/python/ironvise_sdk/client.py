"""LedgerClient - async-first REST client for IronVise."""

import asyncio
import json
import math
from contextlib import aclosing

import httpx
from pydantic import BaseModel, ValidationError
from typing import Any, AsyncIterator, TypeVar
from urllib.parse import quote

from ironvise_sdk.models import (
    AppendResult,
    ComplianceBundle,
    ConfigResponse,
    CreateTokenResponse,
    IntentVerdict,
    LedgerEvent,
    MetricsSummary,
    PendingApproval,
    SecurityMetrics,
    Session,
    StatusResponse,
    TokenListRow,
    TripwireCheckResult,
    TripwireConfig,
    VerifySessionResult,
    WebhookListRow,
)


_ERROR_EXCERPT_CHARS = 300

_Model = TypeVar("_Model", bound=BaseModel)

#: Statuses worth a retry on a GET: the server (or its proxy) is temporarily
#: unavailable, not refusing the request.
_RETRIABLE_STATUS_CODES = frozenset({502, 503, 504})
_RETRY_BASE_SECONDS = 0.25
_RETRY_MAX_SECONDS = 4.0

#: Module-level indirection so tests can replace the wait with a no-op instead
#: of waiting out real backoff delays.
_sleep = asyncio.sleep


def _retry_delay(attempt: int, retry_after: str | None = None) -> float:
    """Seconds to wait before retry number *attempt* (0-based).

    Honours a ``Retry-After`` header, in seconds, when present and valid;
    otherwise backs off exponentially from ``_RETRY_BASE_SECONDS``. Both are
    capped at ``_RETRY_MAX_SECONDS``.
    """
    if retry_after is not None:
        try:
            seconds = float(retry_after)
        except ValueError:
            seconds = None
        if seconds is not None and math.isfinite(seconds) and seconds >= 0:
            return min(seconds, _RETRY_MAX_SECONDS)
    return min(_RETRY_BASE_SECONDS * 2**min(attempt, 4), _RETRY_MAX_SECONDS)


def _server_message(body: str | None) -> str:
    """The server's own words for a failure, bounded for use in an exception message.

    The server answers errors with plain text; a JSON body's ``error`` or
    ``message`` field is used when there is one.
    """
    if not body:
        return ""
    text = body
    try:
        parsed = json.loads(body)
    except ValueError:
        parsed = None
    if isinstance(parsed, dict):
        for key in ("error", "message"):
            if isinstance(parsed.get(key), str):
                text = parsed[key]
                break
    text = text.strip()
    return text if len(text) <= _ERROR_EXCERPT_CHARS else f"{text[:_ERROR_EXCERPT_CHARS]}…"


class LedgerSdkError(Exception):
    """Raised when the IronVise API returns an unexpected or non-JSON response.

    For an HTTP error the message is ``"<operation>: HTTP <status>: <server message>"``,
    with the server message cut at 300 characters. A 2xx body that is not JSON
    gives ``"<operation>: server returned non-JSON body"``, and JSON that does not
    have the documented shape ``"<operation>: unexpected response shape: …"``.
    An identifier that cannot be sent as one path segment (``""``, ``"."`` or
    ``".."``) is refused before any request, naming the parameter.

    Attributes
    ----------
    status_code:
        HTTP status code of the response, or ``None`` when no HTTP response
        was received (e.g. a network error before the server replied).
    body:
        Raw response body text, or ``None`` if unavailable.
    """

    def __init__(self, message: str, *, status_code: int | None = None, body: str | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body


def _path(context: str, template: str, **ids: str) -> str:
    """Fill *template* with *ids*, each percent-encoded as exactly one path segment.

    ``quote`` leaves dots alone, so ``"."`` and ``".."`` would be resolved as
    dot segments and ``delete_policy("..")`` would become ``DELETE /api``; an
    empty id would drop its segment. No encoding of them survives every proxy
    and server, so they are refused before anything is sent.
    """
    for param, value in ids.items():
        if value in ("", ".", ".."):
            raise LedgerSdkError(
                f"{context}: {param} must not be {value!r}: it cannot be sent as a path segment"
            )
    return template.format(**{param: quote(value, safe="") for param, value in ids.items()})


async def _sse(resp: httpx.Response) -> AsyncIterator[tuple[str, str]]:
    """The event name and data of each server-sent event in *resp*'s body.

    Comments (keep-alives) and events without data are skipped.
    """
    event = "message"
    data: list[str] = []
    # Only CR/LF delimit SSE lines. Universal line decoders also split on
    # Unicode separators that may legally occur inside JSON string values.
    line: list[str] = []
    first_character = True
    skip_lf = False
    async for chunk in resp.aiter_text():
        for char in chunk:
            if first_character:
                first_character = False
                if char == "\ufeff":
                    continue
            if skip_lf:
                skip_lf = False
                if char == "\n":
                    continue
            if char not in ("\r", "\n"):
                line.append(char)
                continue
            skip_lf = char == "\r"
            value_line = "".join(line)
            line = []
            if value_line == "":
                if data:
                    yield event or "message", "\n".join(data)
                event, data = "message", []
                continue
            field, _, value = value_line.partition(":")
            if value.startswith(" "):
                value = value[1:]
            if field == "event":
                event = value
            elif field == "data":
                data.append(value)


class LedgerClient:
    """Async REST client for the IronVise API.

    Usage::

        async with LedgerClient("http://localhost:3000") as client:
            sessions = await client.list_sessions()

    .. warning::
        The ``base_url`` parameter defaults to ``http://localhost:3000``, which
        works for local development only.  In containerised or remote environments
        you **must** pass the correct service URL explicitly::

            LedgerClient(base_url="http://ironvise-host:3000", bearer_token="...")

        Omitting ``base_url`` in Docker Compose / Kubernetes will cause every
        method to fail with a connection-refused error against the loopback
        address inside the calling container.

    *retries* (default ``2``) applies only to GET requests, which are
    idempotent: a connection error (``httpx.NetworkError`` - refused,
    reset, …, not a timeout) or an HTTP 502/503/504 is retried with
    exponential backoff (0.25 s, 0.5 s, …, capped at 4 s), honouring a
    ``Retry-After`` header in seconds when the server sends one (also capped
    at 4 s). POST/PUT/DELETE are never retried, and neither is a timeout or
    any 4xx - those are the caller's to handle. Streaming
    (``stream_events``, ``ask_stream``, ``chat_stream``) is not retried.
    ``retries`` must be a non-negative integer and ``timeout`` a positive,
    finite number of seconds; invalid settings raise ``ValueError``.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:3000",
        *,
        bearer_token: str | None = None,
        timeout: float = 30.0,
        retries: int = 2,
    ) -> None:
        headers: dict[str, str] = {}
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"
        if not isinstance(retries, int) or isinstance(retries, bool):
            raise ValueError(f"retries must be a non-negative integer, got {retries}")
        if retries < 0:
            raise ValueError(f"retries must not be negative, got {retries}")
        if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError(f"timeout must be a positive finite number, got {timeout}")
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers=headers,
            timeout=timeout,
        )
        self._retries = retries

    async def _get(self, url: str, **kwargs: Any) -> httpx.Response:
        """GET with retry: see the class docstring for the retry policy."""
        attempts = self._retries + 1
        for attempt in range(attempts):
            last_attempt = attempt == attempts - 1
            try:
                response = await self._client.get(url, **kwargs)
            except httpx.NetworkError:
                if last_attempt:
                    raise
                await _sleep(_retry_delay(attempt))
                continue
            if not last_attempt and response.status_code in _RETRIABLE_STATUS_CODES:
                await _sleep(_retry_delay(attempt, response.headers.get("retry-after")))
                continue
            return response
        raise AssertionError("unreachable: the loop above always returns or raises")

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "LedgerClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    @staticmethod
    def _check(r: httpx.Response, context: str = "") -> None:
        """Raise :class:`LedgerSdkError` for any non-2xx response."""
        try:
            r.raise_for_status()
        except httpx.HTTPStatusError as exc:
            body: str | None = None
            try:
                body = exc.response.text
            except Exception:
                pass
            label = f"{context}: " if context else ""
            detail = _server_message(body)
            suffix = f": {detail}" if detail else ""
            raise LedgerSdkError(
                f"{label}HTTP {exc.response.status_code}{suffix}",
                status_code=exc.response.status_code,
                body=body,
            ) from exc

    @staticmethod
    def _parse_json(r: httpx.Response, context: str = "") -> Any:
        """Decode JSON from *r*, wrapping decode errors in :class:`LedgerSdkError`."""
        try:
            return r.json()
        except (ValueError, TypeError) as exc:
            label = f"{context}: " if context else ""
            raise LedgerSdkError(f"{label}server returned non-JSON body", status_code=r.status_code, body=r.text) from exc

    @staticmethod
    def _shape_error(r: httpx.Response, context: str, detail: str) -> LedgerSdkError:
        label = f"{context}: " if context else ""
        return LedgerSdkError(
            f"{label}unexpected response shape: {detail}", status_code=r.status_code, body=r.text
        )

    @classmethod
    def _as_model(cls, r: httpx.Response, context: str, model: type[_Model], data: Any) -> _Model:
        """Validate *data* as *model*, wrapping a mismatch in :class:`LedgerSdkError`."""
        try:
            return model.model_validate(data)
        except ValidationError as exc:
            first = exc.errors()[0]
            where = ".".join(str(part) for part in first["loc"])
            detail = f"{model.__name__}{'.' + where if where else ''}: {first['msg']}"
            raise cls._shape_error(r, context, detail) from exc

    @classmethod
    def _parse_model(cls, r: httpx.Response, context: str, model: type[_Model]) -> _Model:
        return cls._as_model(r, context, model, cls._parse_json(r, context))

    @classmethod
    def _parse_models(cls, r: httpx.Response, context: str, model: type[_Model]) -> list[_Model]:
        data = cls._parse_json(r, context)
        if not isinstance(data, list):
            raise cls._shape_error(r, context, f"expected a JSON array, got {type(data).__name__}")
        return [cls._as_model(r, context, model, item) for item in data]

    async def list_sessions(
        self,
        limit: int = 50,
        offset: int | None = None,
        status: str | None = None,
    ) -> list[Session]:
        """Return the most recent *limit* sessions."""
        params: dict[str, Any] = {"limit": limit}
        if offset is not None:
            params["offset"] = offset
        if status is not None:
            params["status"] = status
        r = await self._get("/api/sessions", params=params)
        self._check(r, "list_sessions")
        return self._parse_models(r, "list_sessions", Session)

    async def create_session(
        self,
        goal: str,
        *,
        record: bool = False,
    ) -> Session:
        """Open a new agent session (returns full Session object).

        No ``policy_hash`` or ``session_did`` parameter: the server never
        accepted either on creation. It records the hash of the policy the
        run actually used (or none, decided server-side) and sets
        ``session_did`` itself once the session key exists - both are
        read-only fields on the returned :class:`Session`.

        Pass ``record=True`` for a session you append to yourself: the server
        needs no LLM, runs no audit loop, and keeps the session open for
        :meth:`append_event` until :meth:`seal_session`. Without it the server
        runs its own audit loop (and answers 503 if it has no LLM), and appends
        to the finished session are refused with 409.
        """
        body: dict = {"goal": goal}
        if record:
            body["record"] = True
        r = await self._client.post("/api/sessions", json=body)
        self._check(r, "create_session")
        return self._parse_model(r, "create_session", Session)

    async def seal_session(self, session_id: str) -> None:
        """Mark a session as finished."""
        r = await self._client.post(
            _path("seal_session", "/api/sessions/{session_id}/seal", session_id=session_id)
        )
        self._check(r, "seal_session")

    async def get_events(self, session_id: str) -> list[LedgerEvent]:
        """Fetch all events belonging to *session_id*."""
        r = await self._get("/api/events", params={"session_id": session_id})
        self._check(r, "get_events")
        return self._parse_models(r, "get_events", LedgerEvent)

    async def append_event(
        self,
        session_id: str,
        payload: dict,
    ) -> AppendResult:
        """Append a single event and return the hash + sequence number."""
        r = await self._client.post(
            _path("append_event", "/api/sessions/{session_id}/events", session_id=session_id),
            json=payload,
        )
        self._check(r, "append_event")
        return self._parse_model(r, "append_event", AppendResult)

    async def verify_intent(
        self,
        session_id: str,
        action: str,
        params: dict | None = None,
        justification: str = "",
        reasoning: str = "",
    ) -> IntentVerdict:
        """Ask whether *action* would be permitted - **before** performing it.

        This is the call that makes the SDK a governance path rather than a
        logger. The server runs the same policy → tripwire → guard pipeline the
        cognitive loop uses and answers allow or deny.

        Nothing is executed and nothing is written to the ledger by asking. If
        you want the decision recorded, append it, or use the Claude Code hook
        surface, which records. See ``docs/guides/integrations.md``.

        The verdict is only worth anything if the caller honours it::

            verdict = await client.verify_intent(sid, "run_command",
                                                 {"command": cmd},
                                                 justification="…")
            verdict.raise_if_denied()
            subprocess.run(cmd, shell=True)
        """
        r = await self._client.post(
            _path("verify_intent", "/api/sessions/{session_id}/verify-intent", session_id=session_id),
            json={
                "action": action,
                "params": params or {},
                "justification": justification,
                "reasoning": reasoning,
            },
        )
        self._check(r, "verify_intent")
        return self._parse_model(r, "verify_intent", IntentVerdict)

    async def verify_chain(self, session_id: str) -> bool:
        """Return ``True`` if the chain is intact and every signature verified."""
        result = await self.verify_session(session_id)
        return result.ok and (result.signatures is None or result.signatures.verified)

    async def verify_session(self, session_id: str) -> VerifySessionResult:
        """Return the full verdict: the hash chain (``ok``) and the signatures."""
        r = await self._get(
            _path("verify_session", "/api/sessions/{session_id}/verify", session_id=session_id)
        )
        self._check(r, "verify_session")
        return self._parse_model(r, "verify_session", VerifySessionResult)

    async def prove_compliance(self, session_id: str) -> ComplianceBundle:
        """Return a typed compliance bundle: the event count and each event's sequence and content hash.

        Raises
        ------
        LedgerSdkError
            If the server returns a non-2xx status or a non-JSON body.
        """
        r = await self._get(
            _path("prove_compliance", "/api/sessions/{session_id}/compliance", session_id=session_id)
        )
        self._check(r, "prove_compliance")
        return self._parse_model(r, "prove_compliance", ComplianceBundle)

    async def export_certificate(self, session_id: str) -> bytes:
        """Download the .elc audit certificate for *session_id*."""
        r = await self._get(
            _path("export_certificate", "/api/certificates/{session_id}", session_id=session_id)
        )
        self._check(r, "export_certificate")
        return r.content

    async def get_report(self, session_id: str) -> dict:
        """Download the JSON audit report for *session_id*."""
        r = await self._get(
            _path("get_report", "/api/reports/{session_id}", session_id=session_id)
        )
        self._check(r, "get_report")
        return self._parse_json(r, "get_report")

    async def get_session_vc(self, session_id: str) -> dict:
        """Retrieve the VC-JWT and decoded payload for a completed session."""
        r = await self._get(
            _path("get_session_vc", "/api/sessions/{session_id}/vc", session_id=session_id)
        )
        self._check(r, "get_session_vc")
        return self._parse_json(r, "get_session_vc")

    async def verify_session_vc(self, session_id: str, audience: str | None = None) -> dict:
        """Verify the VC-JWT for a completed session.

        *audience*, when given, is the verifier's own identifier, sent as
        ``?audience=`` and checked against the VC's ``aud`` claim.

        Returns a dict with ``"valid": true/false`` and optional ``"reason"``
        or ``"vc_payload"`` fields.
        """
        params = {"audience": audience} if audience is not None else None
        r = await self._get(
            _path("verify_session_vc", "/api/sessions/{session_id}/vc/verify", session_id=session_id),
            params=params,
        )
        self._check(r, "verify_session_vc")
        return self._parse_json(r, "verify_session_vc")

    async def get_metrics(self) -> MetricsSummary:
        """Fetch Prometheus-compatible metrics as a parsed summary object."""
        r = await self._get("/api/metrics")
        self._check(r, "get_metrics")
        return self._parse_model(r, "get_metrics", MetricsSummary)

    async def get_security_metrics(self) -> SecurityMetrics:
        """Fetch structured security metrics (injection attempts, circuit breaker, etc.)."""
        r = await self._get("/api/metrics/security")
        self._check(r, "get_security_metrics")
        return self._parse_model(r, "get_security_metrics", SecurityMetrics)

    async def get_prometheus_metrics(self) -> str:
        """Return raw Prometheus exposition text."""
        r = await self._get("/metrics")
        self._check(r, "get_prometheus_metrics")
        return r.text

    async def list_policies(self) -> list[str]:
        """Return a list of available policy names.

        Raises
        ------
        LedgerSdkError
            If the server returns a non-2xx status or a non-JSON body.
        """
        r = await self._get("/api/policies")
        self._check(r, "list_policies")
        return self._parse_json(r, "list_policies")

    async def get_policy(self, name: str) -> str:
        """Return the raw content of a named policy file."""
        r = await self._get(_path("get_policy", "/api/policies/{name}", name=name))
        self._check(r, "get_policy")
        return r.text

    async def save_policy(self, name: str, content: str) -> None:
        """Overwrite a policy file on the server."""
        r = await self._client.put(
            _path("save_policy", "/api/policies/{name}", name=name),
            content=content.encode(),
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )
        self._check(r, "save_policy")

    async def delete_policy(self, name: str) -> None:
        """Delete a policy file from the server."""
        r = await self._client.delete(_path("delete_policy", "/api/policies/{name}", name=name))
        self._check(r, "delete_policy")

    async def get_pending_approval(self, session_id: str) -> PendingApproval | None:
        """Check for a pending approval gate on *session_id*.

        Returns a :class:`PendingApproval` if a gate is active, or ``None``.
        """
        r = await self._get(
            _path("get_pending_approval", "/api/approvals/{session_id}/pending", session_id=session_id)
        )
        self._check(r, "get_pending_approval")
        data = self._parse_json(r, "get_pending_approval")
        pending = data.get("pending") if isinstance(data, dict) else None
        if pending is None:
            return None
        return self._as_model(r, "get_pending_approval", PendingApproval, pending)

    async def post_approval_decision(
        self,
        session_id: str,
        gate_id: str,
        approved: bool,
        reason: str | None = None,
    ) -> None:
        """Submit an approve/deny decision for a pending approval gate."""
        body: dict = {"gate_id": gate_id, "approved": approved}
        if reason is not None:
            body["reason"] = reason
        r = await self._client.post(
            _path("post_approval_decision", "/api/approvals/{session_id}", session_id=session_id),
            json=body,
        )
        self._check(r, "post_approval_decision")

    async def get_status(self) -> StatusResponse:
        """Return the server status (demo mode, version, etc.)."""
        r = await self._get("/api/status")
        self._check(r, "get_status")
        return self._parse_model(r, "get_status", StatusResponse)

    async def get_session(self, session_id: str) -> Session:
        """Fetch a single session by its ID."""
        r = await self._get(
            _path("get_session", "/api/sessions/{session_id}", session_id=session_id)
        )
        self._check(r, "get_session")
        return self._parse_model(r, "get_session", Session)

    async def chat(self, session_id: str, message: str) -> dict:
        """Send a chat message within a running session.

        Returns the raw JSON response dict from the server.
        """
        r = await self._client.post(
            _path("chat", "/api/sessions/{session_id}/chat", session_id=session_id),
            json={"message": message},
        )
        self._check(r, "chat")
        return self._parse_json(r, "chat")

    async def chat_stream(self, session_id: str, message: str) -> AsyncIterator[dict]:
        """:meth:`chat`, with the reply streamed as the model generates it.

        Yields ``{"type": "delta", "text": ...}`` for each piece of text, then
        ``{"type": "done", "reply": ..., "backend": ..., "model": ...}`` once
        the whole reply is recorded. A failure after streaming has begun
        raises :class:`LedgerSdkError`, as an error status does.
        """
        path = _path("chat_stream", "/api/sessions/{session_id}/chat/stream", session_id=session_id)
        async with aclosing(self._stream_chat("chat_stream", path, message)) as stream:
            async for event in stream:
                yield event

    async def ask(self, message: str) -> dict:
        """Ask the configured model directly, outside any session.

        The exchange is still recorded in the ledger; no guard or tripwire
        applies. Returns ``{"reply", "backend", "model"}``.
        """
        r = await self._client.post("/api/chat", json={"message": message})
        self._check(r, "ask")
        return self._parse_json(r, "ask")

    async def ask_stream(self, message: str) -> AsyncIterator[dict]:
        """:meth:`ask`, with the reply streamed like :meth:`chat_stream`."""
        async with aclosing(self._stream_chat("ask_stream", "/api/chat/stream", message)) as stream:
            async for event in stream:
                yield event

    async def _stream_chat(self, context: str, path: str, message: str) -> AsyncIterator[dict]:
        async with self._client.stream("POST", path, json={"message": message}) as resp:
            if not resp.is_success:
                await resp.aread()
            self._check(resp, context)
            async for event, data in _sse(resp):
                try:
                    body = json.loads(data)
                except ValueError:
                    continue
                if event == "delta":
                    yield {"type": "delta", "text": body.get("text", "")}
                elif event == "done":
                    yield {"type": "done", **body}
                elif event == "error":
                    raise LedgerSdkError(
                        f"{context}: {body.get('message', 'the stream failed')}",
                        status_code=resp.status_code,
                        body=data,
                    )

    async def get_config(self) -> ConfigResponse:
        """Retrieve the current server configuration."""
        r = await self._get("/api/config")
        self._check(r, "get_config")
        return self._parse_model(r, "get_config", ConfigResponse)

    async def update_config(self, patch: dict) -> dict:
        """Apply a partial configuration update and return the server response.

        For a text field (``database_url``, ``ollama_base_url``,
        ``openai_base_url``, ``ollama_model``, ``guard_llm_backend``,
        ``guard_llm_model``, ``active_policy``): omitting the key keeps the
        stored value, ``""`` clears it back to the environment or built-in
        default, anything else replaces it. ``active_policy`` is additionally
        validated on save - a name that fails to load is refused with a 422
        (``LedgerSdkError.status_code == 422``) rather than silently kept.
        """
        r = await self._client.put("/api/config", json=patch)
        self._check(r, "update_config")
        return self._parse_json(r, "update_config")

    async def get_tripwire_config(self) -> TripwireConfig:
        """Retrieve the current tripwire guard configuration."""
        r = await self._get("/api/tripwire")
        self._check(r, "get_tripwire_config")
        return self._parse_model(r, "get_tripwire_config", TripwireConfig)

    async def update_tripwire_config(self, patch: dict) -> dict:
        """Apply a partial tripwire configuration update."""
        r = await self._client.put("/api/tripwire", json=patch)
        self._check(r, "update_tripwire_config")
        return self._parse_json(r, "update_tripwire_config")

    async def check_tripwire(
        self,
        action: str,
        params: dict | None = None,
        justification: str | None = None,
    ) -> TripwireCheckResult:
        """Ask whether *action* would pass the tripwire - **without recording
        anything**: no session, no ledger event.

        Runs only the tripwire layer built from the same configuration
        :meth:`get_tripwire_config` reads - the allowlists and banned
        patterns - not the policy engine or the semantic guard. Use
        :meth:`verify_intent` for the full pipeline evaluated against a
        session.

        *justification* is omitted from the request when not given, so the
        server applies its own placeholder; pass a real one for a check that
        reflects what the caller would actually say.
        """
        body: dict = {"action": action, "params": params or {}}
        if justification is not None:
            body["justification"] = justification
        r = await self._client.post("/api/tripwire/check", json=body)
        self._check(r, "check_tripwire")
        return self._parse_model(r, "check_tripwire", TripwireCheckResult)

    async def list_tokens(self) -> list[TokenListRow]:
        """List all API tokens (hashed, never the raw secret)."""
        r = await self._get("/api/tokens")
        self._check(r, "list_tokens")
        return self._parse_models(r, "list_tokens", TokenListRow)

    async def create_token(self, role: str, label: str | None = None, expires_in_days: int | None = None) -> CreateTokenResponse:
        """Create a new API token with the given role."""
        body: dict = {"role": role}
        if label is not None:
            body["label"] = label
        if expires_in_days is not None:
            body["expires_in_days"] = expires_in_days
        r = await self._client.post("/api/tokens", json=body)
        self._check(r, "create_token")
        return self._parse_model(r, "create_token", CreateTokenResponse)

    async def delete_token(self, token_hash: str) -> None:
        """Revoke a token by its hash."""
        r = await self._client.delete(
            _path("delete_token", "/api/tokens/{token_hash}", token_hash=token_hash)
        )
        self._check(r, "delete_token")

    async def list_webhooks(self) -> list[WebhookListRow]:
        """List configured SIEM / notification webhooks."""
        r = await self._get("/api/webhooks")
        self._check(r, "list_webhooks")
        return self._parse_models(r, "list_webhooks", WebhookListRow)

    async def create_webhook(
        self,
        label: str,
        url: str,
        *,
        bearer_token: str | None = None,
        siem_format: str = "json",
        filter_kinds: list[str] | None = None,
        enabled: bool = True,
    ) -> WebhookListRow:
        """Register a new webhook endpoint."""
        body: dict = {"label": label, "url": url, "siem_format": siem_format, "enabled": enabled}
        if bearer_token is not None:
            body["bearer_token"] = bearer_token
        if filter_kinds is not None:
            body["filter_kinds"] = filter_kinds
        r = await self._client.post("/api/webhooks", json=body)
        self._check(r, "create_webhook")
        return self._parse_model(r, "create_webhook", WebhookListRow)

    async def delete_webhook(self, webhook_id: str) -> None:
        """Remove a webhook by its ID."""
        r = await self._client.delete(
            _path("delete_webhook", "/api/webhooks/{webhook_id}", webhook_id=webhook_id)
        )
        self._check(r, "delete_webhook")

    async def toggle_webhook(self, webhook_id: str, enabled: bool) -> None:
        """Enable or disable a webhook. The server answers with an empty body."""
        r = await self._client.put(
            _path("toggle_webhook", "/api/webhooks/{webhook_id}", webhook_id=webhook_id),
            json={"enabled": enabled},
        )
        self._check(r, "toggle_webhook")

    async def reset_demo(self) -> dict:
        """Reset the server to demo defaults (demo mode only)."""
        r = await self._client.post("/api/admin/reset-demo")
        self._check(r, "reset_demo")
        return self._parse_json(r, "reset_demo")

    async def stream_events(self, session_id: str | None = None) -> AsyncIterator[dict]:
        """Yield parsed SSE data dicts from the live event stream.

        With a *session_id*, that session's events; without one, every
        session's (``GET /api/stream``).

        Usage::

            async for event in client.stream_events(session_id):
                print(event)

        The caller is responsible for breaking out of the loop.
        """
        path = (
            "/api/stream"
            if session_id is None
            else _path("stream_events", "/api/sessions/{session_id}/events/stream", session_id=session_id)
        )
        async with self._client.stream("GET", path) as resp:
            if not resp.is_success:
                # A streamed body is only read on request; without it the
                # error would carry neither the server's message nor the body.
                await resp.aread()
            self._check(resp, "stream_events")
            async for _event, data in _sse(resp):
                try:
                    yield json.loads(data)
                except ValueError:
                    pass
