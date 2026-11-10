"""Failure paths of every public ``LedgerClient`` method.

The documented contract (``LedgerSdkError`` docstring and the README's "Error
handling" section):

* a non-2xx response raises ``LedgerSdkError`` whose message is
  ``"<operation>: HTTP <status>: <server message>"``, with ``status_code`` and
  the whole ``body`` attached;
* a 2xx body that a method has to parse as JSON and cannot raises
  ``LedgerSdkError("<operation>: server returned non-JSON body")``.

Transport failures (timeouts, refused connections) are not wrapped by the
client: the ``httpx`` exception reaches the caller unchanged. The tests pin
that too, so a change in either direction is a deliberate one.

GET is the one exception: it is idempotent, so a connection error
(``httpx.NetworkError``, not a timeout) or an HTTP 502/503/504 is retried,
honouring ``Retry-After`` - see ``LedgerClient._get`` and
``test_client_retries.py``. POST/PUT/DELETE and every other status are never
retried, which these tests pin by asserting ``route.call_count``.
"""

from __future__ import annotations

import inspect
import json

import httpx
import pydantic
import pytest
import respx

from _endpoints import BY_NAME, ENDPOINTS, Endpoint
from ironvise_sdk.client import LedgerClient, LedgerSdkError

pytestmark = pytest.mark.asyncio

BASE = "http://ledger.test"
IDENT = "550e8400-e29b-41d4-a716-446655440000"
TOKEN = "tok-very-secret-0123456789"

NON_STREAM = [e for e in ENDPOINTS if e.returns != "stream"]

DEFAULT_RETRIES = inspect.signature(LedgerClient.__init__).parameters["retries"].default
_RETRIABLE_STATUSES = {502, 503, 504}


def _expected_calls(ep: Endpoint, retriable: bool) -> int:
    """How many requests a GET makes when every attempt hits the same failure."""
    return 1 + DEFAULT_RETRIES if ep.http == "GET" and ep.returns != "stream" and retriable else 1

NGINX_502 = (
    "<html>\r\n<head><title>502 Bad Gateway</title></head>\r\n<body>\r\n"
    "<center><h1>502 Bad Gateway</h1></center>\r\n<hr><center>nginx</center>\r\n"
    "</body>\r\n</html>\r\n"
)


def _ids(endpoints: list[Endpoint]) -> list[str]:
    return [e.name for e in endpoints]


def _json(body: object) -> dict[str, object]:
    return {"content": json.dumps(body).encode(), "headers": {"content-type": "application/json"}}


#: (status, response kwargs, the server message the error message must end with)
STATUS_CASES = [
    pytest.param(
        401,
        _json({"error": "missing or invalid bearer token"}),
        "missing or invalid bearer token",
        id="401-json-error",
    ),
    pytest.param(
        403,
        {"text": "role 'auditor' may not call this endpoint"},
        "role 'auditor' may not call this endpoint",
        id="403-text",
    ),
    pytest.param(
        429,
        {"text": "rate limited", "headers": {"retry-after": "7"}},
        "rate limited",
        id="429-retry-after",
    ),
    pytest.param(429, {"text": "rate limited"}, "rate limited", id="429-no-retry-after"),
    pytest.param(500, {"text": "internal error\n"}, "internal error", id="500-text"),
    pytest.param(
        502,
        {"text": NGINX_502, "headers": {"content-type": "text/html"}},
        NGINX_502.strip(),
        id="502-html",
    ),
    pytest.param(503, _json({"message": "no LLM configured"}), "no LLM configured", id="503-json-message"),
]


def test_every_public_method_is_in_the_table() -> None:
    """A new client method fails here until it is added to ``_endpoints.py``."""
    public = {
        name
        for name, member in inspect.getmembers(LedgerClient, inspect.isfunction)
        if not name.startswith("_") and name != "close"
    }
    assert public == set(BY_NAME)


@respx.mock
@pytest.mark.parametrize("ep", ENDPOINTS, ids=_ids(ENDPOINTS))
async def test_each_method_requests_its_route(ep: Endpoint) -> None:
    """Pins the table to the client, so the other tests exercise the right request."""
    route = respx.route().mock(return_value=httpx.Response(500, text="x"))
    async with LedgerClient(BASE) as client:
        with pytest.raises(LedgerSdkError):
            await ep.call(client, IDENT)
    request = route.calls.last.request
    assert request.method == ep.http
    assert request.url.path == ep.path(IDENT)
    if ep.query_id:
        assert request.url.params["session_id"] == IDENT


@respx.mock
@pytest.mark.parametrize(("status", "response", "detail"), STATUS_CASES)
@pytest.mark.parametrize("ep", NON_STREAM, ids=_ids(NON_STREAM))
async def test_http_error_raises_ledger_sdk_error_with_the_server_message(
    ep: Endpoint, status: int, response: dict, detail: str
) -> None:
    route = respx.route().mock(return_value=httpx.Response(status, **response))
    async with LedgerClient(BASE, bearer_token=TOKEN) as client:
        with pytest.raises(LedgerSdkError) as excinfo:
            await ep.call(client, IDENT)

    err = excinfo.value
    assert str(err) == f"{ep.op}: HTTP {status}: {detail}"
    assert err.status_code == status
    assert err.body == route.calls.last.response.text
    assert isinstance(err.__cause__, httpx.HTTPStatusError)
    assert TOKEN not in str(err), "the bearer token must never reach an error message"
    assert route.call_count == _expected_calls(ep, status in _RETRIABLE_STATUSES), (
        "a GET retries 502/503/504 (even 429 with Retry-After is left alone); nothing else retries"
    )


@respx.mock
@pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
async def test_stream_events_http_error_raises_ledger_sdk_error(status: int) -> None:
    respx.route().mock(return_value=httpx.Response(status, text="refused"))
    async with LedgerClient(BASE) as client:
        with pytest.raises(LedgerSdkError) as excinfo:
            await BY_NAME["stream_events"].call(client, IDENT)
    assert excinfo.value.status_code == status
    assert str(excinfo.value).startswith(f"stream_events: HTTP {status}")


@respx.mock
async def test_stream_events_http_error_carries_the_server_message() -> None:
    """The README promises the server's explanation and ``exc.body`` for every method."""
    respx.route().mock(return_value=httpx.Response(403, text="role 'auditor' may not stream"))
    async with LedgerClient(BASE) as client:
        with pytest.raises(LedgerSdkError) as excinfo:
            await BY_NAME["stream_events"].call(client, IDENT)
    assert str(excinfo.value) == "stream_events: HTTP 403: role 'auditor' may not stream"
    assert excinfo.value.body == "role 'auditor' may not stream"


@respx.mock
@pytest.mark.parametrize(
    "failure",
    [
        httpx.ConnectError("connection refused"),
        httpx.ConnectTimeout("connect timed out"),
        httpx.ReadTimeout("read timed out"),
    ],
    ids=["connect-error", "connect-timeout", "read-timeout"],
)
@pytest.mark.parametrize("ep", ENDPOINTS, ids=_ids(ENDPOINTS))
async def test_transport_failure_reaches_the_caller_unwrapped(ep: Endpoint, failure: httpx.HTTPError) -> None:
    route = respx.route().mock(side_effect=failure)
    async with LedgerClient(BASE) as client:
        with pytest.raises(type(failure)) as excinfo:
            await ep.call(client, IDENT)
    assert not isinstance(excinfo.value, LedgerSdkError)
    # ConnectError is a NetworkError and retried on GET; the two timeouts are
    # not, even on GET, since they already waited once.
    retriable = isinstance(failure, httpx.NetworkError)
    assert route.call_count == _expected_calls(ep, retriable)


def test_timeout_is_applied_to_every_request() -> None:
    client = LedgerClient(BASE, timeout=2.5)
    assert client._client.timeout == httpx.Timeout(2.5)


BAD_BODIES = [
    pytest.param(
        b"<!doctype html><html><body>Sign in</body></html>",
        {"content-type": "text/html"},
        id="html",
    ),
    pytest.param(b'{"session_id": "550e8400-e29b', {"content-type": "application/json"}, id="truncated-json"),
    pytest.param(b"", {"content-type": "application/json"}, id="empty"),
]


@respx.mock
@pytest.mark.parametrize(("content", "headers"), BAD_BODIES)
@pytest.mark.parametrize("ep", ENDPOINTS, ids=_ids(ENDPOINTS))
async def test_a_2xx_body_that_is_not_json(ep: Endpoint, content: bytes, headers: dict) -> None:
    """JSON methods raise the documented error; the others hand the body back as is."""
    respx.route().mock(return_value=httpx.Response(200, content=content, headers=headers))
    async with LedgerClient(BASE) as client:
        if ep.returns == "json":
            with pytest.raises(LedgerSdkError) as excinfo:
                await ep.call(client, IDENT)
            err = excinfo.value
            assert str(err) == f"{ep.op}: server returned non-JSON body"
            assert err.status_code == 200
            assert err.body == content.decode()
            assert isinstance(err.__cause__, ValueError)
            return
        result = await ep.call(client, IDENT)

    expected = {
        "text": content.decode(),
        "bytes": content,
        "none": None,
        "stream": [],
    }[ep.returns]
    assert result == expected


@respx.mock
@pytest.mark.parametrize(
    ("name", "body"),
    [
        ("list_sessions", None),
        ("list_sessions", {"sessions": []}),
        ("list_sessions", [{"session_id": 1}]),
        ("get_session", []),
        ("append_event", "ok"),
        ("append_event", {"id": "one"}),
        ("get_pending_approval", {"pending": "yes"}),
    ],
    ids=["list-null", "list-object", "list-bad-item", "model-array", "model-string", "model-bad-field", "nested"],
)
async def test_a_2xx_json_body_of_the_wrong_shape_raises_ledger_sdk_error(name: str, body: object) -> None:
    """``LedgerSdkError`` is documented as the error for an unexpected response."""
    respx.route().mock(return_value=httpx.Response(200, **_json(body)))
    async with LedgerClient(BASE) as client:
        with pytest.raises(LedgerSdkError) as excinfo:
            await BY_NAME[name].call(client, IDENT)
    err = excinfo.value
    assert str(err).startswith(f"{name}: unexpected response shape: ")
    assert err.status_code == 200
    assert err.body == json.dumps(body)
    if not str(err).endswith("expected a JSON array, got " + type(body).__name__):
        assert isinstance(err.__cause__, pydantic.ValidationError)


@respx.mock
async def test_stream_events_skips_a_truncated_event_and_keeps_the_rest() -> None:
    sse = 'data: {"seq": 1}\n\ndata: {"seq": 2\n\n: keep-alive\n\ndata: {"seq": 3}\n\n'
    respx.route().mock(
        return_value=httpx.Response(200, text=sse, headers={"content-type": "text/event-stream"})
    )
    async with LedgerClient(BASE) as client:
        events = await BY_NAME["stream_events"].call(client, IDENT)
    assert events == [{"seq": 1}, {"seq": 3}]


@respx.mock
async def test_ask_stream_yields_deltas_then_the_recorded_reply() -> None:
    sse = (
        'event: delta\ndata: {"text": "Hel"}\n\n'
        ": keep-alive\n\n"
        'event: delta\ndata: {"text": "lo"}\n\n'
        'event: done\ndata: {"reply": "Hello", "backend": "openai", "model": "m"}\n\n'
    )
    route = respx.post(f"{BASE}/api/chat/stream").mock(
        return_value=httpx.Response(200, text=sse, headers={"content-type": "text/event-stream"})
    )
    async with LedgerClient(BASE) as client:
        events = [e async for e in client.ask_stream("say hello")]
    assert events == [
        {"type": "delta", "text": "Hel"},
        {"type": "delta", "text": "lo"},
        {"type": "done", "reply": "Hello", "backend": "openai", "model": "m"},
    ]
    assert json.loads(route.calls[0].request.content) == {"message": "say hello"}


@respx.mock
async def test_chat_stream_raises_on_an_error_event_after_the_text_so_far() -> None:
    sse = 'event: delta\ndata: {"text": "Hel"}\n\nevent: error\ndata: {"message": "LLM call failed: cut off"}\n\n'
    respx.post(f"{BASE}/api/sessions/{IDENT}/chat/stream").mock(
        return_value=httpx.Response(200, text=sse, headers={"content-type": "text/event-stream"})
    )
    texts = []
    async with LedgerClient(BASE) as client:
        with pytest.raises(LedgerSdkError, match="chat_stream: LLM call failed: cut off"):
            async for event in client.chat_stream(IDENT, "hi"):
                texts.append(event["text"])
    assert texts == ["Hel"]
