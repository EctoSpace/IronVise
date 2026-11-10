"""Shared machinery for the framework integrations.

Both integrations need the same three things:

* a way to run an async call from a sync callback, whether or not an event loop
  is already running;
* **one** client for the integration's lifetime, rather than a fresh
  :class:`LedgerClient`, ``httpx`` pool and event loop per agent step;
* fail-closed error handling, so an unreachable ledger stops the action instead
  of leaving a gap in an audit trail that is still being trusted.

Keeping it here means the LangChain and AutoGen paths cannot drift apart on any
of them.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import weakref
from typing import Any, Awaitable

from ironvise_sdk.client import LedgerClient, LedgerSdkError

_log = logging.getLogger(__name__)


class RecordingFailed(RuntimeError):
    """Raised when an event could not be recorded and ``fail_open`` is False."""


class _LoopThread:
    """An event loop on a daemon thread, and the one client that lives on it.

    An ``httpx.AsyncClient`` pools connections that belong to the loop they
    were opened on. Running each record in its own ``asyncio.run()`` closed
    that loop under the pooled connection, so against a keep-alive server every
    second record failed with "Event loop is closed". One loop for the
    recorder's lifetime keeps the client and its connections usable, and works
    the same whether or not the caller is inside a running loop.
    """

    def __init__(self, client: LedgerClient, timeout: float) -> None:
        self.client = client
        self._timeout = timeout
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._loop.run_forever, name="ironvise-recorder", daemon=True
        )
        self._thread.start()

    def run(self, coro: Awaitable[Any]) -> Any:
        async def bounded() -> Any:
            return await asyncio.wait_for(coro, timeout=self._timeout)

        return asyncio.run_coroutine_threadsafe(bounded(), self._loop).result()

    def shutdown(self) -> None:
        try:
            self.run(self.client.close())
        except Exception as exc:  # pragma: no cover - best effort
            _log.debug("closing the ledger client failed: %s", exc)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=self._timeout)
        if not self._thread.is_alive():
            self._loop.close()


class LedgerRecorder:
    """Holds one client and records events fail-closed.

    The client runs on an event loop in a background thread that the recorder
    starts on first use. Call :meth:`close`, or use the recorder as a context
    manager, to close the client and stop the thread; a recorder that is
    garbage-collected or still open at interpreter exit is closed then.

    Parameters
    ----------
    fail_open:
        ``False`` by default. A recording failure raises
        :class:`RecordingFailed`; what that stops depends on the framework (the
        whole run for LangChain, the one tool call for AutoGen). Set ``True``
        only where an incomplete audit trail is acceptable - and note that you
        have chosen it, because the previous behaviour was to choose it for
        you, silently.
    timeout:
        Seconds allowed for each record, and the HTTP timeout of the client.
    """

    def __init__(
        self,
        session_id: str,
        base_url: str = "http://localhost:3000",
        bearer_token: str | None = None,
        *,
        fail_open: bool = False,
        timeout: float = 30.0,
    ) -> None:
        self.session_id = session_id
        self.base_url = base_url
        self.bearer_token = bearer_token
        self.fail_open = fail_open
        self.timeout = timeout
        self._runner: _LoopThread | None = None
        self._finalizer: weakref.finalize | None = None
        self._lock = threading.Lock()

    def _started(self) -> _LoopThread:
        with self._lock:
            if self._runner is None:
                client = LedgerClient(
                    self.base_url, bearer_token=self.bearer_token, timeout=self.timeout
                )
                self._runner = _LoopThread(client, self.timeout)
                # Holds the runner, not the recorder, so an unclosed recorder
                # can still be collected and its thread stopped.
                self._finalizer = weakref.finalize(self, self._runner.shutdown)
            return self._runner

    def client(self) -> LedgerClient:
        return self._started().client

    def close(self) -> None:
        with self._lock:
            finalizer, self._finalizer = self._finalizer, None
            self._runner = None
        if finalizer is not None:
            finalizer()

    def __enter__(self) -> "LedgerRecorder":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def run(self, coro: Awaitable[Any]) -> Any:
        """Run *coro* on the recorder's loop and wait for it, bounded by ``timeout``.

        Safe from a sync context inside or outside a running loop: the caller's
        own loop, if any, is never used.
        """
        return self._started().run(coro)

    def record(self, payload: dict, *, already_executed: bool = False) -> None:
        """Append *payload*, raising unless ``fail_open``.

        ``already_executed`` selects the wording of the failure, and the
        distinction is not cosmetic. A recording failure *before* the action
        runs can still stop it, so raising prevents an unrecorded action. A
        failure *after* it has run cannot undo anything: raising there reports
        an incomplete audit trail and aborts the rest of the run, but the side
        effect has happened. Claiming otherwise would be the same class of
        overstatement this integration exists to avoid.
        """
        try:
            self.run(self._append(payload))
        except Exception as exc:
            if self.fail_open:
                _log.warning(
                    "IronVise: failed to record an event, continuing because "
                    "fail_open=True: %s",
                    exc,
                )
                return
            if already_executed:
                raise RecordingFailed(
                    f"Could not record an agent event to the IronVise audit trail: "
                    f"{exc}. The action had already run, so nothing has been rolled "
                    "back and nothing can be - this is an incomplete record of "
                    "something that happened, not a prevented action. The run is "
                    "stopped because continuing would extend an audit trail that is "
                    "already known to have a gap. Pass fail_open=True to continue "
                    "anyway."
                ) from exc
            raise RecordingFailed(
                f"Could not record an agent event to the IronVise audit trail: {exc}. "
                "The action has been stopped before it ran: an audit trail with silent "
                "gaps cannot be relied on, and this integration is fail-closed by "
                "default. Pass fail_open=True to continue anyway."
            ) from exc

    async def _append(self, payload: dict) -> None:
        try:
            await self.client().append_event(self.session_id, payload)
        except LedgerSdkError:
            raise
        except Exception as exc:
            raise LedgerSdkError(f"append_event failed: {exc}") from exc
