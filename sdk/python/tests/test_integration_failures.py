"""What the framework integrations do when the ledger call itself fails.

``test_recorder.py``, ``test_langchain_callback.py`` and ``test_autogen_hook.py``
replace the recorder's ``record`` with a stub. These tests keep the real
recorder and the real ``LedgerClient`` and fail the HTTP call underneath them,
so the whole path from transport error to framework is exercised.

The documented contract (``_recorder.py``, ``langchain/callback.py``,
``autogen/hook.py`` and the README):

* fail-closed by default: any failure to record, whatever its cause, surfaces
  as ``RecordingFailed`` (``LedgerHookError`` for AutoGen) and never as the raw
  transport or HTTP exception;
* a failure before the action prevents it; a failure after it says the action
  had already run;
* LangChain propagates the error, because the handler sets ``raise_error``;
* AutoGen turns the raising tool into an error result: the action is prevented,
  the agent is not halted;
* ``fail_open=True`` logs a warning and lets everything run.
"""

from __future__ import annotations

import asyncio
import json
import logging
import socketserver
import threading
import time
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
import respx

from ironvise_sdk._recorder import LedgerRecorder, RecordingFailed

BASE = "http://ledger.test"
SESSION = "11111111-1111-4111-8111-111111111111"
EVENTS = f"{BASE}/api/sessions/{SESSION}/events"
APPENDED = {"id": 1, "payload_hash": "a" * 64, "sequence": 1}


async def _slow(request: httpx.Request) -> httpx.Response:
    await asyncio.sleep(1.0)
    return httpx.Response(201, json=APPENDED)


#: How the ledger call fails. Each value builds fresh ``Route.mock`` arguments.
FAILURES: dict[str, Callable[[], dict]] = {
    "http-500": lambda: {"return_value": httpx.Response(500, text="internal error")},
    "http-503": lambda: {"return_value": httpx.Response(503, text="ledger unavailable")},
    "http-401": lambda: {"return_value": httpx.Response(401, json={"error": "missing or invalid bearer token"})},
    "http-403": lambda: {"return_value": httpx.Response(403, text="role 'viewer' may not append")},
    "http-429": lambda: {"return_value": httpx.Response(429, text="slow down", headers={"retry-after": "1"})},
    "read-timeout": lambda: {"side_effect": httpx.ReadTimeout("read timed out")},
    "connect-error": lambda: {"side_effect": httpx.ConnectError("connection refused")},
    "unexpected": lambda: {"side_effect": RuntimeError("transport exploded")},
    "recorder-timeout": lambda: {"side_effect": _slow},
}

failure = pytest.mark.parametrize("kind", list(FAILURES))


def _fail(kind: str) -> respx.Route:
    return respx.post(EVENTS).mock(**FAILURES[kind]())


def _recorder(**kw) -> LedgerRecorder:
    return LedgerRecorder(SESSION, BASE, timeout=0.3, **kw)


@respx.mock
@failure
def test_recorder_turns_every_failure_into_recording_failed(kind: str) -> None:
    _fail(kind)
    started = time.monotonic()
    with _recorder() as rec, pytest.raises(RecordingFailed) as excinfo:
        rec.record({"observation": "x"})
    assert type(excinfo.value) is RecordingFailed
    assert "stopped before it ran" in str(excinfo.value)
    assert excinfo.value.__cause__ is not None
    assert time.monotonic() - started < 0.9, "the recorder's own timeout must bound the call"


@respx.mock
@failure
def test_recorder_failure_after_the_action_does_not_claim_it_was_prevented(kind: str) -> None:
    _fail(kind)
    with _recorder() as rec, pytest.raises(RecordingFailed) as excinfo:
        rec.record({"observation": "x"}, already_executed=True)
    message = str(excinfo.value)
    assert "had already run" in message
    assert "nothing has been rolled back" in message
    assert "stopped before it ran" not in message


@respx.mock
@failure
def test_recorder_fail_open_logs_and_returns(kind: str, caplog: pytest.LogCaptureFixture) -> None:
    _fail(kind)
    with caplog.at_level(logging.WARNING, logger="ironvise_sdk._recorder"):
        with _recorder(fail_open=True) as rec:
            assert rec.record({"observation": "x"}) is None
    assert any("fail_open=True" in r.getMessage() for r in caplog.records)


@respx.mock
@pytest.mark.parametrize("kind", ["http-503", "http-401", "read-timeout", "unexpected", "recorder-timeout"])
async def test_recorder_inside_a_running_loop_fails_the_same_way(kind: str) -> None:
    """A sync callback inside an async agent takes the worker-thread path."""
    _fail(kind)
    with _recorder() as rec, pytest.raises(RecordingFailed):
        rec.record({"observation": "x"})
    with _recorder(fail_open=True) as rec:
        assert rec.record({"observation": "x"}) is None


@respx.mock
def test_recorder_http_failure_keeps_the_status_and_server_message() -> None:
    _fail("http-401")
    with _recorder() as rec, pytest.raises(RecordingFailed) as excinfo:
        rec.record({"observation": "x"})
    cause = excinfo.value.__cause__
    assert getattr(cause, "status_code", None) == 401
    assert "append_event: HTTP 401: missing or invalid bearer token" in str(excinfo.value)


@respx.mock
@pytest.mark.parametrize("text", ["🦀 naïve", "שלום ‮exe.gnp", "a b/c?d#e%f", "nul \x00 ok"])
def test_recorder_sends_unicode_payloads_intact(text: str) -> None:
    route = respx.post(f"{BASE}/api/sessions/{SESSION}%20%2F%F0%9F%A6%80/events").mock(
        return_value=httpx.Response(201, json=APPENDED)
    )
    payload = {"observation": text, "tool_name": text}
    with LedgerRecorder(f"{SESSION} /🦀", BASE, timeout=5.0) as rec:
        rec.record(payload)
    assert json.loads(route.calls.last.request.content.decode("utf-8")) == payload


class _LoopbackHTTPServer(ThreadingHTTPServer):
    """Skips the reverse DNS lookup `HTTPServer.server_bind` does for its name.

    On a host whose resolver is slow for 127.0.0.1 that lookup outlasts the
    test timeout before the server even starts.
    """

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


@pytest.fixture
def keepalive_ledger() -> Iterator[str]:
    """A loopback HTTP/1.1 server that keeps connections open, like the real host.

    ``respx`` replaces the transport, so it cannot show a bug that lives in the
    connection pool. Loopback only, started and stopped by the test.
    """

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self) -> None:  # noqa: N802 - http.server API
            self.rfile.read(int(self.headers.get("content-length", 0)))
            body = json.dumps(APPENDED).encode()
            self.send_response(201)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    server = _LoopbackHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def test_recorder_records_twice_against_a_keepalive_server(keepalive_ledger: str) -> None:
    with LedgerRecorder(SESSION, keepalive_ledger, timeout=5.0) as rec:
        rec.record({"observation": "tool_start"})
        rec.record({"observation": "tool_end"})


def test_recorder_keeps_recording_on_one_pooled_connection(keepalive_ledger: str) -> None:
    with LedgerRecorder(SESSION, keepalive_ledger, timeout=5.0) as rec:
        for step in range(5):
            rec.record({"observation": f"step {step}"})


async def test_recorder_records_repeatedly_inside_a_running_loop(keepalive_ledger: str) -> None:
    """A sync callback inside an async agent: the caller's loop is never used."""
    with LedgerRecorder(SESSION, keepalive_ledger, timeout=5.0) as rec:
        for step in range(3):
            rec.record({"observation": f"step {step}"})
        await asyncio.sleep(0)
        rec.record({"observation": "after yielding to the loop"})


def test_closing_the_recorder_stops_its_thread(keepalive_ledger: str) -> None:
    before = {t for t in threading.enumerate() if t.name == "ectoledger-recorder"}
    with LedgerRecorder(SESSION, keepalive_ledger, timeout=5.0) as rec:
        rec.record({"observation": "x"})
        client = rec.client()
    after = {t for t in threading.enumerate() if t.name == "ectoledger-recorder"}
    assert after <= before
    assert client._client.is_closed


def test_a_closed_recorder_can_record_again(keepalive_ledger: str) -> None:
    rec = LedgerRecorder(SESSION, keepalive_ledger, timeout=5.0)
    rec.record({"observation": "first"})
    rec.close()
    rec.record({"observation": "second"})
    rec.close()


def test_the_recorder_timeout_reaches_the_http_client() -> None:
    with LedgerRecorder(SESSION, BASE, timeout=2.5) as rec:
        assert rec.client()._client.timeout == httpx.Timeout(2.5)


@pytest.fixture
def lc_tool():
    pytest.importorskip("langchain_core")
    from langchain_core.tools import StructuredTool

    ran: list[str] = []

    def harmless(x: str) -> str:
        ran.append(x)
        return f"ran:{x}"

    tool = StructuredTool.from_function(func=harmless, name="harmless", description="appends to a list")
    return tool, ran


def _lc_handler(**kw):
    from ironvise_sdk.langchain import LedgerCallbackHandler

    return LedgerCallbackHandler(session_id=SESSION, base_url=BASE, timeout=0.3, **kw)


@respx.mock
@failure
def test_langchain_sync_tool_is_stopped_when_the_ledger_fails(kind: str, lc_tool) -> None:
    tool, ran = lc_tool
    _fail(kind)
    with _lc_handler() as handler, pytest.raises(RecordingFailed) as excinfo:
        tool.invoke({"x": "1"}, config={"callbacks": [handler]})
    assert type(excinfo.value) is RecordingFailed
    assert ran == []


@respx.mock
@failure
async def test_langchain_async_tool_is_stopped_when_the_ledger_fails(kind: str, lc_tool) -> None:
    tool, ran = lc_tool
    _fail(kind)
    with _lc_handler() as handler, pytest.raises(RecordingFailed):
        await tool.ainvoke({"x": "1"}, config={"callbacks": [handler]})
    assert ran == []


@respx.mock
@failure
def test_langchain_fail_open_never_reaches_the_framework(kind: str, lc_tool) -> None:
    tool, ran = lc_tool
    _fail(kind)
    with _lc_handler(fail_open=True) as handler:
        assert tool.invoke({"x": "1"}, config={"callbacks": [handler]}) == "ran:1"
    assert ran == ["1"]


@respx.mock
@pytest.mark.parametrize("kind", ["http-503", "read-timeout", "unexpected"])
async def test_langchain_async_fail_open_never_reaches_the_framework(kind: str, lc_tool) -> None:
    tool, ran = lc_tool
    _fail(kind)
    with _lc_handler(fail_open=True) as handler:
        assert await tool.ainvoke({"x": "1"}, config={"callbacks": [handler]}) == "ran:1"
    assert ran == ["1"]


@respx.mock
@pytest.mark.parametrize("kind", ["http-503", "read-timeout", "unexpected"])
def test_langchain_failure_after_the_tool_ran_says_so(kind: str, lc_tool) -> None:
    tool, ran = lc_tool
    respx.post(EVENTS).mock(
        side_effect=[httpx.Response(201, json=APPENDED), _failing_response(kind)]
    )
    with _lc_handler() as handler, pytest.raises(RecordingFailed) as excinfo:
        tool.invoke({"x": "1"}, config={"callbacks": [handler]})
    assert ran == ["1"]
    assert "had already run" in str(excinfo.value)


def _failing_response(kind: str) -> httpx.Response | Exception:
    """The single response (or exception) of a failure kind, for a side-effect list."""
    spec = FAILURES[kind]()
    return spec.get("return_value") or spec["side_effect"]


def _autogen_agent(tools: list, tool_args: dict):
    pytest.importorskip("autogen_agentchat")
    pytest.importorskip("autogen_ext")
    from autogen_agentchat.agents import AssistantAgent
    from autogen_core import FunctionCall
    from autogen_core.models import CreateResult, RequestUsage
    from autogen_ext.models.replay import ReplayChatCompletionClient

    model = ReplayChatCompletionClient(
        [
            CreateResult(
                finish_reason="function_calls",
                content=[FunctionCall(id="1", name="harmless", arguments=json.dumps(tool_args))],
                usage=RequestUsage(prompt_tokens=0, completion_tokens=0),
                cached=False,
            ),
            "done",
        ],
        model_info={
            "function_calling": True,
            "vision": False,
            "json_output": False,
            "family": "unknown",
            "structured_output": False,
        },
    )
    return AssistantAgent("a", model_client=model, tools=tools, reflect_on_tool_use=False)


def _autogen_hook(**kw):
    pytest.importorskip("autogen_agentchat")
    from ironvise_sdk.autogen import LedgerHook

    return LedgerHook(session_id=SESSION, base_url=BASE, timeout=0.3, **kw)


@respx.mock
@failure
async def test_autogen_tool_is_prevented_and_the_agent_carries_on(kind: str) -> None:
    ran: list[str] = []

    def harmless(x: str) -> str:
        """Appends to a list."""
        ran.append(x)
        return f"ran:{x}"

    _fail(kind)
    with _autogen_hook() as hook:
        agent = _autogen_agent(hook.wrap_tools([harmless]), {"x": "1"})
        result = await agent.run(task="go")

    assert ran == []
    execution = [m for m in result.messages if type(m).__name__ == "ToolCallExecutionEvent"]
    assert execution and execution[0].content[0].is_error
    assert "IronVise audit trail" in execution[0].content[0].content


@respx.mock
@failure
async def test_autogen_wrapped_tool_raises_ledger_hook_error_to_a_direct_caller(kind: str) -> None:
    CancellationToken = pytest.importorskip("autogen_core").CancellationToken

    from ironvise_sdk.autogen import LedgerHookError

    ran: list[str] = []

    def harmless(x: str) -> str:
        """Appends to a list."""
        ran.append(x)
        return x

    _fail(kind)
    with _autogen_hook() as hook:
        tool = hook.wrap_tools([harmless])[0]
        with pytest.raises(LedgerHookError):
            await tool.run_json({"x": "1"}, CancellationToken())
    assert ran == []


@respx.mock
@pytest.mark.parametrize("kind", ["http-503", "read-timeout", "unexpected"])
async def test_autogen_fail_open_lets_the_tool_run(kind: str) -> None:
    ran: list[str] = []

    def harmless(x: str) -> str:
        """Appends to a list."""
        ran.append(x)
        return f"ran:{x}"

    _fail(kind)
    with _autogen_hook(fail_open=True) as hook:
        agent = _autogen_agent(hook.wrap_tools([harmless]), {"x": "1"})
        result = await agent.run(task="go")

    assert ran == ["1"]
    execution = [m for m in result.messages if type(m).__name__ == "ToolCallExecutionEvent"]
    assert execution and not execution[0].content[0].is_error
