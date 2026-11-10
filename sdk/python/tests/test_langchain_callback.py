"""LangChain integration, driven through the real callback manager.

The point of every test here is the *side effect*, not the exception. An earlier
cut of the handler raised on a recording failure and LangChain's `handle_event`
caught it, logged a warning and carried on - so a suite that asserted "the
handler raises" passed while the tool ran unrecorded. These tests invoke a real
`StructuredTool` and assert on a list the tool appends to.
"""

from __future__ import annotations

import pytest

pytest.importorskip("langchain_core")

from langchain_core.tools import StructuredTool  # noqa: E402

from ironvise_sdk.langchain import LedgerCallbackHandler  # noqa: E402
from ironvise_sdk._recorder import RecordingFailed  # noqa: E402

SESSION_ID = "550e8400-e29b-41d4-a716-446655440000"


class _Sentinel:
    """A harmless forbidden side effect: the tool appends, the test reads."""

    def __init__(self) -> None:
        self.ran: list[str] = []

    def tool(self) -> StructuredTool:
        def harmless(x: str) -> str:
            self.ran.append(x)
            return f"ran:{x}"

        return StructuredTool.from_function(
            func=harmless, name="harmless", description="appends to a list"
        )


def _handler(*, fail_open: bool = False, fail_on: tuple[str, ...] = ("tool_start",)):
    """A handler whose recorder fails for the named event kinds."""
    h = LedgerCallbackHandler(session_id=SESSION_ID, fail_open=fail_open)
    recorded: list[dict] = []

    def fake_record(payload: dict, *, already_executed: bool = False) -> None:
        recorded.append(payload)
        if payload.get("kind") in fail_on:
            if fail_open:
                return
            raise RecordingFailed(
                "simulated ledger unavailable"
                + (" (already executed)" if already_executed else "")
            )

    h._recorder.record = fake_record  # type: ignore[method-assign]
    return h, recorded


# The regression: the framework must propagate, not swallow.


def test_raise_error_is_set_so_langchain_propagates() -> None:
    h, _ = _handler()
    assert h.raise_error is True, (
        "BaseCallbackHandler.raise_error defaults to False and "
        "langchain_core.callbacks.manager.handle_event consults it before "
        "re-raising; without this the fail-closed contract stops at the class "
        "boundary"
    )


def test_fail_open_leaves_propagation_off() -> None:
    h, _ = _handler(fail_open=True)
    assert h.raise_error is False


def test_sync_tool_does_not_run_when_the_pre_call_record_fails() -> None:
    sentinel = _Sentinel()
    tool = sentinel.tool()
    h, _ = _handler()

    with pytest.raises(RecordingFailed):
        tool.invoke({"x": "sync"}, config={"callbacks": [h]})

    assert sentinel.ran == [], "the tool ran despite a fail-closed recording failure"


async def test_async_tool_does_not_run_when_the_pre_call_record_fails() -> None:
    sentinel = _Sentinel()
    tool = sentinel.tool()
    h, _ = _handler()

    with pytest.raises(RecordingFailed):
        await tool.ainvoke({"x": "async"}, config={"callbacks": [h]})

    assert sentinel.ran == [], "the tool ran despite a fail-closed recording failure"


# fail_open is a deliberate alternative, not a fallback.


def test_fail_open_lets_the_tool_run_sync() -> None:
    sentinel = _Sentinel()
    tool = sentinel.tool()
    h, recorded = _handler(fail_open=True)

    assert tool.invoke({"x": "sync"}, config={"callbacks": [h]}) == "ran:sync"
    assert sentinel.ran == ["sync"]
    assert [r["kind"] for r in recorded] == ["tool_start", "tool_end"]


async def test_fail_open_lets_the_tool_run_async() -> None:
    sentinel = _Sentinel()
    tool = sentinel.tool()
    h, _ = _handler(fail_open=True)

    assert await tool.ainvoke({"x": "async"}, config={"callbacks": [h]}) == "ran:async"
    assert sentinel.ran == ["async"]


# A post-execution failure must not claim the call was prevented.


def test_post_execution_failure_reports_a_gap_rather_than_a_rollback() -> None:
    sentinel = _Sentinel()
    tool = sentinel.tool()
    h, _ = _handler(fail_on=("tool_end",))

    with pytest.raises(RecordingFailed):
        tool.invoke({"x": "sync"}, config={"callbacks": [h]})

    # The tool did run. That is the honest outcome, and the reason the two
    # failure messages differ.
    assert sentinel.ran == ["sync"]


def test_the_happy_path_records_start_and_end() -> None:
    sentinel = _Sentinel()
    tool = sentinel.tool()
    h, recorded = _handler(fail_on=())

    assert tool.invoke({"x": "ok"}, config={"callbacks": [h]}) == "ran:ok"
    assert sentinel.ran == ["ok"]
    kinds = [r["kind"] for r in recorded]
    assert kinds == ["tool_start", "tool_end"]
    assert recorded[0]["tool_name"] == "harmless"
