"""AutoGen integration, driven through a real ``AssistantAgent``.

The suite this replaces injected a stub implementing AutoGen **0.2**'s
``ConversableAgent.register_hook``. It passed against a dependency the package
does not declare, while ``attach()`` raised ``AttributeError`` on every version
``autogen-agentchat>=0.4`` resolves to. A compatibility test that supplies the
API under test is a test of the stub.

These tests build a real ``AssistantAgent`` over ``ReplayChatCompletionClient``
- AutoGen's own model double, so no model is called - and assert on whether the
tool's side effect happened.
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("autogen_agentchat")
pytest.importorskip("autogen_ext")

from autogen_agentchat.agents import AssistantAgent  # noqa: E402
from autogen_core import CancellationToken, FunctionCall  # noqa: E402
from autogen_core.models import CreateResult, RequestUsage  # noqa: E402
from autogen_core.tools import FunctionTool  # noqa: E402
from autogen_ext.models.replay import ReplayChatCompletionClient  # noqa: E402

from ironvise_sdk._recorder import RecordingFailed  # noqa: E402
from ironvise_sdk.autogen import LedgerHook  # noqa: E402

SESSION_ID = "550e8400-e29b-41d4-a716-446655440000"

# ReplayChatCompletionClient reports no function calling by default, and
# AssistantAgent refuses tools without it.
_MODEL_INFO = {
    "function_calling": True,
    "vision": False,
    "json_output": False,
    "family": "unknown",
    "structured_output": False,
}


class _Sentinel:
    """A harmless forbidden side effect: the tool appends, the test reads."""

    def __init__(self) -> None:
        self.ran: list[str] = []

    def fn(self):
        def harmless(x: str) -> str:
            """Appends to a list."""
            self.ran.append(x)
            return f"ran:{x}"

        return harmless


def _model_calling(tool_name: str, arguments: dict) -> ReplayChatCompletionClient:
    return ReplayChatCompletionClient(
        [
            CreateResult(
                finish_reason="function_calls",
                content=[
                    FunctionCall(id="1", name=tool_name, arguments=json.dumps(arguments))
                ],
                usage=RequestUsage(prompt_tokens=0, completion_tokens=0),
                cached=False,
            ),
            "done",
        ],
        model_info=_MODEL_INFO,
    )


def _hook(*, fail_open: bool = False, fail_on: tuple[str, ...] = ()):
    hook = LedgerHook(session_id=SESSION_ID, fail_open=fail_open)
    recorded: list[dict] = []

    def fake_record(payload: dict, *, already_executed: bool = False) -> None:
        recorded.append(payload)
        if payload.get("kind") in fail_on and not fail_open:
            raise RecordingFailed("simulated ledger unavailable")

    hook._recorder.record = fake_record  # type: ignore[method-assign]
    return hook, recorded


# The regression: the 0.2 API is gone and says so.


def test_attach_names_the_api_it_used_to_call() -> None:
    hook, _ = _hook()
    agent = AssistantAgent("a", model_client=ReplayChatCompletionClient(["hi"]))
    with pytest.raises(NotImplementedError) as excinfo:
        hook.attach(agent)
    message = str(excinfo.value)
    assert "wrap_tools" in message
    assert "0.2" in message


def test_wrapped_tools_are_accepted_by_a_real_assistant_agent() -> None:
    hook, _ = _hook()
    sentinel = _Sentinel()
    tools = hook.wrap_tools([sentinel.fn()])
    agent = AssistantAgent(
        "a", model_client=ReplayChatCompletionClient(["hi"], model_info=_MODEL_INFO), tools=tools
    )
    assert [t.name for t in agent._tools] == ["harmless"]
    assert agent._tools[0].schema["parameters"]["properties"].keys() == {"x"}


async def test_a_recorded_tool_call_runs_and_is_recorded() -> None:
    sentinel = _Sentinel()
    hook, recorded = _hook()
    agent = AssistantAgent(
        "a",
        model_client=_model_calling("harmless", {"x": "ok"}),
        tools=hook.wrap_tools([sentinel.fn()], agent_name="a"),
        reflect_on_tool_use=False,
    )
    await agent.run(task="go")

    assert sentinel.ran == ["ok"]
    assert [r["kind"] for r in recorded] == ["tool_start", "tool_end"]
    assert recorded[0]["tool_name"] == "harmless"
    assert recorded[0]["agent_name"] == "a"


async def test_the_tool_does_not_run_when_the_pre_call_record_fails() -> None:
    sentinel = _Sentinel()
    hook, recorded = _hook(fail_on=("tool_start",))
    agent = AssistantAgent(
        "a",
        model_client=_model_calling("harmless", {"x": "boom"}),
        tools=hook.wrap_tools([sentinel.fn()]),
        reflect_on_tool_use=False,
    )
    result = await agent.run(task="go")

    # This is the assertion that matters: the action did not happen.
    assert sentinel.ran == [], "the tool ran despite a fail-closed recording failure"
    assert [r["kind"] for r in recorded] == ["tool_start"]

    # AutoGen converts a raising tool into an error result rather than
    # propagating, so the agent continues with a failed call in its context.
    # The action is prevented; the *agent* is not halted. Saying otherwise
    # would overstate what this seam does.
    execution = [m for m in result.messages if type(m).__name__ == "ToolCallExecutionEvent"]
    assert execution and execution[0].content[0].is_error


async def test_fail_open_lets_the_tool_run() -> None:
    sentinel = _Sentinel()
    hook, recorded = _hook(fail_open=True, fail_on=("tool_start",))
    agent = AssistantAgent(
        "a",
        model_client=_model_calling("harmless", {"x": "ok"}),
        tools=hook.wrap_tools([sentinel.fn()]),
        reflect_on_tool_use=False,
    )
    await agent.run(task="go")

    assert sentinel.ran == ["ok"]
    assert [r["kind"] for r in recorded] == ["tool_start", "tool_end"]


async def test_a_failing_tool_is_recorded_as_an_error() -> None:
    def explodes(x: str) -> str:
        """Always fails."""
        raise ValueError("tool blew up")

    hook, recorded = _hook()
    tool = hook.wrap_tools([explodes])[0]
    with pytest.raises(ValueError):
        await tool.run_json({"x": "1"}, CancellationToken())
    assert [r["kind"] for r in recorded] == ["tool_start", "tool_error"]


def test_an_existing_basetool_is_wrapped_rather_than_rebuilt() -> None:
    inner = FunctionTool(_Sentinel().fn(), description="appends to a list")
    hook, _ = _hook()
    wrapped = hook.wrap_tools([inner])[0]
    assert wrapped.inner is inner
    assert wrapped.name == inner.name
    assert wrapped.description == inner.description
    assert wrapped.schema == inner.schema


def test_a_non_callable_is_refused() -> None:
    hook, _ = _hook()
    with pytest.raises(TypeError):
        hook.wrap_tools([object()])
