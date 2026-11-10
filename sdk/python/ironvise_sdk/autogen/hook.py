"""AutoGen integration - fail-closed audit recording for AutoGen 0.4+.

**Breaking change.** ``LedgerHook.attach()`` targeted AutoGen 0.2's
``ConversableAgent.register_hook("process_last_received_message", …)``. The
package this SDK actually declares is ``autogen-agentchat>=0.4``, whose
``AssistantAgent`` has no ``register_hook`` at all - so ``attach()`` raised
``AttributeError`` against every version the dependency allowed. The unit tests
did not catch it because they injected a stub implementing the 0.2 API, which
is a test of the stub.

The 0.4+ architecture has a better seam anyway. Tools are
:class:`autogen_core.tools.BaseTool` objects that the agent runs, so wrapping a
tool puts the ledger *between the decision and the action* rather than beside
it:

    from autogen_agentchat.agents import AssistantAgent
    from ironvise_sdk.autogen import LedgerHook

    with LedgerHook(session_id="<uuid>") as hook:
        agent = AssistantAgent(
            "auditor",
            model_client=client,
            tools=hook.wrap_tools([read_file, run_scan]),
        )
        await agent.run(task="…")

``wrap_tools`` records each call *before* the tool runs, so a recording failure
stops the call rather than annotating one that already happened. The result is
recorded afterwards, where a failure can only report an incomplete trail - the
two are reported differently and neither claims a rollback.

Fail-closed by default. Pass ``fail_open=True`` to accept gaps deliberately.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Awaitable, Callable, Mapping, Sequence

from ironvise_sdk._recorder import LedgerRecorder, RecordingFailed

if TYPE_CHECKING:  # pragma: no cover
    from autogen_core import CancellationToken
    from autogen_core.tools import BaseTool

__all__ = ["LedgerHook", "LedgerHookError"]

#: Kept as an alias so ``except LedgerHookError`` reads naturally here, while
#: both integrations raise one type.
LedgerHookError = RecordingFailed

_IMPORT_HINT = (
    "Install 'autogen-agentchat' (pip install ironvise[autogen]) to use "
    "LedgerHook.wrap_tools."
)


def _autogen_tools() -> Any:
    try:
        from autogen_core.tools import BaseTool, FunctionTool
    except ImportError as e:  # pragma: no cover - depends on the environment
        raise ImportError(_IMPORT_HINT) from e
    return BaseTool, FunctionTool


def _recorded_tool_class(base: Any) -> Any:
    """Build the wrapper class lazily, so importing this module needs no AutoGen."""

    class _RecordedTool(base):  # type: ignore[misc, valid-type]
        """Delegates to an inner tool, recording either side of the call."""

        def __init__(self, inner: Any, recorder: LedgerRecorder, agent_name: str | None) -> None:
            super().__init__(
                inner.args_type(),
                inner.return_type(),
                inner.name,
                inner.description,
            )
            self._inner = inner
            self._recorder = recorder
            self._agent_name = agent_name

        @property
        def inner(self) -> Any:
            """The wrapped tool, for callers that need the original object."""
            return self._inner

        async def run(self, args: Any, cancellation_token: "CancellationToken") -> Any:
            arguments = args.model_dump() if hasattr(args, "model_dump") else args
            # Before the call: a failure here prevents it.
            self._recorder.record(
                {
                    "observation": f"tool_start: {self._inner.name} {arguments}",
                    "kind": "tool_start",
                    "tool_name": self._inner.name,
                    "agent_name": self._agent_name,
                }
            )
            try:
                result = await self._inner.run(args, cancellation_token)
            except Exception as exc:
                self._recorder.record(
                    {
                        "observation": f"tool_error: {exc}",
                        "kind": "tool_error",
                        "tool_name": self._inner.name,
                        "agent_name": self._agent_name,
                    },
                    already_executed=True,
                )
                raise
            # After the call: a failure here cannot undo it, and says so.
            self._recorder.record(
                {
                    "observation": f"tool_end: {self._inner.return_value_as_string(result)}",
                    "kind": "tool_end",
                    "tool_name": self._inner.name,
                    "agent_name": self._agent_name,
                },
                already_executed=True,
            )
            return result

        def save_state_json(self) -> Mapping[str, Any]:
            return self._inner.save_state_json()

        def load_state_json(self, state: Mapping[str, Any]) -> None:
            self._inner.load_state_json(state)

    return _RecordedTool


class LedgerHook:
    """Record every tool call an AutoGen agent makes, fail-closed.

    Parameters
    ----------
    fail_open:
        ``False`` by default: a recording failure raises
        :class:`LedgerHookError` from the wrapped tool. Before the call that
        prevents it; after the call it reports an incomplete trail. Either way
        AutoGen turns the error into a failed tool result for the agent, so
        the agent is not halted and ``run()`` returns normally. Set ``True``
        only where an incomplete audit trail is acceptable, knowing you have
        chosen it.
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
        self._recorder = LedgerRecorder(
            session_id,
            base_url,
            bearer_token,
            fail_open=fail_open,
            timeout=timeout,
        )

    # Read-only passthroughs, so existing code reading these keeps working.
    @property
    def session_id(self) -> str:
        return self._recorder.session_id

    @property
    def base_url(self) -> str:
        return self._recorder.base_url

    @property
    def fail_open(self) -> bool:
        return self._recorder.fail_open

    def close(self) -> None:
        self._recorder.close()

    def __enter__(self) -> "LedgerHook":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def wrap_tools(
        self,
        tools: Sequence["BaseTool[Any, Any] | Callable[..., Any] | Callable[..., Awaitable[Any]]"],
        *,
        agent_name: str | None = None,
    ) -> list["BaseTool[Any, Any]"]:
        """Return *tools*, each wrapped so its calls are recorded.

        Plain callables are converted with :class:`autogen_core.tools.FunctionTool`
        first, exactly as ``AssistantAgent`` would have done, so passing the
        result of this call is equivalent to passing the originals - plus the
        ledger.
        """
        base, function_tool = _autogen_tools()
        recorded = _recorded_tool_class(base)

        wrapped: list[Any] = []
        for tool in tools:
            if not isinstance(tool, base):
                if not callable(tool):
                    raise TypeError(f"Unsupported tool type: {type(tool)!r}")
                tool = function_tool(tool, description=(tool.__doc__ or ""))
            wrapped.append(recorded(tool, self._recorder, agent_name))
        return wrapped

    def attach(self, agent: Any) -> None:
        """Removed: this was the AutoGen 0.2 ``register_hook`` API.

        Raises :class:`NotImplementedError` rather than failing later with an
        ``AttributeError`` that reads like an AutoGen bug.
        """
        raise NotImplementedError(
            "LedgerHook.attach() used AutoGen 0.2's "
            "ConversableAgent.register_hook('process_last_received_message', …), "
            "which does not exist in autogen-agentchat 0.4+ - the version this "
            "SDK declares. Use LedgerHook.wrap_tools(...) and pass the result as "
            "the agent's `tools`; it records before each call rather than after "
            "each message, so a recording failure stops the action. See "
            "sdk/python/README.md."
        )
