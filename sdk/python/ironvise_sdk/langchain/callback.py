"""LangChain integration - a callback handler, not a tool.

**Breaking change in 0.8.0.** ``LedgerTool`` is gone. It was a *tool the model
chose to call*, which means the audit trail existed only when the model felt
like producing one - and nothing detected the times it did not. A voluntary
audit trail is not an audit trail; it is a log with a survivorship bias that
looks complete precisely when it is least complete.

``LedgerCallbackHandler`` uses LangChain's callback interface instead.
``on_tool_start`` fires whether or not the model cooperates, because the
framework calls it, not the model. There is nothing for the model to decline.

Fail-closed by default, like the rest of the SDK: if an event cannot be
recorded the run stops. Pass ``fail_open=True`` to accept gaps deliberately.

Stopping the run takes one more thing than raising. LangChain's callback
manager catches everything a handler throws and *logs* it, unless the handler
sets ``raise_error``. An earlier cut of this handler raised and the framework
swallowed it, so a tool ran with no record and the caller saw a successful
return. This handler sets ``raise_error`` from ``fail_open``, and
``tests/test_langchain_callback.py`` drives a real ``StructuredTool`` through
the real callback manager - sync and async - and asserts on the tool's side
effect rather than on the exception.

What fail-closed can and cannot do here is decided by *when* the recording
fails. ``on_tool_start`` runs before the tool, so a failure there prevents the
call. ``on_tool_end`` runs after it, so a failure there stops the rest of the
run but cannot undo what the tool did; the error says so.

Usage::

    from ironvise_sdk.langchain import LedgerCallbackHandler

    handler = LedgerCallbackHandler(session_id="<uuid>")
    agent.invoke({"input": "…"}, config={"callbacks": [handler]})
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

try:
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "Install 'langchain-core' (pip install ironvise[langchain]) to use "
        "LedgerCallbackHandler."
    ) from e

from ironvise_sdk._recorder import LedgerRecorder, RecordingFailed

__all__ = ["LedgerCallbackHandler", "RecordingFailed"]


class LedgerCallbackHandler(BaseCallbackHandler):
    """Record every tool call an agent makes, whether or not the model asks.

    Parameters
    ----------
    session_id:
        The ledger session to append to.
    fail_open:
        ``False`` by default - a recording failure raises, ``raise_error`` is
        set so LangChain propagates it, and the run stops.
    record_llm_calls:
        Also record prompts sent to the model. Off by default: prompts are
        frequently the most sensitive content an agent handles, and putting them
        in an append-only, externally anchorable ledger should be a choice.
    """

    def __init__(
        self,
        session_id: str,
        base_url: str = "http://localhost:3000",
        bearer_token: str | None = None,
        *,
        fail_open: bool = False,
        timeout: float = 30.0,
        record_llm_calls: bool = False,
    ) -> None:
        super().__init__()
        self._recorder = LedgerRecorder(
            session_id,
            base_url,
            bearer_token,
            fail_open=fail_open,
            timeout=timeout,
        )
        self.record_llm_calls = record_llm_calls
        # `BaseCallbackHandler.raise_error` is False by default, and
        # `langchain_core.callbacks.manager.handle_event` consults it before
        # re-raising. Without this line the fail-closed contract stops at the
        # edge of this class.
        self.raise_error = not fail_open

    def close(self) -> None:
        self._recorder.close()

    def __enter__(self) -> "LedgerCallbackHandler":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        self._recorder.record(
            {
                "observation": f"tool_start: {input_str}",
                "kind": "tool_start",
                "tool_name": (serialized or {}).get("name", "unknown"),
                "run_id": str(run_id) if run_id else None,
            }
        )

    def on_tool_end(self, output: Any, *, run_id: UUID | None = None, **kwargs: Any) -> None:
        # The tool has already run. `already_executed` keeps the failure from
        # reading as though the call was prevented.
        self._recorder.record(
            {
                "observation": str(output),
                "kind": "tool_end",
                "run_id": str(run_id) if run_id else None,
            },
            already_executed=True,
        )

    def on_tool_error(
        self, error: BaseException, *, run_id: UUID | None = None, **kwargs: Any
    ) -> None:
        # A failed tool call is part of the record. Omitting failures would make
        # the trail read as though everything the agent attempted succeeded.
        self._recorder.record(
            {
                "observation": f"tool_error: {error}",
                "kind": "tool_error",
                "run_id": str(run_id) if run_id else None,
            },
            already_executed=True,
        )

    def on_agent_action(self, action: Any, **kwargs: Any) -> None:
        self._recorder.record(
            {
                "observation": str(getattr(action, "log", action)),
                "kind": "agent_action",
                "tool_name": getattr(action, "tool", None),
            }
        )

    def on_agent_finish(self, finish: Any, **kwargs: Any) -> None:
        self._recorder.record(
            {
                "observation": str(getattr(finish, "log", finish)),
                "kind": "agent_finish",
            },
            already_executed=True,
        )

    def on_llm_start(
        self, serialized: dict[str, Any], prompts: list[str], **kwargs: Any
    ) -> None:
        if not self.record_llm_calls:
            return
        self._recorder.record(
            {
                "observation": "\n---\n".join(prompts),
                "kind": "llm_start",
                "model": (serialized or {}).get("name"),
            }
        )
