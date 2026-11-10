"""Microsoft AutoGen integration for IronVise.

Fail-closed since 0.8.0: a tool call that cannot be recorded is prevented.
AutoGen hands the agent an error result in its place, so the agent is not
halted and ``run()`` returns normally. Pass ``fail_open=True`` to
:class:`LedgerHook` to accept gaps deliberately.
"""

from ironvise_sdk.autogen.hook import LedgerHook, LedgerHookError

__all__ = ["LedgerHook", "LedgerHookError"]
