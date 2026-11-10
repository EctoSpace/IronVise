"""LangChain integration for IronVise.

``LedgerTool`` was removed in 0.8.0 and replaced by
:class:`~ironvise_sdk.langchain.callback.LedgerCallbackHandler`. It was a tool
the model chose to call, so the audit trail existed only when the model
cooperated and nothing detected the times it did not. The callback fires because
the framework calls it, leaving the model nothing to decline.
"""

from ironvise_sdk.langchain.callback import LedgerCallbackHandler, RecordingFailed

__all__ = ["LedgerCallbackHandler", "RecordingFailed"]
