"""Every public ``LedgerClient`` method, described once for parametrized tests.

``test_client_errors.py`` and ``test_client_unicode.py`` drive each method
through the same failure and encoding cases. Keeping the table here means a new
client method is one row, and ``test_every_public_method_is_in_the_table``
fails until that row exists.
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass
from typing import Any, Awaitable, Callable
from urllib.parse import quote

from ironvise_sdk import LedgerClient

Call = Callable[[LedgerClient, str], Awaitable[Any]]


async def consume(stream: Any) -> list[dict]:
    return [event async for event in stream]


@dataclass(frozen=True)
class Endpoint:
    """One public client method and the request it makes.

    ``template`` is the request path; ``{}`` is where the identifier passed to
    ``call`` lands, percent-encoded. ``returns`` says how the method reads a
    2xx body: ``json`` (parsed, so a bad body is an error), ``text``, ``bytes``,
    ``none`` (ignored) or ``stream`` (SSE).
    """

    name: str
    http: str
    template: str
    call: Call
    returns: str
    context: str | None = None
    query_id: bool = False

    @property
    def op(self) -> str:
        """The operation label the client puts at the start of its error messages."""
        return self.context or self.name

    @property
    def takes_id(self) -> bool:
        return "{}" in self.template or self.query_id

    @property
    def param(self) -> str:
        """The name of the parameter ``call`` passes the identifier as."""
        return list(inspect.signature(getattr(LedgerClient, self.name)).parameters)[1]

    def path(self, ident: str) -> str:
        return self.template.format(quote(ident, safe="")) if "{}" in self.template else self.template


ENDPOINTS: list[Endpoint] = [
    Endpoint("list_sessions", "GET", "/api/sessions", lambda c, i: c.list_sessions(), "json"),
    Endpoint("create_session", "POST", "/api/sessions", lambda c, i: c.create_session("goal"), "json"),
    Endpoint("get_session", "GET", "/api/sessions/{}", lambda c, i: c.get_session(i), "json"),
    Endpoint("seal_session", "POST", "/api/sessions/{}/seal", lambda c, i: c.seal_session(i), "none"),
    Endpoint(
        "get_events", "GET", "/api/events", lambda c, i: c.get_events(i), "json", query_id=True
    ),
    Endpoint(
        "append_event",
        "POST",
        "/api/sessions/{}/events",
        lambda c, i: c.append_event(i, {"observation": "x"}),
        "json",
    ),
    Endpoint("stream_events", "GET", "/api/stream", lambda c, i: consume(c.stream_events()), "stream"),
    Endpoint(
        "stream_events",
        "GET",
        "/api/sessions/{}/events/stream",
        lambda c, i: consume(c.stream_events(i)),
        "stream",
    ),
    Endpoint(
        "verify_intent",
        "POST",
        "/api/sessions/{}/verify-intent",
        lambda c, i: c.verify_intent(i, "read_file", {"path": "/etc/hosts"}),
        "json",
    ),
    Endpoint("verify_session", "GET", "/api/sessions/{}/verify", lambda c, i: c.verify_session(i), "json"),
    Endpoint(
        "verify_chain",
        "GET",
        "/api/sessions/{}/verify",
        lambda c, i: c.verify_chain(i),
        "json",
        context="verify_session",
    ),
    Endpoint(
        "prove_compliance", "GET", "/api/sessions/{}/compliance", lambda c, i: c.prove_compliance(i), "json"
    ),
    Endpoint(
        "export_certificate", "GET", "/api/certificates/{}", lambda c, i: c.export_certificate(i), "bytes"
    ),
    Endpoint("get_report", "GET", "/api/reports/{}", lambda c, i: c.get_report(i), "json"),
    Endpoint("get_session_vc", "GET", "/api/sessions/{}/vc", lambda c, i: c.get_session_vc(i), "json"),
    Endpoint(
        "verify_session_vc",
        "GET",
        "/api/sessions/{}/vc/verify",
        lambda c, i: c.verify_session_vc(i),
        "json",
    ),
    Endpoint("get_metrics", "GET", "/api/metrics", lambda c, i: c.get_metrics(), "json"),
    Endpoint(
        "get_security_metrics", "GET", "/api/metrics/security", lambda c, i: c.get_security_metrics(), "json"
    ),
    Endpoint("get_prometheus_metrics", "GET", "/metrics", lambda c, i: c.get_prometheus_metrics(), "text"),
    Endpoint("list_policies", "GET", "/api/policies", lambda c, i: c.list_policies(), "json"),
    Endpoint("get_policy", "GET", "/api/policies/{}", lambda c, i: c.get_policy(i), "text"),
    Endpoint(
        "save_policy", "PUT", "/api/policies/{}", lambda c, i: c.save_policy(i, "[policy]\n"), "none"
    ),
    Endpoint("delete_policy", "DELETE", "/api/policies/{}", lambda c, i: c.delete_policy(i), "none"),
    Endpoint(
        "get_pending_approval",
        "GET",
        "/api/approvals/{}/pending",
        lambda c, i: c.get_pending_approval(i),
        "json",
    ),
    Endpoint(
        "post_approval_decision",
        "POST",
        "/api/approvals/{}",
        lambda c, i: c.post_approval_decision(i, "gate-1", True),
        "none",
    ),
    Endpoint("get_status", "GET", "/api/status", lambda c, i: c.get_status(), "json"),
    Endpoint("chat", "POST", "/api/sessions/{}/chat", lambda c, i: c.chat(i, "hello"), "json"),
    Endpoint(
        "chat_stream",
        "POST",
        "/api/sessions/{}/chat/stream",
        lambda c, i: consume(c.chat_stream(i, "hello")),
        "stream",
    ),
    Endpoint("ask", "POST", "/api/chat", lambda c, i: c.ask("hello"), "json"),
    Endpoint("ask_stream", "POST", "/api/chat/stream", lambda c, i: consume(c.ask_stream("hello")), "stream"),
    Endpoint("get_config", "GET", "/api/config", lambda c, i: c.get_config(), "json"),
    Endpoint("update_config", "PUT", "/api/config", lambda c, i: c.update_config({}), "json"),
    Endpoint(
        "get_tripwire_config", "GET", "/api/tripwire", lambda c, i: c.get_tripwire_config(), "json"
    ),
    Endpoint(
        "update_tripwire_config",
        "PUT",
        "/api/tripwire",
        lambda c, i: c.update_tripwire_config({}),
        "json",
    ),
    Endpoint(
        "check_tripwire", "POST", "/api/tripwire/check", lambda c, i: c.check_tripwire("read_file"), "json"
    ),
    Endpoint("list_tokens", "GET", "/api/tokens", lambda c, i: c.list_tokens(), "json"),
    Endpoint("create_token", "POST", "/api/tokens", lambda c, i: c.create_token("auditor"), "json"),
    Endpoint("delete_token", "DELETE", "/api/tokens/{}", lambda c, i: c.delete_token(i), "none"),
    Endpoint("list_webhooks", "GET", "/api/webhooks", lambda c, i: c.list_webhooks(), "json"),
    Endpoint(
        "create_webhook",
        "POST",
        "/api/webhooks",
        lambda c, i: c.create_webhook("siem", "https://siem.example/hook"),
        "json",
    ),
    Endpoint("delete_webhook", "DELETE", "/api/webhooks/{}", lambda c, i: c.delete_webhook(i), "none"),
    Endpoint(
        "toggle_webhook", "PUT", "/api/webhooks/{}", lambda c, i: c.toggle_webhook(i, False), "none"
    ),
    Endpoint("reset_demo", "POST", "/api/admin/reset-demo", lambda c, i: c.reset_demo(), "json"),
]

BY_NAME = {e.name: e for e in ENDPOINTS}
