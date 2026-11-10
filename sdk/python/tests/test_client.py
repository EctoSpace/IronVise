"""Tests for LedgerClient - mocked HTTP interaction via respx."""
from __future__ import annotations

import json

import pytest
import respx
import httpx

from ironvise_sdk.client import LedgerClient, LedgerSdkError
from ironvise_sdk.models import (
    AppendResult,
    ComplianceBundle,
    ConfigResponse,
    CreateTokenResponse,
    LedgerEvent,
    MetricsSummary,
    PendingApproval,
    SecurityMetrics,
    Session,
    StatusResponse,
    TokenListRow,
    TripwireCheckResult,
    TripwireConfig,
    VerifySessionResult,
    WebhookListRow,
)

pytestmark = pytest.mark.asyncio


@respx.mock
async def test_list_sessions_returns_session_objects(base_url: str, sample_session: dict) -> None:
    respx.get(f"{base_url}/api/sessions").mock(return_value=httpx.Response(200, json=[sample_session]))
    async with LedgerClient(base_url) as client:
        sessions = await client.list_sessions()
    assert len(sessions) == 1
    assert isinstance(sessions[0], Session)
    assert sessions[0].session_id == sample_session["session_id"]


@respx.mock
async def test_list_sessions_empty(base_url: str) -> None:
    respx.get(f"{base_url}/api/sessions").mock(return_value=httpx.Response(200, json=[]))
    async with LedgerClient(base_url) as client:
        sessions = await client.list_sessions()
    assert sessions == []


@respx.mock
async def test_list_sessions_http_error_raises(base_url: str) -> None:
    respx.get(f"{base_url}/api/sessions").mock(return_value=httpx.Response(500, json={"detail": "internal error"}))
    async with LedgerClient(base_url) as client:
        with pytest.raises(LedgerSdkError) as exc_info:
            await client.list_sessions()
    assert exc_info.value.status_code == 500


@respx.mock
async def test_list_sessions_passes_limit_param(base_url: str) -> None:
    route = respx.get(f"{base_url}/api/sessions").mock(return_value=httpx.Response(200, json=[]))
    async with LedgerClient(base_url) as client:
        await client.list_sessions(limit=10)
    assert route.called
    assert route.calls.last.request.url.params["limit"] == "10"


@respx.mock
async def test_create_session_minimal(base_url: str, sample_session: dict) -> None:
    respx.post(f"{base_url}/api/sessions").mock(return_value=httpx.Response(201, json=sample_session))
    async with LedgerClient(base_url) as client:
        session = await client.create_session(goal="audit the target")
    assert isinstance(session, Session)
    assert session.status == "running"


@respx.mock
async def test_create_session_does_not_accept_policy_hash_or_session_did(base_url: str) -> None:
    """The server never accepted either on creation; it sets both itself.

    ``create_session`` has no such parameters, so passing them raises a
    ``TypeError`` rather than silently discarding them.
    """
    async with LedgerClient(base_url) as client:
        with pytest.raises(TypeError):
            await client.create_session(goal="audit", policy_hash="abc")  # type: ignore[call-arg]
        with pytest.raises(TypeError):
            await client.create_session(goal="audit", session_did="did:key:z6Mk")  # type: ignore[call-arg]


@respx.mock
async def test_create_session_parses_response_fields_it_did_not_send(
    base_url: str, sample_session_finished: dict
) -> None:
    """``goal_hash`` and ``session_did`` are server-decided fields: they show
    up on the returned ``Session`` even though ``create_session`` never sends
    them in the request."""
    respx.post(f"{base_url}/api/sessions").mock(return_value=httpx.Response(201, json=sample_session_finished))
    async with LedgerClient(base_url) as client:
        session = await client.create_session(goal="audit")
    assert session.session_did == sample_session_finished["session_did"]
    assert session.finished_at is not None


@respx.mock
async def test_create_session_does_not_send_record_unless_asked(base_url: str, sample_session: dict) -> None:
    route = respx.post(f"{base_url}/api/sessions").mock(return_value=httpx.Response(201, json=sample_session))
    async with LedgerClient(base_url) as client:
        await client.create_session(goal="audit")
        await client.create_session(goal="audit", record=False)
    for call in route.calls:
        assert json.loads(call.request.content) == {"goal": "audit"}


@respx.mock
async def test_create_session_record_true_is_sent(base_url: str, sample_session: dict) -> None:
    route = respx.post(f"{base_url}/api/sessions").mock(
        return_value=httpx.Response(201, json={**sample_session, "llm_backend": "sdk-recorder"})
    )
    async with LedgerClient(base_url) as client:
        session = await client.create_session(goal="audit", record=True)
    assert json.loads(route.calls.last.request.content) == {"goal": "audit", "record": True}
    assert session.llm_backend == "sdk-recorder"


@respx.mock
async def test_create_session_error_raises(base_url: str) -> None:
    respx.post(f"{base_url}/api/sessions").mock(return_value=httpx.Response(422, json={"detail": "invalid goal"}))
    async with LedgerClient(base_url) as client:
        with pytest.raises(LedgerSdkError) as exc_info:
            await client.create_session(goal="")
    assert exc_info.value.status_code == 422


@respx.mock
async def test_seal_session_success(base_url: str, session_id: str) -> None:
    respx.post(f"{base_url}/api/sessions/{session_id}/seal").mock(return_value=httpx.Response(200, json={}))
    async with LedgerClient(base_url) as client:
        await client.seal_session(session_id)


@respx.mock
async def test_seal_session_not_found_raises(base_url: str) -> None:
    respx.post(f"{base_url}/api/sessions/nonexistent/seal").mock(return_value=httpx.Response(404, json={"detail": "not found"}))
    async with LedgerClient(base_url) as client:
        with pytest.raises(LedgerSdkError) as exc_info:
            await client.seal_session("nonexistent")
    assert exc_info.value.status_code == 404


@respx.mock
async def test_get_events_parses_the_server_rows(base_url: str, session_id: str, server_events: list[dict]) -> None:
    route = respx.get(f"{base_url}/api/events").mock(return_value=httpx.Response(200, json=server_events))
    async with LedgerClient(base_url) as client:
        events = await client.get_events(session_id)
    assert route.calls.last.request.url.params["session_id"] == session_id
    assert all(isinstance(e, LedgerEvent) for e in events)
    assert [(e.id, e.sequence, e.prev_hash, e.payload_hash, e.payload) for e in events] == [
        (r["id"], r["sequence"], r["previous_hash"], r["content_hash"], r["payload"]) for r in server_events
    ]


@respx.mock
async def test_get_events_empty_session(base_url: str, session_id: str) -> None:
    respx.get(f"{base_url}/api/events").mock(return_value=httpx.Response(200, json=[]))
    async with LedgerClient(base_url) as client:
        events = await client.get_events(session_id)
    assert events == []


@respx.mock
async def test_append_event_returns_append_result(base_url: str, session_id: str, sample_append_result: dict) -> None:
    respx.post(f"{base_url}/api/sessions/{session_id}/events").mock(return_value=httpx.Response(201, json=sample_append_result))
    async with LedgerClient(base_url) as client:
        result = await client.append_event(session_id, {"type": "thought", "content": "hello"})
    assert isinstance(result, AppendResult)
    assert result.id == sample_append_result["id"]
    assert result.sequence == 1


@respx.mock
async def test_append_event_4xx_raises(base_url: str, session_id: str) -> None:
    respx.post(f"{base_url}/api/sessions/{session_id}/events").mock(return_value=httpx.Response(400, json={"detail": "bad payload"}))
    async with LedgerClient(base_url) as client:
        with pytest.raises(LedgerSdkError) as exc_info:
            await client.append_event(session_id, {})
    assert exc_info.value.status_code == 400


@respx.mock
async def test_append_event_409_carries_the_server_message(base_url: str, session_id: str) -> None:
    # The text of crates/host/src/server/sdk.rs, append_event_handler, for a sealed session.
    message = (
        f"session {session_id} is completed: it is sealed, and an event appended now would make it "
        'fail verification. To record a run, create the session with "record": true; it stays '
        "open until you seal it."
    )
    respx.post(f"{base_url}/api/sessions/{session_id}/events").mock(return_value=httpx.Response(409, text=message))
    async with LedgerClient(base_url) as client:
        with pytest.raises(LedgerSdkError) as exc_info:
            await client.append_event(session_id, {})
    assert exc_info.value.status_code == 409
    assert exc_info.value.body == message
    assert str(exc_info.value) == f"append_event: HTTP 409: {message}"


@respx.mock
async def test_error_message_uses_the_json_error_field(base_url: str) -> None:
    respx.get(f"{base_url}/api/sessions").mock(return_value=httpx.Response(403, json={"error": "admin role required"}))
    async with LedgerClient(base_url) as client:
        with pytest.raises(LedgerSdkError) as exc_info:
            await client.list_sessions()
    assert str(exc_info.value) == "list_sessions: HTTP 403: admin role required"
    assert exc_info.value.body == '{"error":"admin role required"}'


@respx.mock
async def test_error_message_uses_the_json_message_field(base_url: str) -> None:
    respx.get(f"{base_url}/api/sessions").mock(return_value=httpx.Response(403, json={"message": "no", "status": 403}))
    async with LedgerClient(base_url) as client:
        with pytest.raises(LedgerSdkError) as exc_info:
            await client.list_sessions()
    assert str(exc_info.value) == "list_sessions: HTTP 403: no"


@respx.mock
async def test_error_message_is_bounded_but_body_is_whole(base_url: str) -> None:
    body = "x" * 1000
    respx.get(f"{base_url}/api/sessions").mock(return_value=httpx.Response(500, text=body))
    async with LedgerClient(base_url) as client:
        with pytest.raises(LedgerSdkError) as exc_info:
            await client.list_sessions()
    assert str(exc_info.value) == f"list_sessions: HTTP 500: {'x' * 300}…"
    assert exc_info.value.body == body


@respx.mock
async def test_error_message_without_a_body_is_just_the_status(base_url: str) -> None:
    respx.get(f"{base_url}/api/sessions").mock(return_value=httpx.Response(502))
    async with LedgerClient(base_url) as client:
        with pytest.raises(LedgerSdkError) as exc_info:
            await client.list_sessions()
    assert str(exc_info.value) == "list_sessions: HTTP 502"


SIGNATURES_OK = {"verified": True, "verdict": "verified", "message": "2 signed events verified", "signed": 2, "unsigned": 0}
SIGNATURES_FAILED = {
    "verified": False,
    "verdict": "signature_mismatch",
    "message": "event 2 is not signed by the session key",
    "signed": 0,
    "unsigned": 0,
}


@respx.mock
async def test_verify_chain_ok(base_url: str, session_id: str) -> None:
    respx.get(f"{base_url}/api/sessions/{session_id}/verify").mock(
        return_value=httpx.Response(200, json={"ok": True, "signatures": SIGNATURES_OK})
    )
    async with LedgerClient(base_url) as client:
        result = await client.verify_chain(session_id)
    assert result is True


@respx.mock
async def test_verify_chain_tampered(base_url: str, session_id: str) -> None:
    respx.get(f"{base_url}/api/sessions/{session_id}/verify").mock(
        return_value=httpx.Response(200, json={"ok": False, "signatures": SIGNATURES_OK})
    )
    async with LedgerClient(base_url) as client:
        result = await client.verify_chain(session_id)
    assert result is False


@respx.mock
async def test_verify_chain_false_when_chain_links_but_signatures_fail(base_url: str, session_id: str) -> None:
    respx.get(f"{base_url}/api/sessions/{session_id}/verify").mock(
        return_value=httpx.Response(200, json={"ok": True, "signatures": SIGNATURES_FAILED})
    )
    async with LedgerClient(base_url) as client:
        result = await client.verify_chain(session_id)
    assert result is False


@respx.mock
async def test_verify_chain_trusts_ok_alone_on_an_older_server(base_url: str, session_id: str) -> None:
    route = respx.get(f"{base_url}/api/sessions/{session_id}/verify")
    async with LedgerClient(base_url) as client:
        route.mock(return_value=httpx.Response(200, json={"ok": True}))
        assert await client.verify_chain(session_id) is True
        route.mock(return_value=httpx.Response(200, json={"ok": False}))
        assert await client.verify_chain(session_id) is False


@respx.mock
async def test_verify_session_returns_the_parsed_verdict(base_url: str, session_id: str) -> None:
    respx.get(f"{base_url}/api/sessions/{session_id}/verify").mock(
        return_value=httpx.Response(200, json={"ok": True, "signatures": SIGNATURES_FAILED})
    )
    async with LedgerClient(base_url) as client:
        result = await client.verify_session(session_id)
    assert isinstance(result, VerifySessionResult)
    assert result.ok is True
    assert result.signatures is not None
    assert result.signatures.verified is False
    assert result.signatures.verdict == "signature_mismatch"
    assert result.signatures.message == SIGNATURES_FAILED["message"]
    assert (result.signatures.signed, result.signatures.unsigned) == (0, 0)


@respx.mock
async def test_verify_session_without_signatures(base_url: str, session_id: str) -> None:
    respx.get(f"{base_url}/api/sessions/{session_id}/verify").mock(return_value=httpx.Response(200, json={"ok": True}))
    async with LedgerClient(base_url) as client:
        result = await client.verify_session(session_id)
    assert result.ok is True
    assert result.signatures is None


@respx.mock
async def test_verify_session_not_found_raises(base_url: str) -> None:
    respx.get(f"{base_url}/api/sessions/nonexistent/verify").mock(return_value=httpx.Response(404, text="no session"))
    async with LedgerClient(base_url) as client:
        with pytest.raises(LedgerSdkError) as exc_info:
            await client.verify_session("nonexistent")
    assert exc_info.value.status_code == 404


@respx.mock
async def test_prove_compliance_parses_the_server_bundle(base_url: str, session_id: str, server_compliance: dict) -> None:
    respx.get(f"{base_url}/api/sessions/{session_id}/compliance").mock(return_value=httpx.Response(200, json=server_compliance))
    async with LedgerClient(base_url) as client:
        result = await client.prove_compliance(session_id)
    assert isinstance(result, ComplianceBundle)
    assert result.session_id == session_id
    assert result.event_count == 3
    assert [(e.sequence, e.content_hash) for e in result.events] == [(e["sequence"], e["content_hash"]) for e in server_compliance["events"]]


@respx.mock
async def test_prove_compliance_error_carries_the_server_message(base_url: str, session_id: str) -> None:
    respx.get(f"{base_url}/api/sessions/{session_id}/compliance").mock(
        return_value=httpx.Response(500, text="Compliance proof failed: database error")
    )
    async with LedgerClient(base_url) as client:
        with pytest.raises(LedgerSdkError) as exc_info:
            await client.prove_compliance(session_id)
    assert str(exc_info.value) == "prove_compliance: HTTP 500: Compliance proof failed: database error"


@respx.mock
async def test_export_certificate_returns_bytes(base_url: str, session_id: str) -> None:
    pdf_bytes = b"%PDF-1.4 fake certificate content"
    respx.get(f"{base_url}/api/certificates/{session_id}").mock(return_value=httpx.Response(200, content=pdf_bytes, headers={"content-type": "application/pdf"}))
    async with LedgerClient(base_url) as client:
        result = await client.export_certificate(session_id)
    assert isinstance(result, bytes)
    assert result.startswith(b"%PDF")


@respx.mock
async def test_get_report_returns_dict(base_url: str, session_id: str) -> None:
    report = {"session_id": session_id, "findings": [{"title": "Open port"}], "summary": "ok"}
    respx.get(f"{base_url}/api/reports/{session_id}").mock(return_value=httpx.Response(200, json=report))
    async with LedgerClient(base_url) as client:
        result = await client.get_report(session_id)
    assert isinstance(result, dict)
    assert result["summary"] == "ok"


@respx.mock
async def test_get_session_vc_returns_dict(base_url: str, session_id: str) -> None:
    vc_data = {"vc_jwt": "ey.ey.sig", "vc_payload": {"sub": session_id}}
    respx.get(f"{base_url}/api/sessions/{session_id}/vc").mock(return_value=httpx.Response(200, json=vc_data))
    async with LedgerClient(base_url) as client:
        result = await client.get_session_vc(session_id)
    assert result["vc_jwt"] == "ey.ey.sig"


@respx.mock
async def test_verify_session_vc_valid(base_url: str, session_id: str) -> None:
    vc_verify = {"valid": True, "signature_verified": True, "vc_jwt": "ey.ey.sig", "vc_payload": {}}
    route = respx.get(f"{base_url}/api/sessions/{session_id}/vc/verify").mock(return_value=httpx.Response(200, json=vc_verify))
    async with LedgerClient(base_url) as client:
        result = await client.verify_session_vc(session_id)
    assert result["valid"] is True
    assert "audience" not in route.calls.last.request.url.params


@respx.mock
async def test_verify_session_vc_sends_audience_when_given(base_url: str, session_id: str) -> None:
    vc_verify = {"valid": True, "signature_verified": True, "vc_jwt": "ey.ey.sig", "vc_payload": {}}
    route = respx.get(f"{base_url}/api/sessions/{session_id}/vc/verify").mock(return_value=httpx.Response(200, json=vc_verify))
    async with LedgerClient(base_url) as client:
        await client.verify_session_vc(session_id, audience="https://verifier.example")
    assert route.calls.last.request.url.params["audience"] == "https://verifier.example"


@respx.mock
async def test_get_metrics_parses_summary(base_url: str, sample_metrics: dict) -> None:
    respx.get(f"{base_url}/api/metrics").mock(return_value=httpx.Response(200, json=sample_metrics))
    async with LedgerClient(base_url) as client:
        metrics = await client.get_metrics()
    assert isinstance(metrics, MetricsSummary)
    assert metrics.total_sessions == 7
    assert metrics.total_events == 130


@respx.mock
async def test_get_metrics_extra_fields_captured(base_url: str) -> None:
    # `extra` in MetricsSummary is a named field that the server must explicitly
    # populate; Pydantic v2 ignores unknown top-level keys by default.
    respx.get(f"{base_url}/api/metrics").mock(return_value=httpx.Response(200, json={"total_sessions": 0, "total_events": 0, "p99_latency_ms": 42.5}))
    async with LedgerClient(base_url) as client:
        metrics = await client.get_metrics()
    assert metrics.extra == {}  # unknown keys are discarded; server must send {"extra": {...}}


@respx.mock
async def test_get_security_metrics(base_url: str) -> None:
    data = {"injection_attempts_detected_7d": 3, "injection_attempts_by_layer": {"tripwire": 2, "guard_llm": 1}, "sessions_aborted_circuit_breaker": 0, "chain_verification_failures": 0}
    respx.get(f"{base_url}/api/metrics/security").mock(return_value=httpx.Response(200, json=data))
    async with LedgerClient(base_url) as client:
        sec = await client.get_security_metrics()
    assert isinstance(sec, SecurityMetrics)
    assert sec.injection_attempts_detected_7d == 3
    assert sec.injection_attempts_by_layer["tripwire"] == 2


@respx.mock
async def test_get_prometheus_metrics(base_url: str) -> None:
    raw = "# HELP sessions_total Total sessions\nsessions_total 42\n"
    respx.get(f"{base_url}/metrics").mock(return_value=httpx.Response(200, text=raw))
    async with LedgerClient(base_url) as client:
        text = await client.get_prometheus_metrics()
    assert "sessions_total 42" in text


@respx.mock
async def test_list_policies_returns_list(base_url: str) -> None:
    respx.get(f"{base_url}/api/policies").mock(return_value=httpx.Response(200, json=["soc2-audit", "iso42001"]))
    async with LedgerClient(base_url) as client:
        policies = await client.list_policies()
    assert policies == ["soc2-audit", "iso42001"]


@respx.mock
async def test_get_policy_returns_text(base_url: str) -> None:
    toml_content = "[rules]\nmin_justification_length = 10\n"
    respx.get(f"{base_url}/api/policies/soc2-audit").mock(return_value=httpx.Response(200, text=toml_content))
    async with LedgerClient(base_url) as client:
        content = await client.get_policy("soc2-audit")
    assert "min_justification_length" in content


@respx.mock
async def test_save_policy_success(base_url: str) -> None:
    respx.put(f"{base_url}/api/policies/soc2-audit").mock(return_value=httpx.Response(200))
    async with LedgerClient(base_url) as client:
        await client.save_policy("soc2-audit", "[rules]\nmin_justification_length = 10")


@respx.mock
async def test_delete_policy_success(base_url: str) -> None:
    respx.delete(f"{base_url}/api/policies/soc2-audit").mock(return_value=httpx.Response(200))
    async with LedgerClient(base_url) as client:
        await client.delete_policy("soc2-audit")


@respx.mock
async def test_get_pending_approval_returns_pending(base_url: str, session_id: str) -> None:
    pending_data = {
        "pending": {
            "gate_id": "gate-1",
            "action_name": "run_command",
            "action_params_summary": "ls -la /etc",
            "created_at": "2026-02-22T10:05:00Z",
        }
    }
    respx.get(f"{base_url}/api/approvals/{session_id}/pending").mock(return_value=httpx.Response(200, json=pending_data))
    async with LedgerClient(base_url) as client:
        result = await client.get_pending_approval(session_id)
    assert isinstance(result, PendingApproval)
    assert result.gate_id == "gate-1"
    assert result.action_name == "run_command"


@respx.mock
async def test_get_pending_approval_returns_none(base_url: str, session_id: str) -> None:
    respx.get(f"{base_url}/api/approvals/{session_id}/pending").mock(return_value=httpx.Response(200, json={"pending": None}))
    async with LedgerClient(base_url) as client:
        result = await client.get_pending_approval(session_id)
    assert result is None


@respx.mock
async def test_post_approval_decision_approve(base_url: str, session_id: str) -> None:
    respx.post(f"{base_url}/api/approvals/{session_id}").mock(return_value=httpx.Response(200, json={"ok": True}))
    async with LedgerClient(base_url) as client:
        await client.post_approval_decision(session_id, gate_id="gate-1", approved=True, reason="Looks safe")


@respx.mock
async def test_post_approval_decision_deny(base_url: str, session_id: str) -> None:
    respx.post(f"{base_url}/api/approvals/{session_id}").mock(return_value=httpx.Response(200, json={"ok": True}))
    async with LedgerClient(base_url) as client:
        await client.post_approval_decision(session_id, gate_id="gate-1", approved=False)


@respx.mock
async def test_bearer_token_is_sent(base_url: str, sample_session: dict) -> None:
    route = respx.get(f"{base_url}/api/sessions").mock(return_value=httpx.Response(200, json=[sample_session]))
    async with LedgerClient(base_url, bearer_token="super-secret-token") as client:
        await client.list_sessions()
    assert route.calls.last.request.headers.get("authorization") == "Bearer super-secret-token"


async def test_client_timeout_raises() -> None:
    async with LedgerClient("http://127.0.0.1:19999", timeout=0.01) as client:
        with pytest.raises(httpx.TransportError):
            await client.list_sessions()


@respx.mock
async def test_get_status(base_url: str) -> None:
    respx.get(f"{base_url}/api/status").mock(return_value=httpx.Response(200, json={"demo_mode": True, "version": "0.7.2"}))
    async with LedgerClient(base_url) as client:
        status = await client.get_status()
    assert isinstance(status, StatusResponse)
    assert status.demo_mode is True
    assert status.version == "0.7.2"
    # An older server sends none of the 0.8.0 capability fields.
    assert status.ledger_backend == ""
    assert status.agent_supported is False


@respx.mock
async def test_get_status_parses_0_8_0_capability_fields(base_url: str) -> None:
    data = {
        "demo_mode": False,
        "version": "0.8.0",
        "ledger_backend": "postgres",
        "agent_supported": True,
        "exports_supported": True,
        "webhooks_live": True,
    }
    respx.get(f"{base_url}/api/status").mock(return_value=httpx.Response(200, json=data))
    async with LedgerClient(base_url) as client:
        status = await client.get_status()
    assert status.ledger_backend == "postgres"
    assert status.agent_supported is True
    assert status.exports_supported is True
    assert status.webhooks_live is True


@respx.mock
async def test_get_session_by_id(base_url: str, session_id: str, sample_session: dict) -> None:
    respx.get(f"{base_url}/api/sessions/{session_id}").mock(return_value=httpx.Response(200, json=sample_session))
    async with LedgerClient(base_url) as client:
        session = await client.get_session(session_id)
    assert isinstance(session, Session)
    assert session.session_id == session_id


@respx.mock
async def test_chat(base_url: str, session_id: str) -> None:
    reply = {"role": "assistant", "content": "Hello from the LLM"}
    respx.post(f"{base_url}/api/sessions/{session_id}/chat").mock(return_value=httpx.Response(200, json=reply))
    async with LedgerClient(base_url) as client:
        result = await client.chat(session_id, message="Hi")
    assert result["role"] == "assistant"


@respx.mock
async def test_get_config(base_url: str) -> None:
    data = {"database_url": "sqlite://db.sqlite", "llm_backend": "ollama", "ollama_base_url": "", "ollama_model": "", "guard_required": False, "max_steps": 50, "agent_allowed_domains": [], "sandbox_mode": "docker", "demo_mode": True}
    respx.get(f"{base_url}/api/config").mock(return_value=httpx.Response(200, json=data))
    async with LedgerClient(base_url) as client:
        config = await client.get_config()
    assert isinstance(config, ConfigResponse)
    assert config.max_steps == 50
    # An older server sends none of the 0.8.0 fields; defaults keep parsing lenient.
    assert config.ledger_backend == ""
    assert config.active_policy is None


@respx.mock
async def test_get_config_parses_0_8_0_fields(base_url: str) -> None:
    data = {
        "database_url": "sqlite://db.sqlite",
        "llm_backend": "ollama",
        "ollama_base_url": "",
        "openai_base_url": "https://api.openai.com/v1",
        "ollama_model": "",
        "guard_required": True,
        "guard_required_source": "environment",
        "max_steps": 50,
        "agent_allowed_domains": [],
        "sandbox_mode": "docker",
        "demo_mode": True,
        "show_developer_tools": True,
        "ledger_backend": "postgres",
        "agent_supported": True,
        "exports_supported": False,
        "webhooks_live": True,
        "active_policy": "soc2-audit",
        "policy_from_environment": None,
    }
    respx.get(f"{base_url}/api/config").mock(return_value=httpx.Response(200, json=data))
    async with LedgerClient(base_url) as client:
        config = await client.get_config()
    assert config.openai_base_url == "https://api.openai.com/v1"
    assert config.guard_required_source == "environment"
    assert config.ledger_backend == "postgres"
    assert config.agent_supported is True
    assert config.webhooks_live is True
    assert config.active_policy == "soc2-audit"
    assert config.policy_from_environment is None


@respx.mock
async def test_update_config(base_url: str) -> None:
    respx.put(f"{base_url}/api/config").mock(return_value=httpx.Response(200, json={"ok": True}))
    async with LedgerClient(base_url) as client:
        result = await client.update_config({"max_steps": 100})
    assert result["ok"] is True


@respx.mock
async def test_get_tripwire_config(base_url: str) -> None:
    data = {"allowed_paths": ["/tmp"], "allowed_domains": ["example.com"], "banned_command_patterns": [], "min_justification_length": 10, "require_https": True}
    respx.get(f"{base_url}/api/tripwire").mock(return_value=httpx.Response(200, json=data))
    async with LedgerClient(base_url) as client:
        tw = await client.get_tripwire_config()
    assert isinstance(tw, TripwireConfig)
    assert tw.require_https is True
    # Older servers send neither field; defaults keep parsing lenient.
    assert tw.allowed_mcp_tools == []
    assert tw.saved is None


@respx.mock
async def test_get_tripwire_config_parses_allowed_mcp_tools_and_saved(base_url: str) -> None:
    data = {
        "allowed_paths": ["/tmp"],
        "allowed_domains": ["example.com"],
        "banned_command_patterns": [],
        "min_justification_length": 10,
        "require_https": True,
        "allowed_mcp_tools": ["fs/read", "web/*"],
        "saved": True,
    }
    respx.get(f"{base_url}/api/tripwire").mock(return_value=httpx.Response(200, json=data))
    async with LedgerClient(base_url) as client:
        tw = await client.get_tripwire_config()
    assert tw.allowed_mcp_tools == ["fs/read", "web/*"]
    assert tw.saved is True


@respx.mock
async def test_update_tripwire_config(base_url: str) -> None:
    respx.put(f"{base_url}/api/tripwire").mock(return_value=httpx.Response(200, json={"ok": True}))
    async with LedgerClient(base_url) as client:
        result = await client.update_tripwire_config({"require_https": False})
    assert result["ok"] is True


@respx.mock
async def test_check_tripwire_allowed(base_url: str) -> None:
    route = respx.post(f"{base_url}/api/tripwire/check").mock(
        return_value=httpx.Response(200, json={"allowed": True, "reason": None, "rule": None, "matched": None})
    )
    async with LedgerClient(base_url) as client:
        result = await client.check_tripwire(
            "read_file", params={"path": "/tmp/report.txt"}, justification="Checking before the agent reads it."
        )
    assert isinstance(result, TripwireCheckResult)
    assert result.allowed is True
    assert result.reason is None
    sent = json.loads(route.calls.last.request.content)
    assert sent == {
        "action": "read_file",
        "params": {"path": "/tmp/report.txt"},
        "justification": "Checking before the agent reads it.",
    }


@respx.mock
async def test_check_tripwire_refused(base_url: str) -> None:
    respx.post(f"{base_url}/api/tripwire/check").mock(
        return_value=httpx.Response(
            200,
            json={
                "allowed": False,
                "reason": "path /etc/shadow is not in the allowed paths",
                "rule": "allowed_paths",
                "matched": "/etc/shadow",
            },
        )
    )
    async with LedgerClient(base_url) as client:
        result = await client.check_tripwire("read_file", params={"path": "/etc/shadow"})
    assert result.allowed is False
    assert result.rule == "allowed_paths"
    assert result.matched == "/etc/shadow"


@respx.mock
async def test_check_tripwire_omits_justification_when_not_given(base_url: str) -> None:
    route = respx.post(f"{base_url}/api/tripwire/check").mock(
        return_value=httpx.Response(200, json={"allowed": True, "reason": None, "rule": None, "matched": None})
    )
    async with LedgerClient(base_url) as client:
        await client.check_tripwire("complete")
    sent = json.loads(route.calls.last.request.content)
    assert sent == {"action": "complete", "params": {}}


@respx.mock
async def test_check_tripwire_http_error_raises(base_url: str) -> None:
    respx.post(f"{base_url}/api/tripwire/check").mock(return_value=httpx.Response(400, json={"detail": "bad request"}))
    async with LedgerClient(base_url) as client:
        with pytest.raises(LedgerSdkError) as exc_info:
            await client.check_tripwire("")
    assert exc_info.value.status_code == 400


@respx.mock
async def test_list_tokens(base_url: str) -> None:
    data = [{"token_hash": "abc", "role": "Admin", "label": "CI", "created_at": "2026-01-01T00:00:00Z", "expires_at": None}]
    respx.get(f"{base_url}/api/tokens").mock(return_value=httpx.Response(200, json=data))
    async with LedgerClient(base_url) as client:
        tokens = await client.list_tokens()
    assert len(tokens) == 1
    assert isinstance(tokens[0], TokenListRow)
    assert tokens[0].role == "Admin"


@respx.mock
async def test_create_token(base_url: str) -> None:
    data = {"token": "raw-secret-123", "token_hash": "hashed", "role": "Agent", "label": "test"}
    respx.post(f"{base_url}/api/tokens").mock(return_value=httpx.Response(201, json=data))
    async with LedgerClient(base_url) as client:
        result = await client.create_token(role="Agent", label="test")
    assert isinstance(result, CreateTokenResponse)
    assert result.token == "raw-secret-123"


@respx.mock
async def test_delete_token(base_url: str) -> None:
    respx.delete(f"{base_url}/api/tokens/abc123").mock(return_value=httpx.Response(200))
    async with LedgerClient(base_url) as client:
        await client.delete_token("abc123")


@respx.mock
async def test_list_webhooks(base_url: str) -> None:
    data = [{"id": "wh-1", "label": "Slack", "url": "https://hooks.slack.com/x", "siem_format": "json", "filter_kinds": [], "enabled": True, "created_at": "2026-01-01T00:00:00Z"}]
    respx.get(f"{base_url}/api/webhooks").mock(return_value=httpx.Response(200, json=data))
    async with LedgerClient(base_url) as client:
        webhooks = await client.list_webhooks()
    assert len(webhooks) == 1
    assert isinstance(webhooks[0], WebhookListRow)


@respx.mock
async def test_create_webhook(base_url: str) -> None:
    data = {"id": "wh-2", "label": "Splunk", "url": "https://splunk.example.com", "siem_format": "cef", "filter_kinds": ["alert"], "enabled": True, "created_at": "2026-01-01T00:00:00Z"}
    route = respx.post(f"{base_url}/api/webhooks").mock(return_value=httpx.Response(201, json=data))
    async with LedgerClient(base_url) as client:
        result = await client.create_webhook(label="Splunk", url="https://splunk.example.com", siem_format="cef", filter_kinds=["alert"])
    assert isinstance(result, WebhookListRow)
    assert result.siem_format == "cef"
    # enabled defaults true and bearer_token is omitted when not given.
    sent = json.loads(route.calls.last.request.content)
    assert sent["enabled"] is True
    assert "bearer_token" not in sent


@respx.mock
async def test_create_webhook_with_bearer_token_and_enabled(base_url: str) -> None:
    data = {"id": "wh-3", "label": "SIEM", "url": "https://siem.example.com", "siem_format": "json", "filter_kinds": [], "enabled": False, "created_at": "2026-01-01T00:00:00Z"}
    route = respx.post(f"{base_url}/api/webhooks").mock(return_value=httpx.Response(201, json=data))
    async with LedgerClient(base_url) as client:
        result = await client.create_webhook(
            label="SIEM", url="https://siem.example.com", bearer_token="s3cret", enabled=False
        )
    sent = json.loads(route.calls.last.request.content)
    assert sent["bearer_token"] == "s3cret"
    assert sent["enabled"] is False
    assert result.enabled is False


@respx.mock
async def test_delete_webhook(base_url: str) -> None:
    respx.delete(f"{base_url}/api/webhooks/wh-1").mock(return_value=httpx.Response(200))
    async with LedgerClient(base_url) as client:
        await client.delete_webhook("wh-1")


@respx.mock
async def test_toggle_webhook(base_url: str) -> None:
    # The server answers 200 with no body (webhooks_api::toggle_webhook).
    route = respx.put(f"{base_url}/api/webhooks/wh-1").mock(return_value=httpx.Response(200))
    async with LedgerClient(base_url) as client:
        result = await client.toggle_webhook("wh-1", enabled=False)
    assert result is None
    assert json.loads(route.calls.last.request.content) == {"enabled": False}


@respx.mock
async def test_reset_demo(base_url: str) -> None:
    respx.post(f"{base_url}/api/admin/reset-demo").mock(return_value=httpx.Response(200, json={"ok": True, "message": "demo reset"}))
    async with LedgerClient(base_url) as client:
        result = await client.reset_demo()
    assert result["ok"] is True


@respx.mock
async def test_stream_events_without_a_session_reads_every_session(base_url: str) -> None:
    body = 'event: event\ndata: {"session_id": "a", "sequence": 1}\n\nevent: event\ndata: {"session_id": "b", "sequence": 1}\n\n'
    respx.get(f"{base_url}/api/stream").mock(return_value=httpx.Response(200, text=body))
    async with LedgerClient(base_url) as client:
        events = [e async for e in client.stream_events()]
    assert [e["session_id"] for e in events] == ["a", "b"]
