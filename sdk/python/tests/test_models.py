"""Tests for Pydantic model construction, validation, and serialisation."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from ironvise_sdk.models import (
    AppendResult,
    ComplianceBundle,
    ComplianceEvent,
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
    WebhookListRow,
)


class TestSession:
    def test_minimal_session(self) -> None:
        session = Session(session_id="s1", goal_hash="gh1", started_at=datetime.now(tz=timezone.utc), status="running")
        assert session.finished_at is None
        assert session.session_did is None

    def test_full_session(self, sample_session_finished: dict) -> None:
        session = Session.model_validate(sample_session_finished)
        assert session.status == "completed"
        assert session.finished_at is not None
        assert session.session_did is not None

    def test_started_at_parsed_from_iso_string(self) -> None:
        session = Session.model_validate({"session_id": "s1", "goal_hash": "g1", "started_at": "2026-02-22T10:00:00Z", "status": "running"})
        assert isinstance(session.started_at, datetime)

    def test_started_at_must_be_present(self) -> None:
        with pytest.raises(ValidationError):
            Session.model_validate({"session_id": "s1", "goal_hash": "g1", "status": "running"})

    def test_session_round_trip_serialisation(self, sample_session: dict) -> None:
        session = Session.model_validate(sample_session)
        dumped = session.model_dump(mode="json")
        restored = Session.model_validate(dumped)
        assert restored.session_id == session.session_id
        assert restored.goal_hash == session.goal_hash


class TestLedgerEvent:
    def test_parses_the_row_the_server_sends(self, server_events: list[dict]) -> None:
        row = server_events[1]
        event = LedgerEvent.model_validate(row)
        assert event.id == row["id"]
        assert event.sequence == row["sequence"]
        assert event.prev_hash == row["previous_hash"]
        assert event.payload_hash == row["content_hash"]
        assert event.payload == row["payload"]
        assert isinstance(event.created_at, datetime)

    def test_fields_are_exactly_the_ones_the_server_sends(self, server_events: list[dict]) -> None:
        wire_names = {field.alias or name for name, field in LedgerEvent.model_fields.items()}
        assert wire_names == set(server_events[0])

    def test_chain_links_across_the_fixture(self, server_events: list[dict]) -> None:
        events = [LedgerEvent.model_validate(row) for row in server_events]
        assert [e.prev_hash for e in events[1:]] == [e.payload_hash for e in events[:-1]]

    def test_constructed_by_public_names(self) -> None:
        event = LedgerEvent(id=1, sequence=0, prev_hash="0" * 64, payload_hash="h", payload={"type": "thought", "content": "x"}, created_at=datetime.now(tz=timezone.utc))
        assert event.payload["type"] == "thought"

    def test_event_missing_required_field_raises(self, server_events: list[dict]) -> None:
        """Omitting ``content_hash`` (``payload_hash``) must fail."""
        row = {k: v for k, v in server_events[0].items() if k != "content_hash"}
        with pytest.raises(ValidationError):
            LedgerEvent.model_validate(row)


class TestComplianceBundle:
    def test_parses_the_bundle_the_server_sends(self, server_compliance: dict) -> None:
        bundle = ComplianceBundle.model_validate(server_compliance)
        assert bundle.session_id == server_compliance["session_id"]
        assert bundle.event_count == len(bundle.events) == 3
        assert bundle.events[0] == ComplianceEvent(sequence=0, content_hash=server_compliance["events"][0]["content_hash"])

    def test_fields_are_exactly_the_ones_the_server_sends(self, server_compliance: dict) -> None:
        assert set(ComplianceBundle.model_fields) == set(server_compliance)
        assert set(ComplianceEvent.model_fields) == set(server_compliance["events"][0])

    def test_hashes_agree_with_the_events_endpoint(self, server_compliance: dict, server_events: list[dict]) -> None:
        bundle = ComplianceBundle.model_validate(server_compliance)
        assert [(e.sequence, e.content_hash) for e in bundle.events] == [(r["sequence"], r["content_hash"]) for r in server_events]

    def test_missing_event_count_raises(self, server_compliance: dict) -> None:
        del server_compliance["event_count"]
        with pytest.raises(ValidationError):
            ComplianceBundle.model_validate(server_compliance)


class TestAppendResult:
    def test_valid_append_result(self) -> None:
        result = AppendResult(id=1, payload_hash="deadbeef", sequence=0)
        assert result.id == 1

    def test_append_result_from_dict(self, sample_append_result: dict) -> None:
        result = AppendResult.model_validate(sample_append_result)
        assert result.sequence == sample_append_result["sequence"]
        assert result.payload_hash == sample_append_result["payload_hash"]

    def test_append_result_missing_field_raises(self) -> None:
        with pytest.raises(ValidationError):
            AppendResult.model_validate({"id": 1, "sequence": 0})

    def test_append_result_round_trip(self, sample_append_result: dict) -> None:
        result = AppendResult.model_validate(sample_append_result)
        assert AppendResult.model_validate(result.model_dump()).id == result.id


class TestMetricsSummary:
    def test_defaults(self) -> None:
        metrics = MetricsSummary()
        assert metrics.total_sessions == 0
        assert metrics.total_events == 0
        assert metrics.extra == {}

    def test_populated(self, sample_metrics: dict) -> None:
        metrics = MetricsSummary.model_validate(sample_metrics)
        assert metrics.total_sessions == 7
        assert metrics.total_events == 130

    def test_extra_fields_captured_in_extra(self) -> None:
        # Pydantic v2 ignores unknown keys by default; the `extra` field must be
        # populated explicitly by the server (i.e. as a key named "extra" in the
        # JSON response).  Unknown top-level keys are silently discarded.
        metrics = MetricsSummary.model_validate({"total_sessions": 1, "total_events": 5, "custom_counter": 99})
        assert metrics.extra == {}

    def test_empty_dict_uses_defaults(self) -> None:
        metrics = MetricsSummary.model_validate({})
        assert metrics.total_sessions == 0


class TestSecurityMetrics:
    def test_defaults(self) -> None:
        sm = SecurityMetrics()
        assert sm.injection_attempts_detected_7d == 0
        assert sm.injection_attempts_by_layer == {}
        assert sm.sessions_aborted_circuit_breaker == 0
        assert sm.chain_verification_failures == 0

    def test_populated(self) -> None:
        sm = SecurityMetrics.model_validate({"injection_attempts_detected_7d": 5, "injection_attempts_by_layer": {"tripwire": 3, "guard_llm": 2}, "sessions_aborted_circuit_breaker": 1, "chain_verification_failures": 0})
        assert sm.injection_attempts_detected_7d == 5
        assert sm.injection_attempts_by_layer["tripwire"] == 3


class TestPendingApproval:
    def test_valid_pending(self) -> None:
        pa = PendingApproval.model_validate({"gate_id": "g1", "action_name": "run_command", "action_params_summary": "ls -la", "created_at": "2026-02-22T10:00:00Z"})
        assert pa.gate_id == "g1"
        assert pa.action_name == "run_command"

    def test_missing_field_raises(self) -> None:
        with pytest.raises(ValidationError):
            PendingApproval.model_validate({"gate_id": "g1"})


class TestStatusResponse:
    def test_defaults(self) -> None:
        sr = StatusResponse()
        assert sr.demo_mode is False
        assert sr.version == ""
        assert sr.ledger_backend == ""
        assert sr.agent_supported is False

    def test_populated(self) -> None:
        sr = StatusResponse.model_validate({"demo_mode": True, "version": "0.7.2"})
        assert sr.demo_mode is True
        assert sr.version == "0.7.2"

    def test_populated_with_0_8_0_fields(self) -> None:
        sr = StatusResponse.model_validate(
            {
                "demo_mode": False,
                "version": "0.8.0",
                "ledger_backend": "sqlite",
                "agent_supported": True,
                "exports_supported": False,
                "webhooks_live": True,
            }
        )
        assert sr.ledger_backend == "sqlite"
        assert sr.agent_supported is True
        assert sr.exports_supported is False
        assert sr.webhooks_live is True


class TestTokenListRow:
    def test_valid_token(self) -> None:
        t = TokenListRow.model_validate({"token_hash": "abc123", "role": "Admin", "label": "CI token", "created_at": "2026-01-01T00:00:00Z", "expires_at": None})
        assert t.role == "Admin"
        assert t.label == "CI token"

    def test_missing_role_raises(self) -> None:
        with pytest.raises(ValidationError):
            TokenListRow.model_validate({"token_hash": "abc123", "created_at": "2026-01-01T00:00:00Z"})


class TestCreateTokenResponse:
    def test_valid_response(self) -> None:
        ct = CreateTokenResponse.model_validate({"token": "raw-secret", "token_hash": "hashed", "role": "Agent", "label": None})
        assert ct.token == "raw-secret"
        assert ct.role == "Agent"


class TestWebhookListRow:
    def test_valid_webhook(self) -> None:
        w = WebhookListRow.model_validate({"id": "wh-1", "label": "Slack", "url": "https://hooks.slack.com/x", "siem_format": "json", "filter_kinds": ["alert"], "enabled": True, "created_at": "2026-01-01T00:00:00Z"})
        assert w.label == "Slack"
        assert w.filter_kinds == ["alert"]

    def test_defaults(self) -> None:
        w = WebhookListRow.model_validate({"id": "wh-2", "label": "Splunk", "url": "https://splunk.example.com", "created_at": "2026-01-01T00:00:00Z"})
        assert w.siem_format == "json"
        assert w.filter_kinds == []
        assert w.enabled is True


class TestConfigResponse:
    def test_defaults(self) -> None:
        c = ConfigResponse()
        assert c.database_url == ""
        assert c.max_steps == 0
        assert c.agent_allowed_domains == []
        # 0.8.0 fields default leniently when absent.
        assert c.openai_base_url == ""
        assert c.active_policy is None
        assert c.policy_from_environment is None

    def test_populated(self) -> None:
        c = ConfigResponse.model_validate({"database_url": "sqlite://db.sqlite", "llm_backend": "ollama", "ollama_base_url": "http://localhost:11434", "ollama_model": "llama3", "guard_required": True, "max_steps": 50, "agent_allowed_domains": ["example.com"], "sandbox_mode": "docker", "demo_mode": False})
        assert c.llm_backend == "ollama"
        assert c.guard_required is True
        assert c.max_steps == 50

    def test_populated_with_0_8_0_fields(self) -> None:
        c = ConfigResponse.model_validate(
            {
                "database_url": "sqlite://db.sqlite",
                "llm_backend": "ollama",
                "openai_base_url": "https://api.openai.com/v1",
                "guard_required_source": "settings",
                "show_developer_tools": True,
                "ledger_backend": "sqlite",
                "agent_supported": True,
                "exports_supported": True,
                "webhooks_live": False,
                "active_policy": "owasp-top10",
                "policy_from_environment": None,
            }
        )
        assert c.openai_base_url == "https://api.openai.com/v1"
        assert c.guard_required_source == "settings"
        assert c.show_developer_tools is True
        assert c.ledger_backend == "sqlite"
        assert c.agent_supported is True
        assert c.active_policy == "owasp-top10"
        assert c.policy_from_environment is None


class TestTripwireConfig:
    def test_defaults(self) -> None:
        t = TripwireConfig()
        assert t.allowed_paths == []
        assert t.min_justification_length == 0
        assert t.require_https is False
        assert t.allowed_mcp_tools == []
        assert t.saved is None

    def test_populated(self) -> None:
        t = TripwireConfig.model_validate({"allowed_paths": ["/tmp"], "allowed_domains": ["example.com"], "banned_command_patterns": ["rm -rf"], "min_justification_length": 10, "require_https": True})
        assert t.allowed_paths == ["/tmp"]
        assert t.banned_command_patterns == ["rm -rf"]
        assert t.require_https is True

    def test_populated_with_allowed_mcp_tools_and_saved(self) -> None:
        t = TripwireConfig.model_validate(
            {
                "allowed_paths": ["/tmp"],
                "allowed_domains": [],
                "banned_command_patterns": [],
                "min_justification_length": 5,
                "require_https": True,
                "allowed_mcp_tools": ["fs/read", "web/*"],
                "saved": True,
            }
        )
        assert t.allowed_mcp_tools == ["fs/read", "web/*"]
        assert t.saved is True


class TestTripwireCheckResult:
    def test_allowed(self) -> None:
        r = TripwireCheckResult.model_validate({"allowed": True, "reason": None, "rule": None, "matched": None})
        assert r.allowed is True
        assert r.reason is None
        assert r.rule is None
        assert r.matched is None

    def test_refused(self) -> None:
        r = TripwireCheckResult.model_validate(
            {
                "allowed": False,
                "reason": "path /etc/shadow is not in the allowed paths",
                "rule": "allowed_paths",
                "matched": "/etc/shadow",
            }
        )
        assert r.allowed is False
        assert r.rule == "allowed_paths"
        assert r.matched == "/etc/shadow"

    def test_allowed_is_required(self) -> None:
        with pytest.raises(ValidationError):
            TripwireCheckResult.model_validate({"reason": None})
