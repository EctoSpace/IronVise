"""Tests for the shared recorder behind both framework integrations.

The behaviour under test is the 0.8.0 breaking change: recording is
**fail-closed**. Before this, both integrations caught every exception and
logged a warning, so an unreachable ledger left silent gaps in an audit trail
that callers went on trusting.

These exercise the recorder directly rather than through LangChain or AutoGen,
so they run without either framework installed - which is also what makes them
genuine SDK tests rather than integration tests wearing a costume.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from ironvise_sdk._recorder import LedgerRecorder, RecordingFailed

BASE = "http://ledger.test"
SESSION = "11111111-1111-4111-8111-111111111111"


def _recorder(**kw) -> LedgerRecorder:
    return LedgerRecorder(SESSION, BASE, timeout=5.0, **kw)


@respx.mock
def test_a_successful_append_returns_quietly() -> None:
    route = respx.post(f"{BASE}/api/sessions/{SESSION}/events").mock(
        return_value=httpx.Response(
            201, json={"id": 1, "payload_hash": "a" * 64, "sequence": 1}
        )
    )
    with _recorder() as rec:
        rec.record({"observation": "hello"})
    assert route.called


@respx.mock
def test_a_server_error_raises_by_default() -> None:
    # The point of the change: a failure stops the agent instead of becoming a
    # warning in a log nobody reads.
    respx.post(f"{BASE}/api/sessions/{SESSION}/events").mock(
        return_value=httpx.Response(500, text="boom")
    )
    with _recorder() as rec, pytest.raises(RecordingFailed) as excinfo:
        rec.record({"observation": "hello"})
    assert "audit trail" in str(excinfo.value)
    assert "fail_open=True" in str(excinfo.value), (
        "the error should name the escape hatch, or callers will just wrap it in "
        "a bare except"
    )


@respx.mock
def test_a_transport_failure_raises_by_default() -> None:
    respx.post(f"{BASE}/api/sessions/{SESSION}/events").mock(
        side_effect=httpx.ConnectError("refused")
    )
    with _recorder() as rec, pytest.raises(RecordingFailed):
        rec.record({"observation": "hello"})


@respx.mock
def test_fail_open_restores_the_old_behaviour_when_asked_for() -> None:
    respx.post(f"{BASE}/api/sessions/{SESSION}/events").mock(
        return_value=httpx.Response(503, text="unavailable")
    )
    with _recorder(fail_open=True) as rec:
        rec.record({"observation": "hello"})  # must not raise


@respx.mock
def test_one_client_is_reused_across_records() -> None:
    # Previously each observation built a fresh LedgerClient, httpx pool and
    # event loop. Holding one is the difference between a connection per agent
    # step and a connection per run.
    respx.post(f"{BASE}/api/sessions/{SESSION}/events").mock(
        return_value=httpx.Response(
            201, json={"id": 1, "payload_hash": "a" * 64, "sequence": 1}
        )
    )
    with _recorder() as rec:
        rec.record({"observation": "one"})
        first = rec.client()
        rec.record({"observation": "two"})
        assert rec.client() is first


def test_closing_twice_is_harmless() -> None:
    rec = _recorder()
    rec.close()
    rec.close()
