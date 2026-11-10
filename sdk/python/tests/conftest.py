"""Sample-data fixtures for the SDK's own tests.

Intentionally duplicated with ``tests/api/conftest.py``. The two suites are
independent now -- this one exercises the client library and needs no server,
while ``tests/api`` is a black-box suite against a running Rust host -- and
pytest has no clean way to share a conftest across sibling roots. Ninety lines
of literal sample data is a smaller cost than coupling the suites back together.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

import ironvise_sdk.client as _client_module

# No `pytest_plugins` here. conftest_adversarial spins up a live Rust host,
# which belongs to the black-box suite in tests/api/, not to the SDK's own
# tests. Loading it here is what made `pip install ectoledger-sdk` ship a suite
# that could not run without a Rust build.


@pytest.fixture(autouse=True)
def _fast_retry_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    """Skip the real backoff delay between GET retries in every test.

    ``LedgerClient._get`` awaits the module-level ``_sleep`` between
    attempts; replacing it here keeps the whole suite fast while leaving the
    retry *logic* (attempt counts, which errors retry) exercised for real. A
    test that cares about the delay itself patches ``_sleep`` again locally.
    """

    async def _no_wait(_seconds: float) -> None:
        return None

    monkeypatch.setattr(_client_module, "_sleep", _no_wait)


@pytest.fixture(autouse=True, scope="session")
def _one_default_ssl_context() -> Iterator[None]:
    """Build httpx's default SSL context once instead of once per client.

    Loading the CA bundle costs ~50 ms, and the client tests build a fresh
    ``LedgerClient`` for each of several hundred cases; that alone made the
    suite take over a minute. A context built from the default arguments is
    the same every time, so only that call is cached; any other is passed
    through. If httpx moves this private hook, the suite runs slower, not
    differently.
    """
    try:
        from httpx._transports import default as transports
    except ImportError:  # pragma: no cover - depends on the httpx version
        yield
        return
    build = getattr(transports, "create_ssl_context", None)
    if build is None:  # pragma: no cover - depends on the httpx version
        yield
        return
    shared = []

    def cached(verify=True, cert=None, trust_env=True):
        if verify is not True or cert is not None or trust_env is not True:
            return build(verify=verify, cert=cert, trust_env=trust_env)
        if not shared:
            shared.append(build(verify=verify, cert=cert, trust_env=trust_env))
        return shared[0]

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(transports, "create_ssl_context", cached)
        yield


BASE_URL = "http://localhost:3000"
SESSION_ID = "550e8400-e29b-41d4-a716-446655440000"

# Response bodies shaped exactly as the Rust server sends them, shared with the
# TypeScript suite so both SDKs parse the same bytes.
SERVER_RESPONSES = Path(__file__).resolve().parents[2] / "fixtures" / "server-responses"


@pytest.fixture
def base_url() -> str:
    return BASE_URL


@pytest.fixture
def session_id() -> str:
    return SESSION_ID


# SHA-256 of the empty string: any well-formed digest will do for these tests.
GOAL_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@pytest.fixture
def sample_session() -> dict:
    return {
        "session_id": SESSION_ID,
        "goal_hash": GOAL_HASH,
        "started_at": "2026-02-22T10:00:00Z",
        "finished_at": None,
        "status": "running",
        "session_did": None,
    }


@pytest.fixture
def sample_session_finished() -> dict:
    return {
        "session_id": SESSION_ID,
        "goal_hash": GOAL_HASH,
        "started_at": "2026-02-22T10:00:00Z",
        "finished_at": "2026-02-22T11:00:00Z",
        "status": "completed",
        "session_did": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    }


# SHA-256 of an appended event's payload
EVENT_1_CONTENT_HASH = "2c624232cdd221771294dfbb310aca000462b31802e26ad0a0f5f6c4e7f2e08b"


@pytest.fixture
def server_events() -> list[dict]:
    """``GET /api/events`` rows: ``crates/host/src/server/exports.rs``, ``get_events_json``."""
    return json.loads((SERVER_RESPONSES / "events.json").read_text())


@pytest.fixture
def server_compliance() -> dict:
    """``GET /api/sessions/{id}/compliance``: ``crates/host/src/pool.rs``, ``prove_compliance_for_session``."""
    return json.loads((SERVER_RESPONSES / "compliance.json").read_text())


@pytest.fixture
def sample_append_result() -> dict:
    return {"id": 42, "payload_hash": EVENT_1_CONTENT_HASH, "sequence": 1}


@pytest.fixture
def sample_metrics() -> dict:
    return {"total_sessions": 7, "total_events": 130}
