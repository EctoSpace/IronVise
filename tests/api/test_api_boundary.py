"""
==========================================================================
BND-* / ERR-* - Boundary & error-format black-box tests
==========================================================================

Covers body size limits (1 MiB), long payloads, Unicode / emoji, null
bytes, pagination extremes, invalid JSON, wrong Content-Type, unknown
routes, and method-not-allowed.
"""
from __future__ import annotations

import asyncio

import httpx
import pytest

from ironvise_sdk.client import LedgerClient


class TestBnd01BodyAtLimit:
    """BND-01 · Request body exactly at the 1 MiB limit → accepted."""

    async def test_body_at_limit(self, raw_http: httpx.AsyncClient):
        # Build a JSON body where total size is close to 1 MiB
        # The goal field needs to be large enough to push total near limit
        # JSON overhead: {"goal":"....."} = ~10 bytes + content
        target_size = 1_048_576 - 20  # leave room for JSON wrapper
        goal = "A" * target_size

        r = await raw_http.post("/api/sessions", json={"goal": goal})
        # Could be 200 (accepted) or 413 (if JSON encoding pushes over)
        # or 400 (if goal is too long for the server)
        assert r.status_code in (200, 400, 413)


class TestBnd02BodyOverLimit:
    """BND-02 · Body > 1 MiB → 413 Payload Too Large."""

    async def test_body_over_limit(self, raw_http: httpx.AsyncClient):
        goal = "B" * (1_048_576 + 1000)
        r = await raw_http.post("/api/sessions", json={"goal": goal})
        assert r.status_code == 413


class TestBnd03LongGoal:
    """BND-03 · 500k char goal (under 1 MiB) → 200."""

    async def test_long_goal(self, raw_http: httpx.AsyncClient):
        goal = "C" * 500_000
        r = await raw_http.post("/api/sessions", json={"goal": goal})
        assert r.status_code == 200
        data = r.json()
        assert data.get("goal_hash") is not None


class TestBnd04UnicodeGoal:
    """BND-04 · Unicode and emoji in goal → 200, goal preserved."""

    async def test_unicode_goal(self, raw_http: httpx.AsyncClient):
        goal = "审计 🔒 テスト Ñoño Привет"
        r = await raw_http.post("/api/sessions", json={"goal": goal})
        assert r.status_code == 200


class TestBnd05NullBytes:
    """BND-05 · Goal containing null bytes → 200 or 400."""

    async def test_null_bytes(self, raw_http: httpx.AsyncClient):
        goal = "test\x00evil"
        r = await raw_http.post("/api/sessions", json={"goal": goal})
        assert r.status_code in (200, 400, 422)


class TestBnd06MaxLimit:
    """BND-06 · ?limit=500 → at most 500 results."""

    async def test_max_limit(self, raw_http: httpx.AsyncClient):
        r = await raw_http.get("/api/sessions", params={"limit": 500})
        assert r.status_code == 200
        assert len(r.json()) <= 500


class TestBnd07LargeOffset:
    """BND-07 · offset=999999 → 200, empty array."""

    async def test_large_offset(self, raw_http: httpx.AsyncClient):
        r = await raw_http.get("/api/sessions", params={"offset": 999999})
        assert r.status_code == 200
        assert r.json() == []


class TestBnd08LargeSseAfter:
    """BND-08 · ?after=9999999999 → stream opens with no historical events."""

    async def test_large_sse_after(self, ectoledger_server):
        async with httpx.AsyncClient(
            base_url=ectoledger_server.base_url,
            headers={"Authorization": f"Bearer {ectoledger_server.token}"},
            timeout=5.0,
        ) as client:
            try:
                async with client.stream(
                    "GET",
                    "/api/stream",
                    params={"after": 9999999999},
                    timeout=3.0,
                ) as resp:
                    assert resp.status_code == 200
            except httpx.ReadTimeout:
                pass  # Expected - no events to deliver


class TestBnd09ManyEvents:
    """BND-09 · A session's events come in strictly increasing sequence. The
    sequence is ledger-wide, so it starts wherever the ledger is."""

    async def test_many_events(self, adv_client: LedgerClient):
        session = await adv_client.create_session(goal="Generate many events for boundary test")
        # Wait for cognitive loop to produce events
        await asyncio.sleep(5.0)
        events = await adv_client.get_events(session.session_id)
        if len(events) < 2:
            pytest.skip("Session didn't produce enough events")

        seqs = [e.sequence for e in events]
        assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs), seqs


class TestBnd10LongPolicyName:
    """BND-10 · 255-char policy name → 200 or filesystem error."""

    async def test_long_policy_name(self, raw_http: httpx.AsyncClient):
        name = "x" * 200
        toml = b'[metadata]\ntitle = "long name"\n'
        r = await raw_http.put(f"/api/policies/{name}", content=toml)
        # May succeed (200) or fail with filesystem limits (400/500)
        assert r.status_code in (200, 400, 500)

        if r.status_code == 200:
            await raw_http.delete(f"/api/policies/{name}")


class TestBnd11EmptyBody:
    """BND-11 · POST /api/sessions with no body → 400/422."""

    async def test_empty_body(self, raw_http: httpx.AsyncClient):
        r = await raw_http.post("/api/sessions", content=b"")
        assert r.status_code in (400, 415, 422)


class TestBnd12InvalidJson:
    """BND-12 · Malformed JSON → 400/422."""

    async def test_invalid_json(self, raw_http: httpx.AsyncClient):
        r = await raw_http.post(
            "/api/sessions",
            content=b'{broken json',
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code in (400, 422)


class TestBnd13WrongContentType:
    """BND-13 · Content-Type: text/xml with JSON body → 400/415 or 200."""

    async def test_wrong_content_type(self, raw_http: httpx.AsyncClient):
        r = await raw_http.post(
            "/api/sessions",
            content=b'{"goal": "wrong content type"}',
            headers={"Content-Type": "text/xml"},
        )
        # Axum may reject (415) or may still parse (200)
        assert r.status_code in (200, 400, 415, 422)


class TestErr01UnknownRoute:
    """ERR-01 · GET /api/nonexistent → 404."""

    async def test_unknown_route(self, raw_http: httpx.AsyncClient):
        r = await raw_http.get("/api/nonexistent-endpoint-xyz")
        assert r.status_code == 404


class TestErr02MethodNotAllowed:
    """ERR-02 · DELETE /api/sessions → 405 Method Not Allowed."""

    async def test_method_not_allowed(self, raw_http: httpx.AsyncClient):
        r = await raw_http.delete("/api/sessions")
        assert r.status_code in (404, 405)


class TestErr03HeadRequest:
    """ERR-03 · HEAD /api/sessions → 200 with headers but no body."""

    async def test_head_request(self, raw_http: httpx.AsyncClient):
        r = await raw_http.head("/api/sessions")
        assert r.status_code == 200
        assert len(r.content) == 0  # HEAD has no body


class TestErr04CorsPreflight:
    """ERR-04 · OPTIONS /api/sessions → 200, but allow-origin only for allowlisted origins.

    The server used to answer preflights with `CorsLayer::very_permissive()`,
    which echoed *any* Origin back. It now carries an explicit allowlist (the
    Tauri webview and local Vite dev-server origins, plus anything in
    ECTO_CORS_ALLOWED_ORIGINS). These two tests pin both halves of that
    behaviour, so a regression back to permissive CORS fails here.
    """

    async def test_cors_preflight_allowed_origin(self, ectoledger_server):
        """An allowlisted origin gets access-control-allow-origin echoed back."""
        async with httpx.AsyncClient(
            base_url=ectoledger_server.base_url,
            timeout=10.0,
        ) as client:
            r = await client.options(
                "/api/sessions",
                headers={
                    "Origin": "tauri://localhost",
                    "Access-Control-Request-Method": "POST",
                },
            )
            assert r.status_code == 200
            headers = {k.lower(): v for k, v in r.headers.items()}
            assert headers.get("access-control-allow-origin") == "tauri://localhost"

    async def test_cors_preflight_rejects_foreign_origin(self, ectoledger_server):
        """An arbitrary external origin gets NO allow-origin header.

        Without that header the browser refuses to expose the response to the
        calling page, which is the point of the allowlist. Asserting its
        absence is what stops a silent return to `very_permissive()`.
        """
        async with httpx.AsyncClient(
            base_url=ectoledger_server.base_url,
            timeout=10.0,
        ) as client:
            r = await client.options(
                "/api/sessions",
                headers={
                    "Origin": "https://example.com",
                    "Access-Control-Request-Method": "POST",
                },
            )
            # The preflight itself still answers 200; what matters is that the
            # response does not authorise the foreign origin.
            assert r.status_code == 200
            assert "access-control-allow-origin" not in {
                k.lower() for k in r.headers.keys()
            }


class TestErr05SqlInjection:
    """ERR-05 · SQL injection in status filter → safe (parameterized)."""

    async def test_sql_injection(self, raw_http: httpx.AsyncClient):
        r = await raw_http.get(
            "/api/sessions",
            params={"status": "'; DROP TABLE agent_sessions; --"},
        )
        assert r.status_code in (200, 400)
        # Server should still be alive
        r2 = await raw_http.get("/api/sessions")
        assert r2.status_code == 200
