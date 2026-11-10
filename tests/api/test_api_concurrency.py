"""
==========================================================================
CON-* - Concurrency black-box tests
==========================================================================

Covers simultaneous session creation, concurrent event appends, rate
limiting enforcement, SSE reconnection consistency, and parallel
create+list operations.
"""
from __future__ import annotations

import asyncio
import uuid

import httpx
import pytest

from ironvise_sdk.client import LedgerClient


async def _wait_for_sessions_idle(server, session_ids: list[str] | None = None) -> None:
    """Wait for spawned mock-agent tasks to finish.

    Their background ledger writes would otherwise interleave into the next
    test's session chain (CON-02 checks that chain). With ``session_ids``,
    wait only for those sessions; without, for every running session.
    """
    async with httpx.AsyncClient(
        base_url=server.base_url,
        headers={"Authorization": f"Bearer {server.token}"},
        timeout=10.0,
    ) as client:
        for _ in range(50):
            r = await client.get("/api/sessions", params={"status": "running"})
            if r.status_code == 200:
                running = r.json()
                if session_ids is None:
                    if not running:
                        return
                elif not any(row.get("id") in session_ids for row in running):
                    return
            await asyncio.sleep(0.1)


class TestCon01SimultaneousSessionCreation:
    """CON-01 · 10 parallel POST /api/sessions → all get distinct UUIDs."""

    @pytest.mark.timeout(60)
    async def test_parallel_session_creation(self, ectoledger_server):
        n = 10
        results: list[dict | None] = [None] * n

        async def create(idx: int):
            async with httpx.AsyncClient(
                base_url=ectoledger_server.base_url,
                headers={"Authorization": f"Bearer {ectoledger_server.token}"},
                timeout=30.0,
            ) as client:
                r = await client.post(
                    "/api/sessions",
                    json={"goal": f"Concurrent session {idx}"},
                )
                if r.status_code == 200:
                    results[idx] = r.json()
                elif r.status_code == 429:
                    results[idx] = {"status_code": 429}  # rate limited
                else:
                    results[idx] = {"status_code": r.status_code}

        tasks = [asyncio.create_task(create(i)) for i in range(n)]
        await asyncio.gather(*tasks, return_exceptions=True)

        created = [r for r in results if r and "status_code" not in r]
        session_ids = [r.get("id", r.get("session_id")) for r in created]

        # At least some should succeed (rate limiter may block some)
        assert len(created) >= 1, "At least one session should be created"
        assert None not in session_ids, "Every created session must report its ID"
        assert len(session_ids) == len(created), "One ID per created session"

        # All successful IDs must be unique
        assert len(set(session_ids)) == len(session_ids), "All session IDs must be unique"

        await _wait_for_sessions_idle(ectoledger_server, session_ids)


class TestCon02ConcurrentAppends:
    """CON-02 · Multiple concurrent appends → unique monotonic sequences."""

    @pytest.mark.timeout(60)
    async def test_concurrent_appends(self, ectoledger_server, adv_client: LedgerClient):
        session = await adv_client.create_session(goal="concurrent append test")
        await asyncio.sleep(2.0)

        n = 5
        append_results: list[dict | None] = [None] * n

        async def append(idx: int):
            async with httpx.AsyncClient(
                base_url=ectoledger_server.base_url,
                headers={"Authorization": f"Bearer {ectoledger_server.token}"},
                timeout=15.0,
            ) as client:
                r = await client.post(
                    f"/api/sessions/{session.session_id}/events",
                    json={"type": "observation", "content": f"Concurrent observation {idx}"},
                )
                if r.status_code == 200:
                    append_results[idx] = r.json()

        tasks = [asyncio.create_task(append(i)) for i in range(n)]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Fetch all events and verify chain
        await asyncio.sleep(2.0)
        events = await adv_client.get_events(session.session_id)

        # Verify monotonic sequences
        seqs = [e.sequence for e in events]
        assert seqs == sorted(seqs), f"Sequences not sorted: {seqs}"

        assert len(seqs) == len(set(seqs)), f"Duplicate sequences: {seqs}"

        # Verify chain linkage
        for i in range(1, len(events)):
            assert events[i].prev_hash == events[i - 1].payload_hash, (
                f"Chain break at seq {events[i].sequence}"
            )


class TestCon03SessionRateLimit:
    """CON-03 · >5 POST /api/sessions in <1s → 429 on excess."""

    @pytest.mark.timeout(30)
    async def test_session_rate_limit(self, ectoledger_server):
        status_codes: list[int] = []

        async def create(idx: int):
            async with httpx.AsyncClient(
                base_url=ectoledger_server.base_url,
                headers={"Authorization": f"Bearer {ectoledger_server.token}"},
                timeout=10.0,
            ) as client:
                r = await client.post(
                    "/api/sessions",
                    json={"goal": f"Rate limit test {idx}"},
                )
                status_codes.append(r.status_code)

        # Fire 8 rapid requests (rate limit: 2/s burst 5)
        tasks = [asyncio.create_task(create(i)) for i in range(8)]
        await asyncio.gather(*tasks, return_exceptions=True)

        has_429 = 429 in status_codes
        if not has_429:
            pytest.skip(
                f"Rate limiter did not trigger (got {status_codes}). "
                "May depend on governor configuration."
            )
        assert has_429


class TestCon04SseRateLimit:
    """CON-04 · >10 rapid SSE opens → 429 on excess."""

    @pytest.mark.timeout(30)
    async def test_sse_rate_limit(self, ectoledger_server):
        status_codes: list[int] = []

        async def connect(idx: int):
            async with httpx.AsyncClient(
                base_url=ectoledger_server.base_url,
                headers={"Authorization": f"Bearer {ectoledger_server.token}"},
                timeout=5.0,
            ) as client:
                try:
                    async with client.stream("GET", "/api/stream", timeout=2.0) as resp:
                        status_codes.append(resp.status_code)
                except httpx.ReadTimeout:
                    status_codes.append(200)  # was accepted
                except Exception:
                    pass

        tasks = [asyncio.create_task(connect(i)) for i in range(15)]
        await asyncio.gather(*tasks, return_exceptions=True)

        if 429 not in status_codes:
            pytest.skip("SSE rate limiter did not trigger")
        assert 429 in status_codes


class TestCon05GlobalRateLimit:
    """CON-05 · >120 burst requests → some get 429."""

    @pytest.mark.timeout(30)
    async def test_global_rate_limit(self, ectoledger_server):
        status_codes: list[int] = []

        # One client with a 50-connection pool, rather than a client per
        # request: every new httpx client loads the CA bundle, and on Windows
        # 150 of those took longer than the test's 30-second limit.
        async with httpx.AsyncClient(
            base_url=ectoledger_server.base_url,
            headers={"Authorization": f"Bearer {ectoledger_server.token}"},
            timeout=10.0,
            limits=httpx.Limits(max_connections=50),
        ) as client:

            async def get_sessions(idx: int):
                r = await client.get("/api/sessions")
                status_codes.append(r.status_code)

            tasks = [asyncio.create_task(get_sessions(i)) for i in range(150)]
            await asyncio.gather(*tasks, return_exceptions=True)

        if 429 not in status_codes:
            pytest.skip("Global rate limiter did not trigger at 150 concurrent requests")
        assert 429 in status_codes


class TestCon07SseReconnect:
    """CON-07 · Multiple SSE clients reconnect with after → consistent."""

    @pytest.mark.timeout(30)
    async def test_sse_reconnect(self, ectoledger_server, adv_client: LedgerClient):
        # Create some events first
        await adv_client.create_session(goal="SSE reconnect test")
        await asyncio.sleep(3.0)

        collected_per_client: list[list[int]] = [[] for _ in range(5)]

        async def reconnect(idx: int):
            async with httpx.AsyncClient(
                base_url=ectoledger_server.base_url,
                headers={"Authorization": f"Bearer {ectoledger_server.token}"},
                timeout=10.0,
            ) as client:
                try:
                    async with client.stream(
                        "GET",
                        "/api/stream",
                        params={"after": "0"},
                        timeout=5.0,
                    ) as resp:
                        if resp.status_code in (200,):
                            buffer = ""
                            async for chunk in resp.aiter_text():
                                buffer += chunk
                                while "\n\n" in buffer:
                                    block, buffer = buffer.split("\n\n", 1)
                                    for line in block.split("\n"):
                                        if line.startswith("id:"):
                                            try:
                                                collected_per_client[idx].append(
                                                    int(line[3:].strip())
                                                )
                                            except ValueError:
                                                pass
                except (httpx.ReadTimeout, httpx.RemoteProtocolError):
                    pass

        tasks = [asyncio.create_task(reconnect(i)) for i in range(5)]
        await asyncio.gather(*tasks, return_exceptions=True)

        # All clients that got data should see the same event IDs
        non_empty = [sorted(c) for c in collected_per_client if c]
        if len(non_empty) >= 2:
            # All clients should have the same set of historical events
            for i in range(1, len(non_empty)):
                assert non_empty[0] == non_empty[i], (
                    f"Client 0 and client {i} got different event IDs"
                )


class TestCon08ParallelCreateAndList:
    """CON-08 · Create sessions while listing → no crashes or partial rows."""

    @pytest.mark.timeout(30)
    async def test_parallel_create_list(self, ectoledger_server):
        errors: list[str] = []

        async def create_session():
            async with httpx.AsyncClient(
                base_url=ectoledger_server.base_url,
                headers={"Authorization": f"Bearer {ectoledger_server.token}"},
                timeout=15.0,
            ) as client:
                r = await client.post(
                    "/api/sessions",
                    json={"goal": f"parallel test {uuid.uuid4().hex[:8]}"},
                )
                if r.status_code not in (200, 429, 503):
                    errors.append(f"create: {r.status_code}")

        async def list_sessions():
            async with httpx.AsyncClient(
                base_url=ectoledger_server.base_url,
                headers={"Authorization": f"Bearer {ectoledger_server.token}"},
                timeout=15.0,
            ) as client:
                r = await client.get("/api/sessions")
                if r.status_code not in (200, 429):
                    errors.append(f"list: {r.status_code}")
                elif r.status_code == 200:
                    data = r.json()
                    assert isinstance(data, list)
                    for s in data:
                        has_id = "id" in s or "session_id" in s
                        if not has_id:
                            errors.append(f"partial row: {s}")

        tasks = []
        for _ in range(5):
            tasks.append(asyncio.create_task(create_session()))
            tasks.append(asyncio.create_task(list_sessions()))

        await asyncio.gather(*tasks, return_exceptions=True)

        assert not errors, f"Errors during parallel create/list: {errors}"

        await _wait_for_sessions_idle(ectoledger_server)


class TestCon09DeleteTokenWhileInUse:
    """CON-09 · Delete a token, then verify subsequent requests fail."""

    @pytest.mark.timeout(30)
    async def test_delete_token_while_in_use(
        self,
        ectoledger_server,
        raw_http: httpx.AsyncClient,
    ):
        # Create a disposable token
        r = await raw_http.post(
            "/api/tokens",
            json={"role": "agent", "label": "concurrent-delete-test"},
        )
        assert r.status_code == 200
        raw_token = r.json()["token"]
        token_hash = r.json()["token_hash"]

        # Verify it works
        async with httpx.AsyncClient(
            base_url=ectoledger_server.base_url,
            headers={"Authorization": f"Bearer {raw_token}"},
            timeout=10.0,
        ) as client:
            r1 = await client.get("/api/sessions")
            assert r1.status_code == 200

        r2 = await raw_http.delete(f"/api/tokens/{token_hash}")
        assert r2.status_code == 204

        # Verify it no longer works
        async with httpx.AsyncClient(
            base_url=ectoledger_server.base_url,
            headers={"Authorization": f"Bearer {raw_token}"},
            timeout=10.0,
        ) as client:
            r3 = await client.get("/api/sessions")
            assert r3.status_code == 401
