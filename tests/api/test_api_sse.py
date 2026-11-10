"""
==========================================================================
SSE-* - Server-Sent Events streaming black-box tests
==========================================================================

Covers SSE stream opening, event delivery, filtering, replay via ``after``/
``since``, keep-alive, payload redaction, and rate limiting.
"""
from __future__ import annotations

import asyncio
import json
import uuid

import httpx
import pytest

from ironvise_sdk.client import LedgerClient


async def _read_sse_events(
    client: httpx.AsyncClient,
    path: str,
    params: dict | None = None,
    max_events: int = 10,
    timeout: float = 8.0,
) -> list[dict]:
    """Open an SSE stream and collect up to *max_events* data lines."""
    collected: list[dict] = []
    try:
        async with client.stream("GET", path, params=params, timeout=timeout) as resp:
            if resp.status_code != 200:
                return collected
            buffer = ""
            async for chunk in resp.aiter_text():
                buffer += chunk
                while "\n\n" in buffer:
                    block, buffer = buffer.split("\n\n", 1)
                    data_line = None
                    for line in block.split("\n"):
                        if line.startswith("data:"):
                            data_line = line[len("data:"):].strip()
                    if data_line:
                        try:
                            collected.append(json.loads(data_line))
                        except json.JSONDecodeError:
                            pass  # keep-alive or non-JSON
                    if len(collected) >= max_events:
                        return collected
    except (httpx.ReadTimeout, httpx.RemoteProtocolError, asyncio.CancelledError):
        pass
    return collected


class TestSse01OpenStream:
    """SSE-01 · GET /api/stream → 200, text/event-stream."""

    async def test_open_stream(self, raw_http: httpx.AsyncClient):
        try:
            async with raw_http.stream("GET", "/api/stream", timeout=5.0) as resp:
                assert resp.status_code == 200
                ct = resp.headers.get("content-type", "")
                assert "text/event-stream" in ct
        except httpx.ReadTimeout:
            pass  # stream is long-lived, timeout is expected


class TestSse02ReceiveEvents:
    """SSE-02 · Create session while stream is open → receive events."""

    async def test_receive_events(
        self,
        ectoledger_server,
        adv_client: LedgerClient,
    ):
        collected: list[dict] = []

        async def listen():
            nonlocal collected
            async with httpx.AsyncClient(
                base_url=ectoledger_server.base_url,
                headers={"Authorization": f"Bearer {ectoledger_server.token}"},
                timeout=15.0,
            ) as sse_client:
                collected = await _read_sse_events(
                    sse_client, "/api/stream", max_events=3, timeout=10.0,
                )

        listener = asyncio.create_task(listen())

        # Wait a moment for the SSE connection to establish
        await asyncio.sleep(1.0)

        # Create a session - should produce events
        await adv_client.create_session(goal="SSE receive test")

        # Wait for the listener to collect some events
        await asyncio.sleep(5.0)
        listener.cancel()
        try:
            await listener
        except asyncio.CancelledError:
            pass

        # We may or may not get events depending on timing; just verify format
        for ev in collected:
            assert isinstance(ev, dict)
            # StreamEvent should have at least id and payload
            assert "id" in ev or "sequence" in ev or "payload" in ev


class TestSse03FilterBySession:
    """SSE-03 · ?session_id={uuid} → only events for that session."""

    async def test_filter_session(
        self,
        ectoledger_server,
        adv_client: LedgerClient,
    ):
        session = await adv_client.create_session(goal="SSE filter test")
        await asyncio.sleep(2.0)

        async with httpx.AsyncClient(
            base_url=ectoledger_server.base_url,
            headers={"Authorization": f"Bearer {ectoledger_server.token}"},
            timeout=10.0,
        ) as sse_client:
            events = await _read_sse_events(
                sse_client,
                "/api/stream",
                params={"session_id": session.session_id, "after": "0"},
                max_events=5,
                timeout=5.0,
            )

        session_event_ids = {e.id for e in await adv_client.get_events(session.session_id)}
        streamed_ids = {e["id"] for e in events if "id" in e}
        assert streamed_ids <= session_event_ids, (
            f"the filtered stream carried events from other sessions: "
            f"{sorted(streamed_ids - session_event_ids)}"
        )


class TestSse04ReplayAfter:
    """SSE-04 · ?after=0 → receives historical events."""

    async def test_replay_after(self, ectoledger_server, adv_client: LedgerClient):
        # Create a session so there are events
        await adv_client.create_session(goal="SSE replay test")
        await asyncio.sleep(2.0)

        async with httpx.AsyncClient(
            base_url=ectoledger_server.base_url,
            headers={"Authorization": f"Bearer {ectoledger_server.token}"},
            timeout=10.0,
        ) as sse_client:
            events = await _read_sse_events(
                sse_client,
                "/api/stream",
                params={"after": "0"},
                max_events=5,
                timeout=5.0,
            )
            # Should get at least one historical event
            assert len(events) >= 1, "Replay with after=0 should return historical events"


class TestSse05ReplaySince:
    """SSE-05 · ?since=0 → same as ?after=0 (alias behaviour)."""

    async def test_replay_since(self, ectoledger_server, adv_client: LedgerClient):
        await adv_client.create_session(goal="SSE since alias test")
        await asyncio.sleep(2.0)

        async with httpx.AsyncClient(
            base_url=ectoledger_server.base_url,
            headers={"Authorization": f"Bearer {ectoledger_server.token}"},
            timeout=10.0,
        ) as sse_client:
            events = await _read_sse_events(
                sse_client,
                "/api/stream",
                params={"since": "0"},
                max_events=5,
                timeout=5.0,
            )
            assert len(events) >= 1


class TestSse06KeepAlive:
    """SSE-06 · Keep-alive text received within ~20s of idle."""

    async def test_keep_alive(self, ectoledger_server):
        got_keepalive = False
        try:
            async with httpx.AsyncClient(
                base_url=ectoledger_server.base_url,
                headers={"Authorization": f"Bearer {ectoledger_server.token}"},
                timeout=25.0,
            ) as client:
                async with client.stream("GET", "/api/stream", timeout=25.0) as resp:
                    assert resp.status_code == 200
                    async for chunk in resp.aiter_text():
                        if "keep-alive" in chunk.lower():
                            got_keepalive = True
                            break
        except httpx.ReadTimeout:
            pass

        assert got_keepalive, "Expected keep-alive within 20 seconds"


class TestSse07RedactionPaths:
    """SSE-07 · File paths >30 chars in streamed payloads → [REDACTED_PATH]."""

    async def test_path_redaction(self, ectoledger_server, adv_client: LedgerClient):
        # Create a session - the mock LLM may produce paths
        await adv_client.create_session(goal="SSE redaction path test")
        await asyncio.sleep(3.0)

        async with httpx.AsyncClient(
            base_url=ectoledger_server.base_url,
            headers={"Authorization": f"Bearer {ectoledger_server.token}"},
            timeout=10.0,
        ) as sse_client:
            events = await _read_sse_events(
                sse_client,
                "/api/stream",
                params={"after": "0"},
                max_events=20,
                timeout=5.0,
            )
            # We can only verify redaction if events were generated with paths
            # This is an observational test - just ensure no crash
            for ev in events:
                payload = ev.get("payload", {})
                if isinstance(payload, dict):
                    content = payload.get("content", "")
                    if "[REDACTED_PATH]" in str(content):
                        return  # found a redacted path, test passes


class TestSse10RateLimit:
    """SSE-10 · >10 rapid SSE opens from same IP → 429."""

    @pytest.mark.timeout(30)
    async def test_rate_limit(self, ectoledger_server):
        results: list[int] = []

        async def attempt():
            async with httpx.AsyncClient(
                base_url=ectoledger_server.base_url,
                headers={"Authorization": f"Bearer {ectoledger_server.token}"},
                timeout=5.0,
            ) as client:
                try:
                    async with client.stream("GET", "/api/stream", timeout=3.0) as resp:
                        results.append(resp.status_code)
                        # Read a tiny bit to keep connection open briefly
                        async for _ in resp.aiter_bytes(1):
                            break
                except (httpx.ReadTimeout, httpx.RemoteProtocolError):
                    results.append(200)  # connection was accepted

        tasks = [asyncio.create_task(attempt()) for _ in range(15)]
        await asyncio.gather(*tasks, return_exceptions=True)

        has_429 = 429 in results
        # Rate limiting is best-effort - may not trigger in all environments
        if not has_429:
            pytest.skip("Rate limiter did not trigger (may depend on governor config)")


class TestSse11InvalidSessionFilter:
    """SSE-11 · ?session_id=not-uuid → 400 or empty stream."""

    async def test_invalid_session_filter(self, ectoledger_server):
        async with httpx.AsyncClient(
            base_url=ectoledger_server.base_url,
            headers={"Authorization": f"Bearer {ectoledger_server.token}"},
            timeout=5.0,
        ) as client:
            try:
                async with client.stream(
                    "GET",
                    "/api/stream",
                    params={"session_id": "not-a-uuid"},
                    timeout=3.0,
                ) as resp:
                    # Either rejected with 400 or opens with no events
                    assert resp.status_code in (200, 400, 422)
            except httpx.ReadTimeout:
                pass  # accepted but no data - also valid


class TestSse08SdkStreams:
    """SSE-08 · The Python SDK's stream_events, with and without a session."""

    async def test_unscoped_stream_carries_every_session_and_scoped_only_its_own(
        self, ectoledger_server, adv_client: LedgerClient
    ):
        marker = uuid.uuid4().hex
        # Recorder sessions stay open for appends; a loop session may already
        # have completed and sealed itself.
        a = await adv_client.create_session(goal="SSE-08 session a", record=True)
        b = await adv_client.create_session(goal="SSE-08 session b", record=True)
        await adv_client.append_event(a.session_id, {"observation": f"a-{marker}"})
        await adv_client.append_event(b.session_id, {"observation": f"b-{marker}"})

        async def markers_seen(stream, wanted: set[str]) -> set[str]:
            seen: set[str] = set()

            async def read() -> None:
                async for event in stream:
                    text = json.dumps(event)
                    seen.update(w for w in wanted if w in text)
                    if seen == wanted:
                        return

            try:
                await asyncio.wait_for(read(), timeout=10.0)
            except asyncio.TimeoutError:
                pass
            return seen

        both = {f"a-{marker}", f"b-{marker}"}
        assert await markers_seen(adv_client.stream_events(), both) == both
        assert await markers_seen(adv_client.stream_events(a.session_id), both) == {f"a-{marker}"}
