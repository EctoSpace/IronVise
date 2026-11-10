"""GET retry policy of ``LedgerClient``: see the class docstring and
``LedgerClient._get`` in ``ironvise_sdk/client.py``.

Only GET is retried, only on a connection error (``httpx.NetworkError``, not a
timeout) or an HTTP 502/503/504, with exponential backoff honouring
``Retry-After`` in seconds. ``tests/conftest.py`` patches the module-level
``_sleep`` to a no-op for every test in this suite so these run fast; the
tests that care about the delay itself patch it again locally to record the
seconds requested instead of actually waiting.
"""

from __future__ import annotations

import httpx
import pytest
import respx

import ironvise_sdk.client as client_module
from ironvise_sdk.client import LedgerClient, LedgerSdkError

pytestmark = pytest.mark.asyncio

BASE = "http://ledger.test"


@respx.mock
async def test_get_retried_on_503_then_succeeds() -> None:
    route = respx.get(f"{BASE}/api/sessions").mock(
        side_effect=[
            httpx.Response(503, text="LLM backend not ready"),
            httpx.Response(503, text="LLM backend not ready"),
            httpx.Response(200, json=[]),
        ]
    )
    async with LedgerClient(BASE) as client:
        sessions = await client.list_sessions()
    assert sessions == []
    assert route.call_count == 3


@respx.mock
async def test_retry_after_header_is_honoured(monkeypatch: pytest.MonkeyPatch) -> None:
    waited: list[float] = []

    async def _record_sleep(seconds: float) -> None:
        waited.append(seconds)

    monkeypatch.setattr(client_module, "_sleep", _record_sleep)
    route = respx.get(f"{BASE}/api/sessions").mock(
        side_effect=[
            httpx.Response(503, text="slow down", headers={"Retry-After": "2"}),
            httpx.Response(200, json=[]),
        ]
    )
    async with LedgerClient(BASE) as client:
        await client.list_sessions()
    assert route.call_count == 2
    assert waited == [2.0]


@respx.mock
async def test_retry_after_is_capped(monkeypatch: pytest.MonkeyPatch) -> None:
    waited: list[float] = []

    async def _record_sleep(seconds: float) -> None:
        waited.append(seconds)

    monkeypatch.setattr(client_module, "_sleep", _record_sleep)
    route = respx.get(f"{BASE}/api/sessions").mock(
        side_effect=[
            httpx.Response(503, text="slow down", headers={"Retry-After": "600"}),
            httpx.Response(200, json=[]),
        ]
    )
    async with LedgerClient(BASE) as client:
        await client.list_sessions()
    assert route.call_count == 2
    assert waited == [client_module._RETRY_MAX_SECONDS]


@respx.mock
async def test_network_error_is_retried_with_exponential_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    waited: list[float] = []

    async def _record_sleep(seconds: float) -> None:
        waited.append(seconds)

    monkeypatch.setattr(client_module, "_sleep", _record_sleep)
    route = respx.get(f"{BASE}/api/sessions").mock(
        side_effect=[
            httpx.ConnectError("connection refused"),
            httpx.ConnectError("connection refused"),
            httpx.Response(200, json=[]),
        ]
    )
    async with LedgerClient(BASE) as client:
        await client.list_sessions()
    assert route.call_count == 3
    assert waited == [
        client_module._RETRY_BASE_SECONDS,
        client_module._RETRY_BASE_SECONDS * 2,
    ]


@respx.mock
async def test_post_is_never_retried_on_503() -> None:
    route = respx.post(f"{BASE}/api/sessions").mock(return_value=httpx.Response(503, text="not ready"))
    async with LedgerClient(BASE) as client:
        with pytest.raises(LedgerSdkError):
            await client.create_session("goal")
    assert route.call_count == 1


@respx.mock
async def test_post_is_never_retried_on_network_error() -> None:
    route = respx.post(f"{BASE}/api/sessions").mock(side_effect=httpx.ConnectError("refused"))
    async with LedgerClient(BASE) as client:
        with pytest.raises(httpx.ConnectError):
            await client.create_session("goal")
    assert route.call_count == 1


@respx.mock
async def test_4xx_is_never_retried() -> None:
    route = respx.get(f"{BASE}/api/sessions").mock(return_value=httpx.Response(404, text="not found"))
    async with LedgerClient(BASE) as client:
        with pytest.raises(LedgerSdkError):
            await client.list_sessions()
    assert route.call_count == 1


@respx.mock
async def test_timeout_is_never_retried() -> None:
    route = respx.get(f"{BASE}/api/sessions").mock(side_effect=httpx.ReadTimeout("read timed out"))
    async with LedgerClient(BASE) as client:
        with pytest.raises(httpx.ReadTimeout):
            await client.list_sessions()
    assert route.call_count == 1


@respx.mock
async def test_retries_exhausted_surfaces_the_last_error() -> None:
    route = respx.get(f"{BASE}/api/sessions").mock(
        side_effect=[
            httpx.Response(503, text="attempt 1"),
            httpx.Response(503, text="attempt 2"),
            httpx.Response(503, text="attempt 3"),
        ]
    )
    async with LedgerClient(BASE) as client:
        with pytest.raises(LedgerSdkError) as excinfo:
            await client.list_sessions()
    assert excinfo.value.body == "attempt 3"
    assert route.call_count == 3  # the default of 2 retries: 1 + 2 attempts


@respx.mock
async def test_retries_zero_disables_retrying() -> None:
    route = respx.get(f"{BASE}/api/sessions").mock(return_value=httpx.Response(503, text="not ready"))
    async with LedgerClient(BASE, retries=0) as client:
        with pytest.raises(LedgerSdkError):
            await client.list_sessions()
    assert route.call_count == 1


@respx.mock
async def test_custom_retries_count() -> None:
    route = respx.get(f"{BASE}/api/sessions").mock(return_value=httpx.Response(503, text="not ready"))
    async with LedgerClient(BASE, retries=5) as client:
        with pytest.raises(LedgerSdkError):
            await client.list_sessions()
    assert route.call_count == 6  # 1 + 5 retries


def test_default_retries_is_two() -> None:
    client = LedgerClient(BASE)
    assert client._retries == 2


def test_negative_retries_is_rejected() -> None:
    with pytest.raises(ValueError, match="retries must not be negative"):
        LedgerClient(BASE, retries=-1)


@pytest.mark.parametrize("retries", [float("nan"), float("inf"), -1, 0.5, True])
async def test_invalid_retry_settings_are_rejected(retries):
    with pytest.raises(ValueError):
        LedgerClient(BASE, retries=retries)

@pytest.mark.parametrize("timeout", [float("nan"), float("inf"), -1, 0])
async def test_invalid_timeout_settings_are_rejected(timeout):
    with pytest.raises(ValueError):
        LedgerClient(BASE, timeout=timeout)

async def test_retry_delay_stays_capped_for_large_retry_counts():
    assert client_module._retry_delay(10000) == 4.0


async def test_nonfinite_retry_after_uses_normal_backoff():
    assert client_module._retry_delay(0, "inf") == 0.25
