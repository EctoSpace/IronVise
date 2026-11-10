"""`verify_intent` must return a deny through the SDK, not just from curl.

The endpoint being correct and the *client* being correct are different
claims, and only the second one is what a user of the SDK depends on.

Skipped unless ECTOLEDGER_LIVE_URL points at a running Observer:

    ECTOLEDGER_LIVE_URL=http://127.0.0.1:3201 \\
    ECTOLEDGER_LIVE_TOKEN=gate \\
    python3 -m pytest sdk/python/tests/test_verify_intent_live.py -v

Read the assertions carefully: this checks that a deny comes back and that
nothing was committed. `verify-intent` deliberately commits nothing and executes
nothing, so a denial here does *not* land in the ledger - the surface that
records a refusal is the Claude Code hook. Asserting the event count is
unchanged is how that distinction stays true rather than merely documented.
"""

import asyncio
import os

import pytest

from ironvise_sdk import IntentDenied, LedgerClient

URL = os.environ.get("ECTOLEDGER_LIVE_URL")
TOKEN = os.environ.get("ECTOLEDGER_LIVE_TOKEN", "")

pytestmark = pytest.mark.skipif(
    not URL, reason="set ECTOLEDGER_LIVE_URL to run against a live Observer"
)


async def settled(client, session_id: str) -> int:
    """Wait until the session stops growing, then return its event count.

    A recorder session (`record=True`) runs no agent loop and should already
    be still; waiting anyway keeps the before/after measurement honest if a
    server ever appends on its own.
    """
    last = -1
    for _ in range(40):
        now = len(await client.get_events(session_id))
        if now == last:
            return now
        last = now
        await asyncio.sleep(0.25)
    return last


@pytest.mark.asyncio
async def test_verify_intent_denies_a_banned_command_and_commits_nothing():
    async with LedgerClient(URL, bearer_token=TOKEN) as client:
        session = await client.create_session(goal="SDK verify_intent round-trip", record=True)
        sid = session.session_id

        before = await settled(client, sid)

        verdict = await client.verify_intent(
            sid,
            "run_command",
            {"command": "rm -rf /"},
            justification="checking that the SDK surfaces a refusal",
        )
        assert verdict.allowed is False, f"expected a deny, got {verdict}"
        assert verdict.reason, "a refusal with no reason is not auditable"
        assert verdict.stage, "a refusal that will not say which check refused is half a verdict"

        # The typed helper is the one callers are told to use; it must agree.
        with pytest.raises(IntentDenied):
            verdict.raise_if_denied()

        after = len(await client.get_events(sid))  # no settle: nothing should have moved
        assert after == before, (
            "verify_intent committed an event. It is specified to commit nothing "
            "and execute nothing; the surface that records a refusal is the hook."
        )


@pytest.mark.asyncio
async def test_verify_intent_allows_a_permitted_action():
    async with LedgerClient(URL, bearer_token=TOKEN) as client:
        session = await client.create_session(goal="SDK verify_intent allow path", record=True)
        verdict = await client.verify_intent(
            session.session_id,
            "read_file",
            {"path": "README.md"},
            justification="a permitted read, to prove deny is not the only answer",
        )
        assert verdict.allowed is True, f"expected an allow, got {verdict}"
        verdict.raise_if_denied()  # must not raise
