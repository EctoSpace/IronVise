#!/usr/bin/env bash
# Gate 8 (Python): the SDK as a user installs it, against the candidate server.
#
# Builds the wheel, installs it into a fresh venv (the source tree is never on
# sys.path), starts `ironvise serve` on a throwaway SQLite ledger, and through
# the installed package: gets a deny and an allow from verify_intent, records a
# session, seals it and verifies it.
#
# Usage: scripts/check-python-wheel.sh   (ECTOLEDGER_BIN overrides the binary)
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${ECTOLEDGER_BIN:-$ROOT/target/debug/ironvise}
WORK=$(mktemp -d)
SERVER=""
cleanup() {
    [ -n "$SERVER" ] && kill "$SERVER" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

[ -x "$BIN" ] || { echo "no binary at $BIN (cargo build -p ectoledger)" >&2; exit 1; }

export PIP_DISABLE_PIP_VERSION_CHECK=1
python3 -m pip wheel --no-deps -q -w "$WORK/dist" "$ROOT/sdk/python"
python3 -m venv "$WORK/venv"
"$WORK/venv/bin/pip" install -q "$WORK"/dist/*.whl
echo "installed $(basename "$WORK"/dist/*.whl)"

PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
TOKEN=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
mkdir -p "$WORK/project"
echo "hello" > "$WORK/project/notes.txt"
(
    cd "$WORK/project"
    DATABASE_URL="sqlite:$WORK/ledger.db" OBSERVER_TOKEN="$TOKEN" ECTO_BIND_PORT="$PORT" \
        ECTO_DATA_DIR="$WORK/data" GUARD_REQUIRED=false exec "$BIN" serve
) > "$WORK/server.log" 2>&1 &
SERVER=$!

for _ in $(seq 1 60); do
    curl -fsS -o /dev/null 2>/dev/null -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$PORT/api/sessions" && break
    sleep 0.5
done

cd "$WORK"
URL="http://127.0.0.1:$PORT" TOKEN="$TOKEN" NOTES="$WORK/project/notes.txt" \
    "$WORK/venv/bin/python" - <<'PY'
import asyncio, os
import ironvise_sdk
import ironvise_sdk.client
from importlib.metadata import version
from importlib.util import find_spec
from ironvise_sdk import LedgerClient

assert "site-packages" in ironvise_sdk.__file__, ironvise_sdk.__file__
assert version("ironvise") == ironvise_sdk.__version__
assert find_spec("ectoledger_sdk") is None, "legacy namespace must not be shipped"

async def main():
    async with LedgerClient(os.environ["URL"], bearer_token=os.environ["TOKEN"]) as c:
        s = await c.create_session("wheel check", record=True)
        deny = await c.verify_intent(s.session_id, "run_command", {"command": "rm -rf /"},
                                     justification="checking that this is refused")
        assert not deny.allowed and deny.stage == "tripwire", deny
        allow = await c.verify_intent(s.session_id, "read_file", {"path": os.environ["NOTES"]},
                                      justification="reading the notes for the check")
        assert allow.allowed, allow
        await c.append_event(s.session_id, {"note": "recorded through the installed wheel"})
        await c.seal_session(s.session_id)
        assert await c.verify_chain(s.session_id)
        print(f"deny ({deny.stage}: {deny.reason}); allow; recorded, sealed, verified {s.session_id}")

asyncio.run(main())
PY
echo "python wheel: OK"
