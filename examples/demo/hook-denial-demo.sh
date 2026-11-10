#!/usr/bin/env bash
#
# The demo: a disallowed command is denied before it runs, the denial is in the
# hash chain, the chain verifies, and then one byte is changed and verification
# fails naming the break.
#
# This is the script, not a recording. It is written to be *run*, not watched:
# every step asserts, so it doubles as an end-to-end test of the hook, the
# ledger and the verifier together. A recording is a rendering of this; the
# script is the thing that can be checked.
#
#   bash examples/demo/hook-denial-demo.sh
#
# Needs: a release or debug build of `ironvise`, and the `sqlite3` CLI on
# PATH. No Postgres, no model, no network - the whole demo runs on SQLite
# against a local Observer.
#
# To record it:
#   DEMO_PACE=1 python3 -m asciinema rec demo.cast \\
#       -c "bash examples/demo/hook-denial-demo.sh"
#   agg demo.cast demo.gif        # https://github.com/asciinema/agg

set -euo pipefail

# ── setup ────────────────────────────────────────────────────────────────────
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${ECTOLEDGER_BIN:-$ROOT/target/debug/ironvise}"
PORT="${DEMO_PORT:-3140}"
WORK="$(mktemp -d)"
SERVER_PID=""

# Git Bash hands `/tmp/…` to native Windows binaries two different ways: paths
# in argv are rewritten to `C:\Users\…\Temp\…`, paths in the environment are
# passed through untouched and the binary then resolves `/tmp` drive-relative to
# `C:\tmp`. DATABASE_URL is an environment variable and the sqlite3 argument is
# argv, so the server and the queries below would use two different files and
# every read would report `no such table`. Resolve to a native path once, up
# front, and both agree. No-op everywhere except Git Bash / MSYS.
command -v cygpath >/dev/null 2>&1 && WORK="$(cygpath -m "$WORK")"

# Colours, only when attached to a terminal, so piped output stays clean.
if [ -t 1 ]; then
  B=$'\e[1m'; G=$'\e[32m'; R=$'\e[31m'; D=$'\e[2m'; N=$'\e[0m'
else
  B=""; G=""; R=""; D=""; N=""
fi

cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# Pacing exists only for recording. Unset, the script runs flat out and works
# as an end-to-end test; set DEMO_PACE=1 and it becomes watchable. A demo that
# is only ever a recording rots, so the fast path is the default.
pause() { [ -n "${DEMO_PACE:-}" ] && sleep "${1:-1}" || true; }

step() { pause 0.6; printf '\n%s▸ %s%s\n' "$B" "$1" "$N"; pause 0.5; }
ok()   { printf '%s  ✓ %s%s\n' "$G" "$1" "$N"; pause 0.8; }
bad()  { printf '%s  ✗ %s%s\n' "$R" "$1" "$N"; exit 1; }
run()  { printf '%s  $ %s%s\n' "$D" "$1" "$N"; pause 0.7; }

[ -x "$BIN" ] || { echo "build first:  cargo build --bin ironvise"; exit 1; }

# The demo reads and tampers with the ledger through the sqlite3 CLI, which is
# not a build dependency and is absent on a stock Windows or macOS box. Check it
# here rather than letting step 3 die with a bare "command not found" after the
# earlier steps have already printed their ✓.
command -v sqlite3 >/dev/null || {
  echo "sqlite3 not found - this demo inspects the ledger with it."
  echo "  Debian/Ubuntu:  sudo apt-get install -y sqlite3"
  echo "  macOS:          brew install sqlite"
  echo "  Windows:        winget install SQLite.SQLite"
  exit 1
}

# ── 1. start a ledger ────────────────────────────────────────────────────────
step "Start IronVise on a fresh SQLite ledger"
run "ironvise serve"
DATABASE_URL="sqlite:$WORK/ledger.sqlite" OBSERVER_TOKEN=demo GUARD_REQUIRED=false \
  ECTO_BIND_HOST=127.0.0.1 ECTO_BIND_PORT="$PORT" \
  "$BIN" serve >"$WORK/serve.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 60); do
  curl -sf --max-time 1 -H "Authorization: Bearer demo" \
    "http://127.0.0.1:$PORT/api/sessions" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf --max-time 2 -H "Authorization: Bearer demo" \
  "http://127.0.0.1:$PORT/api/sessions" >/dev/null 2>&1 \
  || bad "server did not start - see $WORK/serve.log"
ok "listening on 127.0.0.1:$PORT"

export ECTOLEDGER_URL="http://127.0.0.1:$PORT" ECTOLEDGER_TOKEN=demo

# The hook's reply is one long JSON line. Left alone it wraps mid-word in a
# terminal, which reads as noise in a recording; break it at the field boundary
# instead. The bytes are unchanged - this is presentation only.
show_json() {
  sed 's/,"permissionDecisionReason"/,\
        "permissionDecisionReason"/' <<<"    $1"
}

hook() {  # hook <tool> <json-input>
  printf '{"session_id":"demo","tool_name":"%s","tool_input":%s,"cwd":"%s","hook_event_name":"PreToolUse"}' \
    "$1" "$2" "$ROOT" | "$BIN" hook
}

# ── 2. an allowed call ───────────────────────────────────────────────────────
step "Claude Code asks to run a harmless command"
run 'ironvise hook   <<< {"tool_name":"Bash","tool_input":{"command":"ls -la"}}'
ALLOW=$(hook Bash '{"command":"ls -la"}')
# No objection is sent as no output: Claude Code's own permissions then decide,
# as if the hook were not installed. ECTOLEDGER_HOOK_MODE=approve sends "allow".
[ -z "$ALLOW" ] || bad "expected no output for an allowed call, got: $ALLOW"
printf '%s    (no output)%s\n' "$D" "$N"
ok "no objection - recorded, and left to Claude Code's own permissions"

# ── 3. a denied call ─────────────────────────────────────────────────────────
step "Now it asks to run something destructive"
run 'ironvise hook   <<< {"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}'
DENY=$(hook Bash '{"command":"rm -rf /"}')
show_json "$DENY"
grep -q '"permissionDecision":"deny"' <<<"$DENY" || bad "expected deny"
ok "DENIED before execution - Claude Code honours this and does not run it"

# ── 4. the denial is in the chain ────────────────────────────────────────────
step "The refusal is a first-class ledger event, not a log line"
run "sqlite3 ledger.sqlite 'SELECT sequence, payload FROM agent_events'"
sqlite3 "$WORK/ledger.sqlite" \
  "SELECT '    ' || sequence || '  ' || json_extract(payload,'\$.type') ||
          COALESCE('  ' || json_extract(payload,'\$.reason'), '')
   FROM agent_events ORDER BY sequence;"
ENFORCED=$(sqlite3 "$WORK/ledger.sqlite" \
  "SELECT json_extract(payload,'\$.enforced') FROM agent_events
   WHERE json_extract(payload,'\$.type')='tripwire_rejection' LIMIT 1;")
[ "$ENFORCED" = "1" ] || bad "denial should be recorded as enforced"
ok "recorded as tripwire_rejection with enforced=true - the action did not happen"

# ── 5. the chain verifies ────────────────────────────────────────────────────
step "Verify the session"
SID=$(sqlite3 "$WORK/ledger.sqlite" "SELECT id FROM agent_sessions LIMIT 1")
run "ironvise verify-session $SID"
DATABASE_URL="sqlite:$WORK/ledger.sqlite" OBSERVER_TOKEN=demo \
  "$BIN" verify-session "$SID" 2>&1 | grep -v OBSERVER_TOKEN | grep -v Dashboard | sed 's/^/    /'
ok "signatures verified"

# ── 6. tamper with one byte ──────────────────────────────────────────────────
step "Now change one byte in the ledger, as an attacker with database access would"
run "sqlite3 ledger.sqlite 'UPDATE agent_events SET payload = ... WHERE sequence = 2'"
# The immutability trigger refuses this, which is the database layer doing its
# job. It is no defence against someone holding the file, so drop it first -
# the hash chain is the layer that has to catch that.
sqlite3 "$WORK/ledger.sqlite" "DROP TRIGGER IF EXISTS agent_events_no_update;"
sqlite3 "$WORK/ledger.sqlite" \
  "UPDATE agent_events SET payload = json_set(payload,'\$.reason','looked fine to me') WHERE sequence = 2;"
ok "the recorded reason for the denial now reads \"looked fine to me\""

# ── 7. verification fails ────────────────────────────────────────────────────
step "Verify again"
run "ironvise verify-session $SID"
if DATABASE_URL="sqlite:$WORK/ledger.sqlite" OBSERVER_TOKEN=demo \
     "$BIN" verify-session "$SID" >"$WORK/verify2.log" 2>&1; then
  grep -qiE 'broken|mismatch|invalid|failed' "$WORK/verify2.log" \
    || bad "tampering was NOT detected - this is the claim failing"
fi
grep -viE 'OBSERVER_TOKEN|Dashboard' "$WORK/verify2.log" | sed 's/^/    /'
ok "tampering detected"

# Not part of the story, but part of the test: approve mode forwards the allow.
APPROVE=$(printf '{"session_id":"demo-approve","tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"%s"}' \
  "$ROOT" | ECTOLEDGER_HOOK_MODE=approve "$BIN" hook)
grep -q '"permissionDecision":"allow"' <<<"$APPROVE" || bad "approve mode should send allow, got: $APPROVE"

printf '\n%s%s%s\n' "$B" "The point:" "$N"
cat <<'TXT'
    The command was refused before it ran, the refusal is in the chain as
    structured evidence, and altering that evidence afterwards is detectable
    by anyone holding the ledger.

    What this does NOT show: that the log is complete. A hash chain constrains
    what can happen after an event is written. It says nothing about an event
    that was never written.
TXT
