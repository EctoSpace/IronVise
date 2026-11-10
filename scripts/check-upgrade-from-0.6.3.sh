#!/usr/bin/env bash
# Gate 7: a session recorded by a real v0.6.3 build verifies under the candidate.
#
# v0.6.3's CLI records to PostgreSQL only, so this needs one:
#   ADMIN_URL   a PostgreSQL URL allowed to create databases
#               (default postgres://postgres:postgres@127.0.0.1:5432/postgres)
#   OLD_BIN     a v0.6.3 `ectoledger` built from the tag without its Linux
#               sandbox feature, e.g.
#                 git worktree add /tmp/v063 v0.6.3
#                 (cd /tmp/v063 && cargo build -p ectoledger --bin ectoledger \
#                    --no-default-features)
#               With it, v0.6.3's seccomp filter refused fchmod and it never
#               saved a key file on Linux; macOS and Windows builds did.
#   NEW_BIN     the candidate (default target/debug/ironvise)
#
# The old build runs a real audit against a scripted Ollama stand-in (one
# read_file, then complete with a finding). The candidate then opens that
# database, which applies its own migrations, and must verify the session,
# the whole ledger, and a certificate it exports for the session.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
ADMIN_URL=${ADMIN_URL:-postgres://postgres:postgres@127.0.0.1:5432/postgres}
NEW_BIN=${NEW_BIN:-$ROOT/target/debug/ironvise}
VERIFY_CERT=$(dirname "$NEW_BIN")/verify-cert
: "${OLD_BIN:?set OLD_BIN to a v0.6.3 ectoledger binary}"
# v0.6.3 has no --version, so which build OLD_BIN is cannot be checked here.

DB="ectoledger_upgrade_$$"
DB_URL="${ADMIN_URL%/*}/$DB"
WORK=$(mktemp -d)
MOCK=""
cleanup() {
    [ -n "$MOCK" ] && kill "$MOCK" 2>/dev/null || true
    psql -q "$ADMIN_URL" -c "DROP DATABASE IF EXISTS $DB WITH (FORCE)" >/dev/null 2>&1 || true
    if [ -n "${KEEP:-}" ]; then echo "kept $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT
psql -q "$ADMIN_URL" -c "CREATE DATABASE $DB" >/dev/null

# A scripted Ollama: /api/tags lists the model, /api/chat answers in turn.
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
mkdir -p "$WORK/project"
echo "db_password=example" > "$WORK/project/config.ini"
python3 - "$PORT" "$WORK/project/config.ini" > "$WORK/mock.log" 2>&1 <<'PY' &
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
port, path = int(sys.argv[1]), sys.argv[2]
turns = [
    {"action": "read_file", "params": {"path": path},
     "justification": "Read the config to check for secrets.", "reasoning": "First step."},
    {"action": "complete", "params": {"findings": [{
        "severity": "medium", "title": "Plaintext password in config",
        "evidence": "config.ini holds db_password", "recommendation": "Use a secret store.",
        "evidence_sequence": [], "evidence_quotes": []}]},
     "justification": "Audit finished with one finding.", "reasoning": "Done."},
]
class H(BaseHTTPRequestHandler):
    def _send(self, body):
        data = json.dumps(body).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_GET(self):
        self._send({"models": [{"name": "mock", "model": "mock"}]})
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        turn = turns.pop(0) if turns else turns_done
        self._send({"message": {"role": "assistant", "content": json.dumps(turn)}, "done": True})
turns_done = {"action": "complete", "params": {"findings": []},
              "justification": "Nothing further to do.", "reasoning": "Done."}
HTTPServer(("127.0.0.1", port), H).serve_forever()
PY
MOCK=$!
sleep 1

# v0.6.3 saves the session key under this password, in its pre-0.8 format,
# to .ectoledger/keys in the working directory: it sandboxes itself to that
# directory, so a key directory elsewhere gets an empty file.
KEY_PASSWORD="upgrade-check-password"
printf '%s' "$KEY_PASSWORD" > "$WORK/key-password"

echo "== v0.6.3 records a session"
(
    cd "$WORK/project"
    DATABASE_URL="$DB_URL" LLM_BACKEND=ollama OLLAMA_BASE_URL="http://127.0.0.1:$PORT" \
        OLLAMA_MODEL=mock GUARD_REQUIRED=false ECTO_KEY_PASSWORD="$KEY_PASSWORD" \
        "$OLD_BIN" audit "Check the project config for secrets" --no-guard --no-guard-confirmed </dev/null
) > "$WORK/old.log" 2>&1 || { cat "$WORK/old.log"; exit 1; }
SESSION=$(psql -qtA "$DB_URL" -c "SELECT id FROM agent_sessions ORDER BY created_at DESC LIMIT 1")
EVENTS=$(psql -qtA "$DB_URL" -c "SELECT count(*) FROM agent_events WHERE session_id = '$SESSION'")
echo "session $SESSION, $EVENTS events, recorded by $OLD_BIN"
[ "$EVENTS" -ge 3 ] || { cat "$WORK/old.log"; echo "too few events" >&2; exit 1; }

KEY=$(psql -qtA "$DB_URL" -c "SELECT session_public_key FROM agent_sessions WHERE id = '$SESSION'")
[ -s "$WORK/project/.ectoledger/keys/session-$SESSION.key" ] || {
    grep -i "key" "$WORK/old.log" | tail -5
    echo "v0.6.3 saved no key file for $SESSION" >&2
    exit 1
}

run_new() {
    (cd "$WORK/project" && DATABASE_URL="$DB_URL" "$NEW_BIN" "$@" </dev/null)
}

echo "== the candidate opens it (migrations apply) and verifies it"
run_new verify-session "$SESSION"
run_new verify-ledger
echo "== and signs a certificate with the key file v0.6.3 saved"
run_new report "$SESSION" --format certificate --no-ots --output "$WORK/upgraded.elc" \
    --key-password-fd 3 3< "$WORK/key-password"
"$VERIFY_CERT" --strict --expected-key "$KEY" "$WORK/upgraded.elc"
run_new verify-session "$SESSION" --against "$WORK/upgraded.elc" --expected-key "$KEY"
echo "upgrade from v0.6.3: OK"
