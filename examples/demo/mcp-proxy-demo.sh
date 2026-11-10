#!/usr/bin/env bash
#
# `ironvise mcp-proxy` in front of a real MCP server: the official
# filesystem server (@modelcontextprotocol/server-filesystem), with a policy
# that forbids its write_file tool. A read goes through, the write is refused
# before the server sees it, the file is never created, and both decisions
# verify as signed ledger events. Every step asserts.
#
#   bash examples/demo/mcp-proxy-demo.sh
#
# Needs: a built `ironvise`, node/npm (fetches the pinned server once),
# python3 (plays the MCP client), sqlite3.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${ECTOLEDGER_BIN:-$ROOT/target/debug/ironvise}"
PORT="${DEMO_PORT:-3170}"
SERVER_PKG="@modelcontextprotocol/server-filesystem@2026.8.31"
WORK="$(mktemp -d)"
SERVE_PID=""
cleanup() { [ -n "$SERVE_PID" ] && kill "$SERVE_PID" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

ok()  { printf '  ✓ %s\n' "$1"; }
bad() { printf '  ✗ %s\n' "$1"; exit 1; }

[ -x "$BIN" ] || { echo "build first: cargo build --bin ironvise"; exit 1; }
for t in npm python3 sqlite3 curl; do command -v "$t" >/dev/null || { echo "$t not found"; exit 1; }; done

echo "▸ Fetch the filesystem MCP server ($SERVER_PKG)"
npm install --silent --no-audit --no-fund --prefix "$WORK/npm" "$SERVER_PKG" >/dev/null
MCP_SERVER="$WORK/npm/node_modules/.bin/mcp-server-filesystem"
[ -x "$MCP_SERVER" ] || bad "server binary not found"
mkdir -p "$WORK/files" && printf 'hello from the sandbox\n' >"$WORK/files/hello.txt"
ok "installed"

echo "▸ Start IronVise with a policy that forbids mcp:files/write_file"
cat >"$WORK/policy.toml" <<'TOML'
name = "mcp demo: read, never write"
[[forbidden_actions]]
action = "mcp:files/write_file"
TOML
( cd "$WORK" && DATABASE_URL="sqlite:$WORK/ledger.sqlite" OBSERVER_TOKEN=demo GUARD_REQUIRED=false \
    ECTO_POLICY_PATH="$WORK/policy.toml" ECTO_DATA_DIR="$WORK/data" \
    ECTO_BIND_HOST=127.0.0.1 ECTO_BIND_PORT="$PORT" exec "$BIN" serve >"$WORK/serve.log" 2>&1 ) &
SERVE_PID=$!
for _ in $(seq 1 60); do
  curl -sf --max-time 1 -H "Authorization: Bearer demo" "http://127.0.0.1:$PORT/api/sessions" >/dev/null 2>&1 && break
  sleep 1
done
curl -sf -H "Authorization: Bearer demo" "http://127.0.0.1:$PORT/api/sessions" >/dev/null || bad "server did not start"
ok "listening on 127.0.0.1:$PORT"

echo "▸ An MCP client talks to the server through the proxy"
ECTOLEDGER_URL="http://127.0.0.1:$PORT" ECTOLEDGER_TOKEN=demo \
  BIN="$BIN" MCP_SERVER="$MCP_SERVER" FILES="$WORK/files" python3 - <<'PY'
import json, os, subprocess, sys

proxy = subprocess.Popen(
    [os.environ["BIN"], "mcp-proxy", "--name", "files", "--",
     os.environ["MCP_SERVER"], os.environ["FILES"]],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

def send(msg):
    proxy.stdin.write(json.dumps(msg) + "\n")
    proxy.stdin.flush()

def call(i, method, params):
    send({"jsonrpc": "2.0", "id": i, "method": method, "params": params})
    while True:
        reply = json.loads(proxy.stdout.readline())
        if reply.get("id") == i:
            return reply

call(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "demo", "version": "1"}})
send({"jsonrpc": "2.0", "method": "notifications/initialized"})
tools = [t["name"] for t in call(2, "tools/list", {})["result"]["tools"]]
read_tool = "read_text_file" if "read_text_file" in tools else "read_file"

hello = os.path.join(os.environ["FILES"], "hello.txt")
read = call(3, "tools/call", {"name": read_tool, "arguments": {"path": hello}})
text = read["result"]["content"][0]["text"]
assert "hello from the sandbox" in text and not read["result"].get("isError"), read
print(f"  ✓ {read_tool} went through: {text.strip()!r}")

target = os.path.join(os.environ["FILES"], "planted.txt")
write = call(4, "tools/call", {"name": "write_file", "arguments": {"path": target, "content": "x"}})
assert write["result"]["isError"] is True, write
reason = write["result"]["content"][0]["text"]
assert "forbidden by policy" in reason, reason
assert not os.path.exists(target), "the refused write happened"
print(f"  ✓ write_file refused before the server saw it: {reason}")

proxy.stdin.close()
sys.exit(proxy.wait() and 0)
PY

echo "▸ Both decisions are in the ledger, and the session verifies"
SID=$(sqlite3 "$WORK/ledger.sqlite" "SELECT id FROM agent_sessions WHERE llm_backend='mcp-proxy' LIMIT 1")
sqlite3 "$WORK/ledger.sqlite" "SELECT '    ' || sequence || '  ' || json_extract(payload,'\$.type') || '  ' ||
  COALESCE(json_extract(payload,'\$.name'), json_extract(payload,'\$.reason'), json_extract(payload,'\$.tool'), '')
  FROM agent_events WHERE session_id='$SID' ORDER BY sequence"
[ "$(sqlite3 "$WORK/ledger.sqlite" "SELECT count(*) FROM agent_events WHERE session_id='$SID'
     AND json_extract(payload,'\$.type')='tripwire_rejection' AND payload LIKE '%write_file%'")" = 1 ] \
  || bad "the refusal is not in the ledger"
DATABASE_URL="sqlite:$WORK/ledger.sqlite" OBSERVER_TOKEN=demo "$BIN" verify-session "$SID" >"$WORK/verify.log" 2>&1 \
  || { cat "$WORK/verify.log"; bad "verify-session failed"; }
ok "$(grep -o 'All [0-9]* event signatures verified' "$WORK/verify.log" || echo verified)"

echo "▸ What the read returned is in the ledger by hash, and only by hash"
[ "$(sqlite3 "$WORK/ledger.sqlite" "SELECT count(*) FROM agent_events WHERE session_id='$SID'
     AND payload LIKE '%hello from the sandbox%'")" = 0 ] || bad "the file's text is in the ledger"
DATABASE_URL="sqlite:$WORK/ledger.sqlite" OBSERVER_TOKEN=demo \
  "$BIN" data-receipts "$SID" --file "$WORK/files/hello.txt" >"$WORK/receipts.log" 2>&1 \
  || { cat "$WORK/receipts.log"; bad "hello.txt does not match the read's receipt"; }
ok "$(grep -o 'hello.txt: exactly what the tool returned at #[0-9]*' "$WORK/receipts.log")"
