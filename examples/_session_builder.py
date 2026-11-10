"""Drive a real session through the Claude Code hook and seal it.

Shared by `examples/challenge/generate.py` and
`examples/verified-session/generate.py`. It lives here because both need the
same thing - a genuine hook-driven ledger, not a hand-assembled one - and a
copy in each is how the two would quietly drift apart.

Nothing in here fabricates events. A real server is started against a
throwaway SQLite file, the real `ironvise hook` binary is invoked once per
tool call, and the session is sealed over HTTP. What comes out is a ledger the
ordinary verifier accepts, because it was produced the ordinary way.
"""

import json
import os
import signal
import sqlite3
import subprocess
import sys
import time
from contextlib import closing
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = Path(os.environ.get("ECTOLEDGER_BIN", ROOT / "target/release/ironvise"))
TOKEN = "example"

# The hook builds a session's goal from the working directory it is handed
# (`hook.rs`: "Claude Code session in {cwd}"), so this string ends up inside
# every generated ledger, inside the goal hash over it, and inside any
# certificate cut from it. It is a fixed neutral path rather than the real
# repository root: passing the latter baked one contributor's home directory
# and this repository's name into committed, publicly shipped fixtures, and it
# made the artefacts differ depending on who last ran the script.
SESSION_CWD = "/workspace/ectoledger-example"


def _wait_for_server(base: str, token: str, log_path: Path) -> None:
    for _ in range(60):
        try:
            req = urllib.request.Request(
                f"{base}/api/sessions", headers={"Authorization": f"Bearer {token}"}
            )
            urllib.request.urlopen(req, timeout=1).read()
            return
        except (urllib.error.URLError, OSError):
            time.sleep(1)
    raise SystemExit(f"server never came up; see {log_path}")


def build_session(workdir: Path, commands, port: int, token: str = TOKEN,
                  hook_session_id: str = "example",
                  certificate_to: Path | None = None,
                  ots: bool = False) -> tuple[Path, str]:
    """Run a real session through the hook; return (sealed ledger, session id).

    When *certificate_to* is given the certificate is exported over HTTP
    **before the server is stopped**, because that is the only moment the
    session's Ed25519 key exists. The hook holds it in memory for the life of
    the process and it is never written to disk, so a certificate cut from the
    sealed database afterwards - which is what this script used to do - can only
    be unsigned. Exporting here is what makes the shipped example a signed
    receipt rather than an internally consistent document of unknown origin.
    """
    db = workdir / "live.db"
    env = {
        **os.environ,
        "DATABASE_URL": f"sqlite:{db}",
        "OBSERVER_TOKEN": token,
        "GUARD_REQUIRED": "false",
        "ECTO_BIND_HOST": "127.0.0.1",
        "ECTO_BIND_PORT": str(port),
    }
    log_path = workdir / "serve.log"
    log = open(log_path, "w")
    proc = subprocess.Popen([str(BIN), "serve"], env=env, stdout=log, stderr=log)
    try:
        base = f"http://127.0.0.1:{port}"
        _wait_for_server(base, token, log_path)

        hook_env = {**env, "ECTOLEDGER_URL": base, "ECTOLEDGER_TOKEN": token}
        for cmd in commands:
            payload = json.dumps({
                "session_id": hook_session_id, "tool_name": "Bash",
                "tool_input": {"command": cmd}, "cwd": SESSION_CWD,
                "hook_event_name": "PreToolUse",
            })
            subprocess.run([str(BIN), "hook"], input=payload, text=True,
                           env=hook_env, capture_output=True)

        # Seal it, so the session commits to its own length (F-2).
        # Closed explicitly: on Windows an open handle keeps the file from
        # being deleted, which failed every caller's temporary-directory cleanup.
        with closing(sqlite3.connect(db)) as c:
            sid = c.execute("SELECT id FROM agent_sessions LIMIT 1").fetchone()[0]
        req = urllib.request.Request(
            f"{base}/api/sessions/{sid}/seal", method="POST",
            headers={"Authorization": f"Bearer {token}",
                     "Content-Type": "application/json"},
            data=b"{}")
        try:
            urllib.request.urlopen(req, timeout=10).read()
        except urllib.error.HTTPError as e:
            print(f"    note: seal returned {e.code}; continuing", file=sys.stderr)

        if certificate_to is not None:
            url = f"{base}/api/certificates/{sid}" + ("?ots=true" if ots else "")
            req = urllib.request.Request(
                url, headers={"Authorization": f"Bearer {token}"})
            # The OTS calendar round trip is the slow part; the rest is local.
            body = urllib.request.urlopen(req, timeout=120 if ots else 20).read()
            cert = json.loads(body)
            if not cert.get("signature"):
                raise SystemExit(
                    "the server returned an unsigned certificate - it should still "
                    "hold this session's key at this point")
            certificate_to.write_text(json.dumps(cert, indent=2, sort_keys=True))
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=30)
        log.close()

    # VACUUM INTO, never a file copy: the WAL sidecar is part of the database
    # and a bare `cp` ships something SQLite calls malformed.
    out = workdir / "sealed.db"
    with closing(sqlite3.connect(db)) as c:
        c.execute("VACUUM INTO ?", (str(out),))
    return out, sid
