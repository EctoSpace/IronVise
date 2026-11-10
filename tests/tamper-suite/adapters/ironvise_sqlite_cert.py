"""IronVise SQLite ledger, checked with a certificate held elsewhere.

The same genuine session and the same attacks as `ironvise_sqlite`, but the
auditor also kept the signed `.elc` exported when the session ended, and runs

    ironvise verify-ledger --strict
    ironvise verify-session <id> --against audit.elc --expected-key <key>

The two attacks no database-only verifier can catch (a truncation behind a
rewritten seal, and a session re-signed with a new key) are "must detect" here,
because the certificate commits to the tip, every event hash and the key.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
from pathlib import Path

_base_path = Path(__file__).with_name("ironvise_sqlite.py")
_spec = importlib.util.spec_from_file_location("ironvise_sqlite_base", _base_path)
base = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(base)


class _Adapter(base._Adapter):
    name = ("IronVise SQLite ledger plus a held certificate, "
            "`verify-session --against audit.elc --expected-key`")

    def make_clean(self, workdir: Path) -> Path:
        port = int(os.environ.get("TAMPER_SUITE_PORT", "3293"))
        self.cert = workdir / "held.elc"
        ledger, sid = base.build_session(workdir, base.COMMANDS, port,
                                         hook_session_id="tamper-suite-cert",
                                         certificate_to=self.cert)
        self.sid = sid
        # The key the auditor wrote down when the certificate was handed over.
        self.key = json.loads(self.cert.read_text())["session_public_key"]
        return ledger

    def verify(self, path: Path) -> tuple[bool, str]:
        ok, detail = super().verify(path)
        if not ok:
            return ok, detail
        env = {**os.environ, "DATABASE_URL": f"sqlite:{path}", "OBSERVER_TOKEN": "x"}
        r = subprocess.run([str(base.BIN), "verify-session", self.sid, "--against",
                            str(self.cert), "--expected-key", self.key],
                           env=env, capture_output=True, text=True)
        if r.returncode == 0:
            return True, detail
        err = [ln for ln in r.stderr.splitlines() if ln.startswith("Error:")]
        last = err or [ln for ln in r.stdout.splitlines() if ln.strip()]
        msg = (last[-1] if last else "verify-session --against failed").strip()
        # The temporary path would make every run's report differ.
        return False, msg.removeprefix("Error: ").replace(str(self.cert), self.cert.name)

    def cases(self):
        out = []
        for c in super().cases():
            if c.id in ("truncate-tail-reseal", "resign-own-key"):
                c.expectation, c.beyond, c.note = "must", "", ""
            out.append(c)
        return out


ADAPTER = _Adapter()
