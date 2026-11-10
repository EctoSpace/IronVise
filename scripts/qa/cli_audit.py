#!/usr/bin/env python3
"""The documented CLI audit with a built-in policy pack, with a real model.

Runs `ironvise audit "List the files in this folder" --policy <pack>` in a
scratch folder with its own SQLite ledger and checks, from the ledger, that a
command really ran (exit 0, the folder's files in its output), that the
session recorded the pack's SHA-256, and that no "Loop detected" cut it short
(the Windows run once looped on `ls`, which the Windows allowlist lacks).

Exit status: 0 when every check passes, 1 otherwise.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

from qa_report import Report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--binary", required=True, type=Path, help="the ironvise binary")
    parser.add_argument("--pack", required=True, type=Path, help="a policy pack, e.g. soc2-audit.toml")
    parser.add_argument("--model", default=os.environ.get("ECTO_SCENARIO_MODEL", "qwen2.5:7b"))
    parser.add_argument("--ollama", default=os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434"))
    args = parser.parse_args()

    report = Report()
    work = Path(tempfile.mkdtemp(prefix="ecto-qa-cli-"))
    try:
        for name in ("alpha.txt", "beta.txt"):
            (work / name).write_text("qa\n")
        ledger = work / "ledger.db"
        env = {
            **{k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "TEMP", "TMP")},
            "ECTO_DATA_DIR": str(work / "data"),
            "DATABASE_URL": f"sqlite:{ledger.as_posix()}",
            "GUARD_REQUIRED": "false",
            "LLM_BACKEND": "ollama",
            "OLLAMA_BASE_URL": args.ollama,
            "OLLAMA_MODEL": args.model,
            "AGENT_MAX_STEPS": "4",
            "ECTO_DEV_MODE": "true",
            "ECTO_BIND_PORT": "0",
        }
        done = subprocess.run(
            [str(args.binary.resolve()), "audit", "List the files in this folder", "--policy", str(args.pack.resolve())],
            cwd=work, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, encoding="utf-8",
            errors="replace",
            timeout=900,
        )
        report.check("cli: the audit exits 0", done.returncode == 0, done.stderr.strip()[-200:])

        db = sqlite3.connect(ledger)
        sessions = db.execute("SELECT status, policy_hash FROM agent_sessions").fetchall()
        payloads = [json.loads(p) for (p,) in db.execute("SELECT payload FROM agent_events ORDER BY sequence")]
        db.close()
        observations = [p.get("content", "") for p in payloads if p.get("type") == "observation"]
        thoughts = [p.get("content", "") for p in payloads if p.get("type") == "thought"]

        report.check("cli: a command really ran and listed the folder",
                     any("exit_code: Some(0)" in o and "alpha.txt" in o for o in observations), observations[:2])
        expected = hashlib.sha256(args.pack.read_bytes()).hexdigest()
        report.check("cli: the session records the pack's SHA-256",
                     bool(sessions) and sessions[-1][1] == expected, sessions)
        report.check("cli: no loop detection", not any("Loop detected" in t for t in thoughts), thoughts[-1:])
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return report.summary()


if __name__ == "__main__":
    sys.exit(main())
