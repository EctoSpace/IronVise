#!/usr/bin/env python3
"""Run scenarios.py against `ironvise serve`, isolated, on any platform.

Starts the server with its own data folder, SQLite ledger, working folder
and port (nothing of the user's is read or written), waits until it answers,
runs the scenarios with `guard-worker` as the worker to look for, and stops
the server. Linux and Windows use this; macOS also drives the built app
(run-mac.sh).

Exit status: the scenarios' (0 when every check passes).
"""

from __future__ import annotations

import argparse
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_until_up(url: str, proc: subprocess.Popen, seconds: int = 60) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise SystemExit(f"the server exited at startup (code {proc.returncode})")
        try:
            urllib.request.urlopen(url, timeout=2)
            return
        except OSError:
            time.sleep(0.5)
    raise SystemExit(f"the server did not answer {url} within {seconds} s")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--bin-dir", required=True, type=Path,
                        help="folder with ectoledger, guard-worker and verify-cert (e.g. target/debug)")
    parser.add_argument("--model", default=os.environ.get("ECTO_SCENARIO_MODEL", "qwen2.5:7b"))
    parser.add_argument("--guard-model", default=os.environ.get("ECTO_SCENARIO_GUARD_MODEL"))
    args = parser.parse_args()

    exe = ".exe" if os.name == "nt" else ""
    root = Path(tempfile.mkdtemp(prefix="ecto-qa-serve-"))
    data, workspace, out = root / "data", root / "workspace", root / "out"
    for folder in (data, workspace, out):
        folder.mkdir()
    for name in ("alpha.txt", "beta.txt"):
        (workspace / name).write_text("qa\n")

    port, token = free_port(), secrets.token_hex(24)
    env = {
        **os.environ,
        "ECTO_DATA_DIR": str(data),
        "DATABASE_URL": f"sqlite:{(root / 'ledger.db').as_posix()}",
        "OBSERVER_TOKEN": token,
        "ECTO_BIND_HOST": "127.0.0.1",
        "ECTO_BIND_PORT": str(port),
        "GUARD_REQUIRED": "false",
        "LLM_BACKEND": "ollama",
        "OLLAMA_BASE_URL": os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434"),
        "RUST_LOG": "warn",
    }
    env.pop("ECTO_POLICY_PATH", None)
    server = subprocess.Popen([str(args.bin_dir.resolve() / f"ironvise{exe}"), "serve"],
                              cwd=workspace, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        wait_until_up(f"http://127.0.0.1:{port}/api/status", server)
        cmd = [
            sys.executable, str(HERE / "scenarios.py"),
            "--base", f"http://127.0.0.1:{port}/api",
            "--token", token,
            "--settings-file", str(data / "settings.json"),
            "--verify-cert", str(args.bin_dir.resolve() / f"verify-cert{exe}"),
            "--out", str(out),
            "--worker-marker", "guard-worker",
            "--model", args.model,
        ]
        if args.guard_model:
            cmd += ["--guard-model", args.guard_model]
        return subprocess.run(cmd).returncode
    finally:
        server.terminate()
        try:
            server.wait(timeout=15)
        except subprocess.TimeoutExpired:
            server.kill()
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
