#!/usr/bin/env python3
"""IronVise's end-to-end QA suite, on macOS (Apple Silicon), Linux and Windows.

    python3 scripts/qa/run.py            # make test-e2e
    py scripts\\qa\\run.py               # Windows

Every step runs against real software: the built binaries, a real local model
through Ollama, the platform's real sandbox and credential store. Nothing of
the user's is read or written: servers and the app get scratch data folders,
ledgers and working folders.

Steps, on every platform:
  selftest    the QA scripts' own tests (scripts/qa/test_*.py; needs pytest)
  sandbox     executor tests: commands run under the OS sandbox, which refuses
              what it should (macOS: a read outside the workspace)
  contract    every command the desktop webview calls, with the JSON its call
              site sends, through real Tauri IPC (this platform's webview origin)
  guard       the guard worker over HMAC with a real model (also the desktop
              binary as `--guard-worker` when it is built)
  cli         the documented `audit --policy soc2-audit.toml`
  serve       scripts/qa/scenarios.py against an isolated `ironvise serve`
  keychain    a saved API key survives a restart (test service only); skipped
              where no credential store runs (a Linux session without the
              Secret Service)
  gui         the desktop UI's Playwright suite (pixel baselines on macOS only)
macOS also:
  app         the release app bundle: strict codesign, then scenarios.py
              against the app itself, launched in a scratch HOME
  stability   the app stays up and answering while idle

Needs Ollama on 127.0.0.1:11434 (or OLLAMA_BASE_URL) with a chat model; the
first chat model is used unless ECTO_SCENARIO_MODEL names one.

Options:
  --skip-app-build   reuse target/release's app bundle (macOS)
  --only STEP[,..]   run only these steps
  --stability SECS   idle time for the stability step (default 120)
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
QA = ROOT / "scripts" / "qa"
IS_MAC, IS_WINDOWS = sys.platform == "darwin", os.name == "nt"
EXE = ".exe" if IS_WINDOWS else ""
BIN = ROOT / "target" / "debug"
OLLAMA = os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434")


@dataclass
class Outcome:
    step: str
    status: str  # PASS, FAIL or SKIP
    note: str = ""


def banner(text: str) -> None:
    print(f"\n== {text}", flush=True)


def run(cmd: list[str], **kwargs) -> int:
    """Run a command, streaming its output; its exit status."""
    print("$ " + " ".join(str(c) for c in cmd), flush=True)
    return subprocess.run([str(c) for c in cmd], cwd=kwargs.pop("cwd", ROOT), **kwargs).returncode


def cargo_test(*args: str) -> bool:
    return run(["cargo", "test", "-q", *args]) == 0


def ollama_chat_model() -> str:
    """The first model Ollama lists that can chat (not an embedding model)."""
    with urllib.request.urlopen(f"{OLLAMA}/api/tags", timeout=10) as resp:
        names = [m["name"] for m in json.load(resp)["models"]]
    for name in names:
        req = urllib.request.Request(f"{OLLAMA}/api/show", data=json.dumps({"model": name}).encode(), method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            if "completion" in json.load(resp).get("capabilities", []):
                return name
    raise SystemExit("Ollama has no chat model; pull one first (e.g. `ollama pull qwen2.5:7b`)")


def credential_store_available() -> bool:
    if IS_MAC or IS_WINDOWS:
        return True
    probe = subprocess.run(["busctl", "--user", "list"], capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
    return probe.returncode == 0 and "org.freedesktop.secrets" in probe.stdout


def step_selftest(_: argparse.Namespace) -> Outcome:
    probe = subprocess.run([sys.executable, "-m", "pytest", "--version"], capture_output=True)
    if probe.returncode != 0:
        return Outcome("selftest", "SKIP", "pytest not installed")
    code = run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", QA])
    return Outcome("selftest", "PASS" if code == 0 else "FAIL")


def step_sandbox(_: argparse.Namespace) -> Outcome:
    return Outcome("sandbox", "PASS" if cargo_test("-p", "ectoledger", "--lib", "executor") else "FAIL")


def step_contract(_: argparse.Namespace) -> Outcome:
    return Outcome("contract", "PASS" if cargo_test("-p", "ironvise-gui", "ipc_contract") else "FAIL")


def step_guard(args: argparse.Namespace) -> Outcome:
    workers = ["--", str(BIN / f"guard-worker{EXE}")]
    desktop = desktop_binary()
    if desktop:
        workers += ["--", str(desktop), "--guard-worker"]
    with tempfile.TemporaryDirectory(prefix="ecto-qa-guard-") as data:
        code = run([sys.executable, QA / "guard_worker.py", data, "--model", args.guard_model, *workers])
    note = "standalone and desktop binary" if desktop else "standalone (desktop binary not built)"
    return Outcome("guard", "PASS" if code == 0 else "FAIL", note)


def step_cli(args: argparse.Namespace) -> Outcome:
    code = run([sys.executable, QA / "cli_audit.py", "--binary", BIN / f"ironvise{EXE}",
                "--pack", ROOT / "crates" / "host" / "policies" / "soc2-audit.toml", "--model", args.model])
    return Outcome("cli", "PASS" if code == 0 else "FAIL")


def step_serve(args: argparse.Namespace) -> Outcome:
    code = run([sys.executable, QA / "serve_scenarios.py", "--bin-dir", BIN,
                "--model", args.model, "--guard-model", args.guard_model])
    return Outcome("serve", "PASS" if code == 0 else "FAIL")


def step_keychain(_: argparse.Namespace) -> Outcome:
    if not credential_store_available():
        return Outcome("keychain", "SKIP", "no Secret Service in this session")
    ok = cargo_test("-p", "ironvise-gui", "a_saved_key_survives", "--", "--ignored")
    return Outcome("keychain", "PASS" if ok else "FAIL")


def step_gui(_: argparse.Namespace) -> Outcome:
    npm = shutil.which("npm")
    if not npm:
        return Outcome("gui", "SKIP", "npm not installed")
    gui = ROOT / "gui"
    if run([npm, "ci", "--no-audit", "--no-fund"], cwd=gui) != 0 or run([npm, "run", "check"], cwd=gui) != 0:
        return Outcome("gui", "FAIL", "npm ci or type check")
    extra = [] if IS_MAC else ["--", "--ignore-snapshots"]
    code = run([npm, "run", "test:visual", *extra], cwd=gui)
    return Outcome("gui", "PASS" if code == 0 else "FAIL", "" if IS_MAC else "pixel baselines are macOS-only")


def desktop_binary() -> Path | None:
    if IS_MAC:
        app = ROOT / "target" / "release" / "bundle" / "macos" / "IronVise.app" / "Contents" / "MacOS" / "ironvise-gui"
        return app if app.exists() else None
    for candidate in (ROOT / "target" / "release" / f"ironvise-gui{EXE}", BIN / f"ironvise-gui{EXE}"):
        if candidate.exists():
            return candidate
    return None


def step_app(args: argparse.Namespace) -> Outcome:
    if not args.skip_app_build:
        if run(["npx", "tauri", "build", "--bundles", "app"], cwd=ROOT / "gui") != 0:
            return Outcome("app", "FAIL", "the app bundle did not build")
    bundle = ROOT / "target" / "release" / "bundle" / "macos" / "IronVise.app"
    if run(["codesign", "--verify", "--strict", bundle]) != 0:
        return Outcome("app", "FAIL", "strict codesign verification")

    home = Path(tempfile.mkdtemp(prefix="ecto-qa-app-"))
    workspace, out = home / "workspace", home / "out"
    workspace.mkdir()
    out.mkdir()
    for name in ("alpha.txt", "beta.txt"):
        (workspace / name).write_text("qa\n")
    token = secrets.token_hex(24)
    log = home / "app.log"
    env = {"PATH": os.environ["PATH"], "HOME": str(home), "OBSERVER_TOKEN": token, "RUST_LOG": "info"}
    app = subprocess.Popen([desktop_binary()], cwd=workspace, env=env,
                           stdout=log.open("w", encoding="utf-8"), stderr=subprocess.STDOUT)
    args.app_state = (app, home, token)
    port = None
    for _ in range(90):
        text = log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""
        if "listening on http://127.0.0.1:" in text:
            port = text.split("listening on http://127.0.0.1:")[1].split()[0].strip()
            break
        time.sleep(1)
    if not port:
        return Outcome("app", "FAIL", "the app did not start its server")
    args.app_port = port
    settings = home / "Library" / "Application Support" / "io.ectoledger.agent-ledger" / "settings.json"
    code = run([sys.executable, QA / "scenarios.py", "--base", f"http://127.0.0.1:{port}/api",
                "--token", token, "--settings-file", settings, "--verify-cert", BIN / "verify-cert",
                "--out", out, "--worker-marker", "ironvise-gui --guard-worker",
                "--model", args.model, "--guard-model", args.guard_model])
    return Outcome("app", "PASS" if code == 0 else "FAIL", "strict codesign; scenarios against the app")


def step_stability(args: argparse.Namespace) -> Outcome:
    state = getattr(args, "app_state", None)
    if not state or not getattr(args, "app_port", None):
        return Outcome("stability", "SKIP", "the app step did not start the app")
    app, _, token = state
    deadline = time.monotonic() + args.stability
    while time.monotonic() < deadline:
        time.sleep(5)
        if app.poll() is not None:
            return Outcome("stability", "FAIL", f"the app exited (code {app.returncode})")
        req = urllib.request.Request(f"http://127.0.0.1:{args.app_port}/api/config",
                                     headers={"Authorization": f"Bearer {token}"})
        try:
            urllib.request.urlopen(req, timeout=10)
        except urllib.error.HTTPError as err:
            # A 429 is the rate limiter still answering after the scenarios'
            # burst of requests: the app is alive. Any other status is not.
            if err.code != 429:
                return Outcome("stability", "FAIL", f"the API answered {err.code}")
        except OSError as err:
            return Outcome("stability", "FAIL", f"the API stopped answering: {err}")
    return Outcome("stability", "PASS", f"{args.stability} s idle")


STEPS = {
    "selftest": step_selftest,
    "sandbox": step_sandbox,
    "contract": step_contract,
    "guard": step_guard,
    "cli": step_cli,
    "serve": step_serve,
    "keychain": step_keychain,
    "gui": step_gui,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--skip-app-build", action="store_true")
    parser.add_argument("--only", default="", help="comma-separated steps")
    parser.add_argument("--stability", type=int, default=120)
    args = parser.parse_args()

    if IS_MAC and platform.machine() != "arm64":
        print("This suite's macOS steps target Apple Silicon.", file=sys.stderr)
        return 2
    try:
        args.model = os.environ.get("ECTO_SCENARIO_MODEL") or ollama_chat_model()
    except OSError as err:
        print(f"Ollama is not answering at {OLLAMA}: {err}", file=sys.stderr)
        return 2
    args.guard_model = os.environ.get("ECTO_SCENARIO_GUARD_MODEL") or args.model

    steps = dict(STEPS)
    if IS_MAC:
        # The app bundle is built first so the guard step also covers it.
        steps = {"app": step_app, **steps, "stability": step_stability}
    wanted = [s for s in args.only.split(",") if s]
    unknown = set(wanted) - set(steps)
    if unknown:
        parser.error(f"not a step on this platform: {', '.join(sorted(unknown))} (steps: {', '.join(steps)})")
    if wanted:
        steps = {name: fn for name, fn in steps.items() if name in wanted}

    print(f"IronVise QA on {platform.system()} {platform.machine()}: model {args.model}, "
          f"guard {args.guard_model}, steps {', '.join(steps)}")
    if run(["cargo", "build", "-q", "-p", "ectoledger", "--bins"]) != 0:
        return 1

    outcomes: list[Outcome] = []
    try:
        for name, step in steps.items():
            banner(name)
            outcomes.append(step(args))
    finally:
        state = getattr(args, "app_state", None)
        if state:
            app, home, _ = state
            app.terminate()
            try:
                app.wait(timeout=15)
            except subprocess.TimeoutExpired:
                app.kill()
            shutil.rmtree(home, ignore_errors=True)

    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True,
                            encoding="utf-8", errors="replace").stdout.strip()
    banner(f"summary ({platform.system()} {platform.machine()}, {commit})")
    for o in outcomes:
        print(f"  {o.step:<10} {o.status}" + (f"  ({o.note})" if o.note else ""))
    return 1 if any(o.status == "FAIL" for o in outcomes) else 0


if __name__ == "__main__":
    sys.exit(main())
