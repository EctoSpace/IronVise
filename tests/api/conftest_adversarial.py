"""Fixtures for adversarial black-box testing against a live IronVise server.

The server is started once per pytest session with:
  - DATABASE_URL=sqlite::memory:   (ephemeral, no external DB)
  - LLM_BACKEND=mock               (deterministic, no real LLM)
  - GUARD_REQUIRED=false            (isolate scanner/tripwire from guard LLM)
  - SCANNER_SENSITIVITY=medium      (default production level)

Override the binary path via ``ECTOLEDGER_BINARY`` env-var.  If the binary
is not found the entire adversarial test module is skipped.
"""

from __future__ import annotations

import os
import shutil
import signal
import socket
import subprocess
import tempfile
import sys
import time
from pathlib import Path
from typing import AsyncGenerator, Generator

import httpx
import pytest
import pytest_asyncio

from ironvise_sdk.client import LedgerClient

_WORKSPACE_ROOT = Path(__file__).resolve().parents[2]  # tests/api -> repo root


def _binary_candidates() -> list[Path]:
    """Return platform-ordered list of candidate binary paths.

    Only includes actual compiled server binaries - NOT the ``ectoledger-mac``
    / ``ectoledger-linux`` shell script wrappers, which are end-user launchers
    and do not accept the ``--server`` flag used by this fixture.
    """
    if sys.platform == "win32":
        return [
            _WORKSPACE_ROOT / "target" / "debug" / "ironvise.exe",
            _WORKSPACE_ROOT / "target" / "release" / "ironvise.exe",
        ]
    return [
        _WORKSPACE_ROOT / "target" / "debug" / "ironvise",
        _WORKSPACE_ROOT / "target" / "release" / "ironvise",
    ]


def _scan_candidates(candidates: list[Path]) -> Path | None:
    """Return the first existing, executable candidate or ``None``."""
    for c in candidates:
        if c.is_file() and os.access(c, os.X_OK):
            return c
    return None


def _try_cargo_build() -> Path | None:
    """Attempt ``cargo build -p ectoledger`` and return the binary path on success.

    Works on macOS, Linux, and Windows (requires ``cargo`` on PATH).
    Returns ``None`` if Cargo is unavailable or the build fails.
    """
    import shutil

    cargo = shutil.which("cargo")
    if cargo is None:
        return None

    print(
        "\n⏳  IronVise binary not found - running `cargo build -p ectoledger` …",
        flush=True,
    )
    try:
        result = subprocess.run(
            [cargo, "build", "-p", "ectoledger"],
            cwd=str(_WORKSPACE_ROOT),
            timeout=300,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"⚠️  cargo build failed: {exc}", flush=True)
        return None

    if result.returncode != 0:
        tail = "\n".join(result.stderr.strip().splitlines()[-20:])
        print(f"⚠️  cargo build exited {result.returncode}:\n{tail}", flush=True)
        return None

    print("✅  cargo build succeeded", flush=True)
    return _scan_candidates(_binary_candidates())


def _find_binary() -> Path | None:
    """Locate the ectoledger server binary, building it if necessary.

    Resolution order:
    1. ``ECTOLEDGER_BINARY`` environment variable (explicit path).
    2. Common build output paths (``target/debug``, ``target/release``,
       platform convenience binaries).
    3. **Auto-build**: run ``cargo build -p ectoledger`` and scan again.

    Returns ``None`` only when the binary cannot be found *or* built.
    """
    # 1. Explicit override
    explicit = os.environ.get("ECTOLEDGER_BINARY")
    if explicit:
        p = Path(explicit)
        if p.is_file():
            return p
        return None

    # 2. Scan known candidate paths
    candidates = _binary_candidates()
    found = _scan_candidates(candidates)
    if found is not None:
        return found

    # 3. Attempt to build automatically
    return _try_cargo_build()


def _free_port() -> int:
    """Return a free TCP port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class EctoServer:
    """Handle to a running IronVise server subprocess."""

    def __init__(self, process: subprocess.Popen, base_url: str, token: str, env: dict | None = None) -> None:
        self.process = process
        self.base_url = base_url
        self.token = token
        self.env = env or {}

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)


@pytest.fixture(scope="session")
def ectoledger_server() -> Generator[EctoServer, None, None]:
    """Start an ephemeral IronVise server for the test session."""
    binary = _find_binary()
    if binary is None:
        pytest.skip(
            "IronVise binary not found.  Set ECTOLEDGER_BINARY or build "
            "with `cargo build` first."
        )

    port = _free_port()
    token = os.environ.get("OBSERVER_TOKEN", "test-adversarial-token")

    # Its own data folder: settings.json, policies and keys are read from
    # ECTO_DATA_DIR, which otherwise defaults to the working directory.
    data_dir = tempfile.mkdtemp(prefix="ecto-api-tests-")
    env = {
        **os.environ,
        "ECTO_DATA_DIR": data_dir,
        "DATABASE_URL": "sqlite::memory:",
        "LLM_BACKEND": "mock",
        "GUARD_REQUIRED": "false",
        "SCANNER_SENSITIVITY": os.environ.get("SCANNER_SENSITIVITY", "medium"),
        "ECTO_BIND_HOST": "127.0.0.1",
        "ECTO_BIND_PORT": str(port),
        "OBSERVER_TOKEN": token,
        # Relax rate limits so tests can create many sessions without hitting 429.
        "API_RATE_LIMIT_PER_SECOND": "10000",
        "API_RATE_LIMIT_BURST": "100000",
        "SESSION_RATE_LIMIT_PER_SECOND": "1000",
        "SESSION_RATE_LIMIT_BURST": "10000",
        "SSE_RATE_LIMIT_PER_SECOND": "1000",
        "SSE_RATE_LIMIT_BURST": "10000",
        # Lower SSE keepalive interval so keepalive events arrive well within
        # pytest's global 15-second timeout, but still longer than the 8-second
        # httpx read-timeout used in _read_sse_events so that the stream
        # timeout fires before the next keepalive refreshes the timer.
        "SSE_KEEPALIVE_SECS": "10",
        "RUST_LOG": "warn",
    }

    # The server's output goes to a file, not a pipe: nothing reads a pipe
    # while the tests run, and once its buffer is full (4 KiB on Windows) the
    # server blocks on its next log line, so a test that provoked a few
    # warnings hung until pytest timed it out.
    log_path = os.path.join(data_dir, "server.log")
    log = open(log_path, "wb")
    try:
        proc = subprocess.Popen(
            [str(binary), "serve"],
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    except OSError as exc:
        log.close()
        pytest.skip(f"Cannot launch IronVise binary: {exc}")

    base_url = f"http://127.0.0.1:{port}"

    deadline = time.monotonic() + 30
    ready = False
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            proc.wait()
            log.close()
            with open(log_path, "rb") as f:
                stderr = f.read().decode(errors="replace")
            # A fail, not a skip: a server that cannot start is the thing
            # under test failing, and a skip would report every test green.
            pytest.fail(
                f"IronVise exited at startup (code {proc.returncode}). "
                f"stderr: {stderr[:500]}"
            )
        try:
            r = httpx.get(f"{base_url}/healthz", timeout=2)
            if r.status_code < 500:
                ready = True
                break
        except httpx.ConnectError:
            time.sleep(0.3)
        except Exception:
            time.sleep(0.3)

    if not ready:
        proc.kill()
        proc.wait()
        log.close()
        pytest.fail("IronVise did not become ready within 30 s")

    server = EctoServer(proc, base_url, token, env=env)
    yield server
    server.stop()
    log.close()
    shutil.rmtree(data_dir, ignore_errors=True)


@pytest_asyncio.fixture
async def adv_client(ectoledger_server: EctoServer) -> AsyncGenerator[LedgerClient, None]:
    """Provide an authenticated LedgerClient pointing at the ephemeral server."""
    async with LedgerClient(
        ectoledger_server.base_url,
        bearer_token=ectoledger_server.token,
        timeout=15.0,
    ) as client:
        yield client


@pytest_asyncio.fixture
async def raw_http(ectoledger_server: EctoServer) -> AsyncGenerator[httpx.AsyncClient, None]:
    """Provide a raw httpx client for endpoints not wrapped by the SDK."""
    async with httpx.AsyncClient(
        base_url=ectoledger_server.base_url,
        headers={"Authorization": f"Bearer {ectoledger_server.token}"},
        timeout=15.0,
    ) as client:
        yield client
