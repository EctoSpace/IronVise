"""Tests for scripts/check-sdk-coverage.py against a fixture router and SDKs."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]

# Every route the script exempts must exist, or it reports the exemption as stale.
EXEMPT_ROUTES = """
        .route("/", get(index))
        .route("/api/hook/tool-call", post(hook::tool_call))
        .route("/api/hook/tool-result", post(hook::tool_result))
        .route(
            "/api/config/tripwire",
            get(get_tripwire_config).put(put_tripwire_config),
        )
        .route("/api/webhooks/{id}/toggle", put(toggle_webhook))
        .route("/api/sessions/{session_id}/events/stream", get(stream_events_by_session))
"""

WRAPPED = [f"/api/thing{i}/{{id}}" for i in range(30)]


@pytest.fixture
def tree(tmp_path: Path, install_script):
    script = install_script("check-sdk-coverage.py")

    def write(*, routes: str, python_rows: list[tuple[str, str]], ts_paths: list[str]):
        router = tmp_path / "crates/host/src/server/mod.rs"
        router.parent.mkdir(parents=True, exist_ok=True)
        router.write_text("let r = Router::new()" + routes + ";\n")
        endpoints = tmp_path / "sdk/python/tests/_endpoints.py"
        endpoints.parent.mkdir(parents=True, exist_ok=True)
        # Exempt only for TypeScript, so the Python table must still list it.
        python_rows = [*python_rows, ("GET", "/api/sessions/{}/events/stream")]
        rows = "\n".join(f'    Endpoint("m", "{m}", "{p}", None, "json"),' for m, p in python_rows)
        endpoints.write_text(f"ENDPOINTS = [\n{rows}\n]\n")
        client = tmp_path / "sdk/typescript/src/client.ts"
        client.parent.mkdir(parents=True, exist_ok=True)
        client.write_text("\n".join(f"this.get(`{p}`);" for p in ts_paths))
        return subprocess.run([sys.executable, str(script)], capture_output=True, text=True)

    return write


def wrapped_routes() -> str:
    return "".join(f'\n        .route("{p}", get(h))' for p in WRAPPED)


def test_the_repository_routes_are_all_covered() -> None:
    result = subprocess.run(
        [sys.executable, str(REPO / "scripts/check-sdk-coverage.py")], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr


def test_a_route_both_sdks_call_passes(tree) -> None:
    paths = [p.replace("{id}", "{}") for p in WRAPPED]
    result = tree(
        routes=EXEMPT_ROUTES + wrapped_routes(),
        python_rows=[("GET", p) for p in paths],
        ts_paths=[p.replace("{id}", "${segment(id)}") for p in WRAPPED],
    )
    assert result.returncode == 0, result.stderr


def test_a_route_neither_sdk_calls_fails_by_name(tree) -> None:
    paths = [p.replace("{id}", "{}") for p in WRAPPED]
    result = tree(
        routes=EXEMPT_ROUTES + wrapped_routes() + '\n        .route("/api/new", post(new_handler))',
        python_rows=[("GET", p) for p in paths],
        ts_paths=[p.replace("{id}", "${segment(id)}") for p in WRAPPED],
    )
    assert result.returncode == 1
    assert "Python SDK does not call POST /api/new" in result.stderr
    assert "TypeScript SDK does not call /api/new" in result.stderr


def test_an_sdk_calling_the_path_with_the_wrong_method_fails(tree) -> None:
    paths = [p.replace("{id}", "{}") for p in WRAPPED]
    result = tree(
        routes=EXEMPT_ROUTES + wrapped_routes(),
        python_rows=[("POST", paths[0])] + [("GET", p) for p in paths[1:]],
        ts_paths=[p.replace("{id}", "${segment(id)}") for p in WRAPPED],
    )
    assert result.returncode == 1
    assert f"Python SDK does not call GET {paths[0]}" in result.stderr


def test_an_exemption_for_a_route_the_server_dropped_fails(tree) -> None:
    paths = [p.replace("{id}", "{}") for p in WRAPPED]
    result = tree(
        routes=EXEMPT_ROUTES.replace('        .route("/api/hook/tool-call", post(hook::tool_call))\n', "") + wrapped_routes(),
        python_rows=[("GET", p) for p in paths],
        ts_paths=[p.replace("{id}", "${segment(id)}") for p in WRAPPED],
    )
    assert result.returncode == 1
    assert "NOT_WRAPPED lists POST /api/hook/tool-call, which the server no longer mounts" in result.stderr


def test_an_exemption_for_a_route_both_sdks_now_call_fails(tree) -> None:
    paths = [p.replace("{id}", "{}") for p in WRAPPED]
    result = tree(
        routes=EXEMPT_ROUTES + wrapped_routes(),
        python_rows=[("GET", p) for p in paths] + [("POST", "/api/hook/tool-call")],
        ts_paths=[p.replace("{id}", "${segment(id)}") for p in WRAPPED] + ["/api/hook/tool-call"],
    )
    assert result.returncode == 1
    assert "NOT_WRAPPED lists POST /api/hook/tool-call, which both SDKs now call" in result.stderr
