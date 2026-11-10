#!/usr/bin/env python3
"""Every HTTP route the server mounts is reachable from both SDKs.

    python3 scripts/check-sdk-coverage.py

Routes are read from the router in crates/host/src/server/mod.rs. The Python
SDK is checked by method and path against sdk/python/tests/_endpoints.py,
whose own test already requires every public client method to have a row.
The TypeScript client is checked by path against the path literals in
sdk/typescript/src/client.ts. A route either has SDK coverage or a reason in
NOT_WRAPPED; a reason that no longer matches a route, or names one both SDKs
now call, is an error too, so the list cannot go stale.

Limits: the TypeScript client is checked by path, not by method, because its
helpers do not all name the method next to the path; the Python table is
checked by both. Routes are read from the router's `.route("…", get(…)…)`
calls; a handler written inline as a closure that itself calls `get(` would
be counted as an extra method, which fails the check rather than passing it.

Exit codes: 0 covered, 1 a route is missing, 2 the check could not run.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ROUTER = ROOT / "crates/host/src/server/mod.rs"
PY_ENDPOINTS = ROOT / "sdk/python/tests/_endpoints.py"
TS_CLIENT = ROOT / "sdk/typescript/src/client.ts"

METHODS = ("get", "post", "put", "delete", "patch")

# (method, path) -> why no SDK wraps it. Paths use "{}" for any parameter.
NOT_WRAPPED: dict[tuple[str, str], str] = {
    ("GET", "/"): "the Observer dashboard page, for browsers",
    ("POST", "/api/hook/tool-call"): "called by `ironvise hook`, not by SDK users",
    ("POST", "/api/hook/tool-result"): "called by `ironvise hook`, not by SDK users",
    ("GET", "/api/config/tripwire"): "alias of /api/tripwire, kept for older Python SDKs",
    ("PUT", "/api/config/tripwire"): "alias of /api/tripwire, kept for older Python SDKs",
    ("PUT", "/api/webhooks/{}/toggle"): "alias of PUT /api/webhooks/{id}, kept for older Python SDKs",
}

# Paths the TypeScript client reaches through a different, equivalent route.
TS_NOT_WRAPPED: dict[str, str] = {
    "/api/sessions/{}/events/stream": "the TypeScript client streams through /api/stream?session_id=",
}


def fail(message: str) -> None:
    print(f"check-sdk-coverage: {message}", file=sys.stderr)
    sys.exit(2)


def normalise(path: str) -> str:
    """`{id}`, `${segment(id)}` and `{}` all become `{}`; a query string is dropped."""
    query = re.search(r"(?<!/)\$\{", path)
    if query:
        path = path[: query.start()]
    path = re.sub(r"\$\{[^}]*\}", "{}", path)
    path = re.sub(r"\{[^}]*\}", "{}", path)
    return path.split("?", 1)[0]


def server_routes(source: str) -> set[tuple[str, str]]:
    routes: set[tuple[str, str]] = set()
    for match in re.finditer(r"\.route\(\s*\"([^\"]+)\"\s*,", source):
        depth, i = 1, match.end()
        while depth and i < len(source):
            depth += {"(": 1, ")": -1}.get(source[i], 0)
            i += 1
        handlers = source[match.end() : i - 1]
        verbs = re.findall(r"(?<![A-Za-z_])(" + "|".join(METHODS) + r")\(", handlers)
        if not verbs:
            fail(f"no HTTP method found for route {match.group(1)!r}")
        routes.update((verb.upper(), normalise(match.group(1))) for verb in verbs)
    return routes


def python_endpoints(source: str) -> set[tuple[str, str]]:
    covered: set[tuple[str, str]] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "Endpoint":
            args = [a.value for a in node.args[:3] if isinstance(a, ast.Constant)]
            if len(args) == 3:
                _, method, template = args
                covered.add((method.upper(), normalise(template)))
    return covered


def typescript_paths(source: str) -> set[str]:
    source = source.replace("${this.baseUrl}", "")
    literals = re.findall(r"[`\"'](/(?:api/|metrics)[^`\"']*)[`\"']", source)
    return {normalise(p) for p in literals}


def main() -> int:
    for path in (ROUTER, PY_ENDPOINTS, TS_CLIENT):
        if not path.is_file():
            fail(f"missing {path.relative_to(ROOT)}")

    routes = server_routes(ROUTER.read_text())
    if len(routes) < 30:
        fail(f"found only {len(routes)} routes; the router parser is out of date")
    python = python_endpoints(PY_ENDPOINTS.read_text())
    typescript = typescript_paths(TS_CLIENT.read_text())

    problems: list[str] = []
    for method, path in sorted(routes):
        if (method, path) in NOT_WRAPPED:
            continue
        if (method, path) not in python:
            problems.append(f"Python SDK does not call {method} {path}")
        if path not in typescript and path not in TS_NOT_WRAPPED:
            problems.append(f"TypeScript SDK does not call {path}")
    for method, path in sorted(set(NOT_WRAPPED) & routes):
        if (method, path) in python and path in typescript:
            problems.append(f"NOT_WRAPPED lists {method} {path}, which both SDKs now call")
    for method, path in sorted(set(NOT_WRAPPED) - routes):
        problems.append(f"NOT_WRAPPED lists {method} {path}, which the server no longer mounts")
    for path in sorted(set(TS_NOT_WRAPPED) - {p for _, p in routes}):
        problems.append(f"TS_NOT_WRAPPED lists {path}, which the server no longer mounts")

    if problems:
        print("check-sdk-coverage: FAILED", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    wrapped = len(routes) - len(NOT_WRAPPED)
    print(f"check-sdk-coverage: OK - {len(routes)} routes; {wrapped} wrapped by both SDKs, "
          f"{len(NOT_WRAPPED)} deliberately not wrapped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
