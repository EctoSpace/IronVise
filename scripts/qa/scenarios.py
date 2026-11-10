#!/usr/bin/env python3
"""End-to-end scenarios against a running IronVise server, with a real model.

The platform runners (run-mac.sh, run-linux.sh, run-windows.ps1) start the
server in isolation (a scratch data folder; on macOS the built desktop app in
a scratch HOME) and call this with its API base. Each scenario was first
checked by hand during the 0.8 audit, and most found a defect the mocked
tests could not: settings that would not clear, a guard that could not run in
the app, a policy screen that chose nothing, sessions that saw each other,
commands the macOS sandbox killed, a certificate naming a policy that never
ran. Each is now a named PASS/FAIL line.

Exit status: 0 when every check passes, 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from qa_report import Report


class Api:
    """The server's REST API; waits out its rate limiter rather than failing."""

    def __init__(self, base: str, token: str) -> None:
        self.base, self.token = base.rstrip("/"), token

    def call(self, method: str, path: str, body: object = None, *, token: str | None = "",
             raw: bool = False, text: str | None = None) -> tuple[int, object]:
        """`body` is sent as JSON, `text` as plain text (policies are TOML)."""
        if text is not None:
            data = text.encode()
        else:
            data = json.dumps(body).encode() if body is not None else None
        bearer = self.token if token == "" else token
        for _ in range(30):
            req = urllib.request.Request(self.base + path, data=data, method=method)
            if bearer:
                req.add_header("Authorization", "Bearer " + bearer)
            if data is not None:
                req.add_header("Content-Type", "text/plain" if text is not None else "application/json")
            try:
                with urllib.request.urlopen(req, timeout=180) as resp:
                    payload = resp.read()
                    if raw:
                        return resp.status, payload
                    return resp.status, json.loads(payload) if payload else None
            except urllib.error.HTTPError as err:
                # Not `text`: that parameter picks the Content-Type, and
                # overwriting it would send a JSON body as text/plain on the
                # retry after a 429 (and get a 415).
                error_body = err.read().decode(errors="replace")
                if err.code == 429:
                    time.sleep(3)
                    continue
                return err.code, error_body[:400]
        return 429, "rate limited for 90 s"


def processes() -> str:
    """Command lines (POSIX) or image names (Windows) of running processes."""
    if os.name == "nt":
        cmd = ["tasklist", "/FO", "CSV", "/NH"]
    else:
        cmd = ["ps", "-axo", "args"]
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace").stdout


@dataclass
class Run:
    session: dict
    events: list[dict]
    worker_seen: bool
    error: str = ""

    def payloads(self, kind: str) -> list[dict]:
        return [e.get("payload", {}) for e in self.events if e.get("payload", {}).get("type") == kind]

    def actions_before_loop_detection(self) -> int | None:
        """Own actions before a "Loop detected" thought (None if none). Loop
        detection needs three repeats; fewer means it counted another
        session's actions."""
        actions = 0
        for event in self.events:
            payload = event.get("payload", {})
            if payload.get("type") == "action":
                actions += 1
            if payload.get("type") == "thought" and "Loop detected" in (payload.get("content") or ""):
                return actions
        return None


def run_session(api: Api, goal: str, worker_marker: str) -> Run:
    """Start a session as Home → Run does and wait for it to finish."""
    status, created = api.call("POST", "/sessions", {"goal": goal})
    if status not in (200, 201) or not isinstance(created, dict):
        return Run({}, [], False, f"{status} {created}")
    sid, info, seen = created["id"], {}, False
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        time.sleep(0.5)
        seen = seen or worker_marker in processes()
        _, info = api.call("GET", f"/sessions/{sid}")
        if isinstance(info, dict) and info.get("status") not in ("running", "pending"):
            break
    _, events = api.call("GET", f"/events?session_id={sid}")
    return Run(info if isinstance(info, dict) else {}, events if isinstance(events, list) else [], seen)


def settings(api: Api, r: Report, settings_file: Path, model: str, guard_model: str) -> dict:
    status, cfg = api.call("GET", "/config")
    r.check("settings: load", status == 200 and isinstance(cfg, dict), status)
    payload = {
        "database_url": "", "llm_backend": "ollama", "ollama_base_url": "http://127.0.0.1:11434",
        "openai_base_url": "", "ollama_model": model, "guard_required": False,
        "guard_llm_backend": "ollama", "guard_llm_model": guard_model, "max_steps": 6,
        "show_developer_tools": False,
    }
    api.call("PUT", "/config", payload)
    _, cfg = api.call("GET", "/config")
    for key in ("llm_backend", "ollama_base_url", "ollama_model", "guard_llm_model", "max_steps"):
        r.check(f"settings: save and reload {key}", cfg.get(key) == payload[key], cfg.get(key))
    on_disk = json.loads(settings_file.read_text(encoding="utf-8"))
    r.check("settings: settings.json holds what was saved", on_disk.get("ollama_model") == model, on_disk)
    r.check("settings: settings.json holds no API key", "api_key" not in json.dumps(on_disk).lower())
    api.call("PUT", "/config", dict(payload, guard_llm_model=""))
    cleared = json.loads(settings_file.read_text(encoding="utf-8")).get("guard_llm_model")
    r.check("settings: an emptied field is removed from settings.json", cleared in (None, ""), cleared)
    api.call("PUT", "/config", payload)
    _, cfg = api.call("GET", "/config")
    r.check("settings: Ollama defaults to 127.0.0.1, not localhost",
            "localhost" not in cfg.get("ollama_base_url", ""), cfg.get("ollama_base_url"))
    return payload


def tripwire(api: Api, r: Report) -> None:
    status, current = api.call("GET", "/tripwire")
    current = current.get("config", current) if isinstance(current, dict) else {}
    r.check("tripwire: load", status == 200 and "allowed_paths" in current, status)
    keys = ("allowed_paths", "allowed_domains", "banned_command_patterns", "min_justification_length", "require_https")
    edited = {k: current[k] for k in keys if k in current}
    edited["allowed_domains"] = [*edited.get("allowed_domains", []), "example.org"]
    edited["banned_command_patterns"] = [*edited.get("banned_command_patterns", []), r"\bshutdown\b"]
    status, _ = api.call("PUT", "/tripwire", edited)
    r.check("tripwire: save", status == 200, status)

    def check_intent(action: str, params: dict) -> dict:
        _, verdict = api.call("POST", "/tripwire/check", {"action": action, "params": params})
        return verdict if isinstance(verdict, dict) else {}

    allowed = check_intent("run_command", {"command": "ls -la"})
    r.check("tripwire: an inspection command passes", allowed.get("allowed") is True, allowed)
    banned = check_intent("run_command", {"command": "sudo shutdown -h now"})
    r.check("tripwire: the new pattern refuses and names its rule",
            banned.get("allowed") is False and banned.get("rule") == "banned_command_patterns", banned)
    domain = check_intent("http_get", {"url": "https://evil.example.net/x"})
    r.check("tripwire: an unlisted domain is refused", domain.get("allowed") is False, domain)


def access(api: Api, r: Report) -> None:
    status, created = api.call("POST", "/tokens", {"label": "qa agent", "role": "agent"})
    token = created.get("token") if isinstance(created, dict) else None
    r.check("access: create an agent token", status in (200, 201) and bool(token), status)
    _, listing = api.call("GET", "/tokens")
    mine = [t for t in listing if isinstance(t, dict) and t.get("label") == "qa agent"] if isinstance(listing, list) else []
    r.check("access: the list holds its hash, not the token", len(mine) == 1 and token not in json.dumps(listing))
    status, _ = api.call("GET", "/sessions", token=token)
    r.check("access: the token authenticates", status == 200, status)
    if mine:
        api.call("DELETE", f"/tokens/{mine[0]['token_hash']}")
    status, _ = api.call("GET", "/sessions", token=token)
    r.check("access: a revoked token is refused", status == 401, status)
    status, body = api.call("POST", "/webhooks", {"label": "local", "url": "http://127.0.0.1:9/hook"})
    r.check("access: a local webhook is refused and says why",
            status == 400 and "public endpoints only" in str(body), body)


def policy(api: Api, r: Report) -> None:
    status, names = api.call("GET", "/policies")
    r.check("policy: the built-in packs are listed",
            status == 200 and {"soc2-audit", "pci-dss-audit", "owasp-top10"} <= set(names or []), names)
    status, body = api.call("PUT", "/config", {"active_policy": "iso42001"})
    r.check("policy: a pack with no rules cannot be chosen for runs", status == 422 and "no rules" in str(body), body)
    status, _ = api.call("PUT", "/config", {"active_policy": "no-such-policy"})
    r.check("policy: a policy that does not exist cannot be chosen", status == 422, status)
    status, body = api.call("PUT", "/policies/qa-not-a-policy",
                            text='[[command_rules]]\npattern = "nmap"\naction = "deny"\n')
    r.check("policy: saving text that is not a policy is refused and says why",
            status == 422 and "Not a valid policy" in str(body), body)
    status, body = api.call("PUT", "/policies/soc2-audit", text='name = "x"\n')
    r.check("policy: a built-in pack is read only", status == 403 and "read only" in str(body), body)
    status, _ = api.call("PUT", "/config", {"active_policy": "soc2-audit"})
    _, cfg = api.call("GET", "/config")
    r.check("policy: soc2-audit chosen for runs", status == 200 and cfg.get("active_policy") == "soc2-audit",
            cfg.get("active_policy"))


def runs(api: Api, r: Report, verify_cert: Path, out: Path, worker_marker: str) -> None:
    first = run_session(api, "List the files in this folder.", worker_marker)
    r.check("run: starts and finishes", first.session.get("status") == "completed",
            first.error or first.session.get("status"))
    observations = [p.get("content", "") for p in first.payloads("observation")]
    r.check("run: a command really ran (exit 0 with output)",
            any("exit_code: Some(0)" in o for o in observations), observations[:2])
    r.check("run: no sandbox text in command output", not any("sandbox applied" in o for o in observations))
    n = first.actions_before_loop_detection()
    r.check("run: loop detection counts only this session's actions", n is None or n >= 3, f"after {n} actions")
    digest = first.session.get("policy_hash")
    r.check("run: the session records the chosen policy's hash",
            isinstance(digest, str) and len(digest) == 64, digest)

    sid = first.session.get("id", "")
    status, verdict = api.call("GET", f"/sessions/{sid}/verify")
    r.check("history: Verify passes (chain and every signature)",
            status == 200 and isinstance(verdict, dict) and verdict.get("ok") is True, verdict)
    status, cert = api.call("GET", f"/certificates/{sid}", raw=True)
    cert_file = out / "run.elc"
    if status == 200:
        cert_file.write_bytes(cert)
    r.check("history: the certificate exports", status == 200 and len(cert) > 100, status)
    result = subprocess.run([str(verify_cert), str(cert_file)], capture_output=True, text=True,
                            encoding="utf-8", errors="replace")
    r.check("history: the certificate is internally consistent offline", result.returncode == 0,
            (result.stdout.strip().splitlines() or [result.stderr])[-1])
    status, vc = api.call("GET", f"/sessions/{sid}/vc/verify")
    r.check("history: the verifiable credential verifies",
            status == 200 and isinstance(vc, dict) and vc.get("valid") is True, vc)

    second = run_session(api, "List the files in this folder.", worker_marker)
    n = second.actions_before_loop_detection()
    r.check("isolation: a repeated task is not cut short by another session's actions",
            n is None or n >= 3, f"loop detected after {n} of its own actions")


def guard(api: Api, r: Report, payload: dict, guard_model: str, worker_marker: str) -> None:
    api.call("PUT", "/config", dict(payload, guard_required=True, guard_llm_backend="ollama",
                                    guard_llm_model=guard_model))
    api.call("PUT", "/config", {"active_policy": ""})
    guarded = run_session(api, "List the files in this folder.", worker_marker)
    r.check("guard: a guarded run finishes", guarded.session.get("status") == "completed",
            guarded.error or guarded.session.get("status"))
    r.check(f"guard: the guard worker ran ({worker_marker})", guarded.worker_seen)
    r.check("guard: no missing-worker error", "guard-worker binary not found" not in json.dumps(guarded.events))
    api.call("PUT", "/config", dict(payload, guard_required=False))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--base", required=True, help="API base, e.g. http://127.0.0.1:3000/api")
    parser.add_argument("--token", required=True, help="an admin token the server accepts")
    parser.add_argument("--settings-file", required=True, type=Path, help="the server's settings.json")
    parser.add_argument("--verify-cert", required=True, type=Path, help="the verify-cert binary")
    parser.add_argument("--out", required=True, type=Path, help="a scratch folder for exported files")
    parser.add_argument("--worker-marker", required=True,
                        help="text that identifies the running guard worker in the process list")
    parser.add_argument("--model", default=os.environ.get("ECTO_SCENARIO_MODEL", "qwen2.5:7b"))
    parser.add_argument("--guard-model", default=os.environ.get("ECTO_SCENARIO_GUARD_MODEL"))
    args = parser.parse_args()
    guard_model = args.guard_model or args.model

    api, report = Api(args.base, args.token), Report()
    payload = settings(api, report, args.settings_file, args.model, guard_model)
    tripwire(api, report)
    access(api, report)
    policy(api, report)
    runs(api, report, args.verify_cert, args.out, args.worker_marker)
    guard(api, report, payload, guard_model, args.worker_marker)

    return report.summary()


if __name__ == "__main__":
    sys.exit(main())
