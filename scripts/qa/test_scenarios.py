"""Tests for the QA scripts' own plumbing (python3 -m pytest scripts/qa)."""

from __future__ import annotations

import http.server
import json
import threading

from scenarios import Api


class _Server(http.server.ThreadingHTTPServer):
    seen: list[tuple[str, str]]


class _OnceRateLimited(http.server.BaseHTTPRequestHandler):
    """Answers 429 to the first request, then echoes what it received."""

    def do_PUT(self) -> None:  # noqa: N802 (http.server's naming)
        body = self.rfile.read(int(self.headers["Content-Length"] or 0)).decode()
        self.server.seen.append((self.headers["Content-Type"], body))
        if len(self.server.seen) == 1:
            self.send_response(429)
            self.end_headers()
            self.wfile.write(b"Too Many Requests")
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"ok": True}).encode())

    def log_message(self, *_: object) -> None:
        pass


def _serve() -> _Server:
    server = _Server(("127.0.0.1", 0), _OnceRateLimited)
    server.seen = []
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_a_retry_after_429_resends_the_same_body_and_content_type(monkeypatch) -> None:
    monkeypatch.setattr("scenarios.time.sleep", lambda _: None)
    server = _serve()
    try:
        api = Api(f"http://127.0.0.1:{server.server_port}", "token")
        status, body = api.call("PUT", "/config", {"active_policy": "soc2-audit"})
        assert (status, body) == (200, {"ok": True})
        assert [ct for ct, _ in server.seen] == ["application/json", "application/json"]
        assert server.seen[0][1] == server.seen[1][1]
    finally:
        server.shutdown()


def test_a_text_body_is_sent_as_text(monkeypatch) -> None:
    monkeypatch.setattr("scenarios.time.sleep", lambda _: None)
    server = _serve()
    try:
        Api(f"http://127.0.0.1:{server.server_port}", "token").call("PUT", "/policies/x", text='name = "x"\n')
        assert [ct for ct, _ in server.seen] == ["text/plain", "text/plain"]
    finally:
        server.shutdown()
