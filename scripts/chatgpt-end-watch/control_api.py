#!/usr/bin/env python3
"""Phone-facing control API for chatgpt-end-watch (Android overlay).

Shares the watcher state file (armed flag). Prefer running embedded control
inside chatgpt_end_watch.py; this process is for a dedicated systemd unit
behind Caddy: /api/chatgpt-end-watch/* → 127.0.0.1:8788

  GET  /status  /api/chatgpt-end-watch/status
  POST /start   /api/chatgpt-end-watch/start   (arm)
  POST /stop    /api/chatgpt-end-watch/stop    (disarm)
  GET  /health

Auth: Authorization: Bearer <token> OR X-Control-Token: <token>
"""
from __future__ import annotations

import hmac
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from chatgpt_end_watch import StateStore, iso_et, read_token  # noqa: E402

BIND = os.environ.get("CONTROL_BIND", "127.0.0.1")
PORT = int(os.environ.get("CONTROL_PORT", "8788"))
STATE_FILE = Path(
    os.environ.get(
        "STATE_FILE",
        "/opt/nullink/data/chatgpt-end-watch/state.json",
    )
)
ALLOW_LOOPBACK_NOAUTH = os.environ.get("CONTROL_ALLOW_LOOPBACK_NOAUTH", "1").lower() in (
    "1", "true", "yes",
)


def expected_tokens() -> set[str]:
    tokens: set[str] = set()
    env = (os.environ.get("CONTROL_TOKEN") or "").strip()
    if env:
        tokens.add(env)
    cfile = (os.environ.get("CONTROL_TOKEN_FILE") or "").strip()
    if cfile and Path(cfile).is_file():
        tokens.add(Path(cfile).read_text(encoding="utf-8").strip())
    for tf in (
        os.environ.get("NULLINK_TOKEN_FILE", "").strip(),
        "/opt/nullink/secrets/NULLINK_TOKEN_chatgpt.txt",
        "/workspace/server/secrets/NULLINK_TOKEN_chatgpt.txt",
    ):
        if tf and Path(tf).is_file():
            try:
                tokens.add(read_token(tf))
            except OSError:
                pass
    return {t for t in tokens if t}


def status_payload(store: StateStore) -> dict:
    s = store.read()
    armed = bool(s.get("armed"))
    return {
        "ok": True,
        "ts": iso_et(),
        "active": armed,
        "armed": armed,
        "action": None,
        "control": {
            "user_armed": armed,
            "the_end_halt": not armed and bool(s.get("last_end_at")),
            "last_end_at": s.get("last_end_at"),
            "updated_at": s.get("updated_at"),
        },
        "watch": {
            "after": s.get("after_id"),
            "armed": armed,
            "latest_msg_id": s.get("last_msg_id"),
            "last_activity_ts": s.get("last_activity_ts"),
            "keep_building_count": s.get("keep_building_count", 0),
            "preview": s.get("last_text_preview") or "",
        },
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "chatgpt-end-watch-control/1.2"
    store: StateStore

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _json(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _is_loopback(self) -> bool:
        host = (self.client_address[0] or "").lower()
        return (
            host in ("127.0.0.1", "::1", "localhost")
            or host.startswith("127.")
            or host.endswith("127.0.0.1")
        )

    def _authorized(self) -> bool:
        if ALLOW_LOOPBACK_NOAUTH and self._is_loopback():
            return True
        tokens = expected_tokens()
        if not tokens:
            self._json(503, {"ok": False, "error": "no_control_token_configured"})
            return False
        auth = self.headers.get("Authorization") or ""
        got = ""
        if auth.lower().startswith("bearer "):
            got = auth[7:].strip()
        if not got:
            got = (self.headers.get("X-Control-Token") or "").strip()
        if not got or not any(hmac.compare_digest(got, t) for t in tokens):
            self._json(401, {"ok": False, "error": "unauthorized"})
            return False
        return True

    def _norm(self, path: str) -> str:
        p = path.rstrip("/") or "/"
        for prefix in ("/api/chatgpt-end-watch", "/api"):
            if p.startswith(prefix + "/") or p == prefix:
                rest = p[len(prefix) :] or "/"
                return rest if rest.startswith("/") else "/" + rest
        return p

    def do_GET(self) -> None:  # noqa: N802
        path = self._norm(urlparse(self.path).path)
        if path == "/health":
            self._json(200, {"ok": True, "service": "chatgpt-end-watch-control"})
            return
        if path in ("/status", "/"):
            if not self._authorized():
                return
            self._json(200, status_payload(self.store))
            return
        self._json(404, {"ok": False, "error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        path = self._norm(urlparse(self.path).path)
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        if not self._authorized():
            return
        if path in ("/start", "/arm"):
            self.store.update(armed=True, seen_activity=False, last_stop_at=None)
            out = status_payload(self.store)
            out["action"] = "start"
            self._json(200, out)
            return
        if path in ("/stop", "/disarm"):
            self.store.update(armed=False)
            out = status_payload(self.store)
            out["action"] = "stop"
            self._json(200, out)
            return
        self._json(404, {"ok": False, "error": "not_found"})


def main() -> int:
    store = StateStore(STATE_FILE)
    Handler.store = store
    httpd = ThreadingHTTPServer((BIND, PORT), Handler)
    print(f"control_api listening on http://{BIND}:{PORT}/ state={STATE_FILE}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
