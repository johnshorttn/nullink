#!/usr/bin/env python3
"""Signed GitHub push webhook for the Nullink production deployment worker."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOST = os.environ.get("NULLINK_DEPLOY_HOST", "127.0.0.1")
PORT = int(os.environ.get("NULLINK_DEPLOY_PORT", "8768"))
PATH = os.environ.get("NULLINK_DEPLOY_PATH", "/__deploy/github")
CONFIG_FILE = Path(os.environ.get(
    "SERVER_DEPLOY_CONFIG",
    "/etc/server-deploy/repos.json",
))
SECRET_FILE = Path(os.environ.get(
    "NULLINK_DEPLOY_SECRET_FILE",
    "/opt/nullink/secrets/DEPLOY_WEBHOOK_SECRET.txt",
))
WORKER = os.environ.get(
    "NULLINK_DEPLOY_WORKER",
    "/opt/nullink/deploy/deploy_worker.py",
)
MAX_BODY = 1024 * 1024
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def load_secret() -> bytes:
    secret = SECRET_FILE.read_bytes().strip()
    if len(secret) < 32:
        raise RuntimeError("deployment webhook secret is missing or too short")
    return secret


def valid_signature(body: bytes, supplied: str | None, secret: bytes) -> bool:
    if not supplied or not supplied.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, supplied)


def load_repositories() -> dict:
    data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    repositories = data.get("repositories") or {}
    if not isinstance(repositories, dict):
        raise RuntimeError("invalid repository deployment configuration")
    return repositories


def parse_deployment(body: bytes, event: str | None, repositories: dict) -> tuple[str, str] | None:
    if event != "push":
        return None
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    repository = payload.get("repository") or {}
    full_name = str(repository.get("full_name") or "").lower()
    config = repositories.get(full_name)
    if not isinstance(config, dict):
        return None
    branch = str(config.get("branch") or "main")
    if payload.get("ref") != f"refs/heads/{branch}":
        return None
    commit = str(payload.get("after") or "").lower()
    return (full_name, commit) if SHA_RE.fullmatch(commit) else None


class Handler(BaseHTTPRequestHandler):
    server_version = "NullinkDeploy/1"

    def _json(self, status: int, payload: dict) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path == "/health":
            return self._json(200, {"ok": True, "service": "nullink-deploy"})
        return self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:
        if self.path != PATH:
            return self._json(404, {"error": "not_found"})
        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            return self._json(400, {"error": "invalid_length"})
        if length <= 0 or length > MAX_BODY:
            return self._json(413, {"error": "invalid_body_size"})
        body = self.rfile.read(length)
        if not valid_signature(body, self.headers.get("X-Hub-Signature-256"), load_secret()):
            return self._json(401, {"error": "invalid_signature"})
        deployment = parse_deployment(body, self.headers.get("X-GitHub-Event"), load_repositories())
        if not deployment:
            return self._json(202, {"ok": True, "action": "ignored"})
        repository, commit = deployment
        subprocess.Popen(
            ["/usr/bin/python3", WORKER, repository, commit],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
        return self._json(202, {
            "ok": True,
            "action": "queued",
            "repository": repository,
            "commit": commit,
        })

    def log_message(self, fmt: str, *args: object) -> None:
        # Do not log request headers or bodies; systemd captures this safe summary.
        print(f"{self.address_string()} {fmt % args}")


def main() -> None:
    load_secret()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"Nullink deploy webhook listening on {HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
