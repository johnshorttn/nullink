"""Scoped bot access to the Vault (John 2026-11-04: "Add only access, ask for auth code for read access each time.").

* Deposit (add-only): POST /api/vault/deposit with ``Authorization: Bearer nlvb_...``.
  Always creates a NEW entry (server-chosen id, never overwrites), returns only id/title/created_at,
  never the body. The bot token cannot list, view, edit or delete anything: every other route
  rejects it (it is not a session and not a normal API token).
* Read (per-read authenticator code): POST /api/vault/bot-read with the bot token plus
  ``{"id": ..., "code": "<John's current TOTP>"}``. The code is verified against John's TOTP and
  consumed (no replay of that code or any earlier time step), so each read needs a fresh code John
  types at that moment. One code = one entry. Valid only for the code's own ~30-90 s TOTP window.
  Five bad codes in 15 min lock bot reads for 15 min.
* Everything is written to vault_audit.jsonl with source=<bot name>; no secret values are logged.

Tokens are stored only as SHA-256 hashes in DATA/vault_bot_tokens.json (mode 600). Manage with:
    python3 vault_bot.py add --name morc --sha256 <hex>   # hash of a token generated elsewhere
    python3 vault_bot.py list | revoke --name morc
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import sys
import threading
import time
import urllib.parse

server = None  # bound by handle() / main() to the live server module

TOKEN_PREFIX = "nlvb_"
DEPOSIT_PATH = "/api/vault/deposit"
READ_PATH = "/api/vault/bot-read"
PATHS = (DEPOSIT_PATH, READ_PATH)
DEPOSIT_MAX_PER_HOUR = 30
READ_FAIL_MAX = 5
READ_FAIL_WINDOW_SEC = 15 * 60
_lock = threading.Lock()


def tokens_file():
    return server.DATA / "vault_bot_tokens.json"


def rate_file():
    return server.DATA / "vault_bot_rate.json"


def _load(path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8")) or {}
    except (FileNotFoundError, ValueError):
        return {}


def hash_token(token: str) -> str:
    return hashlib.sha256(str(token).encode("utf-8")).hexdigest()


def add_token(name: str, sha256_hex: str, scopes=("deposit", "read_with_totp")) -> None:
    if not re.fullmatch(r"[0-9a-f]{64}", sha256_hex or ""):
        raise ValueError("sha256 must be 64 lowercase hex chars")
    if not re.fullmatch(r"[a-z0-9_-]{1,32}", name or ""):
        raise ValueError("bad name")
    with _lock:
        data = _load(tokens_file())
        toks = [t for t in data.get("tokens") or [] if t.get("name") != name]
        toks.append({"name": name, "sha256": sha256_hex, "scopes": list(scopes), "created_at": server.iso_now()})
        server._atomic_write_json(tokens_file(), {"tokens": toks})


def revoke_token(name: str) -> bool:
    with _lock:
        data = _load(tokens_file())
        toks = data.get("tokens") or []
        keep = [t for t in toks if t.get("name") != name]
        server._atomic_write_json(tokens_file(), {"tokens": keep})
        return len(keep) != len(toks)


def lookup(token: str | None) -> dict | None:
    if not token or not token.startswith(TOKEN_PREFIX):
        return None
    h = hash_token(token)
    for t in _load(tokens_file()).get("tokens") or []:
        if hmac.compare_digest(str(t.get("sha256") or ""), h):
            return t
    return None


def _rate(name: str, kind: str, window: float, now: float) -> list:
    data = _load(rate_file())
    return [x for x in (data.get(name) or {}).get(kind) or [] if now - float(x) < window]


def _rate_add(name: str, kind: str, window: float, now: float) -> None:
    data = _load(rate_file())
    rec = data.setdefault(name, {})
    rec[kind] = [x for x in rec.get(kind) or [] if now - float(x) < window] + [now]
    server._atomic_write_json(rate_file(), data)


def _no_store_json(h, status: int, payload: dict) -> None:
    h._json(status, payload)


def handle(h, path: str) -> None:
    # server.py runs as __main__ in prod; bind to the module that defines the live handler.
    global server
    server = sys.modules[type(h).__module__]
    ip, ua = server.client_ip(h), str(h.headers.get("User-Agent") or "")[:160]
    bot = lookup(h._bearer_token())
    if not bot:
        server.vault_audit("bot_auth_failed", path=path, ip=ip, ua=ua)
        return h._json(401, {"error": "unauthorized"})
    name = bot["name"]
    scopes = bot.get("scopes") or []
    if path == DEPOSIT_PATH:
        if "deposit" not in scopes:
            return h._json(403, {"error": "forbidden"})
        return _deposit(h, name, ip, ua)
    if "read_with_totp" not in scopes:
        return h._json(403, {"error": "forbidden"})
    return _read(h, name, ip, ua)


def _deposit(h, name, ip, ua):
    now = time.time()
    with _lock:
        if len(_rate(name, "deposit", 3600, now)) >= DEPOSIT_MAX_PER_HOUR:
            server.vault_audit("deposit_rate_limited", source=name, ip=ip, ua=ua)
            return h._json(429, {"error": "rate_limited"})
        _rate_add(name, "deposit", 3600, now)
    body = h._read_json() or {}
    title = str(body.get("title") or "").strip()[:200]
    text_body = str(body.get("body") or "")
    if not title or not text_body.strip():
        return h._json(400, {"error": "empty", "message": "title and body required"})
    if len(text_body) > 100_000:
        return h._json(413, {"error": "too_large"})
    tags = body.get("tags")
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    tags = [str(t)[:40] for t in (tags if isinstance(tags, list) else [])][:10]
    if f"from-{name}" not in tags:
        tags.append(f"from-{name}")
    # Never accept a client id: save_vault_snippet() overwrites when an id exists.
    try:
        entry = server.save_vault_snippet({"title": title, "body": text_body, "tags": tags})
    except server.VaultKeyUnavailable:
        return h._json(503, {"error": "vault_key_unavailable"})
    server.vault_audit("deposit", id=entry["id"], source=name, ip=ip, ua=ua, title=title, body_len=len(text_body))
    return h._json(201, {"ok": True, "id": entry["id"], "title": entry.get("title"),
                         "created_at": entry.get("created_at")})


def _read(h, name, ip, ua):
    now = time.time()
    body = h._read_json() or {}
    vid = urllib.parse.unquote(str(body.get("id") or "")).strip()
    with _lock:
        if len(_rate(name, "read_fail", READ_FAIL_WINDOW_SEC, now)) >= READ_FAIL_MAX:
            server.vault_audit("bot_read_denied", reason="locked", id=vid, source=name, ip=ip, ua=ua)
            return h._json(429, {"error": "locked", "message": "Too many bad codes; try again later."})
        config = server.load_totp()
        if not (config and config.get("enabled") and config.get("secret")):
            server.vault_audit("bot_read_denied", reason="totp_not_enabled", id=vid, source=name, ip=ip, ua=ua)
            return h._json(403, {"error": "totp_not_enabled"})
        if not vid:
            return h._json(400, {"error": "id_required"})
        if not server.verify_totp(str(body.get("code") or ""), config, now=now, consume=True):
            _rate_add(name, "read_fail", READ_FAIL_WINDOW_SEC, now)
            server.vault_audit("bot_read_denied", reason="bad_or_reused_code", id=vid, source=name, ip=ip, ua=ua)
            return h._json(403, {"error": "code_invalid", "message": "Need a fresh authenticator code from John."})
    try:
        item = server.load_vault_snippet(vid, decrypt=True)
    except server.VaultKeyUnavailable:
        return h._json(503, {"error": "vault_key_unavailable"})
    except server.VaultIntegrityError:
        server.vault_audit("integrity_failure", id=vid, source=name, ip=ip, ua=ua)
        return h._json(500, {"error": "vault_integrity"})
    if not item:
        server.vault_audit("bot_read_denied", reason="not_found", id=vid, source=name, ip=ip, ua=ua)
        return h._json(404, {"error": "not_found"})
    if item.get("e2e"):  # 0.6.0: end-to-end encrypted; the server (and so the bot) cannot read it
        server.vault_audit("bot_read_denied", reason="e2e_item", id=vid, source=name, ip=ip, ua=ua)
        return h._json(409, {"error": "e2e_item", "message": server.VAULT_E2E_MESSAGE})
    server.vault_audit("bot_read", id=vid, source=name, ip=ip, ua=ua)
    return h._json(200, {"item": {k: item.get(k) for k in ("id", "title", "body", "tags", "created_at")},
                         "single_use": True})


def main(argv):
    import argparse
    global server
    import server as _srv
    server = _srv
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("add"); a.add_argument("--name", required=True); a.add_argument("--sha256", required=True)
    r = sub.add_parser("revoke"); r.add_argument("--name", required=True)
    sub.add_parser("list")
    args = p.parse_args(argv)
    server.ensure_dirs()
    if args.cmd == "add":
        add_token(args.name, args.sha256.lower()); print(f"added {args.name}")
    elif args.cmd == "revoke":
        print("revoked" if revoke_token(args.name) else "not found")
    else:
        for t in _load(tokens_file()).get("tokens") or []:
            print(t.get("name"), ",".join(t.get("scopes") or []), t.get("created_at"))


if __name__ == "__main__":
    main(sys.argv[1:])
