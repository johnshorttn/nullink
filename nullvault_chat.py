"""NullVault Stage 3: Nullink rooms on the phone (flag NULLVAULT_CHAT, under NULLVAULT_ENABLED).

Why an extended route: the existing message API (/api/messages, /api/sessions) only accepts an owner cookie or
an `nl_` API token with scopes; it does not know NullVault device tokens. These routes reuse the same store and
the same send side effects (server.read_messages / append_message / write_pending / fire_webhook), so the web UI,
bots and bridges see phone messages exactly like web-UI messages from John.

Auth choice (documented): a 10-minute chat session. Opening it needs a fingerprint plus a fresh device signature
(sync-challenge purpose "chat" -> POST /api/vault/chat/session -> `nvc_` bearer, server memory only). Reads and
sends then use that session; the app asks for a tap-to-confirm on every send. Revoking or flagging the phone ends
the session at once. Polling only (the app polls while the room is open); no push.
"""
from __future__ import annotations

import os
import re
import urllib.parse

import nullvault_ext as ext

nv = None
server = None

SESSION_TTL = 600
MAX_TEXT = 8000
SEND_LIMIT = (30, 600)  # 30 sends per 10 min per device
sessions = ext.SessionStore("nvc_", SESSION_TTL)
limits = ext.RateLimit()
_SID = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


def bind(nv_mod, srv):
    global nv, server
    nv, server = nv_mod, srv
    ext.bind(nv_mod, srv)


def enabled() -> bool:
    return nv.enabled() and os.environ.get("NULLVAULT_CHAT", "0") == "1"


def rooms() -> list[dict]:
    try:
        flat = server.flat_sessions_from_roster(server.load_roster())
    except Exception:  # noqa: BLE001
        flat = []
    out, seen = [], set()
    for r in flat:
        sid = str(r.get("id") or "")
        if not _SID.match(sid) or sid in seen:
            continue
        seen.add(sid)
        out.append({"id": sid, "title": str(r.get("title") or sid)[:120], "kind": r.get("kind"),
                    "category": r.get("category"), "bridge": sid in server.BRIDGE_SESSIONS})
    return out


def _room_ok(sid: str) -> bool:
    return any(r["id"] == sid for r in rooms())


def _int(qs, k, default, lo, hi):
    try:
        return max(lo, min(hi, int((qs.get(k) or [default])[0])))
    except (TypeError, ValueError):
        return default


def route(h, method: str, path: str):
    if not enabled():
        return h._json(404, {"error": "not_found"})
    if path == "/api/vault/chat/session":
        if method != "POST":
            return h._json(405, {"error": "method_not_allowed"})
        r = nv._verify_device_request(h, "chat")
        if not r:
            return
        tok, ttl = sessions.issue(r[0]["device_id"])
        server.vault_audit("device_chat_session", device=r[0]["device_id"], ip=nv._ctx(h)[0])
        return h._json(200, {"chat_session": tok, "expires_in": ttl})
    d = sessions.device(h, "chat_session_expired")
    if not d:
        return
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(h.path).query)
    if path == "/api/vault/chat/rooms" and method == "GET":
        return h._json(200, {"rooms": rooms()})
    if path == "/api/vault/chat/messages" and method == "GET":
        sid = str((qs.get("session") or [""])[0])
        if not _room_ok(sid):
            return h._json(404, {"error": "room_not_found"})
        after = _int(qs, "after", 0, 0, 10**12)
        limit = _int(qs, "limit", 50, 1, 100)
        msgs = [m for m in server.read_messages(after_id=after) if m.get("session_id", "morc") == sid]
        tail = qs.get("tail") == ["1"]
        page = msgs[-limit:] if tail else msgs[:limit]
        out = [{"id": int(m.get("id") or 0), "role": str(m.get("role") or ""), "text": str(m.get("text") or ""),
                "ts": m.get("created_at") or m.get("ts")} for m in page]
        nxt = max([m["id"] for m in out], default=after)
        return h._json(200, {"messages": out, "next_after": nxt, "has_more": (not tail) and len(msgs) > limit})
    if path == "/api/vault/chat/send" and method == "POST":
        body = h._read_json() or {}
        sid = str(body.get("session_id") or "")
        text = str(body.get("text") or "").strip()
        if not text:
            return h._json(400, {"error": "empty"})
        if len(text) > MAX_TEXT:
            return h._json(400, {"error": "too_long"})
        if not _room_ok(sid):
            return h._json(404, {"error": "room_not_found"})
        if not limits.hit(d["device_id"], *SEND_LIMIT):
            return h._json(429, {"error": "rate_limited"})
        # Same side effects as the web UI's owner send (server._post_message, cookie branch).
        msg = server.append_message("user", text, session_id=sid)
        if sid not in server.BRIDGE_SESSIONS:
            server.write_pending("notify", {"preview": text[:200]})
            server.fire_webhook("message", text[:200])
        server.vault_audit("device_chat_send", device=d["device_id"], session=sid, chars=len(text), ip=nv._ctx(h)[0])
        return h._json(200, {"ok": True, "message": {"id": msg.get("id"), "role": "user", "text": text, "ts": msg.get("ts")}})
    return h._json(404, {"error": "not_found"})
