"""Nullink realtime push (Socket.IO). Added 2026-10-14.

Runs beside server.py (stdlib ThreadingHTTPServer) as its own ASGI process on 127.0.0.1:8774;
Caddy proxies /socket.io/* here with WebSocket upgrade.

* Auth: every handshake is checked by calling server.py GET /api/rt/whoami with the client's own
  Cookie / Bearer, so the exact REST rules apply. Unauthenticated connects are refused and every
  socket is re-checked every 60 s (revoked or expired sessions are dropped).
* Messages: tails data/messages.jsonl (all writers: server.py, replit room, bridges) and emits
  each new line to Socket.IO room "s:<session_id>". Message id == line number, same as REST.
* join {session, after}: authorised per REST rules (bearer allow-list, owner-only rooms hidden from
  guests, guests get no history/messages), then catch-up of everything after `after`.
* Replit room status is pushed while someone is in s:replit.
REST endpoints are untouched; clients keep HTTP polling as fallback.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

import socketio

ROOT = Path(os.environ.get("NL_ROOT", "/opt/nullink"))
MESSAGES_FILE = Path(os.environ.get("NL_MESSAGES", str(ROOT / "data" / "messages.jsonl")))
API = os.environ.get("NL_API", "http://127.0.0.1:8766")
REPLIT_STATUS = os.environ.get("NL_REPLIT_STATUS", "http://127.0.0.1:8773/replit/api/room-status")
HOSTS = ("nullink.nullverse.cloud", "nullink.216.158.238.236.sslip.io")
ORIGINS = [f"https://{h}" for h in HOSTS]
TAIL_SEC = float(os.environ.get("NL_RT_TAIL_SEC", "0.25"))
RECHECK_SEC = float(os.environ.get("NL_RT_RECHECK_SEC", "60"))
CATCHUP_MAX = 500

log = logging.getLogger("nullink-rt")
sio = socketio.AsyncServer(async_mode="asgi", cors_allowed_origins=ORIGINS,
                           ping_interval=20, ping_timeout=20, max_http_buffer_size=64_000)


def _whoami_sync(cookie: str | None, bearer: str | None, host: str) -> tuple[int, dict]:
    headers = {"Host": host if host in HOSTS else HOSTS[0], "X-Forwarded-Proto": "https",
               "X-Forwarded-For": "127.0.0.1", "Accept": "application/json"}
    if cookie:
        headers["Cookie"] = cookie
    if bearer:
        headers["Authorization"] = "Bearer " + bearer
    req = urllib.request.Request(API + "/api/rt/whoami", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, {}
    except Exception:
        return 503, {}


async def whoami(cred: dict) -> tuple[int, dict]:
    return await asyncio.to_thread(_whoami_sync, cred.get("cookie"), cred.get("bearer"), cred.get("host", ""))


def session_allowed(ident: dict, session: str) -> tuple[bool, str]:
    if not session or len(session) > 64:
        return False, "bad_session"
    if ident.get("guest"):
        if session in (ident.get("owner_only") or []):
            return False, "session_not_allowed"
        return True, ""
    allowed = ident.get("sessions")
    if allowed == "*" or (isinstance(allowed, list) and session in allowed):
        return True, ""
    return False, "session_not_allowed"


def read_after(after: int, session: str, limit: int = CATCHUP_MAX) -> list[dict]:
    out: list[dict] = []
    try:
        with MESSAGES_FILE.open("r", encoding="utf-8") as f:
            for i, line in enumerate(f, start=1):
                if i <= after or not line.strip():
                    continue
                try:
                    m = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if m.get("session_id", "morc") != session:
                    continue
                m["id"] = i
                if "created_at" not in m and m.get("ts"):
                    m["created_at"] = m["ts"]
                out.append(m)
    except FileNotFoundError:
        pass
    return out[-limit:]


@sio.event
async def connect(sid, environ, auth):
    auth = auth if isinstance(auth, dict) else {}
    hauth = environ.get("HTTP_AUTHORIZATION") or ""
    bearer = auth.get("token") or (hauth.split(None, 1)[1].strip() if hauth.lower().startswith("bearer ") else None)
    cred = {"cookie": environ.get("HTTP_COOKIE"), "bearer": bearer,
            "host": (environ.get("HTTP_HOST") or "").split(":")[0]}
    if not cred["cookie"] and not cred["bearer"]:
        raise ConnectionRefusedError("unauthorized")
    st, ident = await whoami(cred)
    if st != 200 or not ident.get("ok"):
        raise ConnectionRefusedError("unauthorized")
    await sio.save_session(sid, {"cred": cred, "ident": ident, "rooms": set()})
    await sio.emit("hello", {"guest": bool(ident.get("guest")), "hide_history": bool(ident.get("hide_history")),
                             "type": ident.get("type")}, to=sid)


@sio.event
async def join(sid, data):
    data = data if isinstance(data, dict) else {}
    session = str(data.get("session") or "morc")
    try:
        after = max(0, int(data.get("after") or 0))
    except (TypeError, ValueError):
        after = 0
    sess = await sio.get_session(sid)
    ident = sess["ident"]
    ok, why = session_allowed(ident, session)
    if not ok:
        return {"ok": False, "error": why}
    for r in list(sess["rooms"]):
        await sio.leave_room(sid, r)
    sess["rooms"] = set()
    if ident.get("guest") and ident.get("hide_history"):
        # Guests: no history and no live messages (same as REST guest_history_hidden).
        await sio.save_session(sid, sess)
        return {"ok": True, "session": session, "history_hidden": True, "messages": []}
    room = "s:" + session
    await sio.enter_room(sid, room)
    sess["rooms"] = {room}
    await sio.save_session(sid, sess)
    msgs = await asyncio.to_thread(read_after, after, session) if after > 0 else []
    if session == "replit" and _last_status.get("replit") is not None:
        await sio.emit("status", {"session": "replit", "data": _last_status["replit"]}, to=sid)
    return {"ok": True, "session": session, "messages": msgs, "catchup": True}


@sio.event
async def leave(sid, data=None):
    sess = await sio.get_session(sid)
    for r in list(sess["rooms"]):
        await sio.leave_room(sid, r)
    sess["rooms"] = set()
    await sio.save_session(sid, sess)
    return {"ok": True}


# ---------- background tasks ----------
_last_status: dict = {}


def _count_state():
    """Returns (byte offset at last complete line, line count)."""
    try:
        data = MESSAGES_FILE.read_bytes()
    except FileNotFoundError:
        return 0, 0
    end = data.rfind(b"\n") + 1
    return end, data[:end].count(b"\n")


async def tail_loop():
    offset, lineno = await asyncio.to_thread(_count_state)
    log.info("tailing %s from line %d", MESSAGES_FILE, lineno)
    while True:
        await asyncio.sleep(TAIL_SEC)
        try:
            size = MESSAGES_FILE.stat().st_size
        except FileNotFoundError:
            continue
        if size < offset:  # truncated/rotated
            offset, lineno = await asyncio.to_thread(_count_state)
            continue
        if size == offset:
            continue
        with MESSAGES_FILE.open("rb") as f:
            f.seek(offset)
            chunk = f.read(size - offset)
        end = chunk.rfind(b"\n") + 1
        if end == 0:
            continue
        offset += end
        for raw in chunk[:end].split(b"\n")[:-1]:
            lineno += 1
            if not raw.strip():
                continue
            try:
                m = json.loads(raw)
            except json.JSONDecodeError:
                continue
            m["id"] = lineno
            if "created_at" not in m and m.get("ts"):
                m["created_at"] = m["ts"]
            sess = str(m.get("session_id") or "morc")
            await sio.emit("message", {"session": sess, "messages": [m]}, room="s:" + sess)


def _room_has_members(room: str) -> bool:
    try:
        return any(True for _ in sio.manager.get_participants("/", room))
    except Exception:
        return False


def _replit_status_sync():
    with urllib.request.urlopen(REPLIT_STATUS, timeout=4) as r:
        return json.loads(r.read())


async def status_loop():
    while True:
        await asyncio.sleep(2)
        if not _room_has_members("s:replit"):
            _last_status.pop("replit", None)
            continue
        try:
            d = await asyncio.to_thread(_replit_status_sync)
        except Exception:
            d = {"bridge_down": True}
        if d != _last_status.get("replit"):
            _last_status["replit"] = d
            await sio.emit("status", {"session": "replit", "data": d}, room="s:replit")


async def recheck_loop():
    while True:
        await asyncio.sleep(RECHECK_SEC)
        try:
            sids = [s for s, _ in sio.manager.get_participants("/", None)]
        except Exception:
            sids = []
        for s in sids:
            try:
                sess = await sio.get_session(s)
                st, ident = await whoami(sess["cred"])
                if st in (401, 403):
                    await sio.emit("auth_expired", {}, to=s)
                    await sio.disconnect(s)
                elif st == 200:
                    sess["ident"] = ident
                    await sio.save_session(s, sess)
            except Exception:
                continue


_started = False


async def plain_app(scope, receive, send):
    global _started
    if scope["type"] == "lifespan":
        while True:
            msg = await receive()
            if msg["type"] == "lifespan.startup":
                if not _started:
                    _started = True
                    for coro in (tail_loop(), status_loop(), recheck_loop()):
                        asyncio.get_running_loop().create_task(coro)
                await send({"type": "lifespan.startup.complete"})
            elif msg["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return
    if scope["type"] == "http" and scope.get("path") == "/rt/health":
        n = len(list(sio.manager.get_participants("/", None))) if True else 0
        body = json.dumps({"ok": True, "clients": n}).encode()
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": body})
        return
    await send({"type": "http.response.start", "status": 404, "headers": []})
    await send({"type": "http.response.body", "body": b"not found"})


app = socketio.ASGIApp(sio, other_asgi_app=plain_app, socketio_path="socket.io")

if __name__ == "__main__":
    import uvicorn
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("NL_RT_PORT", "8774")),
                log_level="warning", proxy_headers=False, ws="websockets")
