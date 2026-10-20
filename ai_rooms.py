"""Per-connection room/channel switching for AI (Bearer) connections.

Config: data/ai_rooms.json (John-controlled; edit with scripts/ai-rooms.py)
  {"channels": [privileged session ids],
   "connections": {token_id: {"admin": bool, "allow_rooms": [...]|null,
                              "current": sid}}}
allow_rooms null/missing = default: rooms the token is already in (minus channels).
Admins may /channel into any id in "channels". deepseek is never reachable.
Audit: data/ai_rooms_audit.jsonl
"""
from __future__ import annotations
import json, threading, time
from pathlib import Path

BASE = Path(__file__).resolve().parent
CONFIG = BASE / "data" / "ai_rooms.json"
AUDIT = BASE / "data" / "ai_rooms_audit.jsonl"
NEVER = frozenset({"deepseek"})
DEFAULT_CHANNELS = ["replit"]
CURRENT = "@current"
_lock = threading.Lock()


def load() -> dict:
    try:
        d = json.loads(CONFIG.read_text(encoding="utf-8"))
        if not isinstance(d, dict):
            d = {}
    except (OSError, json.JSONDecodeError):
        d = {}
    d.setdefault("channels", list(DEFAULT_CHANNELS))
    d.setdefault("connections", {})
    return d


def save(d: dict) -> None:
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG.with_suffix(".tmp")
    tmp.write_text(json.dumps(d, indent=2), encoding="utf-8")
    tmp.replace(CONFIG)


def audit(event: dict) -> None:
    event = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **event}
    with _lock:
        AUDIT.parent.mkdir(parents=True, exist_ok=True)
        with AUDIT.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")


def _conn(d: dict, tid: str) -> dict:
    c = d["connections"].get(tid)
    return c if isinstance(c, dict) else {}


def channels(d: dict | None = None) -> list[str]:
    d = d or load()
    return [str(c) for c in d.get("channels") or [] if str(c) not in NEVER]


def is_admin(tid: str, d: dict | None = None) -> bool:
    return bool(_conn(d or load(), tid).get("admin"))


def rooms_for(tid: str, token_sessions: list, d: dict | None = None) -> list[str]:
    d = d or load()
    chans = set(channels(d))
    allow = _conn(d, tid).get("allow_rooms")
    base = allow if isinstance(allow, list) else list(token_sessions or [])
    out = []
    for s in base:
        s = str(s)
        if s and s not in NEVER and s not in chans and s not in out:
            out.append(s)
    return out


def channels_for(tid: str, d: dict | None = None) -> list[str]:
    d = d or load()
    return channels(d) if is_admin(tid, d) else []


def allowed(tid: str, token_sessions: list, sid: str) -> bool:
    """Extra access granted by the allowlist (token sessions are checked by caller)."""
    sid = str(sid)
    if sid in NEVER:
        return False
    d = load()
    return sid in rooms_for(tid, token_sessions, d) or sid in channels_for(tid, d)


def current(tid: str, token_sessions: list) -> str | None:
    d = load()
    cur = _conn(d, tid).get("current")
    reach = rooms_for(tid, token_sessions, d) + channels_for(tid, d)
    if cur and str(cur) in reach:
        return str(cur)
    return reach[0] if reach else None


def _set_current(tid: str, sid: str) -> None:
    with _lock:
        d = load()
        c = d["connections"].setdefault(tid, {})
        c["current"] = sid
        save(d)


COMMANDS = ("/rooms", "/channels", "/where", "/room", "/channel")


def parse(text: str):
    t = (text or "").strip()
    if not t.startswith("/") or "\n" in t:
        return None
    parts = t.split(None, 1)
    cmd = parts[0].lower()
    if cmd not in COMMANDS:
        return None
    return cmd, (parts[1].strip() if len(parts) > 1 else "")


def _match(name: str, options: list[str], titles: dict) -> str | None:
    n = name.strip().lstrip("#").lower()
    for o in options:
        if o.lower() == n or str(titles.get(o, "")).lower() == n:
            return o
    for o in options:  # "forge" matches "Forge (Bob)"
        if str(titles.get(o, "")).lower().split(" (")[0] == n:
            return o
    return None


def handle(cmd: str, arg: str, auth: dict, titles: dict | None = None) -> tuple[int, dict]:
    titles = titles or {}
    tid = str(auth.get("token_id") or "")
    name = auth.get("name")
    toks = auth.get("sessions") or []
    d = load()
    rooms = rooms_for(tid, toks, d)
    chans = channels_for(tid, d)
    admin = is_admin(tid, d)
    label = lambda s: {"id": s, "title": titles.get(s, s)}
    base = {"ok": True, "command": cmd}
    if cmd == "/rooms":
        return 200, {**base, "rooms": [label(s) for s in rooms],
                     "text": "Rooms: " + (", ".join(rooms) or "(none)")}
    if cmd == "/channels":
        if not admin:
            audit({"event": "refused", "command": cmd, "token_id": tid, "name": name,
                   "reason": "not_admin"})
            return 403, {"ok": False, "command": cmd, "error": "not_admin",
                         "text": "Refused: /channels is for administrator bots only."}
        return 200, {**base, "channels": [label(s) for s in chans],
                     "text": "Channels: " + (", ".join(chans) or "(none)")}
    cur = current(tid, toks)
    if cmd == "/where":
        kind = "channel" if cur in chans else "room"
        return 200, {**base, "current": cur, "kind": kind,
                     "text": f"Current {kind}: {cur or '(none)'}"}
    if not arg:
        return 400, {"ok": False, "command": cmd, "error": "name_required",
                     "text": f"Usage: {cmd} <name>"}
    if cmd == "/channel" and not admin:
        audit({"event": "refused", "command": cmd, "target": arg, "token_id": tid,
               "name": name, "reason": "not_admin"})
        return 403, {"ok": False, "command": cmd, "error": "not_admin",
                     "text": "Refused: /channel is for administrator bots only. Ask John to mark this connection as admin."}
    options = chans if cmd == "/channel" else rooms
    target = _match(arg, options, titles)
    if not target:
        audit({"event": "refused", "command": cmd, "target": arg, "token_id": tid,
               "name": name, "reason": "not_allowed"})
        what = "channel" if cmd == "/channel" else "room"
        return 403, {"ok": False, "command": cmd, "error": "not_allowed",
                     "text": f"Refused: '{arg}' is not a {what} this connection may use. Try {cmd}s."}
    _set_current(tid, target)
    audit({"event": "switch", "command": cmd, "from": cur, "to": target,
           "token_id": tid, "name": name})
    return 200, {**base, "current": target, "previous": cur,
                 "kind": "channel" if cmd == "/channel" else "room",
                 "text": f"Switched to {target}."}
