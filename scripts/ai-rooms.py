#!/usr/bin/env python3
"""John's control for AI room/channel switching.
  ai-rooms.py list
  ai-rooms.py allow <token_id> <room>      # add room to allowlist
  ai-rooms.py deny  <token_id> <room>
  ai-rooms.py reset <token_id>             # back to default (token's own rooms)
  ai-rooms.py admin <token_id> on|off
  ai-rooms.py channel add|remove <session_id>   # mark privileged channel
  ai-rooms.py audit [N]
"""
import json, sys
sys.path.insert(0, "/opt/nullink")
import ai_rooms as R

TOK = R.BASE / "data" / "tokens.json"

def tokens():
    try:
        t = json.loads(TOK.read_text())
    except Exception:
        return []
    return t.get("tokens", []) if isinstance(t, dict) else t

def main(a):
    if not a or a[0] in ("-h", "--help"):
        print(__doc__); return 0
    d = R.load(); cmd = a[0]
    if cmd == "list":
        print("channels:", ", ".join(R.channels(d)) or "(none)")
        for t in tokens():
            if t.get("revoked"):
                continue
            tid = t.get("id"); c = d["connections"].get(tid, {})
            print(f"{tid} {t.get('name')}: admin={bool(c.get('admin'))} "
                  f"rooms={R.rooms_for(tid, t.get('sessions'), d)} "
                  f"current={R.current(tid, t.get('sessions'))}"
                  + ("" if isinstance(c.get('allow_rooms'), list) else " (default allowlist)"))
        return 0
    if cmd == "audit":
        n = int(a[1]) if len(a) > 1 else 20
        lines = R.AUDIT.read_text().splitlines() if R.AUDIT.exists() else []
        print("\n".join(lines[-n:])); return 0
    if cmd == "channel" and len(a) == 3:
        ch = d["channels"]
        if a[1] == "add" and a[2] not in ch: ch.append(a[2])
        if a[1] == "remove" and a[2] in ch: ch.remove(a[2])
        R.save(d); R.audit({"event": "config", "change": f"channel {a[1]} {a[2]}"}); print("ok"); return 0
    if len(a) < 2:
        print(__doc__); return 2
    tid = a[1]
    known = {t.get("id"): t for t in tokens()}
    if tid not in known:
        print("unknown token_id; see: ai-rooms.py list"); return 2
    c = d["connections"].setdefault(tid, {})
    if cmd in ("allow", "deny") and len(a) == 3:
        if a[2] in R.NEVER:
            print("refused: deepseek is never allowed"); return 2
        cur = c.get("allow_rooms")
        if not isinstance(cur, list):
            cur = R.rooms_for(tid, known[tid].get("sessions"), d)
        if cmd == "allow" and a[2] not in cur: cur.append(a[2])
        if cmd == "deny" and a[2] in cur: cur.remove(a[2])
        c["allow_rooms"] = cur
    elif cmd == "reset":
        c.pop("allow_rooms", None)
    elif cmd == "admin" and len(a) == 3 and a[2] in ("on", "off"):
        c["admin"] = a[2] == "on"
    else:
        print(__doc__); return 2
    R.save(d); R.audit({"event": "config", "change": " ".join(a)}); print("ok"); return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
