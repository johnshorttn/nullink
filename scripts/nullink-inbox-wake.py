#!/usr/bin/env python3
"""VPS watcher: post one content-free Slack `nullink-inbox` when Morc's
Nullink inbox has something new.

Triggers (same set the PC chat bridge inbox routine acts on):
  * non-empty data/pending.notify, pending.ask, pending.upload
  * new role=user lines in data/messages.jsonl that are NOT:
      - session deepseek (that room has its own bridge; never wake Morc for it)
      - source mirror / grok-bot / grokbot / grok-bot-history
      - Jinx Slack relay traffic in the chatgpt room
        (source=slack, a leading "[Slack", or a "slack <ref>:" reply line)
      - assistant lines (Morc's own posts)

Does not include message text in the Slack post or in the log.
Debounce: at most one post per 120s; bursts coalesce into the next post.
State: data/.inbox-wake-state.json so the same message or flag bytes
do not wake again (independent of .last-handled, which the handler advances).

Webhook URL is read from /opt/nullink/secrets/slack-incoming-webhook.url
and is never printed.

  nullink-inbox-wake.py            # daemon
  nullink-inbox-wake.py --check    # print unsent counts, do not post
  nullink-inbox-wake.py --selftest # one harmless Slack post, no Nullink writes
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

DATA = Path(os.environ.get("NULLINK_DATA", "/opt/nullink/data"))
WEBHOOK_FILE = Path(os.environ.get(
    "NULLINK_SLACK_WEBHOOK_FILE", "/opt/nullink/secrets/slack-incoming-webhook.url"))
STATE_PATH = Path(os.environ.get(
    "NULLINK_INBOX_WAKE_STATE", str(DATA / ".inbox-wake-state.json")))
LOG_PATH = Path(os.environ.get(
    "NULLINK_INBOX_WAKE_LOG", str(DATA / "inbox-wake.log")))

POLL_SEC = float(os.environ.get("NULLINK_INBOX_WAKE_POLL_SEC", "5"))
DEBOUNCE_SEC = float(os.environ.get("NULLINK_INBOX_WAKE_DEBOUNCE_SEC", "120"))
FLAG_NAMES = ("pending.notify", "pending.ask", "pending.upload")
SKIP_SOURCES = {"mirror", "grok-bot", "grokbot", "grok-bot-history"}
SKIP_SESSIONS = {"deepseek"}
SEEN_CAP = 4000


def log(msg: str) -> None:
    line = time.strftime("%Y-%m-%dT%H:%M:%S%z") + " " + msg
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
        try:
            os.chmod(LOG_PATH, 0o600)
        except OSError:
            pass
    except OSError as exc:
        print(f"log-write-failed {exc.__class__.__name__}", file=sys.stderr)
    print(line, flush=True)


def msg_key(msg: dict) -> str:
    raw = "|".join([
        str(msg.get("ts") or ""),
        str(msg.get("session_id") or ""),
        str(msg.get("role") or ""),
        str(msg.get("text") or ""),
    ]).encode("utf-8", "replace")
    return hashlib.sha256(raw).hexdigest()[:24]


def is_jinx_relay(msg: dict) -> bool:
    """Slack traffic dropped into the chatgpt room for Jinx, not a Morc inbox item."""
    if str(msg.get("session_id") or "") != "chatgpt":
        return False
    if str(msg.get("source") or "").lower() == "slack":
        return True
    text = str(msg.get("text") or "").lstrip()
    low = text.lower()
    if low.startswith("[slack"):
        return True
    # Relay replies are "slack <ref>: ..." (ref is a short token).
    if low.startswith("slack "):
        head = low.split(":", 1)[0]
        ref = head[6:].strip()
        if ref and " " not in ref and len(ref) <= 32:
            return True
    return False


def qualifies(msg: dict) -> bool:
    if not isinstance(msg, dict):
        return False
    if msg.get("role") != "user":
        return False
    sid = str(msg.get("session_id") or "morc")
    if sid in SKIP_SESSIONS:
        return False
    src = str(msg.get("source") or "").lower()
    if src in SKIP_SOURCES:
        return False
    if is_jinx_relay(msg):
        return False
    return True


def read_last_handled() -> str:
    p = DATA / ".last-handled"
    try:
        return p.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def iter_messages():
    path = DATA / "messages.jsonl"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(msg, dict):
            yield msg


def flag_digest(name: str) -> str | None:
    path = DATA / name
    try:
        if not path.is_file() or path.stat().st_size <= 0:
            return None
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def load_state() -> dict:
    try:
        data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            data.setdefault("seen_msgs", [])
            data.setdefault("seen_flags", {})
            data.setdefault("last_wake_epoch", 0)
            data.setdefault("bootstrapped", False)
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return {"seen_msgs": [], "seen_flags": {}, "last_wake_epoch": 0, "bootstrapped": False}


def save_state(state: dict) -> None:
    seen = list(state.get("seen_msgs") or [])
    if len(seen) > SEEN_CAP:
        state["seen_msgs"] = seen[-SEEN_CAP:]
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, STATE_PATH)
    try:
        os.chmod(STATE_PATH, 0o600)
    except OSError:
        pass


def collect_unsent(state: dict) -> tuple[Counter, dict, list[str]]:
    """Return (room counts, flag name->digest, new message keys) not yet announced."""
    seen = set(state.get("seen_msgs") or [])
    seen_flags = dict(state.get("seen_flags") or {})
    rooms: Counter = Counter()
    keys: list[str] = []
    last_handled = read_last_handled()
    for msg in iter_messages():
        if not qualifies(msg):
            continue
        key = msg_key(msg)
        ts = str(msg.get("ts") or "")
        # Already handled by the inbox routine, or already announced by us.
        if key in seen:
            continue
        if last_handled and ts and ts <= last_handled and state.get("bootstrapped"):
            # New relative to our seen-set but not newer than the handler cursor.
            # Remember it so a later scan stays quiet, but do not wake.
            seen.add(key)
            continue
        if state.get("bootstrapped") is False and last_handled and ts and ts <= last_handled:
            continue
        rooms[str(msg.get("session_id") or "morc")] += 1
        keys.append(key)
    # persist the quiet remembers
    state["seen_msgs"] = list(seen)
    flags: dict[str, str] = {}
    for name in FLAG_NAMES:
        digest = flag_digest(name)
        if digest is None:
            seen_flags.pop(name, None)
            continue
        if seen_flags.get(name) == digest:
            continue
        flags[name] = digest
    state["seen_flags"] = seen_flags
    return rooms, flags, keys


def _room_token(name: str) -> str:
    safe = "".join(ch for ch in name if ch.isalnum() or ch in "-_")[:32]
    return safe or "room"

def format_reason(rooms: Counter, flags: dict) -> str:
    # Session ids are collapsed to a short safe token so a crafted id cannot
    # carry message text into Slack.
    rolled: Counter = Counter()
    for name, n in rooms.items():
        rolled[_room_token(str(name))] += n
    room_part = ",".join(f"{k}:{rolled[k]}" for k in sorted(rolled)) or "none"
    flag_part = ",".join(sorted(n.replace("pending.", "") for n in flags)) or "none"
    count = sum(rolled.values()) + len(flags)
    return f"nullink-inbox rooms={room_part} flags={flag_part} count={count}"


def read_webhook() -> str:
    try:
        url = WEBHOOK_FILE.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError(f"webhook-unreadable:{exc.__class__.__name__}") from exc
    if not url.startswith("https://hooks.slack.com/"):
        raise RuntimeError("webhook-rejected")
    return url


def post_text(text: str) -> int:
    url = read_webhook()
    body = json.dumps({"text": text[:300]}).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return int(resp.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)


def bootstrap(state: dict) -> tuple[Counter, dict, list[str]]:
    """First run: remember history at or before .last-handled; wake only for real backlog."""
    seen = set(state.get("seen_msgs") or [])
    last_handled = read_last_handled()
    for msg in iter_messages():
        if not qualifies(msg):
            continue
        ts = str(msg.get("ts") or "")
        if last_handled and ts and ts <= last_handled:
            seen.add(msg_key(msg))
    state["seen_msgs"] = list(seen)
    state["bootstrapped"] = True
    rooms, flags, keys = collect_unsent(state)
    return rooms, flags, keys


def mark_sent(state: dict, keys: list[str], flags: dict) -> None:
    seen = list(state.get("seen_msgs") or [])
    have = set(seen)
    for key in keys:
        if key not in have:
            seen.append(key)
            have.add(key)
    state["seen_msgs"] = seen
    seen_flags = dict(state.get("seen_flags") or {})
    for name, digest in flags.items():
        # Only record if the file still has those bytes (it may have been cleared).
        if flag_digest(name) == digest:
            seen_flags[name] = digest
    state["seen_flags"] = seen_flags
    state["last_wake_epoch"] = time.time()
    state["bootstrapped"] = True
    save_state(state)


def run_daemon() -> int:
    state = load_state()
    pending_rooms: Counter = Counter()
    pending_flags: dict[str, str] = {}
    pending_keys: list[str] = []
    held: set[str] = set()

    def remember_quiet_and_take_new() -> None:
        """Scan live files. Quiet history is saved; unsent items stay in memory only."""
        nonlocal state
        real_seen = [k for k in (state.get("seen_msgs") or []) if k not in held]
        state["seen_msgs"] = list(dict.fromkeys(real_seen + list(held)))
        rooms, flags, keys = collect_unsent(state)
        # collect_unsent may have appended already-handled keys. Keep those, drop held.
        quiet = [k for k in (state.get("seen_msgs") or []) if k not in held]
        state["seen_msgs"] = list(dict.fromkeys(real_seen + [k for k in quiet if k not in set(real_seen)]))
        # keys returned are unsent (not in real_seen and not held, because held was injected).
        for key in keys:
            if key in held:
                continue
            held.add(key)
            pending_keys.append(key)
        pending_rooms.update(rooms)
        pending_flags.update(flags)
        for name in list(pending_flags):
            if flag_digest(name) != pending_flags[name]:
                pending_flags.pop(name, None)
        if not pending_keys and not pending_flags:
            pending_rooms.clear()

    if not state.get("bootstrapped"):
        # Seed seen with history at or before .last-handled, then take any real backlog.
        seen = set(state.get("seen_msgs") or [])
        last_handled = read_last_handled()
        for msg in iter_messages():
            if not qualifies(msg):
                continue
            ts = str(msg.get("ts") or "")
            if last_handled and ts and ts <= last_handled:
                seen.add(msg_key(msg))
        state["seen_msgs"] = list(seen)
        state["bootstrapped"] = True
        save_state(state)
        remember_quiet_and_take_new()
        save_state(state)
        log(f"baseline seen={len(state.get('seen_msgs') or [])} "
            f"unsent_msgs={len(pending_keys)} unsent_flags={len(pending_flags)}")
    else:
        log(f"resume seen={len(state.get('seen_msgs') or [])}")
        remember_quiet_and_take_new()
        save_state(state)

    while True:
        if pending_keys or pending_flags:
            elapsed = time.time() - float(state.get("last_wake_epoch") or 0)
            if elapsed >= DEBOUNCE_SEC:
                # Recompute room counts from keys we still hold, plus flags still present.
                reason = format_reason(pending_rooms, pending_flags)
                try:
                    code = post_text(reason)
                except Exception as exc:
                    log(f"wake failed {exc.__class__.__name__}")
                    code = 0
                if code == 200:
                    log(f"wake http=200 {reason}")
                    mark_sent(state, pending_keys, pending_flags)
                    pending_keys.clear()
                    pending_flags.clear()
                    pending_rooms.clear()
                    held.clear()
                else:
                    log(f"wake http={code} will retry after debounce")
                    state["last_wake_epoch"] = time.time()
                    save_state(state)
        time.sleep(POLL_SEC)
        before = (len(pending_keys), len(pending_flags))
        remember_quiet_and_take_new()
        if (len(pending_keys), len(pending_flags)) != before:
            save_state(state)
        elif state.get("seen_msgs"):
            # persist quiet absorbs without rewriting every poll if nothing changed
            pass


def run_check() -> int:
    state = load_state()
    if not state.get("bootstrapped"):
        tmp = {"seen_msgs": [], "seen_flags": {}, "last_wake_epoch": 0, "bootstrapped": False}
        seen = set()
        last_handled = read_last_handled()
        for msg in iter_messages():
            if not qualifies(msg):
                continue
            ts = str(msg.get("ts") or "")
            if last_handled and ts and ts <= last_handled:
                seen.add(msg_key(msg))
        tmp["seen_msgs"] = list(seen)
        tmp["bootstrapped"] = True
        rooms, flags, keys = collect_unsent(tmp)
        note = "not bootstrapped; rooms/flags are what the first start would post"
        seen_n = 0
        last_wake = 0
    else:
        rooms, flags, keys = collect_unsent(state)
        note = "ok"
        seen_n = len(state.get("seen_msgs") or [])
        last_wake = state.get("last_wake_epoch") or 0
    print(json.dumps({
        "bootstrapped": bool(state.get("bootstrapped")),
        "seen_msgs": seen_n,
        "unsent_msgs": len(keys),
        "rooms": dict(rooms),
        "flags": sorted(flags),
        "debounce_sec": DEBOUNCE_SEC,
        "poll_sec": POLL_SEC,
        "last_wake_epoch": last_wake,
        "note": note,
    }, indent=2))
    return 0


def run_selftest() -> int:
    text = "nullink-inbox selftest rooms=none flags=none count=0"
    code = post_text(text)
    log(f"selftest http={code}")
    return 0 if code == 200 else 1


def main(argv: list[str]) -> int:
    if "--check" in argv:
        return run_check()
    if "--selftest" in argv:
        return run_selftest()
    return run_daemon()


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(0)
