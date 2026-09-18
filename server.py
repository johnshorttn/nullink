#!/usr/bin/env python3
"""Nullink PM — OTP auth + chat bridge + labels/files/editor on port 8766."""
from __future__ import annotations

import difflib
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import shutil
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE = Path(__file__).resolve().parent
SECRETS = BASE / "secrets"
DATA = BASE / "data"
STATIC = BASE / "static"
UPLOADS = BASE / "uploads"
VAULT = DATA / "files"
SCRATCH = BASE / "scratch"
OTP_FILE = SECRETS / "otp.json"
SESSION_SECRET_FILE = SECRETS / "session_secret.txt"
MESSAGES_FILE = DATA / "messages.jsonl"
LAST_HANDLED = DATA / ".last-handled"
LABELS_FILE = DATA / "labels.json"
FILES_FILE = DATA / "files.json"
APPS_FILE = DATA / "apps.json"
ROSTER_FILE = DATA / "roster.json"
PENDING_NOTIFY = DATA / "pending.notify"
PENDING_UPLOAD = DATA / "pending.upload"
RATE_FILE = DATA / "rate_limit.json"
TOKENS_FILE = DATA / "tokens.json"
WEBHOOK_CONFIG = SECRETS / "webhook.json"
WEBHOOK_LOG = Path("/tmp/nullink-webhook.log")
WAKE_LOG = DATA / "wake.log"
WAKE_STATE = DATA / "wake_state.json"
INBOX_DISMISSED = DATA / "inbox_dismissed.json"
SESSION_MEMORY = DATA / "session_memory"
PENDING_ASK = DATA / "pending.ask"
TASKS_FILE = DATA / "tasks.json"
VAULT_DIR = DATA / "vault"  # OTP-gated snippets (not VAULT=data/files)
WEBHOOK_TIMEOUT_SEC = 3
WEBHOOK_RETRIES = 3
WEBHOOK_BACKOFF_SEC = (0.35, 0.7, 1.4)
PRESENCE_STALE_SEC = 15 * 60

PORT = 8766
SESSION_TTL_SEC = 24 * 3600
MAX_FAILS = 5
LOCK_SEC = 15 * 60
COOKIE_NAME = "morc_session"
MAX_UPLOAD_BYTES = 50 * 1024 * 1024
MAX_PLAYGROUND_BYTES = 25 * 1024 * 1024
PLAYGROUND_DIR = BASE / "playground" / "chatgpt"
CHATGPT_PLAYGROUND_LABEL = {
    "id": "chatgpt-playground",
    "name": "ChatGPT Playground",
    "color": "#10a37f",
}

# Uploads: allow any extension (coding, Office, zip, binaries).
# Safety is path sanitization + no execute bit (0644), not an allowlist.
# TEXT_EXT only controls in-browser editor open behavior.
TEXT_EXT = {
    ".txt", ".md", ".markdown", ".csv", ".json", ".jsonl", ".yaml", ".yml",
    ".toml", ".ini", ".cfg", ".conf", ".log", ".html", ".htm", ".css", ".js",
    ".ts", ".tsx", ".jsx", ".py", ".sh", ".bash", ".zsh", ".sql", ".xml",
    ".rst", ".ps1", ".psm1", ".psd1", ".gitignore", ".dockerignore", ".svg",
    ".vb", ".vbs", ".bas", ".cls", ".frm", ".bat", ".cmd", ".ps1xml",
    ".c", ".h", ".cpp", ".hpp", ".cs", ".java", ".go", ".rs", ".rb", ".php",
    ".pl", ".pm", ".r", ".lua", ".kt", ".swift", ".m", ".mm",
    ".vue", ".svelte", ".scss", ".sass", ".less", ".tf", ".proto",
    ".gradle", ".cmake", ".make", ".mk", ".dockerfile",
}

SEED_LABELS = [
    {"id": "yms", "name": "YMS", "color": "#6ea8fe"},
    {"id": "nullink", "name": "Nullink", "color": "#8b7cf7"},
    {"id": "inbox", "name": "Inbox", "color": "#3dd68c"},
    {"id": "chatgpt-playground", "name": "ChatGPT Playground", "color": "#10a37f"},
]

SEED_APPS = {
    "apps": [
        {
            "id": "desktop",
            "title": "VPS Desktop (Guacamole)",
            "url": "/desktop/",
            "kind": "path",
            "embed": "iframe",
            "enabled": True,
            "description": "Apache Guacamole XFCE desktop via same-origin /desktop/",
        },
        {
            "id": "example-local",
            "title": "Example local app (placeholder)",
            "url": "http://127.0.0.1:9999/",
            "kind": "proxy",
            "embed": "iframe",
            "enabled": False,
            "description": "Disabled placeholder for a future loopback HTTP service.",
        },
    ],
    "frame_ancestors_note": (
        "New apps behind the Nullink proxy get CSP frame-ancestors 'self'. "
        "Path apps like /desktop/ are same-origin. External apps must allow "
        "frame-ancestors https://nullink.216.158.238.236.sslip.io 'self'."
    ),
}

PUBLIC_HOST = "nullink.216.158.238.236.sslip.io"

_lock = threading.Lock()


def ensure_dirs() -> None:
    for p in (SECRETS, DATA, STATIC, UPLOADS, VAULT, SCRATCH, SESSION_MEMORY, VAULT_DIR, UPLOADS / "inbox", PLAYGROUND_DIR, UPLOADS / "chatgpt-playground"):
        p.mkdir(parents=True, exist_ok=True)
    try:
        VAULT_DIR.chmod(0o700)
    except OSError:
        pass
    try:
        PLAYGROUND_DIR.parent.chmod(0o750)
        PLAYGROUND_DIR.chmod(0o750)
    except OSError:
        pass
    if not MESSAGES_FILE.exists():
        MESSAGES_FILE.write_text("", encoding="utf-8")
    if not SESSION_SECRET_FILE.exists():
        SESSION_SECRET_FILE.write_text(secrets.token_hex(32), encoding="utf-8")
        SESSION_SECRET_FILE.chmod(0o600)
    if not LABELS_FILE.exists():
        LABELS_FILE.write_text(json.dumps({"labels": SEED_LABELS}, indent=2), encoding="utf-8")
    if not FILES_FILE.exists():
        FILES_FILE.write_text(json.dumps({"files": []}, indent=2), encoding="utf-8")
    if not APPS_FILE.exists():
        APPS_FILE.write_text(json.dumps(SEED_APPS, indent=2) + "\n", encoding="utf-8")
    if not TOKENS_FILE.exists():
        TOKENS_FILE.write_text(json.dumps({"tokens": []}, indent=2) + "\n", encoding="utf-8")
        try:
            TOKENS_FILE.chmod(0o600)
        except OSError:
            pass
    if not TASKS_FILE.exists():
        TASKS_FILE.write_text(json.dumps({"tasks": []}, indent=2) + "\n", encoding="utf-8")
        try:
            TASKS_FILE.chmod(0o600)
        except OSError:
            pass
    if not ROSTER_FILE.exists():
        ROSTER_FILE.write_text(json.dumps({
            "categories": [
                {
                    "id": "gb-leads",
                    "title": "Gb-Leads",
                    "collapsed": False,
                    "bots": [
                        {"id": "morc", "title": "Chief of Staff (Morc)", "kind": "grokbot", "agent_id": "c92d19c1-524a-430d-8ea2-439e63a59a2f"},
                        {"id": "forge", "title": "Forge (Bob)", "kind": "grokbot", "agent_id": "d6b4babf-2f93-4300-9f9e-ca03a6037a35"},
                        {"id": "ed", "title": "Ed", "kind": "grokbot", "agent_id": "ad5ce74f-112c-4037-b663-6730307078d2"},
                        {"id": "ops", "title": "Ops", "kind": "grokbot", "agent_id": "e972635f-8858-4cdb-a555-43a03aedf2fc"},
                        {"id": "doc", "title": "Doc", "kind": "grokbot", "agent_id": "7e5dccc5-08ec-4d7b-8bac-3e3307f72d86"},
                    ],
                },
                {
                    "id": "gb-workers",
                    "title": "Gb-Workers",
                    "collapsed": False,
                    "bots": [
                        {"id": "spark", "title": "Spark", "kind": "grokbot", "agent_id": "aeb3c0a9-fd19-45d0-96b5-199927260a59"},
                        {"id": "anvil", "title": "Anvil", "kind": "grokbot", "agent_id": "b95df559-d40d-47a7-b733-3a79ccef5d87"},
                        {"id": "ra-1", "title": "RA-1", "kind": "grokbot", "agent_id": "615af781-9b08-4f0e-a9e9-14a4b4701724"},
                        {"id": "ra-2", "title": "RA-2", "kind": "grokbot", "agent_id": "4d0684d0-7597-414d-b4b9-5fedbb6cd3c3"},
                        {"id": "bugs", "title": "Bugs", "kind": "grokbot", "agent_id": "03df3063-e1d2-4b7a-af8a-af03d96fec6b"},
                    ],
                },
                {
                    "id": "third-party",
                    "title": "3rd Party",
                    "collapsed": False,
                    "bots": [],
                },
            ]
        }, indent=2) + "\n", encoding="utf-8")


def load_roster() -> dict:
    """Load sidebar roster categories; fall back to morc-only if missing."""
    default = {
        "categories": [{
            "id": "gb-leads",
            "title": "Gb-Leads",
            "collapsed": False,
            "bots": [{
                "id": "morc",
                "title": "Chief of Staff (Morc)",
                "kind": "grokbot",
                "agent_id": "c92d19c1-524a-430d-8ea2-439e63a59a2f",
            }],
        }],
        "default_session": "morc",
    }
    if not ROSTER_FILE.exists():
        return default
    try:
        data = json.loads(ROSTER_FILE.read_text(encoding="utf-8"))
        cats = data.get("categories") or []
        if not isinstance(cats, list):
            return default
        return {
            "categories": cats,
            "default_session": data.get("default_session") or "morc",
        }
    except (json.JSONDecodeError, OSError):
        return default


def flat_sessions_from_roster(roster: dict) -> list:
    out = []
    for cat in roster.get("categories") or []:
        for bot in cat.get("bots") or []:
            if isinstance(bot, dict) and bot.get("id"):
                out.append({
                    "id": bot["id"],
                    "title": bot.get("title") or bot["id"],
                    "kind": bot.get("kind"),
                    "agent_id": bot.get("agent_id"),
                    "category": cat.get("id"),
                })
    return out




def save_roster(roster: dict) -> None:
    ensure_dirs()
    with _lock:
        ROSTER_FILE.write_text(
            json.dumps(roster, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )


def ensure_chatgpt_in_roster() -> None:
    """Ensure a chatgpt session exists under 3rd Party; never remove morc."""
    roster = load_roster()
    ids = {s["id"] for s in flat_sessions_from_roster(roster)}
    if "chatgpt" in ids:
        return
    chatgpt_bot = {
        "id": "chatgpt",
        "title": "ChatGPT",
        "kind": "external",
        "url": "https://chatgpt.com/",
    }
    cats = roster.get("categories") or []
    third = None
    for cat in cats:
        if isinstance(cat, dict) and cat.get("id") in ("third-party", "3rd-party", "third_party"):
            third = cat
            break
    if third is None:
        third = {
            "id": "third-party",
            "title": "3rd Party",
            "collapsed": False,
            "bots": [],
        }
        cats.append(third)
        roster["categories"] = cats
    bots = third.get("bots")
    if not isinstance(bots, list):
        bots = []
        third["bots"] = bots
    bots.append(chatgpt_bot)
    if "morc" not in {s["id"] for s in flat_sessions_from_roster(roster)}:
        # Never drop morc — re-seed into gb-leads if somehow missing
        for cat in roster.get("categories") or []:
            if isinstance(cat, dict) and cat.get("id") == "gb-leads":
                bl = cat.get("bots")
                if not isinstance(bl, list):
                    bl = []
                    cat["bots"] = bl
                bl.insert(0, {
                    "id": "morc",
                    "title": "Chief of Staff (Morc)",
                    "kind": "grokbot",
                    "agent_id": "c92d19c1-524a-430d-8ea2-439e63a59a2f",
                })
                break
    save_roster(roster)




def ensure_chatgpt_playground_label() -> None:
    """Seed/ensure Files UI label chatgpt-playground without removing others."""
    ensure_dirs()
    labels = load_labels()
    by_id = {str(l.get("id")): l for l in labels if isinstance(l, dict)}
    want = dict(CHATGPT_PLAYGROUND_LABEL)
    if "chatgpt-playground" in by_id:
        cur = by_id["chatgpt-playground"]
        changed = False
        if cur.get("name") != want["name"]:
            cur["name"] = want["name"]
            changed = True
        if cur.get("color") != want["color"]:
            cur["color"] = want["color"]
            changed = True
        if changed:
            save_labels(labels)
    else:
        labels.append(want)
        save_labels(labels)
    # Files UI folder for cookie uploads tagged with this label
    (UPLOADS / "chatgpt-playground").mkdir(parents=True, exist_ok=True)
    PLAYGROUND_DIR.mkdir(parents=True, exist_ok=True)


def playground_safe_name(name: str) -> str | None:
    """Allow only [A-Za-z0-9._-] names; block traversal / empty / overly long."""
    raw = str(name or "").strip()
    if not raw or len(raw) > 120:
        return None
    if raw in (".", "..") or "/" in raw or "\\" in raw or chr(0) in raw:
        return None
    # basename only
    base = Path(raw).name
    if base != raw:
        return None
    if not re.fullmatch(r"[A-Za-z0-9._-]+", base):
        return None
    return base


def playground_resolve(name: str) -> Path | None:
    safe = playground_safe_name(name)
    if not safe:
        return None
    return safe_rel_under(PLAYGROUND_DIR, safe)


def list_playground_files() -> list[dict]:
    ensure_dirs()
    PLAYGROUND_DIR.mkdir(parents=True, exist_ok=True)
    out: list[dict] = []
    try:
        entries = sorted(PLAYGROUND_DIR.iterdir(), key=lambda p: p.name.lower())
    except OSError:
        return []
    for p in entries:
        if not p.is_file():
            continue
        if playground_safe_name(p.name) is None:
            continue
        try:
            st = p.stat()
        except OSError:
            continue
        out.append({
            "name": p.name,
            "size": int(st.st_size),
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(st.st_mtime)),
        })
    return out


def write_playground_file(name: str, data: bytes) -> dict:
    if len(data) > MAX_PLAYGROUND_BYTES:
        raise ValueError("too_large")
    dest = playground_resolve(name)
    if dest is None:
        raise ValueError("invalid_name")
    PLAYGROUND_DIR.mkdir(parents=True, exist_ok=True)
    # Write via temp then replace for atomicity
    tmp = dest.with_name(dest.name + ".tmp." + secrets.token_hex(4))
    try:
        tmp.write_bytes(data)
        try:
            tmp.chmod(0o644)
        except OSError:
            pass
        tmp.replace(dest)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
    st = dest.stat()
    meta = {
        "name": dest.name,
        "size": int(st.st_size),
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(st.st_mtime)),
    }
    try:
        sync_playground_to_files_registry(dest.name, meta["size"])
    except Exception:
        pass
    return meta


def delete_playground_file(name: str) -> bool:
    dest = playground_resolve(name)
    if dest is None:
        raise ValueError("invalid_name")
    if not dest.is_file():
        return False
    dest.unlink()
    try:
        remove_playground_from_files_registry(dest.name)
    except Exception:
        pass
    return True


def sync_playground_to_files_registry(name: str, size: int) -> dict:
    """Keep Files UI in sync: register sandbox file under chatgpt-playground label."""
    ensure_chatgpt_playground_label()
    safe = playground_safe_name(name)
    if not safe:
        raise ValueError("invalid_name")
    rel = f"playground/chatgpt/{safe}"
    files = load_files()
    entry = None
    for f in files:
        if not isinstance(f, dict):
            continue
        if f.get("path") == rel:
            entry = f
            break
        if f.get("name") == safe and "chatgpt-playground" in (f.get("labels") or []):
            entry = f
            break
    if entry is None:
        entry = {
            "id": uuid.uuid4().hex[:12],
            "name": safe,
            "path": rel,
            "labels": ["chatgpt-playground"],
            "size": int(size),
            "updated_at": iso_now(),
            "source": "playground",
        }
        files.insert(0, entry)
    else:
        entry["name"] = safe
        entry["path"] = rel
        entry["size"] = int(size)
        entry["updated_at"] = iso_now()
        labs = list(entry.get("labels") or [])
        if "chatgpt-playground" not in labs:
            labs.append("chatgpt-playground")
            entry["labels"] = labs
        if not entry.get("source"):
            entry["source"] = "playground"
    save_files(files)
    return entry


def remove_playground_from_files_registry(name: str) -> None:
    safe = playground_safe_name(name)
    if not safe:
        return
    rel = f"playground/chatgpt/{safe}"
    files = load_files()
    new_files = []
    for f in files:
        if not isinstance(f, dict):
            continue
        if f.get("path") == rel:
            continue
        if f.get("name") == safe and "chatgpt-playground" in (f.get("labels") or []) and str(f.get("path") or "").startswith("playground/"):
            continue
        new_files.append(f)
    if len(new_files) != len(files):
        save_files(new_files)


def upload_dest_for_labels(labels: list[str]) -> Path:
    """Route chatgpt-playground uploads into the VPS sandbox dir."""
    if "chatgpt-playground" in {str(x) for x in labels}:
        PLAYGROUND_DIR.mkdir(parents=True, exist_ok=True)
        return PLAYGROUND_DIR
    folder = label_folder(labels)
    dest_dir = UPLOADS / folder
    dest_dir.mkdir(parents=True, exist_ok=True)
    return dest_dir


def known_bot_ids() -> set[str]:
    ids = {s["id"] for s in flat_sessions_from_roster(load_roster())}
    ids.add("morc")
    return ids


def _safe_bot_id(bot_id: str) -> str | None:
    bid = str(bot_id or "").strip()
    if not bid or len(bid) > 64:
        return None
    if not re.fullmatch(r"[A-Za-z0-9_-]+", bid):
        return None
    return bid


def _default_session_memory(bot_id: str) -> dict:
    return {
        "bot_id": bot_id,
        "goal": "",
        "last_decision": "",
        "blockers": "",
        "notes": "",
        "updated_at": None,
    }


def load_session_memory(bot_id: str) -> dict:
    ensure_dirs()
    bid = _safe_bot_id(bot_id)
    if not bid:
        return _default_session_memory(str(bot_id or ""))
    fp = SESSION_MEMORY / f"{bid}.json"
    with _lock:
        if not fp.exists():
            return _default_session_memory(bid)
        try:
            data = json.loads(fp.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return _default_session_memory(bid)
            base = _default_session_memory(bid)
            for k in ("goal", "last_decision", "blockers", "notes", "updated_at"):
                if k in data:
                    base[k] = data[k]
            base["bot_id"] = bid
            return base
        except (OSError, json.JSONDecodeError):
            return _default_session_memory(bid)


def save_session_memory(bot_id: str, data: dict) -> dict:
    ensure_dirs()
    bid = _safe_bot_id(bot_id)
    if not bid:
        raise ValueError("bad_bot_id")
    out = _default_session_memory(bid)
    for k in ("goal", "last_decision", "blockers", "notes"):
        if k in data and data[k] is not None:
            out[k] = str(data[k])[:4000]
    out["updated_at"] = iso_now()
    fp = SESSION_MEMORY / f"{bid}.json"
    with _lock:
        fp.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        try:
            fp.chmod(0o644)
        except OSError:
            pass
    return out


def load_tasks() -> list[dict]:
    ensure_dirs()
    with _lock:
        if not TASKS_FILE.exists():
            return []
        try:
            data = json.loads(TASKS_FILE.read_text(encoding="utf-8"))
            tasks = data.get("tasks") if isinstance(data, dict) else data
            if not isinstance(tasks, list):
                return []
            return [t for t in tasks if isinstance(t, dict)]
        except (OSError, json.JSONDecodeError):
            return []


def save_tasks(tasks: list[dict]) -> None:
    ensure_dirs()
    with _lock:
        TASKS_FILE.write_text(
            json.dumps({"tasks": tasks}, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        try:
            TASKS_FILE.chmod(0o600)
        except OSError:
            pass


def create_task(
    title: str,
    body: str = "",
    label_id: str | None = None,
    source: str = "selection",
    status: str = "open",
) -> dict:
    title = (title or "").strip() or (body or "").strip()[:80] or "Untitled task"
    body = body if isinstance(body, str) else str(body or "")
    tid = uuid.uuid4().hex[:12]
    now = iso_now()
    entry = {
        "id": tid,
        "title": title[:200],
        "body": body[:8000],
        "label_id": (str(label_id).strip() if label_id else None) or None,
        "source": str(source or "selection")[:40],
        "status": "done" if status == "done" else "open",
        "created_at": now,
        "updated_at": now,
    }
    tasks = load_tasks()
    tasks.insert(0, entry)
    save_tasks(tasks)
    return entry


def update_task(tid: str, patch: dict) -> dict | None:
    tasks = load_tasks()
    found = None
    for t in tasks:
        if t.get("id") == tid:
            found = t
            break
    if not found:
        return None
    if "title" in patch and patch["title"] is not None:
        found["title"] = str(patch["title"]).strip()[:200] or found["title"]
    if "body" in patch and patch["body"] is not None:
        found["body"] = str(patch["body"])[:8000]
    if "label_id" in patch:
        lid = patch["label_id"]
        found["label_id"] = (str(lid).strip() if lid else None) or None
    if "status" in patch and patch["status"] is not None:
        st = str(patch["status"]).strip().lower()
        found["status"] = "done" if st in ("done", "handled", "closed") else "open"
    found["updated_at"] = iso_now()
    save_tasks(tasks)
    return found


def delete_task(tid: str) -> bool:
    tasks = load_tasks()
    new_tasks = [t for t in tasks if t.get("id") != tid]
    if len(new_tasks) == len(tasks):
        return False
    save_tasks(new_tasks)
    return True


def _vault_safe_id(vid: str) -> str | None:
    vid = str(vid or "").strip()
    if not vid or len(vid) > 64:
        return None
    if not re.fullmatch(r"[A-Za-z0-9_-]+", vid):
        return None
    return vid


def _vault_path(vid: str) -> Path | None:
    safe = _vault_safe_id(vid)
    if not safe:
        return None
    return VAULT_DIR / f"{safe}.json"


def _normalize_vault_tags(tags) -> list[str]:
    if not isinstance(tags, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for t in tags:
        s = str(t or "").strip()[:40]
        if not s:
            continue
        key = s.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
        if len(out) >= 24:
            break
    return out


def load_vault_snippet(vid: str) -> dict | None:
    ensure_dirs()
    fp = _vault_path(vid)
    if not fp or not fp.exists():
        return None
    try:
        data = json.loads(fp.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return None
        return {
            "id": str(data.get("id") or vid),
            "title": str(data.get("title") or ""),
            "body": str(data.get("body") or ""),
            "tags": _normalize_vault_tags(data.get("tags")),
            "created_at": data.get("created_at"),
            "updated_at": data.get("updated_at"),
        }
    except (OSError, json.JSONDecodeError):
        return None


def list_vault_snippets(query: str | None = None) -> list[dict]:
    ensure_dirs()
    q = (query or "").strip().lower()
    items: list[dict] = []
    try:
        for fp in sorted(VAULT_DIR.glob("*.json")):
            try:
                data = json.loads(fp.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(data, dict):
                continue
            item = {
                "id": str(data.get("id") or fp.stem),
                "title": str(data.get("title") or ""),
                "body": str(data.get("body") or ""),
                "tags": _normalize_vault_tags(data.get("tags")),
                "created_at": data.get("created_at"),
                "updated_at": data.get("updated_at"),
            }
            if q:
                blob = " ".join([
                    item["title"],
                    item["body"],
                    " ".join(item["tags"]),
                ]).lower()
                if q not in blob:
                    continue
            # list view: truncate body for payload size
            preview = item["body"]
            items.append({
                **item,
                "body": preview[:400],
                "body_len": len(preview),
            })
    except OSError:
        pass
    items.sort(key=lambda x: str(x.get("updated_at") or ""), reverse=True)
    return items


def save_vault_snippet(entry: dict) -> dict:
    ensure_dirs()
    vid = _vault_safe_id(str(entry.get("id") or "")) or uuid.uuid4().hex[:12]
    now = iso_now()
    out = {
        "id": vid,
        "title": str(entry.get("title") or "").strip()[:200] or "Untitled",
        "body": str(entry.get("body") or "")[:100_000],
        "tags": _normalize_vault_tags(entry.get("tags")),
        "created_at": entry.get("created_at") or now,
        "updated_at": now,
    }
    fp = VAULT_DIR / f"{vid}.json"
    with _lock:
        fp.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        try:
            fp.chmod(0o600)
        except OSError:
            pass
        try:
            VAULT_DIR.chmod(0o700)
        except OSError:
            pass
    return out


def delete_vault_snippet(vid: str) -> bool:
    fp = _vault_path(vid)
    if not fp or not fp.exists():
        return False
    try:
        fp.unlink()
        return True
    except OSError:
        return False


def create_labeled_paste(text: str, label_id: str, name: str | None = None) -> dict:
    """Attach selected text to a label as a small text file in the PM registry."""
    ensure_dirs()
    labels = {l["id"]: l for l in load_labels()}
    if label_id not in labels:
        raise ValueError("unknown_label")
    body = text if isinstance(text, str) else str(text or "")
    if not body.strip():
        raise ValueError("empty")
    fid = uuid.uuid4().hex[:12]
    safe = slugify(name or f"paste-{fid[:6]}.txt")
    if not safe.lower().endswith((".txt", ".md")):
        safe = safe + ".txt"
    folder = label_folder([label_id])
    dest_dir = UPLOADS / folder
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / safe
    # avoid overwrite
    if dest.exists():
        dest = dest_dir / f"{dest.stem}-{fid[:4]}{dest.suffix}"
    dest.write_text(body, encoding="utf-8")
    try:
        dest.chmod(0o644)
    except OSError:
        pass
    entry = {
        "id": fid,
        "name": dest.name,
        "path": str(dest.relative_to(BASE)),
        "labels": [label_id],
        "size": dest.stat().st_size,
        "updated_at": iso_now(),
        "source": "paste",
    }
    files = load_files()
    files.insert(0, entry)
    save_files(files)
    return entry


def scratch_base_content(meta: dict) -> tuple[str, str | None, str]:
    """Return (base_text, file_id_or_None, base_label) for diff vs vault/saved."""
    fid = str(meta.get("file_id") or "").strip() or None
    name = str(meta.get("name") or "scratch.txt")
    if fid:
        entry = next((f for f in load_files() if f["id"] == fid), None)
        if entry:
            fp = resolve_file_path(entry)
            if fp and is_text_file(entry.get("name") or fp.name):
                try:
                    return fp.read_text(encoding="utf-8", errors="replace"), fid, entry.get("path") or name
                except OSError:
                    pass
            return "", fid, entry.get("path") or name
    return "", None, f"(new) {name}"


def build_unified_diff(base: str, scratch: str, fromfile: str, tofile: str) -> str:
    diff = difflib.unified_diff(
        base.splitlines(keepends=True),
        scratch.splitlines(keepends=True),
        fromfile=fromfile,
        tofile=tofile,
        lineterm="\n",
    )
    return "".join(diff)


def session_secret() -> bytes:
    return SESSION_SECRET_FILE.read_text(encoding="utf-8").strip().encode()


def hash_pin(pin: str, salt: str) -> str:
    return hashlib.sha256((salt + pin).encode()).hexdigest()


def load_otp() -> dict | None:
    if not OTP_FILE.exists():
        return None
    try:
        return json.loads(OTP_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def load_rate() -> dict:
    if not RATE_FILE.exists():
        return {"fails": 0, "locked_until": 0}
    try:
        return json.loads(RATE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"fails": 0, "locked_until": 0}


def save_rate(data: dict) -> None:
    RATE_FILE.write_text(json.dumps(data), encoding="utf-8")


def sign_session(exp: int) -> str:
    payload = f"ok:{exp}"
    sig = hmac.new(session_secret(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def verify_session(token: str | None) -> bool:
    if not token:
        return False
    try:
        payload, sig = token.rsplit(".", 1)
        expect = hmac.new(session_secret(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expect, sig):
            return False
        kind, exp_s = payload.split(":", 1)
        if kind != "ok":
            return False
        return int(exp_s) >= int(time.time())
    except (ValueError, TypeError):
        return False




# ---------- Scoped Bearer tokens (agent auth) ----------
AGENT_SCOPES = (
    "health:read",
    "sessions:read",
    "messages:read",
    "messages:write",
    "ping:read",
)
ADMIN_SCOPES = (
    "tokens:manage",
    "sessions:manage",
)
ALL_SCOPES = set(AGENT_SCOPES) | set(ADMIN_SCOPES)
DEFAULT_TOKEN_TTL_SEC = 30 * 24 * 3600  # 30 days


def _hash_bearer_token(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def load_tokens() -> list[dict]:
    ensure_dirs()
    with _lock:
        if not TOKENS_FILE.exists():
            return []
        try:
            data = json.loads(TOKENS_FILE.read_text(encoding="utf-8"))
            tokens = data.get("tokens") if isinstance(data, dict) else data
            if not isinstance(tokens, list):
                return []
            return [t for t in tokens if isinstance(t, dict)]
        except (json.JSONDecodeError, OSError):
            return []


def save_tokens(tokens: list[dict]) -> None:
    ensure_dirs()
    with _lock:
        TOKENS_FILE.write_text(
            json.dumps({"tokens": tokens}, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        try:
            TOKENS_FILE.chmod(0o600)
        except OSError:
            pass


def _iso_from_ts(ts: float | None) -> str | None:
    if ts is None:
        return None
    try:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(ts)))
    except (TypeError, ValueError, OSError):
        return None


def create_api_token(
    name: str,
    scopes: list[str],
    sessions: list[str],
    expires_in: int | None = None,
) -> tuple[dict, str]:
    """Create token record + plaintext. Returns (metadata_record, plaintext)."""
    ttl = DEFAULT_TOKEN_TTL_SEC if expires_in is None else int(expires_in)
    if ttl < 60:
        ttl = 60
    plaintext = "nlk_" + secrets.token_urlsafe(32)
    now = time.time()
    record = {
        "id": secrets.token_hex(8),
        "token_hash": _hash_bearer_token(plaintext),
        "token_prefix": plaintext[:12],
        "name": name,
        "scopes": scopes,
        "sessions": sessions,
        "created_at": now,
        "expires_at": now + ttl,
        "revoked_at": None,
        "last_used_at": None,
    }
    ensure_dirs()
    with _lock:
        tokens: list[dict] = []
        if TOKENS_FILE.exists():
            try:
                data = json.loads(TOKENS_FILE.read_text(encoding="utf-8"))
                raw = data.get("tokens") if isinstance(data, dict) else data
                if isinstance(raw, list):
                    tokens = [t for t in raw if isinstance(t, dict)]
            except (json.JSONDecodeError, OSError):
                tokens = []
        tokens.append(record)
        TOKENS_FILE.write_text(
            json.dumps({"tokens": tokens}, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        try:
            TOKENS_FILE.chmod(0o600)
        except OSError:
            pass
    return record, plaintext


def lookup_bearer_token(plaintext: str) -> dict | None:
    if not plaintext or not plaintext.startswith("nlk_"):
        return None
    th = _hash_bearer_token(plaintext)
    now = time.time()
    for rec in load_tokens():
        if rec.get("token_hash") != th:
            continue
        if rec.get("revoked_at"):
            return None
        exp = rec.get("expires_at")
        if exp is not None and float(exp) < now:
            return None
        return rec
    return None


def touch_token_last_used(token_id: str) -> None:
    if not token_id:
        return
    ensure_dirs()
    with _lock:
        if not TOKENS_FILE.exists():
            return
        try:
            data = json.loads(TOKENS_FILE.read_text(encoding="utf-8"))
            tokens = data.get("tokens") if isinstance(data, dict) else data
            if not isinstance(tokens, list):
                return
        except (json.JSONDecodeError, OSError):
            return
        changed = False
        now = time.time()
        for rec in tokens:
            if isinstance(rec, dict) and rec.get("id") == token_id:
                rec["last_used_at"] = now
                changed = True
                break
        if changed:
            TOKENS_FILE.write_text(
                json.dumps({"tokens": tokens}, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )


def revoke_api_token(token_id: str) -> dict | None:
    ensure_dirs()
    with _lock:
        if not TOKENS_FILE.exists():
            return None
        try:
            data = json.loads(TOKENS_FILE.read_text(encoding="utf-8"))
            tokens = data.get("tokens") if isinstance(data, dict) else data
            if not isinstance(tokens, list):
                return None
        except (json.JSONDecodeError, OSError):
            return None
        found = None
        for rec in tokens:
            if isinstance(rec, dict) and rec.get("id") == token_id:
                if not rec.get("revoked_at"):
                    rec["revoked_at"] = time.time()
                found = rec
                break
        if found is not None:
            TOKENS_FILE.write_text(
                json.dumps({"tokens": tokens}, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
        return found


def token_public_view(rec: dict) -> dict:
    return {
        "id": rec.get("id"),
        "name": rec.get("name"),
        "scopes": list(rec.get("scopes") or []),
        "sessions": list(rec.get("sessions") or []),
        "token_prefix": rec.get("token_prefix"),
        "created_at": _iso_from_ts(rec.get("created_at")),
        "expires_at": _iso_from_ts(rec.get("expires_at")),
        "revoked": bool(rec.get("revoked_at")),
        "revoked_at": _iso_from_ts(rec.get("revoked_at")),
        "last_used_at": _iso_from_ts(rec.get("last_used_at")),
    }


def ping_has_change_for_sessions(allowed: list[str] | None) -> tuple[bool, list[str]]:
    """Like ping_has_change, but when allowed is set, only surface message changes
    for those session IDs (no global notify/ask/upload/scratch leakage)."""
    if allowed is None:
        return ping_has_change()
    allowed_set = set(allowed)
    reasons: list[str] = []
    try:
        last_ts = ""
        if LAST_HANDLED.exists():
            last_ts = LAST_HANDLED.read_text(encoding="utf-8").strip()
        newest = None
        if MESSAGES_FILE.exists():
            for ln in MESSAGES_FILE.read_text(encoding="utf-8", errors="replace").splitlines():
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    d = json.loads(ln)
                except json.JSONDecodeError:
                    continue
                if not isinstance(d, dict):
                    continue
                sid = str(d.get("session_id") or "morc")
                if sid not in allowed_set:
                    continue
                if d.get("role") == "user":
                    newest = d
        if newest is not None:
            src = str(newest.get("source") or "").lower()
            if src not in ("mirror", "grok-bot", "grokbot"):
                ts = str(newest.get("ts") or "")
                if not last_ts or (ts and ts > last_ts):
                    reasons.append("message")
    except OSError:
        pass
    return (bool(reasons), reasons)



def parse_multipart(body: bytes, content_type: str) -> dict:
    """Minimal multipart/form-data parser.

    Returns {name: {filename?, data|value}} for fields, except file fields
    (parts with a filename=) are always a list under that name so multi-upload works.
    """
    m = re.search(r'boundary=([^;\s]+)', content_type, re.I)
    if not m:
        raise ValueError("no boundary")
    boundary = m.group(1).strip().strip('"').encode()
    parts = body.split(b"--" + boundary)
    out: dict = {}
    for part in parts:
        if not part or part in (b"--", b"--\r\n", b"\r\n"):
            continue
        if part.startswith(b"--"):
            continue
        if part.startswith(b"\r\n"):
            part = part[2:]
        if part.endswith(b"\r\n"):
            part = part[:-2]
        header_blob, _, content = part.partition(b"\r\n\r\n")
        if not _:
            continue
        headers = header_blob.decode("utf-8", errors="replace")
        name_m = re.search(r'name="([^"]+)"', headers)
        if not name_m:
            continue
        name = name_m.group(1)
        fn_m = re.search(r'filename="([^"]*)"', headers)
        if fn_m is not None:
            item = {"filename": fn_m.group(1), "data": content}
            bucket = out.get(name)
            if bucket is None:
                out[name] = [item]
            elif isinstance(bucket, list):
                bucket.append(item)
            else:
                out[name] = [bucket, item]
        else:
            out[name] = {"value": content.decode("utf-8", errors="replace")}
    return out


def iso_now() -> str:
    now = time.strftime("%Y-%m-%dT%H:%M:%S") + time.strftime("%z")
    if len(now) >= 5 and now[-5] in "+-" and ":" not in now[-5:]:
        now = now[:-2] + ":" + now[-2:]
    return now


def read_messages(after_id: int = 0) -> list[dict]:
    out = []
    if not MESSAGES_FILE.exists():
        return out
    with MESSAGES_FILE.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if not line or i <= after_id:
                continue
            try:
                msg = json.loads(line)
                msg["id"] = i
                out.append(msg)
            except json.JSONDecodeError:
                continue
    return out


def append_message(role: str, text: str, session_id: str = "morc") -> dict:
    msg = {
        "role": role,
        "text": text,
        "ts": iso_now(),
        "session_id": session_id,
    }
    with _lock:
        with MESSAGES_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(msg, ensure_ascii=False) + "\n")
        with MESSAGES_FILE.open("r", encoding="utf-8") as f:
            mid = sum(1 for _ in f)
    msg["id"] = mid
    return msg


def is_localhost(handler: BaseHTTPRequestHandler) -> bool:
    host = handler.client_address[0]
    return host in ("127.0.0.1", "::1", "localhost")


def load_apps_config() -> dict:
    ensure_dirs()
    with _lock:
        try:
            data = json.loads(APPS_FILE.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return dict(SEED_APPS)
            apps = data.get("apps") or []
            if not isinstance(apps, list):
                apps = []
            return {
                "apps": apps,
                "frame_ancestors_note": data.get("frame_ancestors_note")
                    or SEED_APPS.get("frame_ancestors_note"),
            }
        except (json.JSONDecodeError, OSError):
            return dict(SEED_APPS)


def get_app_by_id(app_id: str) -> dict | None:
    for app in load_apps_config().get("apps") or []:
        if isinstance(app, dict) and app.get("id") == app_id:
            return app
    return None


def validate_app_target_url(url: str) -> tuple[str, str] | None:
    """Return (kind, normalized_url) or None if not allowlisted-safe.

    kind is 'path' for same-origin absolute paths, or 'loopback' for http://127.0.0.1|localhost.
    Also accepts https://PUBLIC_HOST/... paths (normalized to path-only).
    """
    raw = (url or "").strip()
    if not raw:
        return None
    if raw.startswith("/") and not raw.startswith("//"):
        # path-only same origin
        if ".." in raw or chr(92) in raw:
            return None
        return ("path", raw)

    parsed = urllib.parse.urlparse(raw)
    host = (parsed.hostname or "").lower()
    if parsed.scheme == "https" and host == PUBLIC_HOST:
        path = parsed.path or "/"
        if ".." in path:
            return None
        return ("path", path + (("?" + parsed.query) if parsed.query else ""))

    if parsed.scheme != "http":
        return None
    if host not in ("127.0.0.1", "localhost"):
        return None
    # Reject anything that isn't plain loopback (no userinfo tricks)
    if parsed.username or parsed.password:
        return None
    port = parsed.port
    netloc = "127.0.0.1" + (f":{port}" if port else "")
    path = parsed.path or "/"
    if ".." in path:
        return None
    normalized = f"http://{netloc}{path}"
    if parsed.query:
        normalized += "?" + parsed.query
    return ("loopback", normalized)


def public_app_view(app: dict) -> dict:
    """Sanitize app entry for API clients."""
    enabled = bool(app.get("enabled", True))
    url = str(app.get("url") or "")
    validated = validate_app_target_url(url)
    kind = app.get("kind") or (validated[0] if validated else "invalid")
    out = {
        "id": app.get("id"),
        "title": app.get("title") or app.get("id"),
        "description": app.get("description") or "",
        "enabled": enabled,
        "embed": app.get("embed") or "iframe",
        "kind": kind,
        "valid": validated is not None,
    }
    if not enabled or validated is None:
        out["embed_url"] = None
        return out
    vkind, vurl = validated
    if vkind == "path":
        out["embed_url"] = vurl
    else:
        # Proxied loopback target
        out["embed_url"] = f"/api/apps/proxy/{urllib.parse.quote(str(app['id']), safe='')}/"
    return out



def load_labels() -> list[dict]:
    with _lock:
        try:
            data = json.loads(LABELS_FILE.read_text(encoding="utf-8"))
            return list(data.get("labels") or [])
        except (json.JSONDecodeError, OSError):
            return list(SEED_LABELS)


def save_labels(labels: list[dict]) -> None:
    with _lock:
        LABELS_FILE.write_text(json.dumps({"labels": labels}, indent=2), encoding="utf-8")


def load_files() -> list[dict]:
    with _lock:
        try:
            data = json.loads(FILES_FILE.read_text(encoding="utf-8"))
            return list(data.get("files") or [])
        except (json.JSONDecodeError, OSError):
            return []


def save_files(files: list[dict]) -> None:
    with _lock:
        FILES_FILE.write_text(json.dumps({"files": files}, indent=2), encoding="utf-8")


def slugify(name: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9._-]+", "-", name.strip()).strip("-._")
    return (s or "file")[:120]


def safe_rel_under(base: Path, rel: str) -> Path | None:
    """Resolve rel under base; reject path escape."""
    try:
        target = (base / rel).resolve()
        base_r = base.resolve()
        if not str(target).startswith(str(base_r) + os.sep) and target != base_r:
            return None
        return target
    except OSError:
        return None


def resolve_file_path(entry: dict) -> Path | None:
    rel = entry.get("path") or ""
    p = safe_rel_under(BASE, rel)
    return p if p and p.is_file() else None


def is_text_file(name: str) -> bool:
    lower = name.lower()
    for ext in TEXT_EXT:
        if lower.endswith(ext):
            return True
    # no extension → treat as text if small later
    if "." not in Path(name).name:
        return True
    return False


def allowed_upload_name(name: str) -> bool:
    """Accept any filename; reject empty / traversal-only names. Basenamed on save."""
    if not name or not str(name).strip():
        return False
    if chr(0) in str(name):
        return False
    stem = Path(str(name)).name
    if not stem or stem in (".", ".."):
        return False
    return True


def write_pending(kind: str, payload: dict) -> None:
    path = PENDING_UPLOAD if kind == "upload" else PENDING_NOTIFY
    try:
        data = dict(payload)
        data["kind"] = kind
        data["ts"] = time.time()
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        # also mirror ask/upload into notify so existing Morc watchers fire
        if kind != "notify" and path != PENDING_NOTIFY:
            PENDING_NOTIFY.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass


def _webhook_log(message: str) -> None:
    line = f"{iso_now()} {message}\n"
    for dest in (WEBHOOK_LOG, WAKE_LOG):
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            with dest.open("a", encoding="utf-8") as log:
                log.write(line)
        except OSError:
            pass


def _default_wake_state() -> dict:
    return {
        "last_success_ts": None,
        "last_fail_ts": None,
        "last_error": None,
        "consecutive_failures": 0,
        "last_kind": None,
        "last_attempt_ts": None,
        "failures": [],
    }


def load_wake_state() -> dict:
    ensure_dirs()
    with _lock:
        if not WAKE_STATE.exists():
            return _default_wake_state()
        try:
            data = json.loads(WAKE_STATE.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return _default_wake_state()
            base = _default_wake_state()
            base.update(data)
            if not isinstance(base.get("failures"), list):
                base["failures"] = []
            return base
        except (OSError, json.JSONDecodeError):
            return _default_wake_state()


def save_wake_state(state: dict) -> None:
    ensure_dirs()
    with _lock:
        try:
            WAKE_STATE.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
            try:
                WAKE_STATE.chmod(0o644)
            except OSError:
                pass
        except OSError:
            pass


def _record_wake_success(kind: str) -> None:
    state = load_wake_state()
    now = iso_now()
    state["last_success_ts"] = now
    state["last_attempt_ts"] = now
    state["last_kind"] = kind
    state["consecutive_failures"] = 0
    state["last_error"] = None
    save_wake_state(state)
    _webhook_log(f"POST ok kind={kind}")


def _record_wake_failure(kind: str, error: str) -> None:
    state = load_wake_state()
    now = iso_now()
    state["last_fail_ts"] = now
    state["last_attempt_ts"] = now
    state["last_kind"] = kind
    state["last_error"] = str(error)[:400]
    state["consecutive_failures"] = int(state.get("consecutive_failures") or 0) + 1
    failures = list(state.get("failures") or [])
    failures.append({
        "id": f"wake-{uuid.uuid4().hex[:10]}",
        "ts": now,
        "kind": kind,
        "error": str(error)[:400],
    })
    state["failures"] = failures[-20:]
    save_wake_state(state)
    _webhook_log(f"POST failed kind={kind}: {error}")


def _parse_iso_ts(value: str | None) -> float | None:
    if not value or not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    try:
        # support ...+00:00 and ...Z
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        # fromisoformat handles offsets with colon
        from datetime import datetime
        return datetime.fromisoformat(s).timestamp()
    except Exception:
        return None



def ping_has_change() -> tuple[bool, list[str]]:
    """Cheap change detector for Morc box watcher. No auth required at /api/ping."""
    reasons: list[str] = []
    for name, p in (
        ("notify", PENDING_NOTIFY),
        ("ask", PENDING_ASK),
        ("upload", PENDING_UPLOAD),
    ):
        try:
            if p.exists() and p.stat().st_size > 0:
                reasons.append(name)
        except OSError:
            pass

    # User messages after .last-handled (same spirit as GitHub wake watcher)
    try:
        last_ts = ""
        if LAST_HANDLED.exists():
            last_ts = LAST_HANDLED.read_text(encoding="utf-8").strip()
        newest = None
        if MESSAGES_FILE.exists():
            for ln in MESSAGES_FILE.read_text(encoding="utf-8", errors="replace").splitlines():
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    d = json.loads(ln)
                except json.JSONDecodeError:
                    continue
                if not isinstance(d, dict):
                    continue
                if d.get("role") == "user":
                    newest = d
        if newest is not None:
            src = str(newest.get("source") or "").lower()
            if src not in ("mirror", "grok-bot", "grokbot"):
                ts = str(newest.get("ts") or "")
                if not last_ts or (ts and ts > last_ts):
                    reasons.append("message")
    except OSError:
        pass

    # Scratch: unanswered Ask Morc + awaiting Accept
    try:
        for meta_path in SCRATCH.glob("*-meta.json"):
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(meta, dict):
                continue
            if meta.get("pending") is True:
                reasons.append("scratch_ask")
                break
            if (meta.get("reviewed_by") or meta.get("reviewed_at")) and not meta.get("accepted_at"):
                reasons.append("scratch_accept")
                break
    except OSError:
        pass

    # Dedupe while preserving order
    seen: set[str] = set()
    ordered: list[str] = []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            ordered.append(r)
    return (len(ordered) > 0, ordered)


def pending_queue_depth() -> int:
    n = 0
    for p in (PENDING_NOTIFY, PENDING_ASK, PENDING_UPLOAD):
        try:
            if p.exists() and p.stat().st_size > 0:
                n += 1
        except OSError:
            pass
    return n


def build_presence() -> dict:
    state = load_wake_state()
    queue = pending_queue_depth()
    last_ok = state.get("last_success_ts")
    last_fail = state.get("last_fail_ts")
    streak = int(state.get("consecutive_failures") or 0)
    last_err = state.get("last_error")
    ok_ts = _parse_iso_ts(last_ok)
    fail_ts = _parse_iso_ts(last_fail)
    now = time.time()
    stale = ok_ts is None or (now - ok_ts) > PRESENCE_STALE_SEC
    recent_fail = fail_ts is not None and (ok_ts is None or fail_ts >= ok_ts)

    if streak >= 3 and recent_fail:
        status = "offline"
        detail = f"Wake failing ({streak}x)" + (f": {last_err}" if last_err else "")
    elif ok_ts is None and fail_ts is None:
        status = "offline" if queue == 0 else "degraded"
        detail = "No wake attempts yet" if queue == 0 else f"Queue depth {queue}; no successful wake yet"
    elif streak > 0 and recent_fail:
        status = "degraded"
        detail = f"Last wake failed" + (f": {last_err}" if last_err else "")
    elif queue > 0:
        status = "degraded"
        detail = f"Pending queue depth {queue}"
    elif stale:
        status = "degraded"
        detail = "Last wake is stale"
    else:
        status = "online"
        detail = "Webhook wake healthy"

    return {
        "status": status,
        "last_wake_ts": last_ok,
        "queue_depth": queue,
        "detail": detail,
        "last_fail_ts": last_fail,
        "consecutive_failures": streak,
    }


def load_inbox_dismissed() -> set[str]:
    ensure_dirs()
    with _lock:
        if not INBOX_DISMISSED.exists():
            return set()
        try:
            data = json.loads(INBOX_DISMISSED.read_text(encoding="utf-8"))
            ids = data.get("ids") if isinstance(data, dict) else data
            if isinstance(ids, list):
                return {str(x) for x in ids}
        except (OSError, json.JSONDecodeError):
            pass
    return set()


def save_inbox_dismissed(ids: set[str]) -> None:
    ensure_dirs()
    with _lock:
        try:
            # keep newest 200
            ordered = list(ids)[-200:]
            INBOX_DISMISSED.write_text(
                json.dumps({"ids": ordered}, indent=2),
                encoding="utf-8",
            )
        except OSError:
            pass


def _read_pending_json(path: Path) -> dict | None:
    try:
        if not path.exists() or path.stat().st_size <= 0:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def _ts_to_iso(value) -> str:
    if isinstance(value, (int, float)):
        try:
            return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(float(value))) + time.strftime("%z")[:3] + ":" + time.strftime("%z")[3:]
        except (OverflowError, OSError, ValueError):
            return iso_now()
    if isinstance(value, str) and value.strip():
        return value.strip()
    return iso_now()


def build_inbox_items() -> list[dict]:
    dismissed = load_inbox_dismissed()
    items: list[dict] = []
    seen_scratch: set[str] = set()

    def add(item: dict) -> None:
        iid = str(item.get("id") or "")
        if not iid or iid in dismissed:
            return
        items.append(item)

    for kind, path in (
        ("pending.notify", PENDING_NOTIFY),
        ("pending.ask", PENDING_ASK),
        ("pending.upload", PENDING_UPLOAD),
    ):
        data = _read_pending_json(path)
        if not data:
            continue
        # Skip notify mirror when a more specific pending.* already carries the ask/upload
        if kind == "pending.notify":
            inner = str(data.get("kind") or "")
            if inner in ("ask-morc", "ask", "upload") and (
                (inner in ("ask-morc", "ask") and PENDING_ASK.exists())
                or (inner == "upload" and PENDING_UPLOAD.exists())
            ):
                continue
        preview = str(data.get("preview") or data.get("message") or data.get("name") or kind)
        sid = str(data.get("scratch_id") or "")
        if sid:
            seen_scratch.add(sid)
        href = "#chat"
        if kind == "pending.upload" and data.get("file_id"):
            href = f"#files/{data.get('file_id')}"
        elif sid:
            href = f"#scratch/{sid}"
        elif data.get("file_id"):
            href = f"#files/{data.get('file_id')}"
        add({
            "id": f"{kind}:{path.name}",
            "kind": kind,
            "title": preview[:160],
            "ts": _ts_to_iso(data.get("ts")),
            "session_id": "morc",
            "href": href,
            "scratch_id": sid or None,
            "file_id": data.get("file_id"),
        })

    # Scratch: unanswered Ask Morc (pending=true) + awaiting Accept (reviewed, not accepted)
    try:
        for meta_path in sorted(SCRATCH.glob("*-meta.json")):
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(meta, dict):
                continue
            sid = str(meta.get("scratch_id") or meta_path.name.replace("-meta.json", ""))
            name = str(meta.get("name") or sid)
            if meta.get("pending") is True:
                if sid in seen_scratch:
                    continue
                seen_scratch.add(sid)
                add({
                    "id": f"unanswered_ask:{sid}",
                    "kind": "unanswered_ask",
                    "title": f"Ask Morc awaiting reply · {name}",
                    "ts": str(meta.get("updated_at") or iso_now()),
                    "session_id": "morc",
                    "href": f"#scratch/{sid}",
                    "scratch_id": sid,
                    "file_id": meta.get("file_id"),
                })
            elif (meta.get("reviewed_by") or meta.get("reviewed_at")) and not meta.get("accepted_at"):
                add({
                    "id": f"scratch_accept:{sid}",
                    "kind": "scratch_accept",
                    "title": f"Scratch awaiting Accept · {name}",
                    "ts": str(meta.get("reviewed_at") or meta.get("updated_at") or iso_now()),
                    "session_id": "morc",
                    "href": f"#scratch/{sid}",
                    "scratch_id": sid,
                    "file_id": meta.get("file_id"),
                })
    except OSError:
        pass

    # Wake failures (unacknowledged)
    state = load_wake_state()
    for fail in list(state.get("failures") or [])[-5:]:
        if not isinstance(fail, dict):
            continue
        fid = str(fail.get("id") or "")
        if not fid:
            continue
        err = str(fail.get("error") or "wake failed")
        add({
            "id": f"wake_failure:{fid}",
            "kind": "wake_failure",
            "title": f"Wake failure · {err[:120]}",
            "ts": str(fail.get("ts") or iso_now()),
            "session_id": "morc",
            "href": "#presence",
        })

    # Open tasks from quick-paste (F3)
    for t in load_tasks():
        if str(t.get("status") or "open") != "open":
            continue
        tid = str(t.get("id") or "")
        if not tid:
            continue
        title = str(t.get("title") or t.get("body") or "Task")[:160]
        add({
            "id": f"task:{tid}",
            "kind": "task",
            "title": title,
            "ts": str(t.get("updated_at") or t.get("created_at") or iso_now()),
            "session_id": "morc",
            "href": f"#task/{tid}",
            "task_id": tid,
            "label_id": t.get("label_id"),
            "body": str(t.get("body") or "")[:400],
        })

    items.sort(key=lambda x: str(x.get("ts") or ""), reverse=True)
    return items


def inbox_dismiss(item_id: str) -> bool:
    ids = load_inbox_dismissed()
    ids.add(str(item_id))
    save_inbox_dismissed(ids)
    return True


def inbox_mark_handled(item_id: str) -> dict:
    """Clear underlying pending/scratch/wake state and dismiss the item."""
    iid = str(item_id)
    cleared = []
    if iid.startswith("pending.notify:"):
        try:
            if PENDING_NOTIFY.exists():
                PENDING_NOTIFY.unlink()
                cleared.append("pending.notify")
        except OSError:
            pass
    elif iid.startswith("pending.ask:"):
        try:
            if PENDING_ASK.exists():
                PENDING_ASK.unlink()
                cleared.append("pending.ask")
        except OSError:
            pass
    elif iid.startswith("pending.upload:"):
        try:
            if PENDING_UPLOAD.exists():
                PENDING_UPLOAD.unlink()
                cleared.append("pending.upload")
        except OSError:
            pass
    elif iid.startswith("unanswered_ask:") or iid.startswith("scratch_accept:"):
        sid = iid.split(":", 1)[1]
        mp = SCRATCH / f"{sid}-meta.json"
        if mp.exists():
            try:
                meta = json.loads(mp.read_text(encoding="utf-8"))
                if not isinstance(meta, dict):
                    meta = {}
                meta["pending"] = False
                if iid.startswith("scratch_accept:"):
                    meta["accepted_at"] = iso_now()
                else:
                    meta["handled_at"] = iso_now()
                mp.write_text(json.dumps(meta, indent=2), encoding="utf-8")
                cleared.append(sid)
            except (OSError, json.JSONDecodeError):
                pass
        try:
            if PENDING_ASK.exists():
                data = _read_pending_json(PENDING_ASK) or {}
                if str(data.get("scratch_id") or "") == sid:
                    PENDING_ASK.unlink()
                    cleared.append("pending.ask")
        except OSError:
            pass
    elif iid.startswith("wake_failure:"):
        wid = iid.split(":", 1)[1]
        state = load_wake_state()
        before = list(state.get("failures") or [])
        state["failures"] = [f for f in before if not (isinstance(f, dict) and f.get("id") == wid)]
        if len(state["failures"]) < len(before):
            cleared.append(wid)
        save_wake_state(state)
    elif iid.startswith("task:"):
        tid = iid.split(":", 1)[1]
        updated = update_task(tid, {"status": "done"})
        if updated:
            cleared.append(tid)

    inbox_dismiss(iid)
    return {"ok": True, "cleared": cleared, "id": iid}


def _post_webhook(payload: dict) -> None:
    """POST one webhook with short retries; never delay the HTTP response."""
    kind = str(payload.get("kind") or "")
    try:
        config = json.loads(WEBHOOK_CONFIG.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return
    except (OSError, json.JSONDecodeError) as exc:
        _webhook_log(f"config read failed: {exc}")
        _record_wake_failure(kind or "config", f"config read failed: {exc}")
        return
    if not isinstance(config, dict):
        _webhook_log("config must be a JSON object")
        return

    if config.get("enabled") is not True:
        return
    url = str(config.get("url") or "").strip()
    header_name = str(config.get("header_name") or "").strip()
    header_value = str(config.get("header_value") or "")
    if not url:
        _webhook_log("config enabled but url is empty")
        _record_wake_failure(kind or "config", "url empty")
        return
    if not header_name or not header_value:
        _webhook_log("config enabled but header_name/header_value is incomplete")
        _record_wake_failure(kind or "config", "header incomplete")
        return

    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    last_exc: Exception | None = None
    for attempt in range(WEBHOOK_RETRIES):
        try:
            request = urllib.request.Request(
                url,
                data=body,
                headers={"Content-Type": "application/json", header_name: header_value},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=WEBHOOK_TIMEOUT_SEC) as response:
                status = getattr(response, "status", response.getcode())
                if 200 <= status < 300:
                    _record_wake_success(kind)
                    return
                last_exc = RuntimeError(f"HTTP {status}")
                _webhook_log(f"POST returned HTTP {status} kind={kind} attempt={attempt + 1}")
        except Exception as exc:
            last_exc = exc
            _webhook_log(f"POST error kind={kind} attempt={attempt + 1}: {exc}")
        if attempt + 1 < WEBHOOK_RETRIES:
            try:
                time.sleep(WEBHOOK_BACKOFF_SEC[min(attempt, len(WEBHOOK_BACKOFF_SEC) - 1)])
            except Exception:
                pass
    _record_wake_failure(kind, str(last_exc) if last_exc else "unknown")


def fire_webhook(kind: str, hint: str) -> None:
    payload = {
        "source": "nullink",
        "kind": kind,
        "ts": iso_now(),
        "hint": str(hint or "").replace("\r", " ").replace("\n", " ").strip()[:200],
    }
    threading.Thread(
        target=_post_webhook,
        args=(payload,),
        name="nullink-webhook",
        daemon=True,
    ).start()



def label_folder(label_ids: list[str]) -> str:
    labels = {l["id"]: l for l in load_labels()}
    for lid in label_ids:
        if lid in labels:
            return slugify(labels[lid]["name"]).lower() or "inbox"
    return "inbox"


class Handler(BaseHTTPRequestHandler):
    server_version = "Nullink/1.1"

    def log_message(self, fmt: str, *args) -> None:
        msg = fmt % args if args else fmt
        if "/api/auth/verify" in msg or "/api/admin/set-otp" in msg:
            print(f"{self.address_string()} - [auth] {self.command} {self.path.split('?')[0]}")
            return
        print(f"{self.address_string()} - {msg}")

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    def _send(self, code: int, body: bytes, content_type: str = "application/json",
              extra_headers: list[tuple[str, str]] | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for k, v in extra_headers:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj: dict | list, extra_headers: list[tuple[str, str]] | None = None) -> None:
        self._send(code, json.dumps(obj).encode(), "application/json", extra_headers)

    def _cookie_token(self) -> str | None:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        c = SimpleCookie()
        try:
            c.load(raw)
        except Exception:
            return None
        if COOKIE_NAME not in c:
            return None
        return c[COOKIE_NAME].value

    def _bearer_token(self) -> str | None:
        raw = self.headers.get("Authorization")
        if not raw:
            return None
        parts = raw.split(None, 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return None
        token = parts[1].strip()
        return token or None

    def _resolve_auth(self) -> dict | None:
        """Precedence: Bearer, then morc_session cookie. Attaches self.auth."""
        bearer = self._bearer_token()
        if bearer is not None:
            # Invalid/malformed Bearer must not fall through to cookie.
            rec = lookup_bearer_token(bearer)
            if not rec:
                self.auth = None
                return None
            auth = {
                "type": "bearer",
                "token_id": rec.get("id"),
                "name": rec.get("name"),
                "scopes": list(rec.get("scopes") or []),
                "sessions": list(rec.get("sessions") or []),
                "token_prefix": rec.get("token_prefix"),
            }
            self.auth = auth
            try:
                touch_token_last_used(str(rec.get("id") or ""))
            except Exception:
                pass
            return auth
        if verify_session(self._cookie_token()):
            auth = {"type": "session", "session_id": "morc_session"}
            self.auth = auth
            return auth
        self.auth = None
        return None

    def _authed(self) -> bool:
        return self._resolve_auth() is not None

    def _require_auth(self) -> bool:
        """Human cookie session required (UI / files / vault / admin)."""
        auth = self._resolve_auth()
        if auth and auth.get("type") == "session":
            return True
        if auth and auth.get("type") == "bearer":
            self._json(403, {"error": "forbidden", "message": "cookie session required"})
            return False
        self._json(401, {"error": "unauthorized"})
        return False

    def _require_api_auth(self, scopes: list[str] | None = None) -> bool:
        """Cookie (full access) OR Bearer with required scopes."""
        # Distinguish missing Authorization Bearer vs invalid Bearer.
        raw_auth = self.headers.get("Authorization")
        if raw_auth is not None:
            parts = raw_auth.split(None, 1)
            if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
                self._json(401, {"error": "unauthorized", "message": "invalid_authorization"})
                return False
            auth = self._resolve_auth()
            if not auth or auth.get("type") != "bearer":
                self._json(401, {"error": "unauthorized", "message": "invalid_token"})
                return False
            if scopes:
                have = set(auth.get("scopes") or [])
                missing = [s for s in scopes if s not in have]
                if missing:
                    self._json(403, {"error": "forbidden", "missing_scopes": missing})
                    return False
            return True
        auth = self._resolve_auth()
        if auth and auth.get("type") == "session":
            return True
        self._json(401, {"error": "unauthorized"})
        return False

    def _session_allowed(self, session_id: str) -> bool:
        auth = getattr(self, "auth", None) or self._resolve_auth()
        if not auth:
            return False
        if auth.get("type") == "session":
            return True
        allowed = auth.get("sessions") or []
        return str(session_id) in {str(s) for s in allowed}

    def _require_session_access(self, session_id: str) -> bool:
        if self._session_allowed(session_id):
            return True
        self._json(403, {"error": "forbidden", "message": "session_not_allowed", "session_id": session_id})
        return False


    def _require_playground_access(self) -> bool:
        """Cookie humans: full playground access.

        Bearer: must include session "chatgpt" in token.sessions (session
        allow-list is the gate; playground:read/write scopes are optional
        and not required). Other Bearer tokens get 403.
        """
        if not self._require_api_auth():
            return False
        auth = getattr(self, "auth", None) or {}
        if auth.get("type") == "session":
            return True
        if auth.get("type") == "bearer":
            allowed = {str(s) for s in (auth.get("sessions") or [])}
            if "chatgpt" in allowed:
                return True
            self._json(403, {
                "error": "forbidden",
                "message": "chatgpt_session_required",
                "detail": "Bearer token sessions must include chatgpt for playground",
            })
            return False
        self._json(401, {"error": "unauthorized"})
        return False

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()

    def do_GET(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)

        if path in ("/", "/index.html"):
            return self._serve_static("index.html", "text/html; charset=utf-8")
        if path == "/app.js":
            return self._serve_static("app.js", "application/javascript; charset=utf-8")
        if path == "/style.css":
            return self._serve_static("style.css", "text/css; charset=utf-8")
        if path == "/tokens.css":
            return self._serve_static("tokens.css", "text/css; charset=utf-8")
        if path == "/health":
            return self._json(200, {"ok": True, "service": "nullink", "port": PORT, "pm": True})

        if path == "/api/ping":
            # Legacy unauthenticated wake for box watchers when no Authorization.
            # Bearer requires ping:read; cookie humans allowed.
            raw_auth = self.headers.get("Authorization")
            if raw_auth is not None:
                if not self._require_api_auth(["ping:read"]):
                    return
                auth = getattr(self, "auth", None) or {}
                allowed = auth.get("sessions") if auth.get("type") == "bearer" else None
                has, reasons = ping_has_change_for_sessions(allowed)
            elif self._cookie_token() and verify_session(self._cookie_token()):
                has, reasons = ping_has_change()
            else:
                has, reasons = ping_has_change()
            body = b"1" if has else b"0"
            headers = [("X-Nullink-Reasons", ",".join(reasons))] if reasons else None
            return self._send(200, body, "text/plain; charset=utf-8", headers)


        if path == "/api/me":
            if not self._require_api_auth():
                return
            auth = getattr(self, "auth", None) or {}
            if auth.get("type") == "bearer":
                return self._json(200, {
                    "authenticated": True,
                    "auth_type": "bearer",
                    "token_id": auth.get("token_id"),
                    "name": auth.get("name"),
                    "scopes": auth.get("scopes") or [],
                    "sessions": auth.get("sessions") or [],
                })
            return self._json(200, {
                "authenticated": True,
                "auth_type": "session",
            })

        if path == "/api/sessions":
            if not self._require_api_auth(["sessions:read"]):
                return
            roster = load_roster()
            sessions = flat_sessions_from_roster(roster)
            auth = getattr(self, "auth", None) or {}
            if auth.get("type") == "bearer":
                allowed = {str(s) for s in (auth.get("sessions") or [])}
                sessions = [s for s in sessions if str(s.get("id") or "") in allowed]
                # Filter categories/bots similarly for cleanliness
                cats = []
                for cat in (roster.get("categories") or []):
                    if not isinstance(cat, dict):
                        continue
                    bots = [b for b in (cat.get("bots") or [])
                            if isinstance(b, dict) and str(b.get("id") or "") in allowed]
                    if bots:
                        c = dict(cat)
                        c["bots"] = bots
                        cats.append(c)
                default = roster.get("default_session") or "morc"
                if default not in allowed:
                    default = next(iter(allowed), default)
                return self._json(200, {
                    "categories": cats,
                    "default_session": default,
                    "sessions": sessions,
                })
            return self._json(200, {
                "categories": roster.get("categories") or [],
                "default_session": roster.get("default_session") or "morc",
                "sessions": sessions,
            })

        if path == "/api/auth/tokens":
            return self._list_tokens()

        if path == "/api/messages/stream":
            return self._sse_messages(qs)

        if path == "/api/messages":
            if not self._require_api_auth(["messages:read"]):
                return
            after = 0
            if "after" in qs:
                try:
                    after = int(qs["after"][0])
                except (ValueError, IndexError):
                    after = 0
            limit = 50
            if "limit" in qs:
                try:
                    limit = int(qs["limit"][0])
                except (ValueError, IndexError):
                    limit = 50
            limit = max(1, min(100, limit))
            sid = (qs.get("session") or ["morc"])[0]
            if not self._require_session_access(sid):
                return
            msgs = read_messages(after_id=after)
            msgs = [m for m in msgs if m.get("session_id", "morc") == sid]
            # Normalize: ensure created_at for agent clients; keep ts for UI
            for m in msgs:
                if "created_at" not in m and m.get("ts"):
                    m["created_at"] = m["ts"]
            page = msgs[:limit]
            has_more = len(msgs) > limit
            if page:
                next_after = max(int(m.get("id") or 0) for m in page)
            else:
                next_after = after
            return self._json(200, {
                "messages": page,
                "next_after": next_after,
                "has_more": has_more,
            })

        if path == "/api/labels":
            if not self._require_auth():
                return
            return self._json(200, {"labels": load_labels()})

        if path == "/api/files":
            if not self._require_auth():
                return
            files = load_files()
            label = (qs.get("label") or [None])[0]
            if label:
                files = [f for f in files if label in (f.get("labels") or [])]
            return self._json(200, {"files": files})

        m = re.match(r"^/api/files/([^/]+)/download$", path)
        if m:
            return self._file_download(m.group(1))

        m = re.match(r"^/api/files/([^/]+)/content$", path)
        if m:
            return self._file_content(m.group(1))

        m = re.match(r"^/api/files/([^/]+)$", path)
        if m and m.group(1) not in ("upload", "preview", "ask-morc", "register", "save", "pull-scratch", "accept-scratch", "reject-scratch"):
            return self._file_get(m.group(1))

        m = re.match(r"^/api/scratch/([^/]+)/diff$", path)
        if m:
            return self._scratch_diff(m.group(1))

        m = re.match(r"^/api/scratch/([^/]+)$", path)
        if m:
            return self._scratch_get(m.group(1))

        m = re.match(r"^/api/session-memory/([^/]+)$", path)
        if m:
            return self._session_memory_get(m.group(1))

        if path == "/api/presence":
            if not self._require_auth():
                return
            return self._json(200, build_presence())

        if path == "/api/inbox":
            if not self._require_auth():
                return
            items = build_inbox_items()
            return self._json(200, {"items": items, "count": len(items)})

        if path == "/api/apps":
            # Allowlist metadata is non-sensitive; proxy still requires auth.
            cfg = load_apps_config()
            apps = [public_app_view(a) for a in (cfg.get("apps") or []) if isinstance(a, dict)]
            return self._json(200, {
                "apps": apps,
                "frame_ancestors_note": cfg.get("frame_ancestors_note"),
            })

        m = re.match(r"^/api/apps/proxy/([^/]+)(/.*)?$", path)
        if m:
            return self._apps_proxy(m.group(1), m.group(2) or "/")

        if path == "/api/tasks":
            if not self._require_auth():
                return
            status = (qs.get("status") or [None])[0]
            tasks = load_tasks()
            if status:
                tasks = [t for t in tasks if str(t.get("status") or "open") == status]
            return self._json(200, {"tasks": tasks, "count": len(tasks)})

        m = re.match(r"^/api/tasks/([^/]+)$", path)
        if m:
            if not self._require_auth():
                return
            tid = urllib.parse.unquote(m.group(1))
            task = next((t for t in load_tasks() if t.get("id") == tid), None)
            if not task:
                return self._json(404, {"error": "not_found"})
            return self._json(200, {"task": task})

        if path == "/api/vault":
            if not self._require_auth():
                return
            q = (qs.get("q") or qs.get("query") or [None])[0]
            items = list_vault_snippets(q)
            return self._json(200, {"items": items, "count": len(items)})

        m = re.match(r"^/api/vault/([^/]+)$", path)
        if m:
            if not self._require_auth():
                return
            vid = urllib.parse.unquote(m.group(1))
            item = load_vault_snippet(vid)
            if not item:
                return self._json(404, {"error": "not_found"})
            return self._json(200, {"item": item})


        if path == "/api/playground/chatgpt":
            return self._playground_list()

        m = re.match(r"^/api/playground/chatgpt/([^/]+)$", path)
        if m:
            return self._playground_get(urllib.parse.unquote(m.group(1)))

        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        path = urllib.parse.urlparse(self.path).path

        if path == "/api/auth/verify":
            return self._auth_verify()
        if path == "/api/auth/logout":
            return self._auth_logout()
        if path == "/api/auth/tokens":
            return self._create_token()
        if path == "/api/messages":
            return self._post_message()
        if path == "/api/admin/set-otp":
            return self._admin_set_otp()
        if path == "/api/admin/reply":
            return self._admin_reply()

        if path == "/api/labels":
            return self._label_create()
        if path == "/api/files/upload":
            return self._file_upload()
        if path == "/api/files/save":
            return self._file_save()
        if path == "/api/files/preview":
            return self._file_preview()
        if path == "/api/files/ask-morc":
            return self._file_ask_morc()
        if path == "/api/files/register":
            return self._file_register()
        if path == "/api/files/pull-scratch":
            return self._pull_scratch()
        if path == "/api/files/accept-scratch":
            return self._accept_scratch()
        if path == "/api/files/reject-scratch":
            return self._reject_scratch()
        if path == "/api/inbox/dismiss":
            return self._inbox_dismiss()
        if path == "/api/inbox/handled":
            return self._inbox_handled()
        if path == "/api/tasks":
            return self._task_create()
        if path == "/api/vault":
            return self._vault_create()
        if path == "/api/selection/label":
            return self._selection_label()

        self._json(404, {"error": "not found"})

    def do_PATCH(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        m = re.match(r"^/api/labels/([^/]+)$", path)
        if m:
            return self._label_update(m.group(1))
        m = re.match(r"^/api/files/([^/]+)$", path)
        if m:
            return self._file_update_meta(m.group(1))
        m = re.match(r"^/api/inbox/([^/]+)$", path)
        if m:
            return self._inbox_patch(m.group(1))
        m = re.match(r"^/api/session-memory/([^/]+)$", path)
        if m:
            return self._session_memory_put(m.group(1), partial=True)
        m = re.match(r"^/api/tasks/([^/]+)$", path)
        if m:
            return self._task_update(m.group(1))
        m = re.match(r"^/api/vault/([^/]+)$", path)
        if m:
            return self._vault_update(m.group(1))
        self._json(404, {"error": "not found"})

    def do_PUT(self) -> None:
        # alias save
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/files/save":
            return self._file_save()
        m = re.match(r"^/api/files/([^/]+)/content$", path)
        if m:
            body = self._read_json()
            body["id"] = m.group(1)
            # reuse save with injected body — stash via attribute
            self._save_body_override = body
            return self._file_save()
        m = re.match(r"^/api/session-memory/([^/]+)$", path)
        if m:
            return self._session_memory_put(m.group(1), partial=False)

        m = re.match(r"^/api/playground/chatgpt/([^/]+)$", path)
        if m:
            return self._playground_put(urllib.parse.unquote(m.group(1)))

        self._json(404, {"error": "not found"})

    def do_DELETE(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        m = re.match(r"^/api/auth/tokens/([^/]+)$", path)
        if m:
            return self._revoke_token(m.group(1))
        m = re.match(r"^/api/labels/([^/]+)$", path)
        if m:
            return self._label_delete(m.group(1))
        m = re.match(r"^/api/files/([^/]+)$", path)
        if m:
            return self._file_delete(m.group(1))
        m = re.match(r"^/api/tasks/([^/]+)$", path)
        if m:
            return self._task_delete(m.group(1))
        m = re.match(r"^/api/vault/([^/]+)$", path)
        if m:
            return self._vault_delete(m.group(1))

        m = re.match(r"^/api/playground/chatgpt/([^/]+)$", path)
        if m:
            return self._playground_delete(urllib.parse.unquote(m.group(1)))

        self._json(404, {"error": "not found"})

    # ---------- presence / inbox ----------
    def _inbox_dismiss(self) -> None:
        if not self._require_auth():
            return
        body = self._read_json()
        iid = str(body.get("id") or "").strip()
        if not iid:
            return self._json(400, {"error": "id_required"})
        inbox_dismiss(iid)
        return self._json(200, {"ok": True, "id": iid})

    def _inbox_handled(self) -> None:
        if not self._require_auth():
            return
        body = self._read_json()
        iid = str(body.get("id") or "").strip()
        if not iid:
            return self._json(400, {"error": "id_required"})
        result = inbox_mark_handled(iid)
        return self._json(200, result)

    def _inbox_patch(self, item_id: str) -> None:
        if not self._require_auth():
            return
        item_id = urllib.parse.unquote(str(item_id or "")).strip()
        body = self._read_json()
        action = str(body.get("action") or body.get("status") or "").strip().lower()
        if action in ("dismiss", "dismissed"):
            inbox_dismiss(item_id)
            return self._json(200, {"ok": True, "id": item_id, "action": "dismiss"})
        if action in ("handled", "done", "clear"):
            return self._json(200, inbox_mark_handled(item_id))
        return self._json(400, {"error": "action_required", "message": "Use action=dismiss|handled"})


    # ---------- ChatGPT file playground ----------
    def _playground_list(self) -> None:
        if not self._require_playground_access():
            return
        return self._json(200, {"files": list_playground_files()})

    def _playground_get(self, name: str) -> None:
        if not self._require_playground_access():
            return
        dest = playground_resolve(name)
        if dest is None:
            return self._json(400, {"error": "invalid_name", "message": "safe names only [A-Za-z0-9._-]"})
        if not dest.is_file():
            return self._json(404, {"error": "not_found"})
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        download = (qs.get("download") or ["0"])[0] in ("1", "true", "yes")
        try:
            data = dest.read_bytes()
        except OSError as exc:
            return self._json(500, {"error": "read_failed", "message": str(exc)})
        # Prefer text if decodable UTF-8; else octet-stream download
        ctype = "application/octet-stream"
        try:
            text_body = data.decode("utf-8")
            ctype = "text/plain; charset=utf-8"
            if not download:
                return self._send(200, text_body.encode("utf-8"), ctype, [
                    ("X-Playground-Name", dest.name),
                    ("X-Playground-Size", str(len(data))),
                ])
        except UnicodeDecodeError:
            text_body = None
        disp = "attachment" if download or text_body is None else "inline"
        headers = [
            ("Content-Disposition", f'{disp}; filename="{dest.name}"'),
            ("X-Playground-Name", dest.name),
            ("X-Playground-Size", str(len(data))),
        ]
        return self._send(200, data, ctype if text_body is None else "text/plain; charset=utf-8", headers)

    def _playground_read_put_body(self) -> tuple[bytes | None, str | None]:
        """Return (data, error). Accepts raw, JSON {content}, or multipart file."""
        length = int(self.headers.get("Content-Length") or 0)
        if length < 0:
            return None, "bad_length"
        if length > MAX_PLAYGROUND_BYTES + 65536:
            return None, "too_large"
        raw = self.rfile.read(length) if length > 0 else b""
        ctype = (self.headers.get("Content-Type") or "").lower()
        if "multipart/form-data" in ctype:
            try:
                form = parse_multipart(raw, self.headers.get("Content-Type") or "")
            except ValueError:
                return None, "multipart_parse_failed"
            # Prefer file field named file/content/upload; else first file part
            data = None
            for key in ("file", "content", "upload", "data"):
                bucket = form.get(key)
                if isinstance(bucket, list) and bucket:
                    data = bucket[0].get("data")
                    break
                if isinstance(bucket, dict) and "data" in bucket:
                    data = bucket.get("data")
                    break
                if isinstance(bucket, dict) and "value" in bucket:
                    data = str(bucket.get("value") or "").encode("utf-8")
                    break
            if data is None:
                for v in form.values():
                    if isinstance(v, list) and v and isinstance(v[0], dict) and "data" in v[0]:
                        data = v[0]["data"]
                        break
            if data is None:
                return None, "empty"
            if not isinstance(data, (bytes, bytearray)):
                data = str(data).encode("utf-8")
            return bytes(data), None
        if "application/json" in ctype:
            try:
                obj = json.loads(raw.decode("utf-8") if raw else "{}")
            except (json.JSONDecodeError, UnicodeDecodeError):
                return None, "invalid_json"
            if not isinstance(obj, dict):
                return None, "invalid_json"
            if "content" in obj:
                content = obj.get("content")
            elif "text" in obj:
                content = obj.get("text")
            elif "data" in obj:
                content = obj.get("data")
            else:
                return None, "missing_content"
            if content is None:
                content = ""
            if isinstance(content, (bytes, bytearray)):
                return bytes(content), None
            return str(content).encode("utf-8"), None
        # raw body (text/plain, octet-stream, or unspecified)
        return raw, None

    def _playground_put(self, name: str) -> None:
        if not self._require_playground_access():
            return
        if playground_safe_name(name) is None:
            return self._json(400, {"error": "invalid_name", "message": "safe names only [A-Za-z0-9._-]"})
        data, err = self._playground_read_put_body()
        if err == "too_large":
            return self._json(413, {"error": "too_large", "max_bytes": MAX_PLAYGROUND_BYTES})
        if err:
            return self._json(400, {"error": err})
        assert data is not None
        if len(data) > MAX_PLAYGROUND_BYTES:
            return self._json(413, {"error": "too_large", "max_bytes": MAX_PLAYGROUND_BYTES})
        try:
            meta = write_playground_file(name, data)
        except ValueError as exc:
            code = str(exc)
            if code == "too_large":
                return self._json(413, {"error": "too_large", "max_bytes": MAX_PLAYGROUND_BYTES})
            if code == "invalid_name":
                return self._json(400, {"error": "invalid_name"})
            return self._json(400, {"error": code})
        except OSError as exc:
            return self._json(500, {"error": "write_failed", "message": str(exc)})
        return self._json(200, {"ok": True, "file": meta})

    def _playground_delete(self, name: str) -> None:
        if not self._require_playground_access():
            return
        try:
            ok = delete_playground_file(name)
        except ValueError:
            return self._json(400, {"error": "invalid_name", "message": "safe names only [A-Za-z0-9._-]"})
        except OSError as exc:
            return self._json(500, {"error": "delete_failed", "message": str(exc)})
        if not ok:
            return self._json(404, {"error": "not_found"})
        return self._json(200, {"ok": True, "deleted": playground_safe_name(name) or name})


    # ---------- labels ----------
    def _label_create(self) -> None:
        if not self._require_auth():
            return
        body = self._read_json()
        name = str(body.get("name") or "").strip()
        if not name:
            return self._json(400, {"error": "empty", "message": "Label name required."})
        color = str(body.get("color") or "").strip() or None
        lid = slugify(name).lower() or secrets.token_hex(4)
        labels = load_labels()
        existing = {l["id"] for l in labels}
        base_id = lid
        n = 2
        while lid in existing:
            lid = f"{base_id}-{n}"
            n += 1
        entry = {"id": lid, "name": name}
        if color:
            entry["color"] = color
        labels.append(entry)
        save_labels(labels)
        return self._json(200, {"ok": True, "label": entry})

    def _label_update(self, lid: str) -> None:
        if not self._require_auth():
            return
        body = self._read_json()
        labels = load_labels()
        found = None
        for l in labels:
            if l["id"] == lid:
                found = l
                break
        if not found:
            return self._json(404, {"error": "not_found"})
        if "name" in body and str(body["name"]).strip():
            found["name"] = str(body["name"]).strip()
        if "color" in body:
            c = str(body["color"] or "").strip()
            if c:
                found["color"] = c
            elif "color" in found:
                del found["color"]
        save_labels(labels)
        return self._json(200, {"ok": True, "label": found})

    def _label_delete(self, lid: str) -> None:
        if not self._require_auth():
            return
        labels = load_labels()
        new_labels = [l for l in labels if l["id"] != lid]
        if len(new_labels) == len(labels):
            return self._json(404, {"error": "not_found"})
        save_labels(new_labels)
        # strip from files
        files = load_files()
        changed = False
        for f in files:
            labs = f.get("labels") or []
            if lid in labs:
                f["labels"] = [x for x in labs if x != lid]
                changed = True
        if changed:
            save_files(files)
        return self._json(200, {"ok": True})

    # ---------- tasks (F3) ----------
    def _task_create(self) -> None:
        if not self._require_auth():
            return
        body = self._read_json()
        title = str(body.get("title") or "").strip()
        text_body = str(body.get("body") or body.get("text") or "").strip()
        if not title and not text_body:
            return self._json(400, {"error": "empty", "message": "title or body required"})
        label_id = body.get("label_id") or body.get("label")
        if label_id is not None:
            label_id = str(label_id).strip() or None
        source = str(body.get("source") or "selection")[:40]
        entry = create_task(title=title or text_body[:80], body=text_body or title, label_id=label_id, source=source)
        return self._json(200, {"ok": True, "task": entry})

    def _task_update(self, tid: str) -> None:
        if not self._require_auth():
            return
        tid = urllib.parse.unquote(str(tid or "")).strip()
        body = self._read_json()
        updated = update_task(tid, body)
        if not updated:
            return self._json(404, {"error": "not_found"})
        return self._json(200, {"ok": True, "task": updated})

    def _task_delete(self, tid: str) -> None:
        if not self._require_auth():
            return
        tid = urllib.parse.unquote(str(tid or "")).strip()
        if not delete_task(tid):
            return self._json(404, {"error": "not_found"})
        return self._json(200, {"ok": True, "id": tid})

    # ---------- vault snippets (F7) ----------
    def _vault_create(self) -> None:
        if not self._require_auth():
            return
        body = self._read_json()
        title = str(body.get("title") or "").strip()
        text_body = str(body.get("body") or "").strip()
        if not title and not text_body:
            return self._json(400, {"error": "empty", "message": "title or body required"})
        tags = body.get("tags") if isinstance(body.get("tags"), list) else []
        # allow tags as comma-separated string
        if isinstance(body.get("tags"), str):
            tags = [t.strip() for t in body["tags"].split(",") if t.strip()]
        entry = save_vault_snippet({
            "title": title or text_body[:60],
            "body": text_body,
            "tags": tags,
        })
        return self._json(200, {"ok": True, "item": entry})

    def _vault_update(self, vid: str) -> None:
        if not self._require_auth():
            return
        vid = urllib.parse.unquote(str(vid or "")).strip()
        existing = load_vault_snippet(vid)
        if not existing:
            return self._json(404, {"error": "not_found"})
        body = self._read_json()
        if "title" in body and body["title"] is not None:
            existing["title"] = str(body["title"]).strip()[:200] or existing["title"]
        if "body" in body and body["body"] is not None:
            existing["body"] = str(body["body"])[:100_000]
        if "tags" in body:
            tags = body["tags"]
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",") if t.strip()]
            existing["tags"] = tags if isinstance(tags, list) else existing.get("tags") or []
        entry = save_vault_snippet(existing)
        return self._json(200, {"ok": True, "item": entry})

    def _vault_delete(self, vid: str) -> None:
        if not self._require_auth():
            return
        vid = urllib.parse.unquote(str(vid or "")).strip()
        if not delete_vault_snippet(vid):
            return self._json(404, {"error": "not_found"})
        return self._json(200, {"ok": True, "id": vid})

    def _selection_label(self) -> None:
        """Attach selected text to a label as a paste file (+ optional task)."""
        if not self._require_auth():
            return
        body = self._read_json()
        text_body = str(body.get("text") or body.get("body") or "").strip()
        label_id = str(body.get("label_id") or body.get("label") or "").strip()
        if not text_body:
            return self._json(400, {"error": "empty", "message": "text required"})
        if not label_id:
            return self._json(400, {"error": "label_required"})
        try:
            file_entry = create_labeled_paste(text_body, label_id, body.get("name"))
        except ValueError as e:
            err = str(e)
            code = 404 if err == "unknown_label" else 400
            return self._json(code, {"error": err})
        task = None
        if body.get("also_task"):
            task = create_task(
                title=str(body.get("title") or text_body[:80]),
                body=text_body,
                label_id=label_id,
                source=str(body.get("source") or "selection-label"),
            )
        return self._json(200, {"ok": True, "file": file_entry, "task": task})

    # ---------- files ----------
    def _file_get(self, fid: str) -> None:
        if not self._require_auth():
            return
        for f in load_files():
            if f["id"] == fid:
                return self._json(200, {"file": f})
        self._json(404, {"error": "not_found"})

    def _file_content(self, fid: str) -> None:
        if not self._require_auth():
            return
        entry = next((f for f in load_files() if f["id"] == fid), None)
        if not entry:
            return self._json(404, {"error": "not_found"})
        fp = resolve_file_path(entry)
        if not fp:
            return self._json(404, {"error": "missing_file"})
        if not is_text_file(entry.get("name") or fp.name):
            return self._json(400, {"error": "not_text", "message": "Binary file — use download."})
        try:
            text = fp.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                text = fp.read_text(encoding="latin-1")
            except OSError as e:
                return self._json(500, {"error": "read_failed", "message": str(e)})
        except OSError as e:
            return self._json(500, {"error": "read_failed", "message": str(e)})
        return self._json(200, {
            "id": fid,
            "name": entry.get("name"),
            "content": text,
            "labels": entry.get("labels") or [],
            "updated_at": entry.get("updated_at"),
        })

    def _file_download(self, fid: str) -> None:
        if not self._require_auth():
            return
        entry = next((f for f in load_files() if f["id"] == fid), None)
        if not entry:
            return self._json(404, {"error": "not_found"})
        fp = resolve_file_path(entry)
        if not fp:
            return self._json(404, {"error": "missing_file"})
        data = fp.read_bytes()
        name = entry.get("name") or fp.name
        disp = f'attachment; filename="{slugify(name)}"'
        self._send(200, data, "application/octet-stream", [
            ("Content-Disposition", disp),
        ])

    def _file_update_meta(self, fid: str) -> None:
        if not self._require_auth():
            return
        body = self._read_json()
        files = load_files()
        entry = next((f for f in files if f["id"] == fid), None)
        if not entry:
            return self._json(404, {"error": "not_found"})
        if "name" in body and str(body["name"]).strip():
            entry["name"] = str(body["name"]).strip()
        if "labels" in body and isinstance(body["labels"], list):
            entry["labels"] = [str(x) for x in body["labels"]]
        entry["updated_at"] = iso_now()
        save_files(files)
        return self._json(200, {"ok": True, "file": entry})

    def _file_delete(self, fid: str) -> None:
        if not self._require_auth():
            return
        files = load_files()
        entry = next((f for f in files if f["id"] == fid), None)
        if not entry:
            return self._json(404, {"error": "not_found"})
        fp = resolve_file_path(entry)
        files = [f for f in files if f["id"] != fid]
        save_files(files)
        # only delete if under uploads/ or data/files/ or scratch/
        if fp:
            try:
                rel = str(fp.relative_to(BASE.resolve()))
                if rel.startswith(("uploads/", "data/files/", "scratch/", "playground/")):
                    fp.unlink(missing_ok=True)
            except (ValueError, OSError):
                pass
        return self._json(200, {"ok": True})

    def _file_save(self) -> None:
        if not self._require_auth():
            return
        body = getattr(self, "_save_body_override", None) or self._read_json()
        self._save_body_override = None
        fid = str(body.get("id") or "").strip()
        content = body.get("content")
        if content is None:
            return self._json(400, {"error": "no_content"})
        if not isinstance(content, str):
            return self._json(400, {"error": "content_must_be_string"})
        if len(content.encode("utf-8")) > MAX_UPLOAD_BYTES:
            return self._json(400, {"error": "too_large", "message": "Max 50MB."})
        files = load_files()
        entry = next((f for f in files if f["id"] == fid), None) if fid else None
        if not entry:
            # create new vault file
            name = str(body.get("name") or "untitled.txt").strip() or "untitled.txt"
            labels = body.get("labels") if isinstance(body.get("labels"), list) else ["inbox"]
            labels = [str(x) for x in labels] or ["inbox"]
            fid = uuid.uuid4().hex[:12]
            dest_dir = upload_dest_for_labels(labels)
            safe_name = slugify(name)
            if "chatgpt-playground" in labels:
                # Keep sandbox names traversal-safe
                if playground_safe_name(safe_name) is None:
                    safe_name = playground_safe_name(slugify(name).replace(" ", "-")) or "file.txt"
            dest = dest_dir / safe_name
            if dest.exists():
                dest = dest_dir / f"{Path(safe_name).stem}-{fid[:6]}{Path(safe_name).suffix or '.txt'}"
            dest.write_text(content, encoding="utf-8")
            try:
                dest.chmod(0o644)
            except OSError:
                pass
            entry = {
                "id": fid,
                "name": name,
                "path": str(dest.relative_to(BASE)),
                "labels": labels,
                "size": dest.stat().st_size,
                "updated_at": iso_now(),
                "source": "upload",
            }
            files.append(entry)
            save_files(files)
            return self._json(200, {"ok": True, "file": entry})

        fp = resolve_file_path(entry)
        if not fp:
            return self._json(404, {"error": "missing_file"})
        if not is_text_file(entry.get("name") or fp.name):
            return self._json(400, {"error": "not_text"})
        fp.write_text(content, encoding="utf-8")
        entry["size"] = fp.stat().st_size
        entry["updated_at"] = iso_now()
        save_files(files)
        return self._json(200, {"ok": True, "file": entry})

    def _file_upload(self) -> None:
        if not self._require_auth():
            return
        ctype = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in ctype:
            return self._json(400, {"error": "multipart_required"})
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return self._json(400, {"error": "empty"})
        # Allow multi-file batches; per-file cap still MAX_UPLOAD_BYTES.
        if length > (MAX_UPLOAD_BYTES * 20) + 65536:
            return self._json(400, {"error": "too_large", "message": "Batch too large."})
        raw = self.rfile.read(length)
        try:
            form = parse_multipart(raw, ctype)
        except Exception as e:
            return self._json(400, {"error": "parse_failed", "message": str(e)})

        raw_files = form.get("file") or form.get("files")
        if not raw_files:
            return self._json(400, {"error": "no_file"})
        if isinstance(raw_files, dict):
            file_items = [raw_files]
        else:
            file_items = list(raw_files)
        file_items = [f for f in file_items if isinstance(f, dict) and "data" in f]
        if not file_items:
            return self._json(400, {"error": "no_file"})

        labels_raw = None
        if "labels" in form:
            labels_raw = form["labels"].get("value") if "value" in form["labels"] else None
        elif "label" in form:
            labels_raw = form["label"].get("value") if "value" in form["label"] else None
        labels_raw = labels_raw or "inbox"
        try:
            if str(labels_raw).strip().startswith("["):
                labels = json.loads(str(labels_raw))
            else:
                labels = [x.strip() for x in str(labels_raw).split(",") if x.strip()]
        except json.JSONDecodeError:
            labels = ["inbox"]
        if not labels:
            labels = ["inbox"]
        known = {l["id"] for l in load_labels()}
        labels = [x for x in labels if x in known] or ["inbox"]

        dest_dir = upload_dest_for_labels(labels)

        saved = []
        errors = []
        for fileitem in file_items:
            filename = Path(fileitem.get("filename") or "upload.bin").name
            if not allowed_upload_name(filename):
                errors.append({"name": filename, "error": "bad_name"})
                continue
            data = fileitem["data"]
            if len(data) > MAX_UPLOAD_BYTES:
                errors.append({"name": filename, "error": "too_large", "message": "Max 50MB per file."})
                continue

            fid = uuid.uuid4().hex[:12]
            safe_name = slugify(filename)
            if "chatgpt-playground" in labels:
                if len(data) > MAX_PLAYGROUND_BYTES:
                    errors.append({"name": filename, "error": "too_large", "message": "Max 25MB for playground."})
                    continue
                if playground_safe_name(safe_name) is None:
                    errors.append({"name": filename, "error": "bad_name", "message": "Playground safe names only [A-Za-z0-9._-]"})
                    continue
            dest = dest_dir / safe_name
            if dest.exists():
                stem, suf = Path(safe_name).stem, Path(safe_name).suffix
                dest = dest_dir / f"{stem}-{fid[:6]}{suf}"
                if "chatgpt-playground" in labels and playground_safe_name(dest.name) is None:
                    errors.append({"name": filename, "error": "bad_name"})
                    continue
            dest.write_bytes(data)
            try:
                dest.chmod(0o644)  # never execute
            except OSError:
                pass

            entry = {
                "id": fid,
                "name": filename,
                "path": str(dest.relative_to(BASE)),
                "labels": labels,
                "size": len(data),
                "updated_at": iso_now(),
                "source": "upload",
            }
            saved.append(entry)

        if not saved:
            return self._json(400, {"error": "upload_failed", "errors": errors})

        files = load_files()
        files.extend(saved)
        save_files(files)

        names = ", ".join(e["name"] for e in saved[:8])
        if len(saved) > 8:
            names += f" (+{len(saved) - 8} more)"
        write_pending("upload", {
            "file_id": saved[0]["id"],
            "file_ids": [e["id"] for e in saved],
            "name": saved[0]["name"],
            "names": [e["name"] for e in saved],
            "path": saved[0]["path"],
            "labels": labels,
            "count": len(saved),
            "preview": f"Uploaded {len(saved)} file(s): {names}",
        })
        fire_webhook("upload", f"Uploaded {len(saved)} file(s): {names}")
        out = {"ok": True, "files": saved, "file": saved[0], "count": len(saved)}
        if errors:
            out["errors"] = errors
        return self._json(200, out)

    def _file_register(self) -> None:
        """Morc/local helper: copy a box path into the vault and register it."""
        if not (is_localhost(self) or self._authed()):
            return self._json(403, {"error": "forbidden"})
        body = self._read_json()
        src = str(body.get("path") or "").strip()
        if not src:
            return self._json(400, {"error": "path_required"})
        src_p = Path(src).expanduser().resolve()
        allowed_roots = [BASE.resolve(), Path("/workspace/athenaeum").resolve()]
        ok_root = False
        for root in allowed_roots:
            try:
                if str(src_p).startswith(str(root) + os.sep) or src_p == root:
                    ok_root = True
                    break
            except OSError:
                continue
        if not ok_root or not src_p.is_file():
            return self._json(400, {"error": "path_not_allowed", "message": "Only under chat-bridge/ or athenaeum/."})

        name = str(body.get("name") or src_p.name).strip()
        labels = body.get("labels") if isinstance(body.get("labels"), list) else ["inbox"]
        labels = [str(x) for x in labels] or ["inbox"]
        fid = uuid.uuid4().hex[:12]
        dest = VAULT / f"{fid}-{slugify(name)}"
        try:
            shutil.copy2(src_p, dest)
            dest.chmod(0o644)
        except OSError as e:
            return self._json(500, {"error": "copy_failed", "message": str(e)})

        entry = {
            "id": fid,
            "name": name,
            "path": str(dest.relative_to(BASE)),
            "labels": labels,
            "size": dest.stat().st_size,
            "updated_at": iso_now(),
            "source": "registered",
            "registered_from": str(src_p),
        }
        files = load_files()
        files.append(entry)
        save_files(files)
        write_pending("upload", {
            "file_id": fid,
            "name": name,
            "path": entry["path"],
            "labels": labels,
            "preview": f"Registered {name}",
        })
        fire_webhook("upload", f"Registered {name}")
        return self._json(200, {"ok": True, "file": entry})

    def _file_preview(self) -> None:
        """Copy current buffer to scratch — does NOT notify Morc alone."""
        if not self._require_auth():
            return
        body = self._read_json()
        content = body.get("content")
        fid = str(body.get("file_id") or body.get("id") or "").strip() or None
        if content is None and fid:
            entry = next((f for f in load_files() if f["id"] == fid), None)
            if not entry:
                return self._json(404, {"error": "not_found"})
            fp = resolve_file_path(entry)
            if not fp:
                return self._json(404, {"error": "missing_file"})
            content = fp.read_text(encoding="utf-8", errors="replace")
        if content is None:
            return self._json(400, {"error": "no_content"})
        if not isinstance(content, str):
            return self._json(400, {"error": "content_must_be_string"})
        sid = str(body.get("scratch_id") or uuid.uuid4().hex[:12])
        name = str(body.get("name") or (fid and next((f["name"] for f in load_files() if f["id"] == fid), None)) or "preview.txt")
        out = SCRATCH / f"{sid}-preview.txt"
        out.write_text(content, encoding="utf-8")
        try:
            out.chmod(0o644)
        except OSError:
            pass
        meta = {
            "scratch_id": sid,
            "path": str(out.relative_to(BASE)),
            "file_id": fid,
            "name": name,
            "line_count": content.count("\n") + (1 if content and not content.endswith("\n") else (0 if not content else 1)),
            "updated_at": iso_now(),
            "size": out.stat().st_size,
        }
        (SCRATCH / f"{sid}-meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        return self._json(200, {"ok": True, "scratch": meta})

    def _file_ask_morc(self) -> None:
        if not self._require_auth():
            return
        body = self._read_json()
        sid = str(body.get("scratch_id") or "").strip()
        content = body.get("content")
        fid = str(body.get("file_id") or body.get("id") or "").strip() or None
        message = str(body.get("message") or body.get("note") or "").strip()
        labels = body.get("labels") if isinstance(body.get("labels"), list) else None

        # ensure scratch exists
        if not sid or not (SCRATCH / f"{sid}-preview.txt").exists():
            # create preview first
            if content is None and fid:
                entry = next((f for f in load_files() if f["id"] == fid), None)
                if entry:
                    fp = resolve_file_path(entry)
                    if fp:
                        content = fp.read_text(encoding="utf-8", errors="replace")
            if content is None:
                content = ""
            sid = sid or uuid.uuid4().hex[:12]
            name = str(body.get("name") or "ask.txt")
            out = SCRATCH / f"{sid}-preview.txt"
            out.write_text(content if isinstance(content, str) else "", encoding="utf-8")
            text = out.read_text(encoding="utf-8")
            line_count = text.count("\n") + (0 if not text or text.endswith("\n") else 1)
            if text and not text.endswith("\n") and line_count == 0:
                line_count = 1
            if text:
                line_count = text.count("\n") + (0 if text.endswith("\n") else 1)
            meta = {
                "scratch_id": sid,
                "path": str(out.relative_to(BASE)),
                "file_id": fid,
                "name": name,
                "line_count": max(line_count, 1 if text else 0),
                "updated_at": iso_now(),
                "size": out.stat().st_size,
            }
            (SCRATCH / f"{sid}-meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        else:
            meta_path = SCRATCH / f"{sid}-meta.json"
            if meta_path.exists():
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            else:
                text = (SCRATCH / f"{sid}-preview.txt").read_text(encoding="utf-8")
                meta = {
                    "scratch_id": sid,
                    "path": f"scratch/{sid}-preview.txt",
                    "file_id": fid,
                    "name": body.get("name") or "preview.txt",
                    "line_count": text.count("\n") + (0 if not text or text.endswith("\n") else 1),
                    "updated_at": iso_now(),
                    "size": (SCRATCH / f"{sid}-preview.txt").stat().st_size,
                }
            if content is not None and isinstance(content, str):
                (SCRATCH / f"{sid}-preview.txt").write_text(content, encoding="utf-8")
                text = content
                meta["line_count"] = text.count("\n") + (0 if not text or text.endswith("\n") else 1)
                meta["size"] = (SCRATCH / f"{sid}-preview.txt").stat().st_size
                meta["updated_at"] = iso_now()
                (SCRATCH / f"{sid}-meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

        if labels is not None:
            meta["labels"] = [str(x) for x in labels]
        meta["ask_message"] = message
        meta["pending"] = True
        (SCRATCH / f"{sid}-meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

        notify = {
            "kind": "ask-morc",
            "scratch_id": sid,
            "path": meta.get("path"),
            "file_id": meta.get("file_id"),
            "name": meta.get("name"),
            "labels": meta.get("labels") or labels or [],
            "line_count": meta.get("line_count"),
            "message": message,
            "preview": message[:200] if message else f"Ask Morc: {meta.get('name')} ({meta.get('line_count')} lines)",
        }
        write_pending("notify", notify)
        # also write pending.ask for clarity
        ask_written = False
        try:
            PENDING_ASK.write_text(json.dumps(notify, ensure_ascii=False), encoding="utf-8")
            ask_written = True
        except OSError:
            pass
        if ask_written:
            fire_webhook("ask_morc", notify.get("preview") or "Ask Morc")

        # optional chat message so John sees it in thread
        if message:
            append_message("user", f"[Ask Morc · {meta.get('name')}] {message}", session_id="morc")
        else:
            append_message(
                "user",
                f"[Ask Morc] Please review scratch `{meta.get('path')}` ({meta.get('line_count')} lines).",
                session_id="morc",
            )

        return self._json(200, {"ok": True, "scratch": meta, "notify": notify})

    def _scratch_get(self, sid: str) -> None:
        if not self._require_auth():
            return
        preview = SCRATCH / f"{sid}-preview.txt"
        if not preview.exists():
            return self._json(404, {"error": "not_found"})
        meta = {}
        mp = SCRATCH / f"{sid}-meta.json"
        if mp.exists():
            try:
                meta = json.loads(mp.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                meta = {}
        content = preview.read_text(encoding="utf-8", errors="replace")
        return self._json(200, {
            "scratch_id": sid,
            "content": content,
            "meta": meta,
            "mtime": preview.stat().st_mtime,
        })


    def _scratch_diff(self, sid: str) -> None:
        if not self._require_auth():
            return
        sid = str(sid or "").strip()
        preview = SCRATCH / f"{sid}-preview.txt"
        if not preview.exists():
            return self._json(404, {"error": "not_found"})
        meta = {}
        mp = SCRATCH / f"{sid}-meta.json"
        if mp.exists():
            try:
                meta = json.loads(mp.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                meta = {}
        scratch_text = preview.read_text(encoding="utf-8", errors="replace")
        base_text, fid, base_label = scratch_base_content(meta)
        to_label = str(meta.get("path") or f"scratch/{sid}-preview.txt")
        diff = build_unified_diff(base_text, scratch_text, f"a/{base_label}", f"b/{to_label}")
        return self._json(200, {
            "ok": True,
            "scratch_id": sid,
            "file_id": fid or meta.get("file_id"),
            "name": meta.get("name"),
            "base_label": base_label,
            "scratch_label": to_label,
            "diff": diff,
            "identical": scratch_text == base_text,
            "meta": meta,
            "mtime": preview.stat().st_mtime,
        })

    def _session_memory_get(self, bot_id: str) -> None:
        if not self._require_auth():
            return
        bid = _safe_bot_id(urllib.parse.unquote(str(bot_id or "")))
        if not bid:
            return self._json(400, {"error": "bad_bot_id"})
        mem = load_session_memory(bid)
        return self._json(200, {"ok": True, "memory": mem})

    def _session_memory_put(self, bot_id: str, partial: bool = False) -> None:
        if not self._require_auth():
            return
        bid = _safe_bot_id(urllib.parse.unquote(str(bot_id or "")))
        if not bid:
            return self._json(400, {"error": "bad_bot_id"})
        body = self._read_json()
        if not isinstance(body, dict):
            body = {}
        current = load_session_memory(bid)
        if partial:
            merged = dict(current)
            for k in ("goal", "last_decision", "blockers", "notes"):
                if k in body:
                    merged[k] = body[k]
        else:
            merged = {
                "goal": body.get("goal", ""),
                "last_decision": body.get("last_decision", ""),
                "blockers": body.get("blockers", ""),
                "notes": body.get("notes", current.get("notes") or ""),
            }
        try:
            saved = save_session_memory(bid, merged)
        except ValueError:
            return self._json(400, {"error": "bad_bot_id"})
        return self._json(200, {"ok": True, "memory": saved})

    def _reject_scratch(self) -> None:
        """Discard scratch preview + meta (Reject)."""
        if not self._require_auth():
            return
        body = self._read_json()
        sid = str(body.get("scratch_id") or "").strip()
        if not sid:
            return self._json(400, {"error": "scratch_id_required"})
        if not re.fullmatch(r"[A-Za-z0-9_-]+", sid):
            return self._json(400, {"error": "bad_scratch_id"})
        preview = SCRATCH / f"{sid}-preview.txt"
        mp = SCRATCH / f"{sid}-meta.json"
        if not preview.exists() and not mp.exists():
            return self._json(404, {"error": "not_found"})
        removed = []
        for p in (preview, mp):
            try:
                if p.exists():
                    p.unlink()
                    removed.append(p.name)
            except OSError as exc:
                return self._json(500, {"error": "unlink_failed", "message": str(exc)})
        return self._json(200, {"ok": True, "scratch_id": sid, "removed": removed})

    def _pull_scratch(self) -> None:
        if not self._require_auth():
            return
        body = self._read_json()
        sid = str(body.get("scratch_id") or "").strip()
        if not sid:
            return self._json(400, {"error": "scratch_id_required"})
        preview = SCRATCH / f"{sid}-preview.txt"
        if not preview.exists():
            return self._json(404, {"error": "not_found"})
        meta = {}
        mp = SCRATCH / f"{sid}-meta.json"
        if mp.exists():
            try:
                meta = json.loads(mp.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass
        content = preview.read_text(encoding="utf-8", errors="replace")
        return self._json(200, {
            "ok": True,
            "scratch_id": sid,
            "content": content,
            "meta": meta,
            "mtime": preview.stat().st_mtime,
        })

    def _accept_scratch(self) -> None:
        """Accept scratch into editor buffer response; optionally save to file."""
        if not self._require_auth():
            return
        body = self._read_json()
        sid = str(body.get("scratch_id") or "").strip()
        if not sid:
            return self._json(400, {"error": "scratch_id_required"})
        # write_through / save: default True when linked file_id exists (Accept = write through)
        save_explicit = None
        if "save" in body:
            save_explicit = bool(body.get("save"))
        elif "write_through" in body:
            save_explicit = bool(body.get("write_through"))
        preview = SCRATCH / f"{sid}-preview.txt"
        if not preview.exists():
            return self._json(404, {"error": "not_found"})
        content = preview.read_text(encoding="utf-8", errors="replace")
        meta = {}
        mp = SCRATCH / f"{sid}-meta.json"
        if mp.exists():
            try:
                meta = json.loads(mp.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                pass
        if save_explicit is None:
            save = bool(str(body.get("file_id") or meta.get("file_id") or "").strip())
        else:
            save = save_explicit
        file_out = None
        if save:
            fid = str(body.get("file_id") or meta.get("file_id") or "").strip()
            files = load_files()
            entry = next((f for f in files if f["id"] == fid), None) if fid else None
            if entry:
                fp = resolve_file_path(entry)
                if fp and is_text_file(entry.get("name") or fp.name):
                    fp.write_text(content, encoding="utf-8")
                    try:
                        fp.chmod(0o644)
                    except OSError:
                        pass
                    entry["size"] = fp.stat().st_size
                    entry["updated_at"] = iso_now()
                    save_files(files)
                    file_out = entry
            else:
                # save as new
                name = str(body.get("name") or meta.get("name") or "accepted.txt")
                labels = body.get("labels") or meta.get("labels") or ["inbox"]
                fid = uuid.uuid4().hex[:12]
                folder = label_folder([str(x) for x in labels])
                dest_dir = UPLOADS / folder
                dest_dir.mkdir(parents=True, exist_ok=True)
                dest = dest_dir / slugify(name)
                if dest.exists():
                    dest = dest_dir / f"{Path(slugify(name)).stem}-{fid[:6]}{Path(slugify(name)).suffix or '.txt'}"
                dest.write_text(content, encoding="utf-8")
                try:
                    dest.chmod(0o644)
                except OSError:
                    pass
                entry = {
                    "id": fid,
                    "name": name,
                    "path": str(dest.relative_to(BASE)),
                    "labels": [str(x) for x in labels],
                    "size": dest.stat().st_size,
                    "updated_at": iso_now(),
                    "source": "scratch",
                }
                files.append(entry)
                save_files(files)
                file_out = entry
        if mp.exists():
            try:
                meta["accepted_at"] = iso_now()
                meta["pending"] = False
                mp.write_text(json.dumps(meta, indent=2), encoding="utf-8")
            except OSError:
                pass
        return self._json(200, {"ok": True, "content": content, "meta": meta, "file": file_out})

    # ---------- SSE / static / auth (unchanged behavior) ----------
    def _sse_messages(self, qs: dict) -> None:
        if not self._require_api_auth(["messages:read"]):
            return
        after = 0
        if "after" in qs:
            try:
                after = int(qs["after"][0])
            except (ValueError, IndexError):
                after = 0
        sid = (qs.get("session") or ["morc"])[0]
        if not self._require_session_access(sid):
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        deadline = time.time() + 55
        last_ping = 0.0
        try:
            while time.time() < deadline:
                msgs = read_messages(after_id=after)
                msgs = [m for m in msgs if m.get("session_id", "morc") == sid]
                if msgs:
                    payload = json.dumps({"messages": msgs})
                    self.wfile.write(f"event: message\ndata: {payload}\n\n".encode())
                    self.wfile.flush()
                    after = max(m["id"] for m in msgs)
                now = time.time()
                if now - last_ping >= 12:
                    self.wfile.write(b"event: ping\ndata: {}\n\n")
                    self.wfile.flush()
                    last_ping = now
                time.sleep(0.4)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return


    def _apps_proxy(self, app_id: str, subpath: str) -> None:
        """Allowlisted reverse proxy to loopback HTTP apps only (not an open relay)."""
        if not self._require_auth():
            return
        app = get_app_by_id(app_id)
        if not app or not bool(app.get("enabled", True)):
            return self._json(404, {"error": "app_not_found"})
        validated = validate_app_target_url(str(app.get("url") or ""))
        if not validated:
            return self._json(400, {"error": "invalid_app_url"})
        kind, target = validated
        if kind != "loopback":
            # Path/same-host apps must be embedded directly (same-origin), not proxied
            return self._json(400, {
                "error": "use_direct_embed",
                "message": "This app is same-origin; iframe its path directly.",
                "embed_url": target,
            })

        # Compose upstream URL: base target directory + subpath + query
        base = urllib.parse.urlparse(target)
        # Ensure subpath is safe
        if not subpath.startswith("/"):
            subpath = "/" + subpath
        if ".." in subpath or chr(92) in subpath:
            return self._json(400, {"error": "bad_path"})
        # Join: if target has a path prefix, append relative subpath under it
        base_path = base.path if base.path.endswith("/") else (base.path.rsplit("/", 1)[0] + "/")
        # When subpath is "/", use target as-is; else append
        if subpath == "/":
            upstream_path = base.path or "/"
        else:
            upstream_path = urllib.parse.urljoin(base_path, subpath.lstrip("/"))
        qs = urllib.parse.urlparse(self.path).query
        upstream = urllib.parse.urlunparse(("http", base.netloc, upstream_path, "", qs, ""))

        # Final safety: must still be loopback http
        up = urllib.parse.urlparse(upstream)
        if up.scheme != "http" or (up.hostname or "").lower() not in ("127.0.0.1", "localhost"):
            return self._json(403, {"error": "forbidden_upstream"})

        try:
            req = urllib.request.Request(
                upstream,
                method="GET",
                headers={
                    "User-Agent": "Nullink-Apps-Proxy/1.0",
                    "Accept": self.headers.get("Accept") or "*/*",
                },
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = resp.read()
                ctype = resp.headers.get("Content-Type") or "application/octet-stream"
                extra = [
                    ("Content-Security-Policy", "frame-ancestors 'self'"),
                    ("X-Frame-Options", "SAMEORIGIN"),
                    ("X-Content-Type-Options", "nosniff"),
                ]
                # Avoid leaking upstream framing restrictions that break embed
                self._send(resp.status, body, ctype, extra)
        except urllib.error.HTTPError as e:
            body = e.read() if e.fp else b""
            ctype = e.headers.get("Content-Type") if e.headers else "text/plain"
            self._send(e.code, body or f"upstream {e.code}".encode(), ctype or "text/plain")
        except Exception as e:
            return self._json(502, {"error": "upstream_unreachable", "message": str(e)[:200]})

    def _serve_static(self, name: str, ctype: str) -> None:
        fp = STATIC / name
        if not fp.exists():
            return self._json(404, {"error": "missing static"})
        data = fp.read_bytes()
        extra = None
        if name == "index.html" or ctype.startswith("text/html"):
            # Allow same-origin iframes for Apps (e.g. /desktop/, /api/apps/proxy/...)
            extra = [
                ("Content-Security-Policy",
                 "default-src 'self'; "
                 "script-src 'self'; "
                 "style-src 'self' 'unsafe-inline'; "
                 "img-src 'self' data: blob:; "
                 "connect-src 'self'; "
                 "frame-src 'self'; "
                 "frame-ancestors 'none'; "
                 "base-uri 'self'; "
                 "form-action 'self'"),
                ("X-Content-Type-Options", "nosniff"),
                ("Referrer-Policy", "same-origin"),
            ]
        self._send(200, data, ctype, extra)

    def _auth_verify(self) -> None:
        with _lock:
            rate = load_rate()
            now = time.time()
            if rate.get("locked_until", 0) > now:
                remaining = int(rate["locked_until"] - now)
                return self._json(429, {
                    "error": "locked",
                    "retry_after_sec": remaining,
                    "message": f"Too many attempts. Try again in {remaining // 60 + 1} min.",
                })

            body = self._read_json()
            pin = str(body.get("pin", "")).strip()
            if not (pin.isdigit() and len(pin) == 6):
                return self._json(400, {"error": "invalid_pin_format", "message": "Enter a 6-digit PIN."})

            otp = load_otp()
            if not otp:
                return self._json(503, {"error": "no_otp", "message": "No PIN set yet. Ask for a new Nullink PIN."})

            expires = otp.get("expires_at")
            if expires and float(expires) < now:
                return self._json(401, {"error": "expired", "message": "PIN expired. Ask for a new Nullink PIN."})

            ok = hmac.compare_digest(
                hash_pin(pin, otp["salt"]),
                otp["pin_hash"],
            )
            if not ok:
                fails = int(rate.get("fails", 0)) + 1
                rate["fails"] = fails
                if fails >= MAX_FAILS:
                    rate["locked_until"] = now + LOCK_SEC
                    rate["fails"] = 0
                    save_rate(rate)
                    return self._json(429, {
                        "error": "locked",
                        "retry_after_sec": LOCK_SEC,
                        "message": "Too many attempts. Locked for 15 minutes.",
                    })
                save_rate(rate)
                left = MAX_FAILS - fails
                return self._json(401, {
                    "error": "wrong_pin",
                    "message": f"Incorrect PIN. {left} attempt(s) left.",
                    "attempts_left": left,
                })

            rate["fails"] = 0
            rate["locked_until"] = 0
            save_rate(rate)
            exp = int(now) + SESSION_TTL_SEC
            token = sign_session(exp)
            cookie = (
                f"{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL_SEC}"
            )
            proto = (self.headers.get("X-Forwarded-Proto") or "").lower()
            if proto == "https":
                cookie += "; Secure"
            return self._json(200, {"ok": True, "expires_in": SESSION_TTL_SEC}, [
                ("Set-Cookie", cookie),
            ])

    def _auth_logout(self) -> None:
        cookie = f"{COOKIE_NAME}=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax"
        return self._json(200, {"ok": True}, [("Set-Cookie", cookie)])

    def _post_message(self) -> None:
        if not self._require_api_auth(["messages:write"]):
            return
        body = self._read_json()
        text = str(body.get("text", "")).strip()
        if not text:
            return self._json(400, {"error": "empty", "message": "Message cannot be empty."})
        if len(text) > 8000:
            return self._json(400, {"error": "too_long", "message": "Message too long."})
        sid = str(body.get("session_id") or "morc")
        if not self._require_session_access(sid):
            return
        msg = append_message("user", text, session_id=sid)
        write_pending("notify", {"preview": text[:200]})
        fire_webhook("message", text[:200])
        return self._json(200, {"ok": True, "message": msg})

    def _create_token(self) -> None:
        if not self._require_auth():
            return
        body = self._read_json()
        name = str(body.get("name") or "").strip() or "agent"
        raw_scopes = body.get("scopes")
        if raw_scopes is None:
            scopes = list(AGENT_SCOPES)
        elif isinstance(raw_scopes, list):
            scopes = [str(s).strip() for s in raw_scopes if str(s).strip()]
        else:
            return self._json(400, {"error": "invalid_scopes"})
        bad = [s for s in scopes if s not in ALL_SCOPES]
        if bad:
            return self._json(400, {"error": "unknown_scopes", "scopes": bad})
        raw_sessions = body.get("sessions")
        if not isinstance(raw_sessions, list) or not raw_sessions:
            return self._json(400, {"error": "sessions_required"})
        sessions = [str(s).strip() for s in raw_sessions if str(s).strip()]
        if not sessions:
            return self._json(400, {"error": "sessions_required"})
        expires_in = body.get("expires_in")
        try:
            expires_in_i = DEFAULT_TOKEN_TTL_SEC if expires_in is None else int(expires_in)
        except (TypeError, ValueError):
            return self._json(400, {"error": "invalid_expires_in"})
        rec, plaintext = create_api_token(name, scopes, sessions, expires_in_i)
        return self._json(200, {
            "ok": True,
            "token_id": rec["id"],
            "token": plaintext,
            "expires_at": _iso_from_ts(rec.get("expires_at")),
            "scopes": scopes,
            "sessions": sessions,
            "name": name,
        })

    def _list_tokens(self) -> None:
        if not self._require_auth():
            return
        tokens = [token_public_view(t) for t in load_tokens()]
        return self._json(200, {"tokens": tokens, "count": len(tokens)})

    def _revoke_token(self, token_id: str) -> None:
        if not self._require_auth():
            return
        tid = urllib.parse.unquote(str(token_id or "")).strip()
        if not tid:
            return self._json(400, {"error": "token_id_required"})
        rec = revoke_api_token(tid)
        if not rec:
            return self._json(404, {"error": "not_found"})
        return self._json(200, {"ok": True, "token_id": tid, "revoked": True})

    def _admin_set_otp(self) -> None:
        if not is_localhost(self):
            return self._json(403, {"error": "localhost_only"})
        body = self._read_json()
        pin = str(body.get("pin", "")).strip()
        if not (pin.isdigit() and len(pin) == 6):
            return self._json(400, {"error": "invalid_pin"})
        ttl = int(body.get("ttl_sec") or 24 * 3600)
        salt = secrets.token_hex(16)
        now = time.time()
        data = {
            "pin_hash": hash_pin(pin, salt),
            "salt": salt,
            "expires_at": now + ttl,
            "created_at": now,
        }
        OTP_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
        OTP_FILE.chmod(0o600)
        current = SECRETS / "CURRENT_PIN.txt"
        current.write_text(pin + "\n", encoding="utf-8")
        current.chmod(0o600)
        save_rate({"fails": 0, "locked_until": 0})
        return self._json(200, {"ok": True, "expires_at": data["expires_at"]})

    def _admin_reply(self) -> None:
        if not is_localhost(self):
            return self._json(403, {"error": "localhost_only"})
        body = self._read_json()
        text = str(body.get("text", "")).strip()
        if not text:
            return self._json(400, {"error": "empty"})
        sid = str(body.get("session_id") or "morc")
        msg = append_message("assistant", text, session_id=sid)
        try:
            _record_wake_success("admin_reply")
        except Exception:
            pass
        return self._json(200, {"ok": True, "message": msg})


def main() -> None:
    ensure_dirs()
    try:
        ensure_chatgpt_in_roster()
    except Exception as exc:
        print(f"ensure_chatgpt_in_roster: {exc}", flush=True)
    try:
        ensure_chatgpt_playground_label()
    except Exception as exc:
        print(f"ensure_chatgpt_playground_label: {exc}", flush=True)
    if MESSAGES_FILE.stat().st_size == 0:
        append_message(
            "assistant",
            "Nullink online. You're talking to Chief of Staff (Morc). Chat, Files, and Ask Morc are ready.",
            session_id="morc",
        )
    httpd = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"Nullink PM listening on 127.0.0.1:{PORT}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
