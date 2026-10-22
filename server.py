#!/usr/bin/env python3
"""Nullink PM — OTP auth + chat bridge + labels/files/editor on port 8766."""
from __future__ import annotations

import difflib
import base64
import hashlib
import hmac
import ipaddress
import io
import ipaddress
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
import sys as _sys
import share_links
import files_manager
import server_drive
import github_drive
import ai_rooms
import avatars

from phone_bridge import PhoneBridgeError, get_bridge

from phone_bridge import PhoneBridgeError, get_bridge

BASE = Path(__file__).resolve().parent
SECRETS = BASE / "secrets"
DATA = BASE / "data"
STATIC = BASE / "static"
UPLOADS = BASE / "uploads"
VAULT = DATA / "files"
SCRATCH = BASE / "scratch"
OTP_FILE = SECRETS / "otp.json"
TOTP_FILE = SECRETS / "totp.json"
SESSION_SECRET_FILE = SECRETS / "session_secret.txt"
MESSAGES_FILE = DATA / "messages.jsonl"
LAST_HANDLED = DATA / ".last-handled"
# Rooms answered by an on-VPS bridge (not Morc): no pending.notify, webhook or /api/ping wake.
# deepseek -> /opt/nullink/bridges/deepseek (nullink-deepseek-bridge.service)
# replit -> /opt/nullink-replit/room.py (nullink-replit.service)
# council -> A2A groundwork (/opt/nullink-a2a): agents post there; nobody is woken, nobody auto-replies.
BRIDGE_SESSIONS = frozenset({"deepseek", "replit", "council"})
OWNER_ONLY_SESSIONS = frozenset({"replit"})
LABELS_FILE = DATA / "labels.json"
FILES_FILE = DATA / "files.json"
APPS_FILE = DATA / "apps.json"
ROSTER_FILE = DATA / "roster.json"
PENDING_NOTIFY = DATA / "pending.notify"
PENDING_UPLOAD = DATA / "pending.upload"
RATE_FILE = DATA / "rate_limit.json"
SESSIONS_FILE = DATA / "auth_sessions.json"
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
TOTP_STEP_SEC = 30
TOTP_DIGITS = 6
TOTP_WINDOW = 1
# __Host- cookie on HTTPS hosts (Path=/, Secure, no Domain); plain name only for
# direct http://127.0.0.1 use. Legacy morc_session cookies are no longer accepted.
COOKIE_NAME = "__Host-nullink_session"
LOCAL_COOKIE_NAME = "nullink_session"
LEGACY_COOKIE_NAME = "morc_session"
MAX_UPLOAD_BYTES = 50 * 1024 * 1024
MAX_PLAYGROUND_BYTES = 25 * 1024 * 1024
PLAYGROUND_DIR = BASE / "playground" / "chatgpt"
PHONE_DATA_DIR = DATA / "phone"
PHONE_STAGING_DIR = DATA / "phone_staging"
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


# ---- Vault encryption at rest (2026-10-19): AES-256-GCM per entry body ----
# Titles, tags, ids and timestamps stay plaintext (for list/search); bodies are encrypted.
# Data key: root-only /etc/nullink/vault/data.key, delivered via systemd LoadCredential
# (vault_data_key). NULLINK_VAULT_KEY_FILE is honoured for tests / root maintenance only.
VAULT_KEY_CRED = "vault_data_key"
VAULT_AAD_PREFIX = b"nullink-vault-v1:"
VAULT_MASK = "\u2022" * 12
VAULT_AUDIT_FILE = DATA / "vault_audit.jsonl"


class VaultKeyUnavailable(Exception):
    pass


class VaultIntegrityError(Exception):
    pass


def _vault_key() -> bytes:
    paths = []
    d = os.environ.get("CREDENTIALS_DIRECTORY")
    if d:
        paths.append(Path(d) / VAULT_KEY_CRED)
    if os.environ.get("NULLINK_VAULT_KEY_FILE"):
        paths.append(Path(os.environ["NULLINK_VAULT_KEY_FILE"]))
    for kp in paths:
        try:
            raw = base64.b64decode(kp.read_text(encoding="ascii").strip(), validate=True)
        except (OSError, ValueError):
            continue
        if len(raw) == 32:
            return raw
    raise VaultKeyUnavailable("vault key not available")


def vault_key_available() -> bool:
    try:
        _vault_key()
        return True
    except VaultKeyUnavailable:
        return False


def vault_encrypt(vid: str, body: str) -> dict:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = secrets.token_bytes(12)
    ct = AESGCM(_vault_key()).encrypt(nonce, body.encode("utf-8"), VAULT_AAD_PREFIX + vid.encode())
    return {"v": 1, "alg": "AES-256-GCM", "n": base64.b64encode(nonce).decode(),
            "c": base64.b64encode(ct).decode()}


def vault_decrypt(vid: str, enc: dict) -> str:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        nonce = base64.b64decode(enc["n"], validate=True)
        ct = base64.b64decode(enc["c"], validate=True)
        if enc.get("v") != 1 or len(nonce) != 12:
            raise ValueError("bad envelope")
        return AESGCM(_vault_key()).decrypt(nonce, ct, VAULT_AAD_PREFIX + vid.encode()).decode("utf-8")
    except (InvalidTag, KeyError, TypeError, ValueError, UnicodeDecodeError) as e:
        raise VaultIntegrityError(f"vault entry {vid} failed authentication") from e


def vault_audit(event: str, **fields) -> None:
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": event}
    for k, v in fields.items():
        rec[k] = v if isinstance(v, (int, float, bool)) or v is None else \
            "".join(ch for ch in str(v) if ch.isprintable())[:200]
    try:
        fd = os.open(VAULT_AUDIT_FILE, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, separators=(",", ":")) + "\n")
    except OSError:
        pass


def _vault_read_raw(vid: str) -> dict | None:
    fp = _vault_path(vid)
    if not fp or not fp.exists():
        return None
    try:
        data = json.loads(fp.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def load_vault_snippet(vid: str, decrypt: bool = True) -> dict | None:
    """decrypt=False returns metadata with a masked body (no key needed).
    decrypt=True raises VaultKeyUnavailable / VaultIntegrityError instead of returning bad data."""
    ensure_dirs()
    data = _vault_read_raw(vid)
    if data is None:
        return None
    vid = str(data.get("id") or vid)
    out = {
        "id": vid,
        "title": str(data.get("title") or ""),
        "tags": _normalize_vault_tags(data.get("tags")),
        "created_at": data.get("created_at"),
        "updated_at": data.get("updated_at"),
        "encrypted": isinstance(data.get("enc"), dict),
    }
    if not decrypt:
        out.update(body=VAULT_MASK, locked=True)
        return out
    if isinstance(data.get("enc"), dict):
        out["body"] = vault_decrypt(vid, data["enc"])
    else:  # legacy plaintext (pre-migration only)
        out["body"] = str(data.get("body") or "")
    out["locked"] = False
    return out


def _vault_matches(item: dict, query: str | None, labels: list[str] | None) -> bool:
    """Title + label search (never the body). Every whitespace token must hit the title or a label
    (case-insensitive substring); `tag:x` / `label:x` tokens must equal a label. `labels` is an
    AND filter of exact (case-insensitive) label names."""
    have = [t.lower() for t in item.get("tags") or []]
    for want in labels or []:
        if want.strip().lower() not in have:
            return False
    title = str(item.get("title") or "").lower()
    for tok in (query or "").lower().split():
        if tok.startswith(("tag:", "label:")):
            name = tok.split(":", 1)[1]
            if name and name not in have:
                return False
            continue
        if tok not in title and not any(tok in t for t in have):
            return False
    return True


def list_vault_snippets(query: str | None = None, labels: list[str] | None = None) -> list[dict]:
    """Masked list. Search matches title and labels only (bodies are encrypted, never indexed)."""
    ensure_dirs()
    items: list[dict] = []
    try:
        for fp in sorted(VAULT_DIR.glob("*.json")):
            item = load_vault_snippet(fp.stem, decrypt=False)
            if not item:
                continue
            if not _vault_matches(item, query, labels):
                continue
            items.append(item)
    except OSError:
        pass
    items.sort(key=lambda x: str(x.get("updated_at") or ""), reverse=True)
    return items


def vault_label_counts() -> list[dict]:
    """[{name, count}] across all entries, case-insensitive merge, most used first. Metadata only."""
    counts: dict[str, list] = {}
    for item in list_vault_snippets():
        for t in item["tags"]:
            c = counts.setdefault(t.lower(), [t, 0])
            c[1] += 1
    out = [{"name": n, "count": c} for n, c in counts.values()]
    out.sort(key=lambda x: (-x["count"], x["name"].lower()))
    return out


def vault_rename_label(old: str, new: str | None) -> int:
    """Rename (or remove, when new is empty) a label on every entry. Rewrites plaintext metadata only:
    the encrypted body blob is left untouched, so no key is needed and nothing is decrypted."""
    ensure_dirs()
    old_l = str(old or "").strip().lower()
    new_s = str(new or "").strip()[:40]
    if not old_l:
        return 0
    changed = 0
    with _lock:
        for fp in sorted(VAULT_DIR.glob("*.json")):
            data = _vault_read_raw(fp.stem)
            if not data:
                continue
            tags = _normalize_vault_tags(data.get("tags"))
            if old_l not in [t.lower() for t in tags]:
                continue
            nt = []
            for t in tags:
                nt.append(new_s if t.lower() == old_l else t)
            data["tags"] = _normalize_vault_tags([t for t in nt if t])
            data["updated_at"] = iso_now()
            tmp = VAULT_DIR / f".{fp.stem}.json.tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
            os.replace(tmp, fp)
            changed += 1
    return changed


def save_vault_snippet(entry: dict) -> dict:
    """Encrypts the body with a fresh nonce on every write. Returns metadata + plaintext body."""
    ensure_dirs()
    vid = _vault_safe_id(str(entry.get("id") or "")) or uuid.uuid4().hex[:12]
    now = iso_now()
    body = str(entry.get("body") or "")[:100_000]
    out = {
        "id": vid,
        "title": str(entry.get("title") or "").strip()[:200] or "Untitled",
        "tags": _normalize_vault_tags(entry.get("tags")),
        "created_at": entry.get("created_at") or now,
        "updated_at": now,
        "enc": vault_encrypt(vid, body),
    }
    fp = VAULT_DIR / f"{vid}.json"
    tmp = VAULT_DIR / f".{vid}.json.tmp"
    with _lock:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
        os.replace(tmp, fp)
        try:
            VAULT_DIR.chmod(0o700)
        except OSError:
            pass
    res = {k: v for k, v in out.items() if k != "enc"}
    res.update(body=body, encrypted=True, locked=False)
    return res


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


def load_totp() -> dict | None:
    if not TOTP_FILE.exists():
        return None
    try:
        data = json.loads(TOTP_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (json.JSONDecodeError, OSError):
        return None


def save_totp(data: dict) -> None:
    TOTP_FILE.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    TOTP_FILE.chmod(0o600)


def totp_enabled() -> bool:
    data = load_totp()
    return bool(data and data.get("enabled") and data.get("secret"))


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _totp_value(secret: str, counter: int) -> str:
    padded = secret.upper() + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    digest = hmac.new(key, int(counter).to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return str(binary % (10 ** TOTP_DIGITS)).zfill(TOTP_DIGITS)


def verify_totp(code: str, config: dict, now: float | None = None, consume: bool = False) -> bool:
    code = str(code or "").replace(" ", "").strip()
    if not (code.isdigit() and len(code) == TOTP_DIGITS):
        return False
    current = int((time.time() if now is None else now) // TOTP_STEP_SEC)
    last = int(config.get("last_counter", -1))
    for delta in range(-TOTP_WINDOW, TOTP_WINDOW + 1):
        counter = current + delta
        if consume and counter <= last:
            continue
        if hmac.compare_digest(_totp_value(str(config.get("secret") or ""), counter), code):
            if consume:
                config["last_counter"] = counter
                save_totp(config)
            return True
    return False


def _recovery_hash(code: str) -> str:
    return hmac.new(session_secret(), str(code).strip().upper().encode(), hashlib.sha256).hexdigest()


def consume_recovery_code(code: str, config: dict) -> bool:
    candidate = _recovery_hash(code)
    hashes = list(config.get("recovery_hashes") or [])
    for idx, stored in enumerate(hashes):
        if hmac.compare_digest(candidate, str(stored)):
            hashes.pop(idx)
            config["recovery_hashes"] = hashes
            save_totp(config)
            return True
    return False


def make_recovery_codes(count: int = 8) -> list[str]:
    codes = []
    for _ in range(count):
        raw = base64.b32encode(secrets.token_bytes(7)).decode("ascii").rstrip("=")[:10]
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def totp_uri(secret: str, account: str = "owner") -> str:
    label = urllib.parse.quote(f"Nullink:{account}", safe="")
    params = urllib.parse.urlencode({
        "secret": secret,
        "issuer": "Nullink",
        "algorithm": "SHA1",
        "digits": str(TOTP_DIGITS),
        "period": str(TOTP_STEP_SEC),
    })
    return f"otpauth://totp/{label}?{params}"


# ---------- Auth state: PIN, lockout, server-side sessions (2026-10-06 hardening) ----------
# One re-entrant lock for all auth state files (otp/totp/rate/sessions). Separate from
# the general _lock so auth code never deadlocks against data helpers.
_auth_lock = threading.RLock()

LOOPBACK_ADDRS = ("127.0.0.1", "::1", "localhost")
# Any of these on a loopback request means it came through a proxy (Caddy), not a local tool.
PROXY_HEADERS = ("X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded", "X-Real-IP")
PUBLIC_HTTPS_HOSTS = {"nullverse.cloud", "nullverse.216.158.238.236.sslip.io",
                      "nullink.nullverse.cloud", "nullink.216.158.238.236.sslip.io"}
# Nullverse projects portal hosts (sign-in page, /projects, short project paths).
PORTAL_HOSTS = {"nullverse.cloud", "nullverse.216.158.238.236.sslip.io"}
SSLIP_PORTAL_HOSTS = {"nullverse.216.158.238.236.sslip.io"}

PIN_TTL_SEC = 24 * 3600
PIN_KDF = "pbkdf2-sha256"
PIN_KDF_ITERATIONS = 200_000

# Per-client lockout (client = Caddy-appended rightmost X-Forwarded-For hop).
IP_MAX_FAILS = 5
IP_LOCK_BASE_SEC = 15 * 60          # 15 min, then 30, 60, ... (doubles each lockout)
IP_LOCK_MAX_SEC = 24 * 3600
IP_STATE_TTL_SEC = 24 * 3600        # forget a client 24h after its last failure/lock
RATE_MAX_IPS = 5000
# Global safety ceiling across all clients (needs >=10 distinct IPs to reach).
GLOBAL_FAIL_WINDOW_SEC = 3600
GLOBAL_MAX_FAILS = 50
GLOBAL_LOCK_SEC = 30 * 60

STEPUP_WINDOW_SEC = 5 * 60
# SSH terminal (2026-10-19): separate TOTP-only step-up, valid 10 minutes, checked by nullink-ssh.
SSH_STEPUP_WINDOW_SEC = 10 * 60
SSH_ALLOWED_ORIGINS = ("https://nullink.nullverse.cloud", "https://nullink.216.158.238.236.sslip.io")
SSH_AUDIT_FILE = Path(__file__).resolve().parent / "data" / "ssh_audit.jsonl"
MAX_SESSIONS = 50
SESSION_TOUCH_SEC = 300
SESSION_COOKIE_VERSION = "v2"


def _atomic_write_json(path: Path, data, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp." + secrets.token_hex(4))
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
    try:
        os.chmod(path, mode)
    except OSError:
        pass


# ----- Single-use PIN -----
def generate_pin() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def _pin_digest(pin: str, salt: str, kdf: str | None, iterations: int | None) -> str:
    if kdf == PIN_KDF:
        return hashlib.pbkdf2_hmac("sha256", pin.encode(), salt.encode(),
                                   int(iterations or PIN_KDF_ITERATIONS)).hex()
    return hash_pin(pin, salt)  # legacy salted SHA-256 records


def write_otp(pin: str, ttl_sec: int | None = None) -> dict:
    """Store a hashed single-use PIN. Never writes the clear PIN anywhere."""
    pin = str(pin or "").strip()
    if not (pin.isdigit() and len(pin) == 6):
        raise ValueError("PIN must be exactly 6 digits")
    ttl = PIN_TTL_SEC if ttl_sec is None else int(ttl_sec)
    ttl = max(60, min(ttl, 7 * 24 * 3600))
    salt = secrets.token_hex(16)
    now = time.time()
    data = {
        "v": 2,
        "kdf": PIN_KDF,
        "iterations": PIN_KDF_ITERATIONS,
        "salt": salt,
        "pin_hash": _pin_digest(pin, salt, PIN_KDF, PIN_KDF_ITERATIONS),
        "created_at": now,
        "expires_at": now + ttl,
        "single_use": True,
    }
    with _auth_lock:
        _atomic_write_json(OTP_FILE, data)
        legacy_clear = SECRETS / "CURRENT_PIN.txt"
        try:
            legacy_clear.unlink()
        except FileNotFoundError:
            pass
        reset_rate_limits()
    return {"expires_at": data["expires_at"], "ttl_sec": ttl}


def check_pin(code: str, now: float, consume: bool) -> bool:
    otp = load_otp()
    if not otp or not otp.get("pin_hash") or not otp.get("salt"):
        return False
    exp = otp.get("expires_at")
    if exp and float(exp) < now:
        return False
    ok = hmac.compare_digest(
        _pin_digest(code, str(otp["salt"]), otp.get("kdf"), otp.get("iterations")),
        str(otp["pin_hash"]),
    )
    if ok and consume:
        try:
            OTP_FILE.unlink()
        except FileNotFoundError:
            pass
    return ok


# ----- Per-client + global lockout -----
def _empty_rate() -> dict:
    return {"v": 2, "ips": {}, "global": {"fails": [], "locked_until": 0}}


def load_rate() -> dict:
    try:
        data = json.loads(RATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _empty_rate()
    if not isinstance(data, dict) or data.get("v") != 2:
        return _empty_rate()  # legacy single global counter is discarded
    data.setdefault("ips", {})
    g = data.setdefault("global", {})
    g.setdefault("fails", [])
    g.setdefault("locked_until", 0)
    return data


def save_rate(data: dict) -> None:
    _atomic_write_json(RATE_FILE, data)


def reset_rate_limits() -> None:
    with _auth_lock:
        save_rate(_empty_rate())


def _prune_rate(rate: dict, now: float) -> None:
    ips = rate["ips"]
    for ip, st in list(ips.items()):
        last = max(float(st.get("last_fail", 0)), float(st.get("locked_until", 0)))
        if now - last > IP_STATE_TTL_SEC:
            del ips[ip]
    if len(ips) > RATE_MAX_IPS:
        keep = sorted(ips.items(), key=lambda kv: float(kv[1].get("last_fail", 0)), reverse=True)[:RATE_MAX_IPS]
        rate["ips"] = dict(keep)
    g = rate["global"]
    g["fails"] = [t for t in g.get("fails", []) if now - float(t) < GLOBAL_FAIL_WINDOW_SEC]


def rate_locked(rate: dict, ip: str, now: float) -> tuple[bool, int, str]:
    g_until = float(rate["global"].get("locked_until", 0))
    if g_until > now:
        return True, int(g_until - now) + 1, "global"
    st = rate["ips"].get(ip) or {}
    until = float(st.get("locked_until", 0))
    if until > now:
        return True, int(until - now) + 1, "client"
    return False, 0, ""


def rate_record_failure(rate: dict, ip: str, now: float) -> dict:
    st = rate["ips"].setdefault(ip, {"fails": 0, "level": 0, "locked_until": 0, "last_fail": 0})
    st["fails"] = int(st.get("fails", 0)) + 1
    st["last_fail"] = now
    g = rate["global"]
    g["fails"].append(now)
    info = {"locked": False, "retry_after": 0, "attempts_left": max(0, IP_MAX_FAILS - st["fails"]), "scope": ""}
    if st["fails"] >= IP_MAX_FAILS:
        level = int(st.get("level", 0))
        dur = min(IP_LOCK_BASE_SEC * (2 ** level), IP_LOCK_MAX_SEC)
        st["locked_until"] = now + dur
        st["level"] = level + 1
        st["fails"] = 0
        info.update(locked=True, retry_after=int(dur), attempts_left=0, scope="client")
    if len(g["fails"]) >= GLOBAL_MAX_FAILS:
        g["locked_until"] = now + GLOBAL_LOCK_SEC
        g["fails"] = []
        info.update(locked=True, retry_after=max(info["retry_after"], GLOBAL_LOCK_SEC), scope=info["scope"] or "global")
    return info


def rate_record_success(rate: dict, ip: str) -> None:
    rate["ips"].pop(ip, None)


def client_ip(handler: BaseHTTPRequestHandler) -> str:
    """Real client IP. Behind Caddy the TCP peer is loopback and Caddy appends the
    address it actually saw as the RIGHTMOST X-Forwarded-For hop; anything to the
    left is client-supplied and untrusted."""
    peer = handler.client_address[0]
    if peer not in LOOPBACK_ADDRS:
        return peer
    values = handler.headers.get_all("X-Forwarded-For") or []
    hops = [h.strip() for v in values for h in str(v).split(",") if h.strip()]
    if not hops:
        return "local"
    cand = hops[-1].strip("[]")
    try:
        return str(ipaddress.ip_address(cand))
    except ValueError:
        return "unparsable"


# ----- Server-side sessions -----
def _sid_key(sid: str) -> str:
    return hashlib.sha256(sid.encode()).hexdigest()


def _session_sig(sid: str) -> str:
    return hmac.new(session_secret(), b"nullink-session-v2." + sid.encode(), hashlib.sha256).hexdigest()


def file_version(fp) -> dict:
    """Content hash + mtime used by the editor's changed-since-open check."""
    data = Path(fp).read_bytes()
    return {"sha256": hashlib.sha256(data).hexdigest(), "mtime_ns": Path(fp).stat().st_mtime_ns}


def load_sessions() -> dict:
    with _auth_lock:
        try:
            data = json.loads(SESSIONS_FILE.read_text(encoding="utf-8"))
            sessions = data.get("sessions") if isinstance(data, dict) else None
            return sessions if isinstance(sessions, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}


def save_sessions(sessions: dict) -> None:
    with _auth_lock:
        _atomic_write_json(SESSIONS_FILE, {"v": 2, "sessions": sessions})


def _prune_sessions(sessions: dict, now: float) -> dict:
    live = {k: v for k, v in sessions.items()
            if isinstance(v, dict) and float(v.get("expires_at", 0)) > now}
    if len(live) > MAX_SESSIONS:
        live = dict(sorted(live.items(), key=lambda kv: float(kv[1].get("created_at", 0)),
                           reverse=True)[:MAX_SESSIONS])
    return live


def create_session(ip: str, ua: str, method: str, now: float | None = None) -> tuple[str, dict]:
    now = time.time() if now is None else now
    sid = secrets.token_urlsafe(32)
    rec = {
        "id": secrets.token_hex(6),
        "created_at": now,
        "expires_at": now + SESSION_TTL_SEC,
        "last_seen_at": now,
        "stepup_at": now,
        "ip": str(ip)[:64],
        "ua": str(ua or "")[:160],
        "method": method,
    }
    with _auth_lock:
        sessions = _prune_sessions(load_sessions(), now)
        sessions[_sid_key(sid)] = rec
        save_sessions(_prune_sessions(sessions, now))
    return f"{SESSION_COOKIE_VERSION}.{sid}.{_session_sig(sid)}", rec


def _session_key_from_cookie(token: str | None) -> str | None:
    if not token or len(token) > 256:
        return None
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != SESSION_COOKIE_VERSION:
        return None
    sid, sig = parts[1], parts[2]
    if not re.fullmatch(r"[A-Za-z0-9_-]{20,128}", sid):
        return None
    if not hmac.compare_digest(_session_sig(sid), sig):
        return None
    return _sid_key(sid)


def get_session(token: str | None, touch: bool = False) -> dict | None:
    key = _session_key_from_cookie(token)
    if not key:
        return None
    now = time.time()
    with _auth_lock:
        sessions = load_sessions()
        rec = sessions.get(key)
        if not isinstance(rec, dict) or float(rec.get("expires_at", 0)) <= now:
            return None
        if touch and now - float(rec.get("last_seen_at", 0)) > SESSION_TOUCH_SEC:
            rec["last_seen_at"] = now
            sessions[key] = rec
            save_sessions(_prune_sessions(sessions, now))
    out = dict(rec)
    out["_key"] = key
    return out


def mark_stepup(key: str, now: float | None = None) -> bool:
    now = time.time() if now is None else now
    with _auth_lock:
        sessions = load_sessions()
        rec = sessions.get(key)
        if not isinstance(rec, dict):
            return False
        rec["stepup_at"] = now
        sessions[key] = rec
        save_sessions(sessions)
        return True


def mark_ssh_stepup(key: str, now: float | None = None) -> bool:
    now = time.time() if now is None else now
    with _auth_lock:
        sessions = load_sessions()
        rec = sessions.get(key)
        if not isinstance(rec, dict) or rec.get("method") == "guest" or rec.get("guest"):
            return False
        rec["ssh_stepup_at"] = now
        sessions[key] = rec
        save_sessions(sessions)
        return True


def ssh_audit(event: str, **fields) -> None:
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "t": round(time.time(), 3),
           "event": event, "src": "nullink"}
    for k, v in fields.items():
        rec[k] = v if isinstance(v, (int, float, bool)) or v is None else \
            "".join(ch for ch in str(v) if ch.isprintable())[:200]
    try:
        fd = os.open(SSH_AUDIT_FILE, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o660)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, separators=(",", ":")) + "\n")
    except OSError:
        pass


def revoke_session(token: str | None) -> bool:
    key = _session_key_from_cookie(token)
    if not key:
        return False
    with _auth_lock:
        sessions = load_sessions()
        if key not in sessions:
            return False
        del sessions[key]
        save_sessions(_prune_sessions(sessions, time.time()))
        return True


def revoke_all_sessions() -> int:
    with _auth_lock:
        n = len(_prune_sessions(load_sessions(), time.time()))
        save_sessions({})
        return n


def verify_session(token: str | None) -> bool:
    return get_session(token) is not None



# ---------- Guest access (owner-approved one-time guest PINs, 2026-10-14) ----------
GUEST_FILE = DATA / "guest_access.json"
GUEST_AUDIT_FILE = DATA / "guest_audit.jsonl"
GUEST_SLACK_WEBHOOK_FILE = SECRETS / "slack-incoming-webhook.url"
GUEST_LINK = "https://nullink.nullverse.cloud/#guest-access"
GUEST_REQ_PER_IP_HOUR = 5
GUEST_MAX_PENDING = 3
GUEST_PENDING_TTL_SEC = 30 * 60
GUEST_PIN_TTL_SEC = 60            # PIN valid 60 s after approval, single use
GUEST_BLOCK_MIN = 10               # sessions run in 10-minute blocks
GUEST_DEFAULT_SESSION_MIN = GUEST_BLOCK_MIN
GUEST_WARN_SEC = 60                # warn owner ~1 min before a block ends
GUEST_SCOPES = ("read", "full")
GUEST_PIN_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
# Paths no guest may touch (any method, any scope): secrets, tokens, sessions, admin,
# desktop/android gate, and the guest-approval surface itself.
GUEST_OWNER_ONLY_PREFIXES = (
    "/api/auth/tokens", "/api/auth/sessions", "/api/auth/logout-all", "/api/auth/stepup",
    "/api/auth/totp", "/api/auth/gate", "/api/vault", "/api/desktop", "/api/admin",
    "/api/guest", "/api/auth/guest", "/guest-audit", "/api/ssh", "/ssh",
)
GUEST_READ_ALLOWED_WRITES = ("/api/auth/logout",)
# John 2026-10-14: guests see the app shell only, not chat history / files / notes.
GUEST_HIDE_HISTORY = True
GUEST_HISTORY_PREFIXES = ("/api/messages", "/api/files", "/api/fm", "/api/inbox", "/api/session-memory",
                          "/api/playground", "/api/tasks", "/uploads", "/api/replit")


def _guest_clean(value, limit: int) -> str:
    s = re.sub(r"[\x00-\x1f\x7f]+", " ", str(value or "")).strip()
    return s[:limit]


def guest_audit(event: str, **fields) -> None:
    rec = {"ts": time.time(), "iso": iso_now(), "event": event}
    rec.update({k: v for k, v in fields.items() if v is not None})
    try:
        GUEST_AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(GUEST_AUDIT_FILE), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass


def load_guest() -> dict:
    with _auth_lock:
        try:
            data = json.loads(GUEST_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                data.setdefault("requests", {})
                data.setdefault("rate", {})
                return data
        except (OSError, json.JSONDecodeError):
            pass
        return {"requests": {}, "rate": {}}


def save_guest(data: dict) -> None:
    with _auth_lock:
        _atomic_write_json(GUEST_FILE, data)


def _guest_prune(data: dict, now: float) -> dict:
    reqs = data.get("requests") or {}
    for r in reqs.values():
        if r.get("status") == "pending" and now - float(r.get("created_at", 0)) > GUEST_PENDING_TTL_SEC:
            r["status"] = "expired"
            r["decided_at"] = now
        if r.get("status") == "approved" and float(r.get("pin_expires_at", 0)) <= now:
            r["status"] = "pin_expired"
            r.pop("pin_hash", None)
    # keep 7 days of history, at most 200 records
    keep = {k: v for k, v in reqs.items() if now - float(v.get("created_at", 0)) < 7 * 86400}
    if len(keep) > 200:
        keep = dict(sorted(keep.items(), key=lambda kv: kv[1].get("created_at", 0), reverse=True)[:200])
    data["requests"] = keep
    rate = data.get("rate") or {}
    data["rate"] = {ip: [t for t in ts if now - t < 3600] for ip, ts in rate.items()
                    if any(now - t < 3600 for t in ts)}
    return data


def generate_guest_pin() -> str:
    raw = "".join(secrets.choice(GUEST_PIN_ALPHABET) for _ in range(10))
    return raw[:5] + "-" + raw[5:]


def _guest_pin_norm(pin: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", str(pin or "").upper())


def _guest_pin_hash(pin: str) -> str:
    return hmac.new(session_secret(), b"nullink-guest-pin." + _guest_pin_norm(pin).encode(),
                    hashlib.sha256).hexdigest()


def _guest_public(r: dict) -> dict:
    return {k: r.get(k) for k in ("id", "name", "reason", "ip", "ua", "created_at", "status",
                                   "decided_at", "scope", "pin_expires_at", "session_minutes",
                                   "redeemed_at", "source")}


def guest_notify_slack(req: dict) -> None:
    def esc(s):
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    try:
        url = GUEST_SLACK_WEBHOOK_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return
    if not url.startswith("https://hooks.slack.com/"):
        return
    text = (f":key: Nullink guest access request *{esc(req['id'])}*\n"
            f"From: {esc(req.get('name') or '(no name)')}\n"
            f"Reason: {esc(req.get('reason') or '(none)')}\n"
            f"IP: {esc(req.get('ip'))}\n"
            f"Approve or deny: {GUEST_LINK}")

    def run():
        try:
            rq = urllib.request.Request(url, data=json.dumps({"text": text}).encode(),
                                        headers={"Content-Type": "application/json"}, method="POST")
            urllib.request.urlopen(rq, timeout=8).read()
            guest_audit("slack_notified", request_id=req["id"])
        except Exception as e:  # noqa: BLE001
            guest_audit("slack_notify_failed", request_id=req["id"], error=type(e).__name__)
    threading.Thread(target=run, daemon=True).start()


def guest_create_request(name: str, reason: str, ip: str, ua: str, now: float | None = None):
    """Returns (status, body). Never reveals other requests."""
    now = time.time() if now is None else now
    with _auth_lock:
        data = _guest_prune(load_guest(), now)
        hits = data["rate"].get(ip, [])
        if len(hits) >= GUEST_REQ_PER_IP_HOUR:
            guest_audit("request_rate_limited", ip=ip)
            return 429, {"error": "rate_limited", "message": "Too many requests. Try again later."}
        pending = [r for r in data["requests"].values() if r.get("status") == "pending"]
        if len(pending) >= GUEST_MAX_PENDING:
            guest_audit("request_rejected_full", ip=ip)
            return 429, {"error": "too_many_pending",
                         "message": "The owner already has several pending requests. Try again later."}
        rid = "GR-" + "".join(secrets.choice(GUEST_PIN_ALPHABET) for _ in range(6))
        poll = secrets.token_urlsafe(18)
        req = {"id": rid, "name": _guest_clean(name, 80), "reason": _guest_clean(reason, 200),
               "ip": str(ip)[:64], "ua": _guest_clean(ua, 160), "created_at": now,
               "status": "pending", "poll_hash": hashlib.sha256(poll.encode()).hexdigest(),
               "source": "request"}
        data["requests"][rid] = req
        data["rate"].setdefault(ip, []).append(now)
        save_guest(data)
    guest_audit("request_created", request_id=rid, ip=req["ip"], name=req["name"], reason=req["reason"])
    guest_notify_slack(req)
    return 201, {"ok": True, "request_id": rid, "poll_token": poll, "status": "pending",
                 "message": "Waiting for the owner to approve. Ask them for your one-time guest PIN."}


def _guest_opts(body: dict):
    scope = str(body.get("scope") or "read")
    if scope not in GUEST_SCOPES:
        return None, "invalid_options"
    return {"scope": scope, "session_minutes": GUEST_BLOCK_MIN}, None


def guest_approve(rid: str, opts: dict, by: str, now: float | None = None):
    now = time.time() if now is None else now
    pin = generate_guest_pin()
    with _auth_lock:
        data = _guest_prune(load_guest(), now)
        r = data["requests"].get(rid)
        if not r:
            return 404, {"error": "not_found"}
        if r.get("status") != "pending":
            return 409, {"error": "not_pending", "status": r.get("status")}
        r.update({"status": "approved", "decided_at": now, "decided_by": by, "scope": opts["scope"],
                  "session_minutes": opts["session_minutes"], "pin_hash": _guest_pin_hash(pin),
                  "pin_expires_at": now + GUEST_PIN_TTL_SEC})
        save_guest(data)
    guest_audit("request_approved", request_id=rid, by=by, scope=opts["scope"],
                pin_ttl_sec=GUEST_PIN_TTL_SEC, session_minutes=opts["session_minutes"])
    return 200, {"ok": True, "request_id": rid, "pin": pin, "pin_expires_at": now + GUEST_PIN_TTL_SEC,
                 "scope": opts["scope"], "session_minutes": opts["session_minutes"]}


def guest_mint(name: str, reason: str, opts: dict, by: str, ip: str, now: float | None = None):
    now = time.time() if now is None else now
    rid = "GR-" + "".join(secrets.choice(GUEST_PIN_ALPHABET) for _ in range(6))
    with _auth_lock:
        data = _guest_prune(load_guest(), now)
        data["requests"][rid] = {"id": rid, "name": _guest_clean(name, 80) or "Guest",
                                 "reason": _guest_clean(reason, 200), "ip": ip, "ua": "",
                                 "created_at": now, "status": "pending", "source": "mint"}
        save_guest(data)
    guest_audit("pin_minted", request_id=rid, by=by)
    return guest_approve(rid, opts, by, now)


def guest_deny(rid: str, by: str, now: float | None = None):
    now = time.time() if now is None else now
    with _auth_lock:
        data = _guest_prune(load_guest(), now)
        r = data["requests"].get(rid)
        if not r:
            return 404, {"error": "not_found"}
        if r.get("status") not in ("pending", "approved"):
            return 409, {"error": "not_pending", "status": r.get("status")}
        r["status"] = "denied"
        r["decided_at"] = now
        r["decided_by"] = by
        r.pop("pin_hash", None)
        save_guest(data)
    guest_audit("request_denied", request_id=rid, by=by)
    return 200, {"ok": True, "request_id": rid, "status": "denied"}


def guest_redeem_pin(pin: str, now: float | None = None):
    """Consume a guest PIN. Returns the request record (copy) or None."""
    now = time.time() if now is None else now
    norm = _guest_pin_norm(pin)
    if len(norm) != 10:
        return None
    h = _guest_pin_hash(norm)
    with _auth_lock:
        data = _guest_prune(load_guest(), now)
        hit = None
        for r in data["requests"].values():
            ph = r.get("pin_hash")
            if r.get("status") == "approved" and ph and hmac.compare_digest(ph, h):
                hit = r
                break
        if not hit:
            save_guest(data)
            return None
        hit["status"] = "redeemed"
        hit["redeemed_at"] = now
        hit.pop("pin_hash", None)
        save_guest(data)
        return dict(hit)


def create_guest_session(req: dict, ip: str, ua: str, now: float | None = None) -> tuple[str, dict]:
    now = time.time() if now is None else now
    sid = secrets.token_urlsafe(32)
    minutes = int(req.get("session_minutes") or GUEST_DEFAULT_SESSION_MIN)
    rec = {"id": secrets.token_hex(6), "created_at": now, "expires_at": now + minutes * 60,
           "last_seen_at": now, "stepup_at": 0, "ip": str(ip)[:64], "ua": str(ua or "")[:160],
           "method": "guest", "label": "guest", "guest": True,
           "scope": req.get("scope") if req.get("scope") in GUEST_SCOPES else "read",
           "guest_name": req.get("name") or "Guest", "request_id": req.get("id")}
    with _auth_lock:
        sessions = _prune_sessions(load_sessions(), now)
        sessions[_sid_key(sid)] = rec
        save_sessions(_prune_sessions(sessions, now))
    with _auth_lock:
        data = load_guest()
        r = data["requests"].get(req.get("id"))
        if r:
            r["session_id"] = rec["id"]
            save_guest(data)
    return f"{SESSION_COOKIE_VERSION}.{sid}.{_session_sig(sid)}", rec


def list_guest_sessions(now: float | None = None) -> list:
    now = time.time() if now is None else now
    out = []
    for rec in _prune_sessions(load_sessions(), now).values():
        if rec.get("method") == "guest":
            out.append({k: rec.get(k) for k in ("id", "created_at", "expires_at", "last_seen_at", "ip",
                                                "ua", "scope", "guest_name", "request_id", "label",
                                                "extensions")})
            out[-1]["expiring_soon"] = float(rec.get("expires_at", 0)) - now <= GUEST_WARN_SEC
    out.sort(key=lambda r: r.get("created_at") or 0, reverse=True)
    return out


def end_guest_sessions(session_id: str | None = None) -> int:
    with _auth_lock:
        sessions = load_sessions()
        drop = [k for k, v in sessions.items() if isinstance(v, dict) and v.get("method") == "guest"
                and (session_id is None or v.get("id") == session_id)]
        for k in drop:
            del sessions[k]
        save_sessions(_prune_sessions(sessions, time.time()))
        return len(drop)


def extend_guest_session(session_id: str, by: str, now: float | None = None):
    now = time.time() if now is None else now
    with _auth_lock:
        sessions = load_sessions()
        for k, v in sessions.items():
            if isinstance(v, dict) and v.get("method") == "guest" and v.get("id") == session_id \
                    and float(v.get("expires_at", 0)) > now:
                v["expires_at"] = float(v["expires_at"]) + GUEST_BLOCK_MIN * 60
                v["extensions"] = int(v.get("extensions") or 0) + 1
                v.pop("warned_for", None)
                sessions[k] = v
                save_sessions(sessions)
                guest_audit("session_extended", by=by, session_id=session_id,
                            new_expires_at=v["expires_at"], extensions=v["extensions"])
                return v
    return None


def _guest_slack(text: str, event: str, **kw) -> None:
    try:
        url = GUEST_SLACK_WEBHOOK_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return
    if not url.startswith("https://hooks.slack.com/"):
        return
    try:
        rq = urllib.request.Request(url, data=json.dumps({"text": text}).encode(),
                                    headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(rq, timeout=8).read()
        guest_audit(event + "_slack", **kw)
    except Exception as e:  # noqa: BLE001
        guest_audit(event + "_slack_failed", error=type(e).__name__, **kw)


def guest_watch_tick(now: float | None = None, notify=True) -> list:
    """Warn once per block ~1 min before expiry; audit expiries. Returns warned ids."""
    now = time.time() if now is None else now
    warned, expired = [], []
    with _auth_lock:
        sessions = load_sessions()
        changed = False
        for k, v in list(sessions.items()):
            if not isinstance(v, dict) or v.get("method") != "guest":
                continue
            exp = float(v.get("expires_at", 0))
            if exp <= now:
                expired.append(v.get("id"))
                del sessions[k]
                changed = True
            elif exp - now <= GUEST_WARN_SEC and v.get("warned_for") != exp:
                v["warned_for"] = exp
                warned.append(dict(v))
                changed = True
        if changed:
            save_sessions(sessions)
    for sid in expired:
        guest_audit("session_expired", session_id=sid)
    for v in warned:
        guest_audit("session_expiring_warned", session_id=v.get("id"))
        if notify:
            name = str(v.get("guest_name") or "Guest").replace("<", "&lt;").replace(">", "&gt;")
            threading.Thread(target=slack_session_warn, daemon=True, args=(v,)).start()
    return [v.get("id") for v in warned]


def guest_watch_start() -> None:
    def loop():
        while True:
            try:
                guest_watch_tick()
            except Exception:  # noqa: BLE001
                pass
            try:
                slack_guest_sweep()
            except Exception:  # noqa: BLE001
                pass
            time.sleep(10)
    threading.Thread(target=loop, daemon=True, name="guest-watch").start()


# ---------- Guest access via Slack DM buttons (Morc bot, 2026-10-14) ----------
# John: alert + Approve/Deny buttons go to his Slack DM (not #general); PIN is DMed; Extend/Close too.
# Webhook (#general) is only a fallback when the DM post fails.
SLACK_OWNER_UID = os.environ.get("NULLINK_SLACK_OWNER_UID", "U0C2TTY5TT3")
SLACK_API_BASE = os.environ.get("SLACK_API_BASE", "https://slack.com/api").rstrip("/")
SLACK_REPLAY_SEC = 300
SLACK_CRED_FILES = {"token": "slack_morc_token", "signing_secret": "slack_morc_signing_secret"}


def _slack_cred(kind: str) -> str | None:
    d = os.environ.get("CREDENTIALS_DIRECTORY")
    paths = [Path(d) / SLACK_CRED_FILES[kind]] if d else []
    paths.append(SECRETS / SLACK_CRED_FILES[kind])
    for p in paths:
        try:
            v = p.read_text(encoding="utf-8").strip()
            if v:
                return v
        except OSError:
            continue
    return None


def slack_verify(secret: str | None, ts: str | None, sig: str | None, body: bytes, now: float | None = None) -> bool:
    if not secret or not ts or not sig:
        return False
    now = time.time() if now is None else now
    try:
        if abs(now - int(ts)) > SLACK_REPLAY_SEC:
            return False
    except ValueError:
        return False
    want = "v0=" + hmac.new(secret.encode(), b"v0:" + ts.encode() + b":" + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, sig)


_SLACK_BACKOFF_UNTIL = 0.0


def slack_call(method: str, params: dict) -> dict:
    tok = _slack_cred("token")
    if not tok:
        return {"ok": False, "error": "no_token"}
    rq = urllib.request.Request(f"{SLACK_API_BASE}/{method}", data=json.dumps(params).encode(),
                                headers={"Authorization": f"Bearer {tok}",
                                         "Content-Type": "application/json; charset=utf-8"}, method="POST")
    global _SLACK_BACKOFF_UNTIL
    if method == "chat.update" and time.time() < _SLACK_BACKOFF_UNTIL:
        return {"ok": False, "error": "ratelimited_backoff"}
    try:
        with urllib.request.urlopen(rq, timeout=8) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 429:
            try:
                wait = float(e.headers.get("Retry-After") or 30)
            except ValueError:
                wait = 30.0
            _SLACK_BACKOFF_UNTIL = time.time() + max(1.0, wait)
            guest_audit("slack_rate_limited", method=method, retry_after=wait)
            return {"ok": False, "error": "ratelimited"}
        return {"ok": False, "error": f"HTTP{e.code}"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": type(e).__name__}


def _slack_dm_channel() -> str | None:
    r = slack_call("conversations.open", {"users": SLACK_OWNER_UID})
    return ((r.get("channel") or {}).get("id")) if r.get("ok") else None


def _sesc(s) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _guest_req_text(req: dict) -> str:
    return (f":key: *Nullink guest access request* `{_sesc(req['id'])}`\n"
            f"*From:* {_sesc(req.get('name') or '(no name)')}\n"
            f"*Reason:* {_sesc(req.get('reason') or '(none)')}\n"
            f"*IP:* {_sesc(req.get('ip'))}")


_SLACK_STATUS_LINE = {
    "approved": ":white_check_mark: Approved by John — PIN sent below (valid 60 s).",
    "redeemed": ":white_check_mark: Approved by John — PIN used.",
    "pin_expired": ":white_check_mark: Approved by John — PIN expired unused.",
    "denied": ":no_entry: Denied.",
    "expired": ":hourglass: Expired (not answered within 30 min).",
}


def guest_request_blocks(req: dict, status: str = "pending") -> list:
    blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": _guest_req_text(req)}}]
    if status == "pending":
        blocks.append({"type": "actions", "block_id": "guest_req", "elements": [
            {"type": "button", "action_id": "guest_approve", "style": "primary", "value": req["id"],
             "text": {"type": "plain_text", "text": "Approve (read-only)"}},
            {"type": "button", "action_id": "guest_deny", "style": "danger", "value": req["id"],
             "text": {"type": "plain_text", "text": "Deny"}}]})
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn",
                       "text": f"The one-time PIN will be DMed here, valid 60 s. Or use {GUEST_LINK}"}]})
    else:
        line = (":white_check_mark: Approved by John — " + _sesc(_guest_used_line(req))) if status == "redeemed" \
            else _SLACK_STATUS_LINE.get(status, _sesc(status))
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": line}]})
    return blocks


def _guest_set_fields(rid: str, **fields) -> None:
    with _auth_lock:
        data = load_guest()
        r = data["requests"].get(rid)
        if r is not None:
            r.update(fields)
            save_guest(data)


def _guest_webhook_fallback(text: str, event: str, **kw) -> None:
    _guest_slack(text, event, **kw)


def guest_notify_slack(req: dict) -> None:  # noqa: F811 (replaces the #general webhook alert)
    def run():
        ch = _slack_dm_channel()
        r = slack_call("chat.postMessage", {"channel": ch, "text": f"Nullink guest access request {req['id']}",
                                            "blocks": guest_request_blocks(req)}) if ch else {"ok": False,
                                                                                              "error": "dm_open_failed"}
        if r.get("ok"):
            _guest_set_fields(req["id"], slack_channel=r.get("channel"), slack_ts=r.get("ts"),
                              slack_state="pending")
            guest_audit("slack_dm_notified", request_id=req["id"])
            return
        guest_audit("slack_dm_failed", request_id=req["id"], error=str(r.get("error"))[:60])
        _guest_webhook_fallback(
            f":key: Nullink guest access request *{_sesc(req['id'])}* from {_sesc(req.get('name') or '(no name)')}. "
            f"(Slack DM failed.) Approve or deny: {GUEST_LINK}", "request_fallback", request_id=req["id"])
    threading.Thread(target=run, daemon=True).start()


def _slack_update_request(rid: str, status: str) -> None:
    data = load_guest()
    r = data["requests"].get(rid)
    if not r or not r.get("slack_ts") or r.get("slack_state") == status:
        return
    res = slack_call("chat.update", {"channel": r["slack_channel"], "ts": r["slack_ts"],
                                     "text": f"Nullink guest request {rid}: {status}",
                                     "blocks": guest_request_blocks(r, status)})
    if res.get("ok"):
        _guest_set_fields(rid, slack_state=status)


def _et_time(ts: float) -> str:
    try:
        from zoneinfo import ZoneInfo
        import datetime as _dt
        d = _dt.datetime.fromtimestamp(ts, ZoneInfo("America/New_York"))
        return d.strftime("%I:%M:%S %p").lstrip("0") + " ET"
    except Exception:  # noqa: BLE001
        return time.strftime("%H:%M:%S UTC", time.gmtime(ts))


def _guest_used_line(r: dict) -> str:
    return (f"Used at {_et_time(float(r.get('redeemed_at') or time.time()))} by "
            f"{r.get('name') or 'Guest'} from {r.get('redeemed_ip') or 'unknown IP'}")


def slack_pin_finalize(rid: str) -> None:
    """Edit the PIN-only DM once the PIN is used or expired. State is persisted, so this
    is driven by the redeem handler (immediately) and the 10 s sweep (expiry, restarts)."""
    with _auth_lock:
        data = _guest_prune(load_guest(), time.time())
        save_guest(data)
    r = data["requests"].get(rid) or {}
    st = r.get("status")
    if not r.get("slack_pin_ts") or r.get("slack_pin_final") or st in ("pending", "approved"):
        return
    text = _guest_used_line(r) if st == "redeemed" else "expired"
    res = slack_call("chat.update", {"channel": r.get("slack_pin_channel") or r.get("slack_channel"),
                                     "ts": r["slack_pin_ts"], "text": text})
    if r.get("slack_ctx_ts"):
        slack_call("chat.update", {"channel": r.get("slack_pin_channel") or r.get("slack_channel"),
                                   "ts": r["slack_ctx_ts"], "text": _ctx_final_text(r)})
    if res.get("ok"):
        _guest_set_fields(rid, slack_pin_final=True)
        guest_audit("slack_pin_dm_finalized", request_id=rid, outcome="used" if st == "redeemed" else "expired",
                    ip=r.get("redeemed_ip"))
    _slack_update_request(rid, st)


def _mmss(sec: float) -> str:
    sec = max(0, int(sec))
    return f"{sec // 60}:{sec % 60:02d}"


def _ctx_text(rid: str, expires_at: float, now: float | None = None) -> str:
    now = time.time() if now is None else now
    return (f":white_check_mark: Approved {rid}. PIN below · Expires in {_mmss(expires_at - now)} "
            f"(at {_et_time(expires_at)}). One-time; read-only guest session, 10 min.")


def _ctx_final_text(r: dict) -> str:
    if r.get("status") == "redeemed":
        return f":white_check_mark: Approved {r['id']} · PIN {_guest_used_line(r)}."
    if r.get("status") == "denied":
        return f":no_entry: {r['id']} denied · PIN cancelled."
    return f":hourglass: Approved {r['id']} · PIN expired unused."


def _slack_pin_dm(rid: str, channel: str, pin: str, expires_at: float) -> None:
    hhmm = _et_time(expires_at)
    c = slack_call("chat.postMessage", {"channel": channel, "text": _ctx_text(rid, expires_at)})
    if c.get("ok"):
        _guest_set_fields(rid, slack_ctx_ts=c.get("ts"), slack_ctx_at=time.time())
    # PIN-only message (plain text, no formatting) so long-press copy grabs just the code.
    r = slack_call("chat.postMessage", {"channel": channel, "text": pin, "mrkdwn": False})
    if not r.get("ok"):
        guest_audit("slack_pin_dm_failed", request_id=rid, error=str(r.get("error"))[:60])
        return
    guest_audit("slack_pin_dm_sent", request_id=rid)
    _guest_set_fields(rid, slack_pin_ts=r.get("ts"), slack_pin_channel=channel)


# ---------- MCP gateway approvals (Phase 1 test copy, 2026-10-17) ----------
# John's signed clicks on mcpgw_* buttons are forwarded to the separate approval service
# (127.0.0.1:8777). Additive only: guest_* / share_* handling is untouched.
MCPGW_FORWARD_URL = os.environ.get("MCPGW_FORWARD_URL", "http://127.0.0.1:8777/internal/slack-action")
MCPGW_FORWARD_SECRET_FILE = os.environ.get("MCPGW_FORWARD_SECRET_FILE", "/etc/mcp-gateway/slack_forward_secret")


def _mcpgw_forward(aid: str, val: str, user: str, channel, msg_ts) -> dict:
    try:
        secret = Path(MCPGW_FORWARD_SECRET_FILE).read_text(encoding="utf-8").strip()
    except OSError:
        secret = ""
    if not secret:
        guest_audit("mcpgw_forward_failed", why="no_secret", action=aid[:30])
        return {"ok": False, "error": "mcpgw_unconfigured"}
    body = json.dumps({"action_id": aid, "value": val[:40], "user": user, "channel": channel, "ts": msg_ts}).encode()
    req = urllib.request.Request(MCPGW_FORWARD_URL, data=body, method="POST",
                                 headers={"Content-Type": "application/json", "X-Mcpgw-Forward": secret})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode("utf-8") or "{}")
    except (urllib.error.URLError, OSError, ValueError) as e:
        guest_audit("mcpgw_forward_failed", why=type(e).__name__, action=aid[:30])
        return {"ok": False, "error": "mcpgw_unreachable"}


def slack_handle_interaction(payload: dict) -> dict:
    """Process one block_actions payload. Returns a small result dict (for tests/audit)."""
    user = ((payload.get("user") or {}).get("id")) or ""
    actions = payload.get("actions") or []
    if payload.get("type") != "block_actions" or not actions:
        return {"ok": False, "error": "unsupported"}
    act = actions[0]
    aid, val = act.get("action_id"), str(act.get("value") or "")
    channel = ((payload.get("channel") or {}).get("id")) or ((payload.get("container") or {}).get("channel_id"))
    msg_ts = ((payload.get("container") or {}).get("message_ts")) or ((payload.get("message") or {}).get("ts"))
    if str(aid).startswith("mcpgw_"):
        # Signed clicks on MCP gateway buttons are forwarded for any Slack user: the approval service
        # verifies the clicker (stage 2: John only; stage 1: the namespace admin's mapped Slack id).
        return _mcpgw_forward(str(aid), val, user, channel, msg_ts)
    if user != SLACK_OWNER_UID:
        guest_audit("slack_click_rejected", slack_user=user[:20], action=str(aid)[:30])
        return {"ok": False, "error": "wrong_user"}
    by = "slack:" + user
    if str(aid).startswith("share_"):
        return share_links.slack_action(aid, val, by, channel, msg_ts)
    if aid in ("guest_approve", "guest_deny") and re.match(r"^GR-[A-Z0-9]{6}$", val):
        if aid == "guest_deny":
            st, out = guest_deny(val, by)
            if st == 200:
                guest_audit("slack_denied", request_id=val, by=by)
                _slack_update_request(val, "denied")
            else:
                _slack_update_request(val, out.get("status") or "expired")
            return {"ok": st == 200, "status": out.get("status"), "code": st}
        st, out = guest_approve(val, {"scope": "read", "session_minutes": GUEST_BLOCK_MIN}, by)
        if st == 200:
            guest_audit("slack_approved", request_id=val, by=by)
            _slack_update_request(val, "approved")
            if channel:
                _slack_pin_dm(val, channel, out["pin"], out["pin_expires_at"])
            return {"ok": True, "status": "approved", "code": 200}
        _slack_update_request(val, out.get("status") or "expired")
        guest_audit("slack_click_noop", request_id=val, by=by, status=out.get("status"))
        return {"ok": False, "status": out.get("status"), "code": st}
    if aid in ("guest_extend", "guest_close") and re.match(r"^[0-9a-f]{12}$", val):
        if aid == "guest_extend":
            v = extend_guest_session(val, by)
            line = (f":heavy_plus_sign: Extended by John — now ends "
                    f"{time.strftime('%H:%M', time.localtime(v['expires_at']))}.") if v else \
                ":hourglass: Session already ended."
        else:
            n = end_guest_sessions(val)
            guest_audit("session_ended", by=by, session_id=val, count=n)
            v = n
            line = ":x: Closed by John." if n else ":hourglass: Session already ended."
            if n:
                _sess_track(val, {"closed_by_john": True})
        tr = (load_guest().get("slack_sessions") or {}).get(val) or {}
        if tr.get("ts"):
            slack_session_status_tick(force={val})
        if channel and msg_ts and msg_ts != tr.get("ts"):
            slack_call("chat.update", {"channel": channel, "ts": msg_ts, "text": line,
                                       "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text":
                                                   (payload.get("message") or {}).get("text") or "Guest session"}},
                                                  {"type": "context", "elements": [{"type": "mrkdwn", "text": line}]}]})
        return {"ok": bool(v), "status": aid}
    return {"ok": False, "error": "unknown_action"}


def _sess_blocks(text: str, sid: str, buttons: bool) -> list:
    b = [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]
    if buttons:
        b.append({"type": "actions", "block_id": "guest_sess", "elements": [
            {"type": "button", "action_id": "guest_extend", "style": "primary", "value": sid,
             "text": {"type": "plain_text", "text": "Extend +10 min"}},
            {"type": "button", "action_id": "guest_close", "style": "danger", "value": sid,
             "text": {"type": "plain_text", "text": "Close"}}]})
    return b


def _sess_text(v: dict, now: float, warn: bool = False) -> str:
    left = float(v.get("expires_at", 0)) - now
    mins = max(0, int((left + 59) // 60))
    scope = "read-only" if (v.get("scope") or "read") == "read" else "full access"
    t = (f":busts_in_silhouette: Guest session ({scope}) for *{_sesc(v.get('guest_name') or 'Guest')}* · "
         f"{mins} min left (ends {_et_time(float(v.get('expires_at', 0)))})")
    if warn or left <= GUEST_WARN_SEC:
        t = ":hourglass: " + t + " — ending soon: Extend or Close?"
    return t


def slack_session_status_tick(now: float | None = None, force: set | None = None) -> None:
    """One DM status message per active guest session, refreshed every 60 s (or immediately for
    ids in `force`); finalized without buttons once the session ends. ts persisted in guest_access.json."""
    now = time.time() if now is None else now
    force = force or set()
    active = {v.get("id"): v for v in _prune_sessions(load_sessions(), now).values()
              if isinstance(v, dict) and v.get("method") == "guest"}
    track = load_guest().get("slack_sessions") or {}
    for sid, v in active.items():
        t = track.get(sid)
        if t and t.get("final"):
            continue
        if not t:
            ch = _slack_dm_channel()
            r = slack_call("chat.postMessage", {"channel": ch, "text": _sess_text(v, now),
                                                "blocks": _sess_blocks(_sess_text(v, now), sid, True)}) if ch else {}
            if r.get("ok"):
                _sess_track(sid, {"channel": r.get("channel"), "ts": r.get("ts"), "last": now,
                                  "name": v.get("guest_name")})
                guest_audit("slack_session_status_posted", session_id=sid)
            continue
        if sid in force or now - float(t.get("last", 0)) >= 60:
            txt = _sess_text(v, now)
            r = slack_call("chat.update", {"channel": t["channel"], "ts": t["ts"], "text": txt,
                                           "blocks": _sess_blocks(txt, sid, True)})
            if r.get("ok") or r.get("error") not in ("ratelimited", "ratelimited_backoff"):
                _sess_track(sid, {"last": now})
    for sid, t in track.items():
        if sid in active or t.get("final") or not t.get("ts"):
            continue
        txt = f":white_circle: Guest session for *{_sesc(t.get('name') or 'Guest')}* ended at {_et_time(now)}."
        if t.get("closed_by_john"):
            txt = f":x: Guest session for *{_sesc(t.get('name') or 'Guest')}* closed by John at {_et_time(now)}."
        r = slack_call("chat.update", {"channel": t["channel"], "ts": t["ts"], "text": txt,
                                       "blocks": _sess_blocks(txt, sid, False)})
        if r.get("ok") or r.get("error") not in ("ratelimited", "ratelimited_backoff"):
            _sess_track(sid, {"final": True, "last": now})


def _sess_track(sid: str, fields: dict) -> None:
    with _auth_lock:
        data = load_guest()
        tr = data.setdefault("slack_sessions", {})
        tr.setdefault(sid, {}).update(fields)
        cutoff = time.time() - 86400
        data["slack_sessions"] = {k: x for k, x in tr.items() if not x.get("final") or x.get("last", 0) > cutoff}
        save_guest(data)


def slack_ctx_countdown_tick(now: float | None = None) -> None:
    now = time.time() if now is None else now
    for rid, r in (load_guest().get("requests") or {}).items():
        if r.get("status") == "approved" and r.get("slack_ctx_ts") and not r.get("slack_pin_final") \
                and float(r.get("pin_expires_at", 0)) > now and now - float(r.get("slack_ctx_at", 0)) >= 9.5:
            res = slack_call("chat.update", {"channel": r.get("slack_pin_channel") or r.get("slack_channel"),
                                             "ts": r["slack_ctx_ts"], "text": _ctx_text(rid, r["pin_expires_at"], now)})
            if res.get("ok"):
                _guest_set_fields(rid, slack_ctx_at=now)


def slack_session_warn(v: dict) -> None:
    if (load_guest().get("slack_sessions") or {}).get(v.get("id"), {}).get("ts"):
        slack_session_status_tick(force={v.get("id")})  # reuse the status message (now says ending soon)
        guest_audit("session_expiring_slack_dm", session_id=v.get("id"), reused=True)
        return
    _slack_session_warn_post(v)


def _slack_session_warn_post(v: dict) -> None:
    name = _sesc(v.get("guest_name") or "Guest")
    text = f":hourglass: Nullink guest session *{name}* (`{v.get('id')}`) ends in about 1 minute."
    ch = _slack_dm_channel()
    r = slack_call("chat.postMessage", {"channel": ch, "text": text, "blocks": [
        {"type": "section", "text": {"type": "mrkdwn", "text": text}},
        {"type": "actions", "block_id": "guest_sess", "elements": [
            {"type": "button", "action_id": "guest_extend", "style": "primary", "value": v.get("id"),
             "text": {"type": "plain_text", "text": "Extend +10 min"}},
            {"type": "button", "action_id": "guest_close", "style": "danger", "value": v.get("id"),
             "text": {"type": "plain_text", "text": "Close"}}]}]}) if ch else {"ok": False}
    if r.get("ok"):
        guest_audit("session_expiring_slack_dm", session_id=v.get("id"))
    else:
        _guest_slack(text + f" Extend (+10 min) or Close: {GUEST_LINK}", "session_expiring",
                     session_id=v.get("id"))


def slack_guest_sweep(now: float | None = None) -> None:
    """Reflect expiries / Nullink-side decisions on the Slack DM alert (removes stale buttons)."""
    now = time.time() if now is None else now
    with _auth_lock:
        data = _guest_prune(load_guest(), now)
        save_guest(data)
    for rid, r in data["requests"].items():
        st = r.get("status")
        if r.get("slack_ts") and st != "pending" and r.get("slack_state") != st and not \
                (st == "approved" and r.get("slack_state") == "approved"):
            _slack_update_request(rid, st)
        if r.get("slack_pin_ts") and not r.get("slack_pin_final") and st not in ("pending", "approved"):
            slack_pin_finalize(rid)
    slack_ctx_countdown_tick(now)
    slack_session_status_tick(now)


# ---------- Guest audit view (owner-only, 2026-10-14) ----------
GUEST_AUDIT_LABELS = {
    "request_created": "Requested", "pin_minted": "PIN created in Nullink", "slack_approved": "Approved via Slack",
    "request_denied": "Denied", "slack_denied": "Denied via Slack", "slack_pin_dm_sent": "PIN sent (Slack DM)",
    "redeemed": "PIN used", "redeem_failed": "Wrong/expired PIN tried", "session_extended": "Session extended",
    "session_ended": "Closed", "sessions_ended_all": "All sessions closed", "session_expired": "Ended (time up)",
    "slack_click_rejected": "Rejected click (not John)", "slack_bad_signature": "Bad signature",
    "slack_click_noop": "Click on already-handled request", "slack_dm_notified": "Alert sent (Slack DM)",
    "slack_notified": "Alert sent (#general webhook)", "slack_dm_failed": "Slack DM failed",
    "request_fallback_slack": "Alert sent (#general fallback)", "slack_pin_dm_failed": "PIN DM failed",
    "session_expiring_warned": "Ending-soon warning", "session_expiring_slack_dm": "Ending-soon warning (Slack)",
    "session_expiring_slack": "Ending-soon warning (#general)", "slack_session_status_posted": "Session status posted (Slack)",
    "request_rate_limited": "Request rate-limited", "request_rejected_full": "Request rejected (too many pending)",
    "guest_blocked": "Guest blocked (forbidden action)", "guest_history_hidden": "Guest blocked (history hidden)",
    "slack_rate_limited": "Slack rate-limited",
}
GUEST_AUDIT_FIELDS = ("iso", "ts", "event", "label", "request_id", "name", "ip", "by", "actor", "scope",
                      "session_id", "outcome", "path", "method", "error", "count", "extensions", "slack_user", "detail")


def _guest_mask(v) -> str:
    n = _guest_pin_norm(v)
    return (n[:5] + "-•••••") if n else "•••••"


def _guest_actor(rec: dict) -> str:
    by = str(rec.get("by") or "")
    if by.startswith("slack:"):
        return "John (Slack)" if by == "slack:" + SLACK_OWNER_UID else "Slack " + by[6:]
    if by.startswith("owner:"):
        return "John (Nullink)"
    ev = rec.get("event") or ""
    if ev in ("request_created", "redeemed", "redeem_failed", "guest_blocked", "guest_history_hidden"):
        return "Guest"
    if ev in ("slack_click_rejected",):
        return "Slack " + str(rec.get("slack_user") or "?")
    return "System"


def guest_audit_query(params: dict, max_rows: int = 5000) -> dict:
    def g(k):
        return str((params.get(k) or [""])[0] if isinstance(params.get(k), list) else (params.get(k) or "")).strip()
    reqs = (load_guest().get("requests") or {})
    sess2req = {q.get("session_id"): rid for rid, q in reqs.items() if q.get("session_id")}
    rows = []
    try:
        lines = GUEST_AUDIT_FILE.read_text(encoding="utf-8").splitlines()[-50000:]
    except OSError:
        lines = []
    for ln in lines:
        try:
            r = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if not isinstance(r, dict):
            continue
        ev = str(r.get("event") or "")
        rid = r.get("request_id") or sess2req.get(r.get("session_id"))
        req = reqs.get(rid) or {}
        if ev == "slack_pin_dm_finalized":
            label = "PIN used (Slack DM updated)" if r.get("outcome") == "used" else "PIN expired"
        elif ev == "request_approved":
            label = "Approved via Slack" if str(r.get("by", "")).startswith("slack:") else "Approved via Nullink"
        else:
            label = GUEST_AUDIT_LABELS.get(ev, ev.replace("_", " ").capitalize())
        out = {"iso": r.get("iso"), "ts": r.get("ts"), "event": ev, "label": label, "request_id": rid,
               "name": r.get("name") or req.get("name"), "ip": r.get("ip") or (req.get("redeemed_ip") if ev == "redeemed" else None) or (req.get("ip") if ev == "request_created" else None),
               "by": r.get("by"), "actor": _guest_actor(r), "scope": r.get("scope") or (req.get("scope") if ev in ("request_approved", "redeemed") else None),
               "session_id": r.get("session_id"), "outcome": r.get("outcome"), "path": r.get("path"),
               "method": r.get("method"), "error": r.get("error"), "count": r.get("count"),
               "extensions": r.get("extensions"), "slack_user": r.get("slack_user")}
        for k, v in r.items():  # never expose a PIN / secret even if one were ever logged
            if any(w in k.lower() for w in ("pin", "secret", "token", "poll", "hash", "cookie")) and v \
                    and k not in ("pin_ttl_sec",):
                out["detail"] = (out.get("detail") or "") + f"{k}={_guest_mask(v)} "
        rows.append({k: out.get(k) for k in GUEST_AUDIT_FIELDS if out.get(k) not in (None, "")})
    f_rid, f_ev, f_q = g("request_id").upper(), g("event"), g("q").lower()
    f_from, f_to = g("from"), g("to")
    def keep(x):
        if f_rid and str(x.get("request_id") or "").upper() != f_rid:
            return False
        if f_ev and f_ev not in (x.get("event"), x.get("label")):
            return False
        d = str(x.get("iso") or "")[:10]
        if f_from and d < f_from or f_to and d > f_to:
            return False
        if f_q and f_q not in json.dumps(x, ensure_ascii=False).lower():
            return False
        return True
    rows = [x for x in rows if keep(x)]
    rows.sort(key=lambda x: float(x.get("ts") or 0), reverse=True)
    total = len(rows)
    try:
        limit = max(1, min(max_rows, int(g("limit") or 200)))
        offset = max(0, int(g("offset") or 0))
    except ValueError:
        limit, offset = 200, 0
    page = rows[offset:offset + limit]
    groups = {}
    for rid in {x.get("request_id") for x in page if x.get("request_id")}:
        q = reqs.get(rid) or {}
        groups[rid] = {k: q.get(k) for k in ("name", "reason", "ip", "status", "scope", "source", "created_at",
                                              "decided_by", "redeemed_at", "redeemed_ip", "session_id")
                       if q.get(k) not in (None, "")}
    events = sorted({x.get("label") for x in rows})
    return {"ok": True, "total": total, "offset": offset, "limit": limit, "rows": page, "requests": groups,
            "labels": events}


def guest_audit_csv(rows: list) -> bytes:
    import csv
    buf = io.StringIO()
    cols = ("time_et", "label", "event", "request_id", "name", "ip", "actor", "scope", "session_id", "outcome", "detail")
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        te = _et_time(float(r.get("ts") or 0))
        try:
            from zoneinfo import ZoneInfo
            import datetime as _dt
            te = _dt.datetime.fromtimestamp(float(r.get("ts") or 0), ZoneInfo("America/New_York")).strftime("%Y-%m-%d %I:%M:%S %p ET")
        except Exception:  # noqa: BLE001
            pass
        vals = [te] + [r.get(c, "") for c in cols[1:]]
        w.writerow([("'" + str(v)) if str(v)[:1] in "=+-@" else v for v in vals])
    return buf.getvalue().encode("utf-8")


def guest_path_blocked(method: str, path: str, scope: str) -> bool:
    if any(path == p or path.startswith(p + "/") or path.startswith(p) for p in GUEST_OWNER_ONLY_PREFIXES):
        return True
    if method != "GET" and scope != "full" and path not in GUEST_READ_ALLOWED_WRITES:
        return True
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
                if sid not in allowed_set or sid in BRIDGE_SESSIONS:
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
    """True only for direct local tools: loopback peer AND no proxy headers.
    Everything relayed by Caddy carries X-Forwarded-* and is rejected."""
    if handler.client_address[0] not in LOOPBACK_ADDRS:
        return False
    for name in PROXY_HEADERS:
        if handler.headers.get(name) is not None:
            return False
    return True


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
            # Messages for Web must run in the VPS browser, inside Guacamole.
            # Publish a dedicated Nullink entry that reuses the allowlisted,
            # same-origin desktop connection instead of embedding Google in a
            # work-PC browser frame. Keep this virtual entry out of apps.json.
            if any(isinstance(app, dict) and app.get("id") == "desktop" for app in apps):
                if not any(isinstance(app, dict) and app.get("id") == "messages" for app in apps):
                    apps = list(apps) + [{
                        "id": "messages",
                        "title": "Google Messages",
                        "url": "/desktop/",
                        "kind": "path",
                        "embed": "iframe",
                        "enabled": True,
                        "description": "Google Messages for Web inside the VPS Chrome session.",
                    }]
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
    """Regular file under BASE (safe_rel_under); symlinks anywhere in the path are refused."""
    return files_manager.safe_entry_path(entry)


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
                if str(d.get("session_id") or "morc") in BRIDGE_SESSIONS:
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




def _load_desktop_credentials() -> dict:
    """Read desk Guacamole credentials from secrets (mode 600)."""
    path = SECRETS / "desktop-credentials.txt"
    out: dict[str, str] = {"username": "desk", "password": ""}
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            k, v = line.split(":", 1)
            k, v = k.strip().lower(), v.strip()
            if k in ("username", "password"):
                out[k] = v
    except OSError:
        pass
    return out


def guacamole_desktop_launch() -> dict:
    """Mint a Guacamole auth token and deep-link into XFCE Desktop.

    Password never goes to the browser — only a short-lived authToken + client URL.
    """
    import base64
    import urllib.parse
    import urllib.request

    creds = _load_desktop_credentials()
    user = creds.get("username") or "desk"
    password = creds.get("password") or ""
    if not password:
        raise RuntimeError("desktop credentials missing password")

    body = urllib.parse.urlencode({"username": user, "password": password}).encode()
    req = urllib.request.Request(
        "http://127.0.0.1:8080/desktop/api/tokens",
        data=body,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=8) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    token = payload.get("authToken")
    if not token:
        raise RuntimeError(f"guacamole token missing: {payload!r}")
    data_source = payload.get("dataSource") or "postgresql"

    conn_id = "1"
    try:
        creq = urllib.request.Request(
            f"http://127.0.0.1:8080/desktop/api/session/data/{urllib.parse.quote(data_source)}/connections?token={urllib.parse.quote(token)}",
            method="GET",
        )
        with urllib.request.urlopen(creq, timeout=8) as cresp:
            conns = json.loads(cresp.read().decode("utf-8"))
        if isinstance(conns, dict) and conns:
            preferred = None
            for cid, meta in conns.items():
                if not isinstance(meta, dict):
                    continue
                name = str(meta.get("name") or "")
                ident = str(meta.get("identifier") or cid)
                if "XFCE" in name.upper():
                    preferred = ident
                    break
                if preferred is None and ("Desktop" in name or meta.get("protocol") == "rdp"):
                    preferred = ident
            if preferred:
                conn_id = preferred
            else:
                first = next(iter(conns.values()))
                conn_id = str((first or {}).get("identifier") or next(iter(conns.keys())))
    except Exception:
        pass

    raw = f"{conn_id}\0{data_source}\0c".encode("utf-8")
    client_id = base64.b64encode(raw).decode("ascii")
    embed_url = f"/desktop/#/client/{client_id}?token={urllib.parse.quote(token)}"
    return {
        "embedUrl": embed_url,
        "username": user,
        "dataSource": data_source,
        "connectionId": conn_id,
        "clientId": client_id,
    }


# ---------- Portal short paths (/link, /mail, ...) ----------
# Edit portal_links.json next to server.py to add or change a project path; it is
# re-read when its mtime changes, so no restart is needed. Invalid entries are
# skipped (and an invalid file keeps the last good map) so a typo never opens a
# redirect to an arbitrary site.
PORTAL_LINKS_FILE = BASE / "portal_links.json"
PORTAL_LINK_PATH_RE = re.compile(r"^/[a-z0-9][a-z0-9-]{0,31}$")
PORTAL_LINK_RESERVED = {"/projects", "/index.html", "/health", "/app.js", "/style.css",
                        "/tokens.css", "/portal.css", "/portal.js", "/api"}
PORTAL_TARGET_HOST_RE = re.compile(
    r"^(?:[a-z0-9-]+\.)*(?:nullverse\.cloud|216\.158\.238\.236\.sslip\.io)$")
_portal_links_cache: dict = {"mtime": None, "links": {}}
_portal_links_lock = threading.Lock()


def _portal_target_ok(url) -> bool:
    if url is None:
        return True
    if not isinstance(url, str) or len(url) > 300 or any(c in url for c in "\\\r\n\t "):
        return False
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    return (parts.scheme == "https" and not parts.username and not parts.password
            and parts.port is None and bool(PORTAL_TARGET_HOST_RE.match(parts.hostname or "")))


def _parse_portal_links(raw: dict) -> dict:
    out = {}
    links = raw.get("links") if isinstance(raw, dict) else None
    if not isinstance(links, dict):
        raise ValueError("links must be an object")
    for path, entry in links.items():
        if not isinstance(path, str) or not PORTAL_LINK_PATH_RE.match(path) or path in PORTAL_LINK_RESERVED:
            continue
        if not isinstance(entry, dict):
            continue
        cloud, sslip = entry.get("cloud"), entry.get("sslip")
        if not (_portal_target_ok(cloud) and _portal_target_ok(sslip)):
            continue
        name = str(entry.get("name") or path[1:])[:60]
        soon = entry.get("status") == "coming_soon" or not (cloud or sslip)
        out[path] = {"name": name, "cloud": cloud or sslip, "sslip": sslip or cloud,
                     "coming_soon": soon, "public": entry.get("public") is True and not soon}
    return out


def load_portal_links() -> dict:
    with _portal_links_lock:
        try:
            mtime = PORTAL_LINKS_FILE.stat().st_mtime_ns
        except OSError:
            return _portal_links_cache["links"]
        if mtime != _portal_links_cache["mtime"]:
            try:
                links = _parse_portal_links(json.loads(PORTAL_LINKS_FILE.read_text(encoding="utf-8")))
            except (OSError, ValueError, UnicodeDecodeError):
                links = _portal_links_cache["links"]
            _portal_links_cache.update(mtime=mtime, links=links)
        return _portal_links_cache["links"]


def portal_next_path(raw: str | None) -> str | None:
    """Only a known short path (or /projects) may be a post-sign-in destination."""
    if raw in ("/projects",):
        return raw
    if isinstance(raw, str) and PORTAL_LINK_PATH_RE.match(raw) and raw in load_portal_links():
        return raw
    return None


def portal_coming_soon_html(name: str) -> bytes:
    import html as _html
    n = _html.escape(name)
    return f"""<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Nullverse · {n}</title>
<link rel="stylesheet" href="/portal.css">
</head>
<body>
<main>
<header><a class="brand" href="/projects" aria-label="Nullverse home"><span class="mark">N</span> Nullverse</a></header>
<section aria-labelledby="heading"><p class="eyebrow">YOUR PRIVATE SPACE</p><h1 id="heading">{n}</h1>
<div class="projects"><article class="card upcoming" aria-disabled="true"><span class="icon" aria-hidden="true">{_html.escape(name[:1].upper())}</span><div class="details"><h2>{n} <span class="badge">Coming soon</span></h2><p>This project is not deployed yet.</p></div></article></div>
<p class="intro"><a href="/projects" style="color:#c8b8f7">← Back to your projects</a></p>
</section>
</main>
</body></html>
""".encode()



# Reports listed on /projects: any *.html dropped in this folder (served by Caddy at /reports/).
PORTAL_REPORTS_DIR = Path("/srv/nullverse-reports")


def list_portal_reports() -> list:
    out = []
    try:
        entries = sorted(PORTAL_REPORTS_DIR.glob("*.html"), key=lambda f: f.stat().st_mtime, reverse=True)
    except OSError:
        return out
    for f in entries:
        if not re.fullmatch(r"[A-Za-z0-9._-]+\.html", f.name) or not f.is_file():
            continue
        try:
            head = f.read_bytes()[:65536].decode("utf-8", "replace")
            st = f.stat()
        except OSError:
            continue
        m = re.search(r"<title[^>]*>(.*?)</title>", head, re.I | re.S)
        import html as _h
        title = _h.unescape(m.group(1)).strip() if m else ""
        out.append({"title": title[:200] or f.stem, "url": "/reports/" + f.name,
                    "modified": int(st.st_mtime)})
    return out

def collect_portal_status() -> dict:
    """Physical host RAM and the filesystem holding app data; no account quotas."""
    memory = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, _, value = line.partition(":")
        if key in {"MemTotal", "MemAvailable"}:
            memory[key] = int(value.split()[0]) * 1024
    total = memory["MemTotal"]
    available = memory["MemAvailable"]
    if total <= 0 or not 0 <= available <= total:
        raise ValueError("invalid memory metrics")
    disk = shutil.disk_usage(DATA)
    if disk.total <= 0 or not 0 <= disk.used <= disk.total:
        raise ValueError("invalid storage metrics")

    def quantities(used, capacity):
        return {"used_bytes": used, "total_bytes": capacity,
                "percent": round(used / capacity * 100, 2)}

    return {"ram": quantities(total - available, total),
            "storage": quantities(disk.used, disk.total),
            "timestamp": time.time()}


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

    def _is_https(self) -> bool:
        if (self.headers.get("X-Forwarded-Proto") or "").lower() == "https":
            return True
        return getattr(self, "req_host", "") in PUBLIC_HTTPS_HOSTS

    def _cookie_name(self) -> str:
        return COOKIE_NAME if self._is_https() else LOCAL_COOKIE_NAME

    def _cookie_token(self) -> str | None:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        c = SimpleCookie()
        try:
            c.load(raw)
        except Exception:
            return None
        name = self._cookie_name()
        if name not in c:
            return None
        return c[name].value

    def _session_cookie(self, value: str, max_age: int) -> str:
        if self._is_https():
            return f"{COOKIE_NAME}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}"
        return f"{LOCAL_COOKIE_NAME}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}"

    def _clear_session_cookies(self) -> list[tuple[str, str]]:
        secure = "; Secure" if self._is_https() else ""
        return [
            ("Set-Cookie", self._session_cookie("", 0)),
            ("Set-Cookie", f"{LEGACY_COOKIE_NAME}=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax{secure}"),
        ]

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
        """Precedence: Bearer, then server-side session cookie. Attaches self.auth."""
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
        rec = get_session(self._cookie_token(), touch=True)
        if rec:
            auth = {"type": "session", "session_id": rec.get("id"), "session_record": rec}
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

    def _phone_device_auth(self) -> dict | None:
        device = get_bridge(PHONE_DATA_DIR, PHONE_STAGING_DIR).authenticate(self._bearer_token())
        if not device:
            self._json(401, {"error": "unauthorized", "message": "invalid_phone_device_token"})
            return None
        return device

    def _phone_pair_client_key(self) -> str:
        peer = str(self.client_address[0] if self.client_address else "unknown")
        try:
            is_local_proxy = ipaddress.ip_address(peer).is_loopback
        except ValueError:
            is_local_proxy = False
        if is_local_proxy:
            forwarded = self.headers.get("X-Forwarded-For", "")
            candidates = [part.strip() for part in forwarded.split(",") if part.strip()]
            if candidates:
                candidate = candidates[-1]
                try:
                    ipaddress.ip_address(candidate)
                    return candidate
                except ValueError:
                    pass
        return peer

    def _phone_error(self, error: PhoneBridgeError) -> None:
        self._json(error.status, {"error": error.code})

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
        if str(session_id) in {str(s) for s in allowed}:
            return True
        try:
            return ai_rooms.allowed(str(auth.get("token_id") or ""), allowed, str(session_id))
        except Exception:
            return False

    def _resolve_room(self, sid, default: str = "morc") -> str:
        """'@current' (or omitted, once a room was chosen) -> this Bearer connection's current room."""
        auth = getattr(self, "auth", None) or {}
        if auth.get("type") != "bearer":
            return str(sid or default)
        tid = str(auth.get("token_id") or "")
        if sid == ai_rooms.CURRENT or (not sid and (ai_rooms.load()["connections"].get(tid) or {}).get("current")):
            return ai_rooms.current(tid, auth.get("sessions") or []) or default
        return str(sid or default)

    def _room_titles(self) -> dict:
        try:
            return {str(x.get("id")): str(x.get("title") or x.get("id"))
                    for x in flat_sessions_from_roster(load_roster()) if isinstance(x, dict)}
        except Exception:
            return {}

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

    def parse_request(self) -> bool:
        if not super().parse_request():
            return False
        # Route by the actual authority only, never by forwarded host headers.
        hosts = self.headers.get_all("Host", [])
        authority = hosts[0].lower() if len(hosts) == 1 else ""
        allowed = PORTAL_HOSTS | {"nullink.nullverse.cloud",
                   "nullink.216.158.238.236.sslip.io", "localhost", "127.0.0.1"}
        host, sep, port = authority.partition(":")
        if host not in allowed or (sep and port not in {"80", "443", str(PORT)}):
            self._json(421, {"error": "untrusted_host"})
            return False
        self.req_host = host
        self.portal_host = host in PORTAL_HOSTS
        if self.portal_host:
            path = urllib.parse.urlsplit(self.path).path
            permitted = {
                "GET": {"/", "/index.html", "/projects", "/app.js", "/style.css",
                        "/tokens.css", "/portal.css", "/portal.js", "/health",
                        "/api/me", "/api/auth/method", "/api/portal/status",
                        "/api/portal/reports"},
                "POST": {"/api/auth/verify", "/api/auth/logout"},
            }
            if (path.startswith("/s/") or path.startswith("/a/") or path.startswith("/f/") or path.startswith("/reports/") or path.startswith("/api/share/")
                    or path == "/share-links") and self.command in ("GET", "POST"):
                return True
            if path not in permitted.get(self.command, set()) and not (
                    self.command == "GET" and path in load_portal_links()):
                self._json(404, {"error": "not_found"})
                return False
        return True

    def do_GET(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if self.portal_host and share_links.handle(self, "GET", path, qs):
            return
        m_f = re.match(r"^/f/([A-Za-z0-9_-]{1,80})$", path)
        if m_f:
            share_links.file_public(self, m_f.group(1))
            return
        if path.startswith("/f/"):
            return self._json(404, {"error": "not_found"})
        if self._guest_gate("GET", path):
            return
        if path.startswith("/api/avatars") and avatars.handle(self, "GET", path):
            return
        if path.startswith("/api/fm") and files_manager.handle(self, "GET", path, qs):
            return
        if path.startswith("/api/sd") and server_drive.handle(self, "GET", path, qs):
            return
        if path.startswith("/api/gh") and github_drive.handle(self, "GET", path, qs):
            return
        if path == "/api/guest/requests":
            return self._guest_owner_list()
        if path == "/api/guest/audit":
            if self._require_owner() is None:
                return
            if (qs.get("format") or [""])[0] == "csv":
                data = guest_audit_query({**qs, "limit": ["5000"], "offset": ["0"]})
                return self._send(200, guest_audit_csv(data["rows"]), "text/csv; charset=utf-8",
                                  [("Content-Disposition", 'attachment; filename="nullink-guest-audit.csv"')])
            return self._json(200, guest_audit_query(qs))
        if path == "/guest-audit":
            if self._require_owner() is None:
                return
            return self._serve_static("guest-audit.html", "text/html; charset=utf-8")
        if path == "/guest-audit.js":
            return self._serve_static("guest-audit.js", "application/javascript; charset=utf-8")
        m = re.match(r"^/api/guest/request/(GR-[A-Z0-9]{6})$", path)
        if m:
            return self._guest_request_status(m.group(1), (qs.get("poll") or [""])[0])
        if path == "/guest.js":
            return self._serve_static("guest.js", "application/javascript; charset=utf-8")

        if path == "/api/portal/reports":
            if not self.portal_host:
                return self._json(404, {"error": "not_found"})
            if not verify_session(self._cookie_token()):
                return self._json(401, {"error": "unauthorized"})
            return self._json(200, {"reports": list_portal_reports()})

        if path == "/api/portal/status":
            if not self.portal_host:
                return self._json(404, {"error": "not_found"})
            if not verify_session(self._cookie_token()):
                return self._json(401, {"error": "unauthorized"})
            try:
                metrics = collect_portal_status()
            except (OSError, ValueError, KeyError, IndexError):
                return self._json(503, {"error": "status_unavailable"})
            return self._json(200, metrics)

        if path == "/api/auth/gate":
            # Caddy forward_auth target for proxied apps (/android, /desktop) on the
            # Nullink hosts. Human cookie session only: Bearer tokens never pass.
            if self.portal_host:
                return self._json(404, {"error": "not_found"})
            if verify_session(self._cookie_token()):
                return self._send(204, b"", extra_headers=[("Vary", "Cookie")])
            accept = self.headers.get("Accept") or ""
            if self.headers.get("Sec-Fetch-Mode") == "navigate" or "text/html" in accept:
                return self._send(302, b"", extra_headers=[("Location", "/")])
            return self._json(401, {"error": "unauthorized"})

        if self.portal_host:
            authenticated = verify_session(self._cookie_token())
            if path in ("/", "/index.html") and authenticated:
                nxt = portal_next_path((qs.get("next") or [None])[0]) or "/projects"
                return self._send(302, b"", extra_headers=[("Location", nxt)])
            links = load_portal_links()
            if path in links:
                link = links[path]
                if not authenticated and not link["public"]:
                    return self._send(302, b"", extra_headers=[
                        ("Location", "/?next=" + urllib.parse.quote(path, safe="/"))])
                if link["coming_soon"]:
                    return self._send(200, portal_coming_soon_html(link["name"]),
                                      "text/html; charset=utf-8", [
                        ("Content-Security-Policy", "default-src 'none'; style-src 'self'; "
                         "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"),
                        ("X-Content-Type-Options", "nosniff"),
                        ("Referrer-Policy", "same-origin")])
                target = link["sslip"] if self.req_host in SSLIP_PORTAL_HOSTS else link["cloud"]
                return self._send(302, b"", extra_headers=[("Location", target),
                                                           ("Referrer-Policy", "no-referrer")])
            if path == "/projects":
                if not authenticated:
                    return self._send(302, b"", extra_headers=[("Location", "/")])
                return self._serve_static("portal.html", "text/html; charset=utf-8")
            if path in ("/portal.css", "/portal.js"):
                return self._serve_static(path[1:], "text/css" if path.endswith("css") else "application/javascript")

        if path in ("/", "/index.html"):
            return self._serve_static("index.html", "text/html; charset=utf-8")
        if path == "/app.js":
            return self._serve_static("app.js", "application/javascript; charset=utf-8")
        if path == "/files-manager.js":
            return self._serve_static("files-manager.js", "application/javascript; charset=utf-8")
        if path in ("/editor.js", "/sanitize.js"):
            return self._serve_static(path[1:], "application/javascript; charset=utf-8")
        if path == "/vendor/codemirror/codemirror.bundle.js":
            return self._serve_static("vendor/codemirror/codemirror.bundle.js", "application/javascript; charset=utf-8")
        if path == "/vendor/codemirror/LICENSE.txt":
            return self._serve_static("vendor/codemirror/LICENSE.txt", "text/plain; charset=utf-8")
        if path == "/bots.js":
            return self._serve_static("bots.js", "application/javascript; charset=utf-8")
        if path == "/avatars.js":
            return self._serve_static("avatars.js", "application/javascript; charset=utf-8")
        if path == "/favorites.js":
            return self._serve_static("favorites.js", "application/javascript; charset=utf-8")
        if path == "/server-drive.js":
            return self._serve_static("server-drive.js", "application/javascript; charset=utf-8")
        if path == "/github-drive.js":
            return self._serve_static("github-drive.js", "application/javascript; charset=utf-8")
        if path == "/vendor/socket.io.min.js":
            return self._serve_static("vendor/socket.io.min.js", "application/javascript; charset=utf-8")
        if path == "/phone-drive.js":
            return self._serve_static("phone-drive.js", "application/javascript; charset=utf-8")
        if path == "/style.css":
            return self._serve_static("style.css", "text/css; charset=utf-8")
        if path == "/tokens.css":
            return self._serve_static("tokens.css", "text/css; charset=utf-8")
        if path == "/health":
            return self._json(200, {"ok": True, "service": "nullink", "port": PORT, "pm": True})
        if path == "/api/auth/method":
            config = load_totp() or {}
            response = {
                "method": "both" if totp_enabled() else "pin",
                "totp_enabled": totp_enabled(),
            }
            if verify_session(self._cookie_token()):
                response["recovery_codes_remaining"] = len(config.get("recovery_hashes") or []) if totp_enabled() else 0
            return self._json(200, response)

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
            rec = auth.get("session_record") or {}
            if rec.get("method") == "guest":
                return self._json(200, {
                    "authenticated": True,
                    "auth_type": "guest",
                    "guest": {"name": rec.get("guest_name"), "scope": rec.get("scope"),
                              "label": "guest", "expires_at": rec.get("expires_at"),
                              "now": time.time(),
                              "waiting_for_extend": float(rec.get("expires_at", 0)) - time.time() <= GUEST_WARN_SEC,
                              "session_id": rec.get("id")},
                })
            return self._json(200, {
                "authenticated": True,
                "auth_type": "session",
                "session": {
                    "id": rec.get("id"),
                    "created_at": rec.get("created_at"),
                    "expires_at": rec.get("expires_at"),
                    "stepup_valid": time.time() - float(rec.get("stepup_at") or 0) <= STEPUP_WINDOW_SEC,
                },
            })

        if path == "/api/auth/sessions":
            return self._list_sessions()

        if path == "/api/rt/whoami":
            # Socket.IO handshake check (rt_server.py): same cookie/Bearer rules as REST.
            if not self._require_api_auth(["messages:read"]):
                return
            auth = getattr(self, "auth", None) or {}
            if auth.get("type") == "bearer":
                return self._json(200, {"ok": True, "type": "bearer", "guest": False,
                                        "sessions": [str(x) for x in (auth.get("sessions") or [])],
                                        "name": auth.get("name")})
            rec = auth.get("session_record") or {}
            guest = rec.get("method") == "guest"
            return self._json(200, {"ok": True, "type": "session", "guest": guest,
                                    "scope": rec.get("scope") if guest else "owner",
                                    "sessions": "*",
                                    "owner_only": sorted(OWNER_ONLY_SESSIONS),
                                    "hide_history": bool(guest and GUEST_HIDE_HISTORY),
                                    "expires_at": rec.get("expires_at")})

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
            cats_out = roster.get("categories") or []
            _rec = get_session(self._cookie_token()) or {}
            if _rec.get("method") == "guest":
                sessions = [x for x in sessions if str(x.get("id") or "") not in OWNER_ONLY_SESSIONS]
                cats_out = [dict(c, bots=[b for b in (c.get("bots") or []) if isinstance(b, dict)
                                          and str(b.get("id") or "") not in OWNER_ONLY_SESSIONS])
                            for c in cats_out if isinstance(c, dict)]
            return self._json(200, {
                "categories": cats_out,
                "default_session": roster.get("default_session") or "morc",
                "sessions": sessions,
            })

        if path == "/api/replit/status":
            if not self._require_owner():
                return
            try:
                with urllib.request.urlopen("http://127.0.0.1:8773/replit/api/room-status", timeout=5) as r:
                    return self._json(200, json.loads(r.read()))
            except Exception:
                return self._json(503, {"error": "replit_bridge_down"})

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
            sid = self._resolve_room((qs.get("session") or [""])[0])
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
            if (qs.get("trash") or [""])[0] != "1":
                files = [f for f in files if not f.get("trashed_at")]
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


        if path == "/api/desktop/launch":
            if not self._require_auth():
                return
            try:
                data = guacamole_desktop_launch()
                return self._json(200, data)
            except Exception as exc:
                return self._json(502, {"error": "desktop_launch_failed", "detail": str(exc)[:300]})

        if path == "/api/desktop/credentials":
            # Removed 2026-10-06: the desk password never goes to the browser.
            # Use /api/desktop/launch (server-side Guacamole sign-in) instead.
            if not self._require_auth():
                return
            return self._json(410, {"error": "removed",
                                    "message": "Use Sign in (automatic desktop sign-in)."})


        if path == "/api/apps":
            # Signed-in only (2026-10-07 lockdown); proxy also requires auth.
            if not self._require_auth():
                return
            cfg = load_apps_config()
            apps = [public_app_view(a) for a in (cfg.get("apps") or []) if isinstance(a, dict)]
            return self._json(200, {
                "apps": apps,
                "frame_ancestors_note": cfg.get("frame_ancestors_note"),
            })

        if path == "/phone-drive/":
            return self._serve_static("phone-drive.html", "text/html; charset=utf-8")

        if path == "/api/phone/devices":
            if not self._require_auth():
                return
            return self._json(200, {"devices": get_bridge(PHONE_DATA_DIR, PHONE_STAGING_DIR).list_devices()})

        if path == "/api/phone/screen/frame":
            if not self._require_auth():
                return
            device_id = (qs.get("device_id") or [""])[0]
            try:
                after = int((qs.get("after") or [0])[0])
                frame = get_bridge(PHONE_DATA_DIR, PHONE_STAGING_DIR).get_screen_frame(device_id, after)
            except (ValueError, PhoneBridgeError) as e:
                return self._phone_error(e if isinstance(e, PhoneBridgeError) else PhoneBridgeError("invalid_frame_sequence"))
            if not frame:
                return self._send(204, b"", "image/jpeg", [("X-Frame-Sequence", str(max(0, after)))])
            return self._send(200, frame["body"], "image/jpeg", [
                ("X-Frame-Sequence", str(frame["sequence"])),
                ("X-Frame-Timestamp", str(int(frame["created"] * 1000))),
            ])

        if path == "/api/phone/commands/next":
            device = self._phone_device_auth()
            if not device:
                return
            wait = (qs.get("wait") or [20])[0]
            try:
                bridge = get_bridge(PHONE_DATA_DIR, PHONE_STAGING_DIR)
                poll = bridge.next_control if (qs.get("channel") or [""])[0] == "control" else bridge.next_command
                command = poll(device["id"], float(wait))
                return self._json(200, {"command": command})
            except (ValueError, PhoneBridgeError) as e:
                return self._phone_error(e if isinstance(e, PhoneBridgeError) else PhoneBridgeError("invalid_wait"))

        if path == "/api/phone/browse":
            if not self._require_auth():
                return
            device_id = (qs.get("device_id") or [""])[0]
            root_id = (qs.get("root_id") or [""])[0]
            document_id = (qs.get("document_id") or ["root"])[0]
            try:
                result = get_bridge(PHONE_DATA_DIR, PHONE_STAGING_DIR).request_phone(
                    device_id, "list", root_id, document_id, timeout=25)
                return self._json(200, {"items": result["items"], "device_id": device_id,
                                       "root_id": root_id, "document_id": document_id})
            except PhoneBridgeError as e:
                return self._phone_error(e)

        if path == "/api/phone/staged":
            if not self._require_auth():
                return
            bridge = get_bridge(PHONE_DATA_DIR, PHONE_STAGING_DIR)
            return self._json(200, {"files": bridge.list_staged()})

        m = re.match(r"^/api/phone/staged/([a-f0-9]{32})/download$", path)
        if m:
            if not self._require_auth():
                return
            item = get_bridge(PHONE_DATA_DIR, PHONE_STAGING_DIR).consume_staged(m.group(1))
            if not item:
                return self._json(404, {"error": "staged_file_expired_or_downloaded"})
            try:
                body = item["path"].read_bytes()
            except OSError:
                return self._json(404, {"error": "staged_file_unavailable"})
            finally:
                try:
                    item["path"].unlink(missing_ok=True)
                except OSError:
                    pass
            name = urllib.parse.quote(item["name"], safe="")
            headers = [("Content-Disposition", f"attachment; filename*=UTF-8''{name}")]
            return self._send(200, body, item["mime"], headers)

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
            if not self._vault_owner():
                return
            q = (qs.get("q") or qs.get("query") or [None])[0]
            labels = [x for v in (qs.get("label") or []) + (qs.get("tag") or []) for x in v.split(",") if x.strip()]
            items = list_vault_snippets(q, labels)
            return self._json(200, {"items": items, "count": len(items), "search": "title_and_tags",
                                    "labels": vault_label_counts()})

        if path == "/api/vault/labels":
            if not self._vault_owner():
                return
            return self._json(200, {"labels": vault_label_counts()})

        m = re.match(r"^/api/vault/([^/]+)$", path)
        if m:
            rec = self._vault_owner()
            if not rec:
                return
            return self._vault_view(urllib.parse.unquote(m.group(1)), rec)

        m = re.match(r"^/api/admin/vault(?:/([^/]+))?$", path)
        if m:
            return self._admin_vault_read(m.group(1))


        if path == "/api/playground/chatgpt":
            return self._playground_list()

        m = re.match(r"^/api/playground/chatgpt/([^/]+)$", path)
        if m:
            return self._playground_get(urllib.parse.unquote(m.group(1)))

        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/slack/interact":
            return self._slack_interact()
        if getattr(self, "portal_host", False) and share_links.handle(
                self, "POST", path, urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)):
            return
        if self._guest_gate("POST", path):
            return
        if path.startswith("/api/avatars") and avatars.handle(self, "POST", path):
            return
        if path.startswith("/api/fm") and files_manager.handle(
                self, "POST", path, urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)):
            return
        if path.startswith("/api/gh") and github_drive.handle(
                self, "POST", path, urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)):
            return
        if path.startswith("/api/sd") and server_drive.handle(
                self, "POST", path, urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)):
            return
        if path == "/api/guest/request":
            return self._guest_request_create()
        if path == "/api/auth/guest/redeem":
            return self._guest_redeem()
        if path.startswith("/api/guest/"):
            return self._guest_owner_action(path)

        if path == "/api/auth/verify":
            return self._auth_verify()
        if path == "/api/auth/logout":
            return self._auth_logout()
        if path == "/api/auth/logout-all":
            return self._auth_logout_all()
        if path == "/api/auth/stepup":
            return self._auth_stepup()
        if path == "/api/ssh/stepup":
            return self._ssh_stepup()
        if path == "/api/admin/ssh-session":
            return self._admin_ssh_session()
        if path == "/api/auth/totp/setup":
            return self._totp_setup()
        if path == "/api/auth/totp/confirm":
            return self._totp_confirm()
        if path == "/api/auth/totp/disable":
            return self._totp_disable()
        if path == "/api/auth/tokens":
            return self._create_token()
        if path == "/api/phone/pairing-code":
            if not self._require_auth():
                return
            return self._json(200, get_bridge(PHONE_DATA_DIR, PHONE_STAGING_DIR).create_pairing_code())
        if path == "/api/phone/pair":
            body = self._read_json()
            try:
                result = get_bridge(PHONE_DATA_DIR, PHONE_STAGING_DIR).pair(
                    body.get("code"), body.get("name"), self._phone_pair_client_key())
                return self._json(201, result)
            except PhoneBridgeError as e:
                return self._phone_error(e)
        if path == "/api/phone/share":
            device = self._phone_device_auth()
            if not device:
                return
            body = self._read_json()
            try:
                result = get_bridge(PHONE_DATA_DIR, PHONE_STAGING_DIR).set_sharing(
                    device["id"], bool(body.get("enabled")), body.get("roots") or [])
                return self._json(200, {"device": result})
            except PhoneBridgeError as e:
                return self._phone_error(e)
        if path == "/api/phone/control/status":
            device = self._phone_device_auth()
            if not device:
                return
            try:
                get_bridge(PHONE_DATA_DIR, PHONE_STAGING_DIR).set_control_state(device["id"], self._read_json())
                return self._json(200, {"ok": True})
            except PhoneBridgeError as e:
                return self._phone_error(e)
        if path == "/api/phone/control":
            if not self._require_auth():
                return
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                return self._json(415, {"error": "json_required"})
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return self._json(400, {"error": "invalid_content_length"})
            if not 0 < length <= 2048:
                return self._json(413, {"error": "control_request_too_large"})
            body = self._read_json()
            try:
                if not isinstance(body, dict) or set(body) != {"device_id", "command"}:
                    raise PhoneBridgeError("invalid_control_request")
                result = get_bridge(PHONE_DATA_DIR, PHONE_STAGING_DIR).request_control(body["device_id"], body["command"])
                return self._json(200, result)
            except PhoneBridgeError as e:
                return self._phone_error(e)
        if path == "/api/phone/screen/status":
            device = self._phone_device_auth()
            if not device:
                return
            body = self._read_json()
            try:
                get_bridge(PHONE_DATA_DIR, PHONE_STAGING_DIR).set_screen_active(
                    device["id"], bool(body.get("active")))
                return self._json(200, {"ok": True, "active": bool(body.get("active"))})
            except PhoneBridgeError as e:
                return self._phone_error(e)
        if path == "/api/messages":
            return self._post_message()
        if path == "/api/admin/set-otp":
            return self._admin_set_otp()
        if path == "/api/admin/a2a-post":
            return self._admin_a2a_post()
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
        if path == "/api/vault/labels/rename":
            rec = self._vault_owner()
            if not rec:
                return
            body = self._read_json()
            old = str(body.get("from") or "").strip()
            if not old:
                return self._json(400, {"error": "missing_from"})
            n = vault_rename_label(old, body.get("to"))
            vault_audit("label_rename" if str(body.get("to") or "").strip() else "label_remove",
                        entries=n, ip=client_ip(self), session=rec.get("id"))
            return self._json(200, {"ok": True, "changed": n, "labels": vault_label_counts()})
        if path == "/api/selection/label":
            return self._selection_label()

        m = re.match(r"^/api/phone/stage$", path)
        if m:
            if not self._require_auth():
                return
            body = self._read_json()
            device_id = str(body.get("device_id") or "")
            root_id = str(body.get("root_id") or "")
            document_id = str(body.get("document_id") or "")
            try:
                staged = get_bridge(PHONE_DATA_DIR, PHONE_STAGING_DIR).request_phone(
                    device_id, "read", root_id, document_id, timeout=30)
                return self._json(201, {"file": staged})
            except PhoneBridgeError as e:
                return self._phone_error(e)

        m = re.match(r"^/api/phone/commands/([a-f0-9]{32})/result$", path)
        if m:
            device = self._phone_device_auth()
            if not device:
                return
            try:
                get_bridge(PHONE_DATA_DIR, PHONE_STAGING_DIR).complete_command(
                    device["id"], m.group(1), self._read_json())
                return self._json(200, {"ok": True})
            except PhoneBridgeError as e:
                return self._phone_error(e)

        self._json(404, {"error": "not found"})

    def do_PATCH(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        if self._guest_gate("PATCH", path):
            return
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
        if self._guest_gate("PUT", path):
            return
        if path == "/api/phone/screen/frame":
            device = self._phone_device_auth()
            if not device:
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return self._json(400, {"error": "invalid_content_length"})
            from phone_bridge import MAX_SCREEN_FRAME_BYTES
            if length <= 0 or length > MAX_SCREEN_FRAME_BYTES:
                return self._json(413, {"error": "screen_frame_too_large_or_empty", "max_bytes": MAX_SCREEN_FRAME_BYTES})
            try:
                body = self.rfile.read(length)
                sequence = get_bridge(PHONE_DATA_DIR, PHONE_STAGING_DIR).publish_screen_frame(device["id"], body)
                return self._json(200, {"ok": True, "sequence": sequence})
            except PhoneBridgeError as e:
                return self._phone_error(e)
        m = re.match(r"^/api/phone/commands/([a-f0-9]{32})/file$", path)
        if m:
            device = self._phone_device_auth()
            if not device:
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return self._json(400, {"error": "invalid_content_length"})
            from phone_bridge import MAX_STAGED_BYTES
            if length < 0 or length > MAX_STAGED_BYTES:
                return self._json(413, {"error": "file_too_large_or_empty", "max_bytes": MAX_STAGED_BYTES})
            name = urllib.parse.unquote(self.headers.get("X-Phone-File-Name") or "phone-file")
            mime = self.headers.get("X-Phone-File-Mime") or "application/octet-stream"
            try:
                body = self.rfile.read(length)
                result = get_bridge(PHONE_DATA_DIR, PHONE_STAGING_DIR).complete_file(
                    device["id"], m.group(1), name, mime, body)
                return self._json(201, {"file": result})
            except PhoneBridgeError as e:
                return self._phone_error(e)
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
        if self._guest_gate("DELETE", path):
            return
        m = re.match(r"^/api/phone/devices/([a-f0-9]{32})$", path)
        if m:
            if not self._require_auth():
                return
            deleted = get_bridge(PHONE_DATA_DIR, PHONE_STAGING_DIR).revoke(m.group(1))
            return self._json(200 if deleted else 404, {"ok": deleted})
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

    # ---------- vault snippets (F7; encrypted + step-up 2026-10-19) ----------
    def _vault_owner(self) -> dict | None:
        """Owner cookie session only (no Bearer/AI tokens, no guests). Sends the error itself."""
        if not self._require_auth():
            return None
        rec = (getattr(self, "auth", None) or {}).get("session_record") or {}
        if rec.get("method") == "guest" or rec.get("guest"):
            self._json(403, {"error": "guest_forbidden"})
            return None
        return rec

    def _vault_stepped_up(self, rec: dict) -> bool:
        return time.time() - float(rec.get("ssh_stepup_at") or 0) <= SSH_STEPUP_WINDOW_SEC

    def _vault_stepup_error(self) -> None:
        self._json(403, {"error": "step_up_required", "stepup_endpoint": "/api/ssh/stepup",
                         "message": "Enter an authenticator code to unlock Vault contents for 10 minutes."})

    def _vault_view(self, vid: str, rec: dict) -> None:
        ip, ua = client_ip(self), str(self.headers.get("User-Agent") or "")[:160]
        if not self._vault_stepped_up(rec):
            item = load_vault_snippet(vid, decrypt=False)
            if not item:
                return self._json(404, {"error": "not_found"})
            vault_audit("view_masked", id=vid, ip=ip, ua=ua, session=rec.get("id"))
            return self._json(200, {"item": item, "locked": True, "stepup_endpoint": "/api/ssh/stepup",
                                    "unlock_window_sec": SSH_STEPUP_WINDOW_SEC})
        try:
            item = load_vault_snippet(vid, decrypt=True)
        except VaultKeyUnavailable:
            return self._json(503, {"error": "vault_key_unavailable"})
        except VaultIntegrityError:
            vault_audit("integrity_failure", id=vid, ip=ip, ua=ua, session=rec.get("id"))
            return self._json(500, {"error": "vault_integrity", "message": "This entry failed its integrity check."})
        if not item:
            return self._json(404, {"error": "not_found"})
        vault_audit("decrypt_view", id=vid, ip=ip, ua=ua, session=rec.get("id"))
        remaining = int(SSH_STEPUP_WINDOW_SEC - (time.time() - float(rec.get("ssh_stepup_at") or 0)))
        return self._json(200, {"item": item, "locked": False, "unlocked_for_sec": max(0, remaining)})

    def _admin_vault_read(self, vid: str | None) -> None:
        """Loopback-only (Morc's server-side access through the app). Audited, no content logged."""
        if not is_localhost(self) or self.headers.get("Authorization") is not None:
            return self._json(403, {"error": "localhost_only"})
        if not vid:
            items = list_vault_snippets()
            return self._json(200, {"items": items, "count": len(items)})
        vid = urllib.parse.unquote(vid)
        try:
            item = load_vault_snippet(vid, decrypt=True)
        except VaultKeyUnavailable:
            return self._json(503, {"error": "vault_key_unavailable"})
        except VaultIntegrityError:
            vault_audit("integrity_failure", id=vid, ip="local", ua="admin-loopback")
            return self._json(500, {"error": "vault_integrity"})
        if not item:
            return self._json(404, {"error": "not_found"})
        vault_audit("decrypt_view", id=vid, ip="local", ua=str(self.headers.get("User-Agent") or "admin-loopback")[:160],
                    actor="morc-local")
        return self._json(200, {"item": item})

    def _vault_create(self) -> None:
        if not self._vault_owner():
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
        try:
            entry = save_vault_snippet({"title": title or text_body[:60], "body": text_body, "tags": tags})
        except VaultKeyUnavailable:
            return self._json(503, {"error": "vault_key_unavailable"})
        vault_audit("create", id=entry["id"], ip=client_ip(self), ua=str(self.headers.get("User-Agent") or "")[:160])
        return self._json(200, {"ok": True, "item": entry})

    def _vault_update(self, vid: str) -> None:
        rec = self._vault_owner()
        if not rec:
            return
        vid = urllib.parse.unquote(str(vid or "")).strip()
        body = self._read_json()
        if body.get("body") is not None and not self._vault_stepped_up(rec):
            return self._vault_stepup_error()
        try:
            existing = load_vault_snippet(vid, decrypt=True)
        except VaultKeyUnavailable:
            return self._json(503, {"error": "vault_key_unavailable"})
        except VaultIntegrityError:
            return self._json(500, {"error": "vault_integrity"})
        if not existing:
            return self._json(404, {"error": "not_found"})
        if "title" in body and body["title"] is not None:
            existing["title"] = str(body["title"]).strip()[:200] or existing["title"]
        if "body" in body and body["body"] is not None:
            existing["body"] = str(body["body"])[:100_000]
        if "tags" in body:
            tags = body["tags"]
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",") if t.strip()]
            existing["tags"] = tags if isinstance(tags, list) else existing.get("tags") or []
        try:
            entry = save_vault_snippet(existing)
        except VaultKeyUnavailable:
            return self._json(503, {"error": "vault_key_unavailable"})
        vault_audit("update", id=vid, ip=client_ip(self), ua=str(self.headers.get("User-Agent") or "")[:160],
                    body_changed=body.get("body") is not None, session=rec.get("id"))
        if not self._vault_stepped_up(rec):
            entry = {**entry, "body": VAULT_MASK, "locked": True}
        return self._json(200, {"ok": True, "item": entry})

    def _vault_delete(self, vid: str) -> None:
        rec = self._vault_owner()
        if not rec:
            return
        if not self._vault_stepped_up(rec):
            return self._vault_stepup_error()
        vault_audit("delete", id=vid, ip=client_ip(self), ua=str(self.headers.get("User-Agent") or "")[:160])
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
            **file_version(fp),
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
            ("X-Content-Type-Options", "nosniff"),
            ("Content-Security-Policy", "default-src 'none'; sandbox"),
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
        """Legacy alias (Files manager S1): DELETE /api/files/<id> moves the entry to Trash.
        Needs step-up like /api/fm/trash; files are only removed from disk by empty-trash."""
        if self._guest_gate("DELETE", "/api/fm/trash"):
            return
        if self.headers.get("Authorization") is not None:
            return self._json(403, {"error": "forbidden", "message": "owner cookie session required"})
        if self._require_owner() is None or not self._require_stepup():
            return
        files = load_files()
        entry = next((f for f in files if f["id"] == fid), None)
        if not entry:
            return self._json(404, {"error": "not_found"})
        if not entry.get("trashed_at"):
            entry["trashed_at"] = iso_now()
            save_files(files)
        return self._json(200, {"ok": True, "trashed": True})

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
            return self._json(200, {"ok": True, "file": entry, **file_version(dest)})

        fp = resolve_file_path(entry)
        if not fp:
            return self._json(404, {"error": "missing_file"})
        if not is_text_file(entry.get("name") or fp.name):
            return self._json(400, {"error": "not_text"})
        # Changed-since-open check: the editor sends the sha256/mtime it opened;
        # a mismatch means someone else wrote the file -> 409 unless force=true.
        base_sha = body.get("base_sha256")
        base_mtime = body.get("base_mtime_ns")
        if (base_sha or base_mtime) and not body.get("force"):
            cur = file_version(fp)
            changed = (base_sha and str(base_sha) != cur["sha256"]) or (
                not base_sha and str(base_mtime) != str(cur["mtime_ns"]))
            if changed:
                return self._json(409, {"error": "conflict", "message":
                                        "File changed since you opened it.", **cur})
        fp.write_text(content, encoding="utf-8")
        entry["size"] = fp.stat().st_size
        entry["updated_at"] = iso_now()
        save_files(files)
        return self._json(200, {"ok": True, "file": entry, **file_version(fp)})

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
                "folder": getattr(self, "_fm_upload_folder", None) or "",
                "trashed_at": None,
                "fm": files_manager.FM_VERSION,
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
                 "frame-src 'self' https://nullmail.nullverse.cloud https://nullmail.216.158.238.236.sslip.io; "
                 "frame-ancestors 'none'; "
                 "base-uri 'self'; "
                 "form-action 'self'"),
                ("X-Content-Type-Options", "nosniff"),
                ("Referrer-Policy", "same-origin"),
            ]
        self._send(200, data, ctype, extra)

    def _check_code(self, code: str, now: float):
        """Verify a login/step-up code. Returns (method|None, error|None) where
        error is (status, body) for format/state problems that are NOT counted
        as guesses. (None, None) means a wrong code."""
        config = load_totp()
        using_totp = bool(config and config.get("enabled") and config.get("secret"))
        if using_totp:
            if not code:
                return None, (400, {"error": "invalid_code_format",
                                    "message": "Enter an authenticator or recovery code."})
            if verify_totp(code, config, now=now, consume=True):
                return "totp", None
            if "-" in code and consume_recovery_code(code, config):
                return "recovery", None
            # The rotating single-use PIN remains a separate first-class option.
            if code.isdigit() and len(code) == 6 and check_pin(code, now, consume=True):
                return "pin", None
            return None, None
        if not (code.isdigit() and len(code) == 6):
            return None, (400, {"error": "invalid_pin_format", "message": "Enter a 6-digit PIN."})
        otp = load_otp()
        if not otp:
            return None, (503, {"error": "no_otp",
                                "message": "No PIN is active (PINs work once). Ask Morc for a new Nullink PIN."})
        expires = otp.get("expires_at")
        if expires and float(expires) < now:
            return None, (401, {"error": "expired", "message": "PIN expired. Ask for a new Nullink PIN."})
        if check_pin(code, now, consume=True):
            return "pin", None
        return None, None

    def _rate_limited_check(self, code: str):
        """Per-client exponential lockout + global ceiling around _check_code."""
        now = time.time()
        ip = client_ip(self)
        with _auth_lock:
            rate = load_rate()
            _prune_rate(rate, now)
            locked, retry, scope = rate_locked(rate, ip, now)
            if locked:
                return None, (429, {
                    "error": "locked",
                    "scope": scope,
                    "retry_after_sec": retry,
                    "message": f"Too many attempts. Try again in {retry // 60 + 1} min.",
                })
            method, err = self._check_code(code, now)
            if err:
                return None, err
            if not method:
                using_totp = totp_enabled()
                info = rate_record_failure(rate, ip, now)
                save_rate(rate)
                if info["locked"]:
                    mins = info["retry_after"] // 60
                    return None, (429, {
                        "error": "locked",
                        "scope": info["scope"],
                        "retry_after_sec": info["retry_after"],
                        "message": f"Too many attempts. Locked for {mins} minutes.",
                    })
                left = info["attempts_left"]
                return None, (401, {
                    "error": "wrong_code" if using_totp else "wrong_pin",
                    "message": f"Incorrect code. {left} attempt(s) left.",
                    "attempts_left": left,
                })
            rate_record_success(rate, ip)
            save_rate(rate)
            return method, None

    def _auth_verify(self) -> None:
        body = self._read_json()
        code = str(body.get("code", body.get("pin", ""))).strip()
        method, err = self._rate_limited_check(code)
        if err:
            return self._json(err[0], err[1])
        value, _rec = create_session(client_ip(self), self.headers.get("User-Agent") or "", method)
        headers = []
        if self._is_https():
            # Expire any legacy cookie so browsers stop sending it.
            headers.append(("Set-Cookie", f"{LEGACY_COOKIE_NAME}=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax; Secure"))
        headers.append(("Set-Cookie", self._session_cookie(value, SESSION_TTL_SEC)))
        return self._json(200, {"ok": True, "expires_in": SESSION_TTL_SEC, "method": method}, headers)

    def _auth_logout(self) -> None:
        revoke_session(self._cookie_token())
        return self._json(200, {"ok": True}, self._clear_session_cookies())

    def _auth_logout_all(self) -> None:
        if not self._require_auth():
            return
        n = revoke_all_sessions()
        return self._json(200, {"ok": True, "revoked": n}, self._clear_session_cookies())

    def _auth_stepup(self) -> None:
        if not self._require_auth():
            return
        rec = (getattr(self, "auth", None) or {}).get("session_record") or {}
        body = self._read_json()
        code = str(body.get("code", body.get("pin", ""))).strip()
        method, err = self._rate_limited_check(code)
        if err:
            return self._json(err[0], err[1])
        mark_stepup(rec.get("_key", ""))
        return self._json(200, {"ok": True, "method": method, "valid_for_sec": STEPUP_WINDOW_SEC})

    # ----- SSH terminal (2026-10-19) -----
    def _ssh_stepup(self) -> None:
        """Owner cookie session + a TOTP code (authenticator only) -> ssh_stepup_at on that session."""
        ip, ua = client_ip(self), str(self.headers.get("User-Agent") or "")[:160]
        if self.headers.get("Authorization") is not None:
            ssh_audit("stepup_refused", reason="authorization_header", ip=ip, ua=ua)
            return self._json(403, {"error": "forbidden", "message": "Owner browser session only."})
        if self.headers.get("Origin") not in SSH_ALLOWED_ORIGINS:
            ssh_audit("stepup_refused", reason="bad_origin", origin=self.headers.get("Origin") or "(none)", ip=ip, ua=ua)
            return self._json(403, {"error": "bad_origin"})
        rec = get_session(self._cookie_token())
        if not rec:
            return self._json(401, {"error": "unauthorized"})
        if rec.get("method") == "guest" or rec.get("guest"):
            ssh_audit("stepup_refused", reason="guest", ip=ip, ua=ua)
            return self._json(403, {"error": "guest_forbidden"})
        if not totp_enabled():
            return self._json(409, {"error": "totp_not_enabled",
                                    "message": "Turn on the authenticator app in Nullink settings first."})
        code = str((self._read_json() or {}).get("code", "")).replace(" ", "").strip()
        now = time.time()
        with _auth_lock:
            rate = load_rate()
            _prune_rate(rate, now)
            locked, retry, scope = rate_locked(rate, ip, now)
            if locked:
                ssh_audit("stepup_refused", reason="locked", ip=ip, ua=ua)
                return self._json(429, {"error": "locked", "retry_after_sec": retry,
                                        "message": f"Too many attempts. Try again in {retry // 60 + 1} min."})
            ok = bool(code.isdigit() and len(code) == TOTP_DIGITS and verify_totp(code, load_totp() or {}, now, consume=True))
            if not ok:
                info = rate_record_failure(rate, ip, now)
                save_rate(rate)
                ssh_audit("stepup_failed", ip=ip, ua=ua, nullink_session=rec.get("id"))
                if info["locked"]:
                    return self._json(429, {"error": "locked", "retry_after_sec": info["retry_after"],
                                            "message": f"Too many attempts. Locked for {info['retry_after'] // 60} minutes."})
                return self._json(401, {"error": "wrong_code", "attempts_left": info["attempts_left"],
                                        "message": f"Incorrect code. {info['attempts_left']} attempt(s) left."})
            rate_record_success(rate, ip)
            save_rate(rate)
        mark_ssh_stepup(rec.get("_key", ""), now)
        ssh_audit("stepup_ok", ip=ip, ua=ua, nullink_session=rec.get("id"))
        return self._json(200, {"ok": True, "valid_for_sec": SSH_STEPUP_WINDOW_SEC})

    def _admin_ssh_session(self) -> None:
        """Loopback-only check for nullink-ssh: is this cookie value a live OWNER session?"""
        if not is_localhost(self):
            return self._json(403, {"error": "localhost_only"})
        if self.headers.get("Authorization") is not None:
            return self._json(403, {"error": "forbidden"})
        token = str((self._read_json() or {}).get("token") or "")
        rec = get_session(token) if token else None
        if not rec:
            return self._json(200, {"ok": False, "reason": "no_session"})
        if rec.get("method") == "guest" or rec.get("guest"):
            return self._json(200, {"ok": False, "reason": "guest"})
        return self._json(200, {"ok": True, "session_id": rec.get("id"), "method": rec.get("method"),
                                "ssh_stepup_at": float(rec.get("ssh_stepup_at") or 0),
                                "expires_at": float(rec.get("expires_at") or 0), "totp_enabled": totp_enabled()})

    def _require_stepup(self) -> bool:
        """Cookie session AND a fresh code (login or /api/auth/stepup) within 5 minutes."""
        if not self._require_auth():
            return False
        rec = (getattr(self, "auth", None) or {}).get("session_record") or {}
        if time.time() - float(rec.get("stepup_at") or 0) <= STEPUP_WINDOW_SEC:
            return True
        self._json(403, {
            "error": "step_up_required",
            "message": "Confirm it's you: enter an authenticator code, recovery code, or a fresh PIN.",
            "stepup_endpoint": "/api/auth/stepup",
        })
        return False

    # ----- Guest access (handler side) -----
    def _guest_gate(self, method: str, path: str) -> bool:
        """True (and response sent) if the caller is a guest session that may not do this."""
        if self.headers.get("Authorization") is not None:
            return False
        rec = get_session(self._cookie_token())
        if not rec or rec.get("method") != "guest":
            return False
        scope = rec.get("scope") or "read"
        if GUEST_HIDE_HISTORY and any(path == p or path.startswith(p + "/") for p in GUEST_HISTORY_PREFIXES):
            guest_audit("guest_history_hidden", session_id=rec.get("id"), method=method, path=path[:120])
            self._json(403, {"error": "guest_history_hidden",
                             "message": "Chat history and files are hidden for guests."})
            return True
        if guest_path_blocked(method, path, scope):
            guest_audit("guest_blocked", session_id=rec.get("id"), method=method, path=path[:120], scope=scope)
            self._json(403, {"error": "guest_forbidden",
                             "message": "Guest sessions cannot do this." if scope == "full"
                             else "Read-only guest session: changes are not allowed."})
            return True
        return False

    def _require_owner(self) -> dict | None:
        auth = self._resolve_auth()
        if not auth or auth.get("type") != "session":
            if auth and auth.get("type") == "bearer":
                self._json(403, {"error": "forbidden", "message": "owner cookie session required"})
            else:
                self._json(401, {"error": "unauthorized"})
            return None
        rec = auth.get("session_record") or {}
        if rec.get("method") == "guest":
            self._json(403, {"error": "guest_forbidden"})
            return None
        return rec

    def _guest_request_create(self) -> None:
        body = self._read_json()
        st, out = guest_create_request(body.get("name"), body.get("reason"), client_ip(self),
                                       self.headers.get("User-Agent") or "")
        return self._json(st, out)

    def _guest_request_status(self, rid: str, poll: str) -> None:
        data = load_guest()
        r = (data.get("requests") or {}).get(rid)
        if not r or not poll or not r.get("poll_hash") or not hmac.compare_digest(
                r["poll_hash"], hashlib.sha256(poll.encode()).hexdigest()):
            return self._json(404, {"error": "not_found"})
        status = r.get("status")
        if status == "pending" and time.time() - float(r.get("created_at", 0)) > GUEST_PENDING_TTL_SEC:
            status = "expired"
        return self._json(200, {"request_id": rid, "status": status})

    def _guest_redeem(self) -> None:
        body = self._read_json()
        pin = str(body.get("pin", body.get("code", "")))[:40]
        now = time.time()
        ip = client_ip(self)
        with _auth_lock:
            rate = load_rate()
            _prune_rate(rate, now)
            locked, retry, scope = rate_locked(rate, ip, now)
            if locked:
                return self._json(429, {"error": "locked", "scope": scope, "retry_after_sec": retry,
                                        "message": f"Too many attempts. Try again in {retry // 60 + 1} min."})
            req = guest_redeem_pin(pin, now)
            if not req:
                info = rate_record_failure(rate, ip, now)
                save_rate(rate)
                guest_audit("redeem_failed", ip=ip)
                return self._json(429 if info["locked"] else 401, {
                    "error": "locked" if info["locked"] else "invalid_guest_pin",
                    "message": "Invalid, used or expired guest PIN."})
            rate_record_success(rate, ip)
            save_rate(rate)
        value, rec = create_guest_session(req, ip, self.headers.get("User-Agent") or "", now)
        guest_audit("redeemed", request_id=req.get("id"), session_id=rec["id"], ip=ip, scope=rec["scope"],
                    name=req.get("name"))
        _guest_set_fields(req.get("id"), redeemed_ip=ip)
        threading.Thread(target=lambda: (slack_pin_finalize(req.get("id")), slack_session_status_tick()),
                         daemon=True).start()
        ttl = int(rec["expires_at"] - now)
        return self._json(200, {"ok": True, "guest": True, "scope": rec["scope"], "expires_in": ttl},
                          [("Set-Cookie", self._session_cookie(value, ttl))])

    def _guest_owner_list(self) -> None:
        if self._require_owner() is None:
            return
        now = time.time()
        with _auth_lock:
            data = _guest_prune(load_guest(), now)
            save_guest(data)
        reqs = sorted(data["requests"].values(), key=lambda r: r.get("created_at", 0), reverse=True)
        return self._json(200, {
            "pending": [_guest_public(r) for r in reqs if r.get("status") == "pending"],
            "recent": [_guest_public(r) for r in reqs if r.get("status") != "pending"][:20],
            "sessions": list_guest_sessions(now),
            "options": {"pin_ttl_sec": GUEST_PIN_TTL_SEC, "block_min": GUEST_BLOCK_MIN,
                        "scopes": list(GUEST_SCOPES)},
        })

    def _slack_interact(self) -> None:
        """Slack interactivity Request URL (Morc app). Signed requests from John only; no cookie auth."""
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 64 * 1024:
            return self._json(400, {"error": "bad_request"})
        raw = self.rfile.read(length)
        if not slack_verify(_slack_cred("signing_secret"), self.headers.get("X-Slack-Request-Timestamp"),
                            self.headers.get("X-Slack-Signature"), raw):
            guest_audit("slack_bad_signature", ip=client_ip(self))
            return self._json(401, {"error": "bad_signature"})
        try:
            form = urllib.parse.parse_qs(raw.decode("utf-8"))
            payload = json.loads((form.get("payload") or ["{}"])[0])
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._json(400, {"error": "bad_payload"})
        _acts = payload.get("actions") or [{}]
        _mcpgw = str((_acts[0] or {}).get("action_id") or "").startswith("mcpgw_")
        if ((payload.get("user") or {}).get("id")) != SLACK_OWNER_UID and not _mcpgw:
            slack_handle_interaction(payload)  # audits the rejection
            return self._send(200, b"", "text/plain")
        self._send(200, b"", "text/plain")  # ack within Slack's 3 s, then work
        threading.Thread(target=slack_handle_interaction, args=(payload,), daemon=True).start()

    def _guest_owner_action(self, path: str) -> None:
        rec = self._require_owner()
        if rec is None:
            return
        by = "owner:" + str(rec.get("id"))
        body = self._read_json()
        m = re.match(r"^/api/guest/requests/(GR-[A-Z0-9]{6})/(approve|deny)$", path)
        if m:
            if m.group(2) == "deny":
                st, out = guest_deny(m.group(1), by)
                return self._json(st, out)
            opts, err = _guest_opts(body)
            if err:
                return self._json(400, {"error": err})
            st, out = guest_approve(m.group(1), opts, by)
            return self._json(st, out)
        if path == "/api/guest/mint":
            opts, err = _guest_opts(body)
            if err:
                return self._json(400, {"error": err})
            st, out = guest_mint(body.get("name") or "Guest", body.get("reason") or "", opts, by, client_ip(self))
            return self._json(st, out)
        if path == "/api/guest/sessions/end-all":
            n = end_guest_sessions()
            guest_audit("sessions_ended_all", by=by, count=n)
            return self._json(200, {"ok": True, "ended": n})
        m = re.match(r"^/api/guest/sessions/([0-9a-f]{12})/extend$", path)
        if m:
            v = extend_guest_session(m.group(1), by)
            if not v:
                return self._json(404, {"error": "not_found"})
            threading.Thread(target=slack_session_status_tick, kwargs={"force": {m.group(1)}}, daemon=True).start()
            return self._json(200, {"ok": True, "expires_at": v["expires_at"], "extensions": v["extensions"]})
        m = re.match(r"^/api/guest/sessions/([0-9a-f]{12})/end$", path)
        if m:
            n = end_guest_sessions(m.group(1))
            guest_audit("session_ended", by=by, session_id=m.group(1), count=n)
            return self._json(200 if n else 404, {"ok": bool(n), "ended": n})
        return self._json(404, {"error": "not found"})

    def _list_sessions(self) -> None:
        if not self._require_auth():
            return
        current = ((getattr(self, "auth", None) or {}).get("session_record") or {}).get("id")
        now = time.time()
        out = []
        for rec in _prune_sessions(load_sessions(), now).values():
            out.append({
                "id": rec.get("id"),
                "current": rec.get("id") == current,
                "created_at": rec.get("created_at"),
                "last_seen_at": rec.get("last_seen_at"),
                "expires_at": rec.get("expires_at"),
                "ip": rec.get("ip"),
                "ua": rec.get("ua"),
                "method": rec.get("method"),
            })
        out.sort(key=lambda r: r.get("created_at") or 0, reverse=True)
        return self._json(200, {"sessions": out, "count": len(out)})

    def _totp_setup(self) -> None:
        if not self._require_stepup():
            return
        if totp_enabled():
            return self._json(409, {"error": "totp_already_enabled"})
        body = self._read_json()
        account = str(body.get("account") or "owner").strip()[:80] or "owner"
        secret = generate_totp_secret()
        save_totp({
            "enabled": False,
            "secret": secret,
            "account": account,
            "created_at": time.time(),
            "last_counter": -1,
            "recovery_hashes": [],
        })
        return self._json(200, {
            "ok": True,
            "secret": secret,
            "uri": totp_uri(secret, account),
            "issuer": "Nullink",
            "account": account,
            "algorithm": "SHA1",
            "digits": TOTP_DIGITS,
            "period": TOTP_STEP_SEC,
        })

    def _totp_confirm(self) -> None:
        if not self._require_stepup():
            return
        body = self._read_json()
        code = str(body.get("code") or "").strip()
        config = load_totp()
        if not config or config.get("enabled") or not config.get("secret"):
            return self._json(409, {"error": "setup_not_pending"})
        if not verify_totp(code, config, consume=False):
            return self._json(401, {"error": "wrong_code", "message": "That authenticator code did not match."})
        recovery_codes = make_recovery_codes()
        config["enabled"] = True
        config["enabled_at"] = time.time()
        config["last_counter"] = -1
        config["recovery_hashes"] = [_recovery_hash(code) for code in recovery_codes]
        save_totp(config)
        return self._json(200, {"ok": True, "recovery_codes": recovery_codes})

    def _totp_disable(self) -> None:
        if not self._require_stepup():
            return
        body = self._read_json()
        code = str(body.get("code") or "").strip()
        config = load_totp()
        if not config or not config.get("enabled"):
            return self._json(409, {"error": "totp_not_enabled"})
        if not verify_totp(code, config, consume=False):
            return self._json(401, {"error": "wrong_code", "message": "A current authenticator code is required."})
        try:
            TOTP_FILE.unlink()
        except FileNotFoundError:
            pass
        return self._json(200, {"ok": True, "method": "pin"})

    def _post_message(self) -> None:
        if not self._require_api_auth(["messages:write"]):
            return
        body = self._read_json()
        text = str(body.get("text", "")).strip()
        if not text:
            return self._json(400, {"error": "empty", "message": "Message cannot be empty."})
        if len(text) > 8000:
            return self._json(400, {"error": "too_long", "message": "Message too long."})
        auth = getattr(self, "auth", None) or {}
        if auth.get("type") == "bearer":
            cmd = ai_rooms.parse(text)
            if cmd:
                code, out = ai_rooms.handle(cmd[0], cmd[1], auth, self._room_titles())
                return self._json(code, out)
        sid = self._resolve_room(body.get("session_id"))
        if not self._require_session_access(sid):
            return
        if sid in OWNER_ONLY_SESSIONS and (get_session(self._cookie_token()) or {}).get("method") == "guest":
            return self._json(403, {"error": "guest_forbidden"})
        msg = append_message("user", text, session_id=sid)
        if sid not in BRIDGE_SESSIONS:
            write_pending("notify", {"preview": text[:200]})
            fire_webhook("message", text[:200])
        return self._json(200, {"ok": True, "message": msg})

    def _create_token(self) -> None:
        if not self._require_stepup():
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
        if not self._require_stepup():
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
        try:
            ttl = int(body.get("ttl_sec") or PIN_TTL_SEC)
        except (TypeError, ValueError):
            return self._json(400, {"error": "invalid_ttl"})
        info = write_otp(pin, ttl)
        return self._json(200, {"ok": True, "expires_at": info["expires_at"], "single_use": True})

    def _admin_a2a_post(self) -> None:
        """Localhost-only: the A2A service posts an authenticated agent's message into the council room."""
        if not is_localhost(self):
            return self._json(403, {"error": "localhost_only"})
        body = self._read_json()
        text = str(body.get("text", "")).strip()
        agent = re.sub(r"[^A-Za-z0-9_.-]", "", str(body.get("agent") or ""))[:64]
        if not text or not agent:
            return self._json(400, {"error": "text_and_agent_required"})
        if len(text) > 8000:
            return self._json(400, {"error": "too_long"})
        msg = append_message("agent", f"[{agent}] {text}", session_id="council")
        return self._json(200, {"ok": True, "message": msg})

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
        avatars.seed_defaults()
    except Exception as exc:  # never block startup on starter avatars
        print(f"avatar seed skipped: {exc}", flush=True)
    try:
        ensure_chatgpt_playground_label()
    except Exception as exc:
        print(f"ensure_chatgpt_playground_label: {exc}", flush=True)
    try:
        print(f"files_manager.migrate: {files_manager.migrate()}", flush=True)
        import fm_uploads
        print(f"fm_uploads.cleanup_stale: {fm_uploads.cleanup_stale()}", flush=True)
    except Exception as exc:
        print(f"files_manager.migrate: {exc}", flush=True)
    if MESSAGES_FILE.stat().st_size == 0:
        append_message(
            "assistant",
            "Nullink online. You're talking to Chief of Staff (Morc). Chat, Files, and Ask Morc are ready.",
            session_id="morc",
        )
    httpd = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"Nullink PM listening on 127.0.0.1:{PORT}", flush=True)
    guest_watch_start()
    httpd.serve_forever()


share_links.bind(_sys.modules[__name__])
files_manager.bind(_sys.modules[__name__])
server_drive.bind(_sys.modules[__name__])
github_drive.bind(_sys.modules[__name__])

if __name__ == "__main__":
    main()
