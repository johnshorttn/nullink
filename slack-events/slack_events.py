#!/usr/bin/env python3
"""Nullverse Slack Events router (one endpoint for every bot app).

Slack -> https://nullink.nullverse.cloud/slack/events/<bot_id> -> Caddy -> 127.0.0.1:8772

* Ingress is authenticated: every request must carry a valid Slack v0 HMAC signature made with that app's
  signing secret, inside a 5-minute replay window. Unsigned/badly signed events are never processed.
  (Bootstrap only: until a bot's signing secret is installed, the side-effect-free url_verification
  challenge is answered so "create app from manifest" can succeed; events are dropped until then.)
* Durable dedup (SQLite): event_id, client_msg_id and channel+ts.
* Auto-join: every bot joins every public, non-archived channel with its own token (startup + periodic sweep,
  channel_created, channel_unarchive). A bot that was removed is never auto-rejoined; a human /invite clears that.
  Private channels still need a one-time /invite. Welcome: on a human invite, or one brief line in channels
  created after auto-join was enabled; sweep joins of existing channels are silent.
* Routes @mentions and DMs to the bot's brain adapter (registry.json):
    slack_wake     -> marker post to #general via Slack Incoming Webhook -> 'Nullink Slack wake' routine
                      (keyword nullink-wake) -> Morc replies in-thread with bots_post
    chatgpt_bridge -> job spool for a browser bridge (Jinx -> dedicated ChatGPT chat per Slack channel);
                      the router posts the answer in the thread as the bot
    nullink_room   -> Nullink room; replies written there as "slack <ref>: ..." are relayed to the thread
  A brain can name a fallback brain + a short ack posted as the bot when the primary isn't ready.
* Guardrails: bot messages ignored except explicit handoffs between registered bots (source bot identity
  checked; durable correlation id per thread, TTL, hop budget); per-bot / per-user rate limits; only bot
  tokens are used (never a human's).

Secrets come from systemd credentials ($CREDENTIALS_DIRECTORY/slack_<file>, root-owned 0600 source files in
/etc/nullink/slack/). Stdlib only. Never logs tokens or secrets.
"""
from __future__ import annotations

import faulthandler
import hashlib
import hmac
import json
import logging
import logging.handlers
import os
import secrets as pysecrets
import sqlite3
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOME = Path(os.environ.get("SLACK_EVENTS_HOME", "/opt/nullink/slack-events"))
REGISTRY = Path(os.environ.get("SLACK_EVENTS_REGISTRY", str(HOME / "registry.json")))
CRED_DIR = os.environ.get("CREDENTIALS_DIRECTORY")  # systemd LoadCredential=slack:/etc/nullink/slack
SECRETS = Path(os.environ.get("SLACK_EVENTS_SECRETS", "/nonexistent"))  # test/dev fallback only
STATE = Path(os.environ.get("SLACK_EVENTS_STATE", str(HOME / "state")))
NULLINK_MESSAGES = Path(os.environ.get("NULLINK_MESSAGES", "/opt/nullink/data/messages.jsonl"))
HOST = os.environ.get("SLACK_EVENTS_HOST", "127.0.0.1")
PORT = int(os.environ.get("SLACK_EVENTS_PORT", "8772"))
SLACK_API = os.environ.get("SLACK_API_BASE", "https://slack.com/api").rstrip("/")
JOIN_SWEEP_SEC = int(os.environ.get("SLACK_JOIN_SWEEP_SEC", "300"))  # safety net; events do the fast path
JOIN_PACE_SEC = float(os.environ.get("SLACK_JOIN_PACE_SEC", "1.2"))   # conversations.join is Tier 3 (~50/min)
RELAY_POLL_SEC = float(os.environ.get("SLACK_RELAY_POLL_SEC", "2"))
MAX_BODY = 1 << 20
FORBIDDEN_SESSIONS = {"deepseek"}  # answered by the DeepSeek bridge; never post there
SIG_MAX_SKEW = 300
LOOPBACK = {"127.0.0.1", "::1"}
HANDOFF_TTL_SEC = 1800
HANDOFF_BUDGET = 2

STATE.mkdir(parents=True, exist_ok=True)
log = logging.getLogger("slack-events")
log.setLevel(logging.INFO)
_h = logging.StreamHandler(sys.stdout)
_h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
log.addHandler(_h)
try:
    _fh = logging.handlers.RotatingFileHandler(STATE / "receiver.log", maxBytes=2_000_000, backupCount=3)
    _fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(_fh)
except OSError:
    pass

_state_lock = threading.RLock()


# ----------------------------------------------------------------------------- helpers
def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("read %s failed: %s", path.name, exc)
        return default


def write_json(path: Path, data) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, path)


def append_jsonl(path: Path, obj: dict) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


_reg_cache: dict = {"mtime": None, "data": {"bots": []}}


def registry() -> dict:
    try:
        mt = REGISTRY.stat().st_mtime
    except OSError:
        return _reg_cache["data"]
    if mt != _reg_cache["mtime"]:
        data = read_json(REGISTRY, None)
        if isinstance(data, dict) and isinstance(data.get("bots"), list):
            _reg_cache.update(mtime=mt, data=data)
            log.info("registry loaded: %s", ", ".join(b.get("id", "?") for b in data["bots"]))
    return _reg_cache["data"]


def get_bot(bot_id: str) -> dict | None:
    for b in registry().get("bots", []):
        if b.get("id") == bot_id:
            return b
    return None


def _secret_file(name: str) -> str | None:
    paths = ([Path(CRED_DIR) / f"slack_{name}"] if CRED_DIR else []) + [SECRETS / name]
    for p in paths:
        try:
            v = p.read_text(encoding="utf-8").strip()
            if v:
                return v
        except OSError:
            continue
    return None


def bot_token(bot: dict) -> str | None:
    return _secret_file(f"{bot['id']}.token")


def signing_secret(bot: dict) -> str | None:
    return _secret_file(f"{bot['id']}.signing_secret")


def slack(token: str, method: str, params: dict | None = None, _retry: bool = True) -> dict:
    data = urllib.parse.urlencode({k: v for k, v in (params or {}).items() if v is not None}).encode()
    req = urllib.request.Request(
        f"{SLACK_API}/{method}",
        data=data,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        if exc.code == 429 and _retry:
            time.sleep(min(int(exc.headers.get("Retry-After", "2") or 2), 30))
            return slack(token, method, params, _retry=False)
        return {"ok": False, "error": f"http_{exc.code}"}
    except Exception as exc:  # network etc.
        return {"ok": False, "error": f"request_failed:{type(exc).__name__}"}


def verify_signature(secret: str, headers, body: bytes) -> bool:
    ts = headers.get("X-Slack-Request-Timestamp") or ""
    sig = headers.get("X-Slack-Signature") or ""
    if not ts.isdigit() or not sig.startswith("v0="):
        return False
    if abs(time.time() - int(ts)) > SIG_MAX_SKEW:
        return False
    base = b"v0:" + ts.encode() + b":" + body
    want = "v0=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, sig)


# ----------------------------------------------------------------------------- state
DB_PATH = STATE / "router.db"


def db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    return con


def db_init() -> None:
    with _state_lock:
        con = db()
        con.executescript("""
            CREATE TABLE IF NOT EXISTS seen (key TEXT PRIMARY KEY, at REAL);
            CREATE TABLE IF NOT EXISTS handoffs (thread_key TEXT PRIMARY KEY, corr TEXT, hops INTEGER,
                                                 created REAL, expires REAL, last_from TEXT, last_to TEXT);
            CREATE TABLE IF NOT EXISTS channels (bot TEXT, channel TEXT, name TEXT, joined_at REAL, left_at REAL,
                                                 active INTEGER, PRIMARY KEY (bot, channel));
            CREATE TABLE IF NOT EXISTS inbox (event_key TEXT PRIMARY KEY, bot TEXT, payload TEXT, state TEXT,
                                              phase TEXT, created REAL, updated REAL, error TEXT);
            CREATE INDEX IF NOT EXISTS inbox_state ON inbox(state, created);
            CREATE TABLE IF NOT EXISTS sends (send_key TEXT PRIMARY KEY, bot TEXT, channel TEXT, thread_ts TEXT,
                                              state TEXT, ts TEXT, error TEXT, created REAL, updated REAL);
            CREATE TABLE IF NOT EXISTS wakes (job TEXT PRIMARY KEY, bot TEXT, channel TEXT, ts TEXT, thread_ts TEXT,
                                              kind TEXT, state TEXT, attempts INTEGER, created REAL, updated REAL,
                                              next_at REAL, woken_at REAL, checked_at REAL, done_at REAL,
                                              done_by TEXT, error TEXT);
            CREATE TABLE IF NOT EXISTS joins (bot TEXT, channel TEXT, name TEXT, state TEXT, why TEXT, removed_by TEXT,
                                              error TEXT, updated REAL, PRIMARY KEY (bot, channel));
            CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
            CREATE TABLE IF NOT EXISTS rate_hits (key TEXT, t REAL);
            CREATE INDEX IF NOT EXISTS rate_hits_kt ON rate_hits(key, t);
            CREATE TABLE IF NOT EXISTS jobs (request_key TEXT PRIMARY KEY, bot TEXT, runtime_id TEXT, ref TEXT,
                                             channel TEXT, thread_ts TEXT, thread_key TEXT, corr TEXT, hop INTEGER,
                                             expires_at REAL, state TEXT, created REAL, updated REAL, error TEXT);
        """)
        hcols = [r[1] for r in con.execute("PRAGMA table_info(handoffs)")]
        if "jobs" not in hcols:
            con.execute("ALTER TABLE handoffs ADD COLUMN jobs INTEGER DEFAULT 0")
        if "origin" not in hcols:
            con.execute("ALTER TABLE handoffs ADD COLUMN origin TEXT")
        con.execute("DELETE FROM rate_hits WHERE t < ?", (time.time() - 86400,))
        cols = [r[1] for r in con.execute("PRAGMA table_info(seen)")]
        if "owner" not in cols:
            con.execute("ALTER TABLE seen ADD COLUMN owner TEXT")
        # crash recovery: events that never reached a side effect are re-run; others need a human look
        con.execute("UPDATE inbox SET state='queued' WHERE state='processing' AND phase='received'")
        con.execute("UPDATE inbox SET state='uncertain', error='interrupted after dispatch started' "
                    "WHERE state='processing'")
        con.execute("DELETE FROM seen WHERE at < ?", (time.time() - 14 * 86400,))
        con.close()


def _seen_mark(key: str, owner: str | None = None) -> bool:
    """Durable dedup. True if key was already claimed by a *different* owner (event); else claim it."""
    with _state_lock:
        con = db()
        try:
            con.execute("INSERT INTO seen (key, at, owner) VALUES (?, ?, ?)", (key, time.time(), owner))
            return False
        except sqlite3.IntegrityError:
            row = con.execute("SELECT owner FROM seen WHERE key = ?", (key,)).fetchone()
            return not (owner and row and row[0] == owner)  # same event re-run after a crash -> not a dup
        finally:
            con.close()


# ----------------------------------------------------------------------------- durable inbox (ingest before ack)
_wake = threading.Event()


def inbox_put(event_key: str, bot_id: str, raw: bytes) -> str:
    """Commit the verified event to SQLite before Slack gets its 200. -> 'queued' | 'dup' | 'busy'."""
    with _state_lock:
        con = db()
        try:
            if con.execute("SELECT count(*) FROM inbox WHERE state IN ('queued','processing')").fetchone()[0] >= 1000:
                return "busy"
            cur = con.execute("INSERT OR IGNORE INTO inbox VALUES (?, ?, ?, 'queued', NULL, ?, ?, NULL)",
                              (event_key, bot_id, raw.decode("utf-8"), time.time(), time.time()))
            return "queued" if cur.rowcount == 1 else "dup"
        finally:
            con.close()


_busy_threads: set[str] = set()  # bot:channel:thread keys a worker is handling right now (guarded by _state_lock)


def _thread_key_of(bot_id: str, payload: dict) -> str:
    ev = payload.get("event") or {}
    ch = ev.get("channel")
    ch = ch.get("id") if isinstance(ch, dict) else (ch or "")
    return f"{bot_id}:{ch}:{ev.get('thread_ts') or ev.get('ts') or ''}"


def inbox_claim() -> tuple[str, str, dict, str] | None:
    """Claim the oldest queued event whose Slack thread no other worker is handling (per-thread ordering)."""
    with _state_lock:
        con = db()
        try:
            skipped: set[str] = set()
            for key, bot_id, raw in con.execute(
                    "SELECT event_key, bot, payload FROM inbox WHERE state='queued' ORDER BY created LIMIT 200").fetchall():
                payload = json.loads(raw)
                tkey = _thread_key_of(bot_id, payload)
                if tkey in _busy_threads or tkey in skipped:
                    skipped.add(tkey)  # keep later events of a busy thread behind the earlier one
                    continue
                con.execute("UPDATE inbox SET state='processing', phase='received', updated=? WHERE event_key=?",
                            (time.time(), key))
                _busy_threads.add(tkey)
                return key, bot_id, payload, tkey
            return None
        finally:
            con.close()


def inbox_release(tkey: str) -> None:
    with _state_lock:
        _busy_threads.discard(tkey)
    _wake.set()


def inbox_set(event_key: str, state: str | None = None, phase: str | None = None, error: str | None = None) -> None:
    with _state_lock:
        con = db()
        con.execute("UPDATE inbox SET state=COALESCE(?, state), phase=COALESCE(?, phase), error=COALESCE(?, error), "
                    "updated=? WHERE event_key=?", (state, phase, error, time.time(), event_key))
        con.close()


# ----------------------------------------------------------------------------- idempotent sends
AMBIGUOUS_ERRORS = ("internal_error", "fatal_error", "request_timeout", "service_unavailable")


def _norm_text(t: str) -> str:
    """Whole-message normalisation for reconcile (never a prefix: different long replies must not match)."""
    t = re.sub(r"<((?:https?|mailto):[^>|]+)(?:\|[^>]*)?>", r"\1", t or "")
    t = t.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
    return re.sub(r"\s+", " ", t).strip()


def _send_row(key: str):
    con = db()
    try:
        return con.execute("SELECT state, ts FROM sends WHERE send_key=?", (key,)).fetchone()
    finally:
        con.close()


def _send_set(key: str, bot_id: str, channel: str, thread_ts: str | None, state: str, ts: str | None = None,
              error: str | None = None) -> None:
    with _state_lock:
        con = db()
        con.execute("INSERT INTO sends VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(send_key) DO UPDATE SET "
                    "state=CASE WHEN sends.state='done' THEN 'done' ELSE excluded.state END, "
                    "ts=COALESCE(excluded.ts, sends.ts), error=excluded.error, updated=excluded.updated",
                    (key, bot_id, channel, thread_ts, state, ts, error, time.time(), time.time()))
        con.close()


def _send_claim(key: str, bot_id: str, channel: str, thread_ts: str | None) -> str | None:
    """Atomically check the send key and claim it for posting. -> None if we now own the post,
    else the existing state ('done' | 'posting' | 'uncertain') that blocks a fresh post."""
    with _state_lock:
        con = db()
        try:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute("SELECT state FROM sends WHERE send_key=?", (key,)).fetchone()
            if row and row[0] in ("done", "posting", "uncertain"):
                con.execute("COMMIT")
                return row[0]
            con.execute("INSERT INTO sends VALUES (?, ?, ?, ?, 'posting', NULL, NULL, ?, ?) ON CONFLICT(send_key) "
                        "DO UPDATE SET state='posting', error=NULL, updated=excluded.updated",
                        (key, bot_id, channel, thread_ts, time.time(), time.time()))
            con.execute("COMMIT")
            return None
        except Exception:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()


def reconcile_send(bot: dict, token: str, channel: str, thread_ts: str | None, text: str) -> str | None:
    """Authoritative read-side check: did our bot already post this text there? -> its ts or None."""
    want = _norm_text(text)
    if thread_ts:
        r = slack(token, "conversations.replies", {"channel": channel, "ts": thread_ts, "limit": 200})
    else:
        r = slack(token, "conversations.history", {"channel": channel, "limit": 50})
    if not r.get("ok"):
        return None
    for m in r.get("messages", []):
        if m.get("bot_id") == bot.get("bot_id") and _norm_text(m.get("text") or "") == want:
            return m.get("ts")
    return None


def send_once(bot: dict, key: str, channel: str, thread_ts: str | None, text: str) -> str:
    """Post at most once per idempotency key. -> 'ok' | 'dup' | 'reconciled' | 'retry' | 'uncertain' | 'failed:<err>'.
    Ambiguous outcomes (network error, 5xx, Slack internal errors, crash mid-send) are reconciled by reading
    the thread; if still unknown the send is parked as 'uncertain' and never blindly retried."""
    token = bot_token(bot)
    if not token:
        return "failed:no_token"
    text = text[:39000]
    row = _send_row(key)
    if row and row[0] == "done":
        return "dup"
    if not (row and row[0] in ("posting", "uncertain")) and not outbound_allowed(bot):
        return "retry"
    held = _send_claim(key, bot["id"], channel, thread_ts)  # check + claim in one transaction
    if held == "done":
        return "dup"
    if held in ("posting", "uncertain"):
        ts = reconcile_send(bot, token, channel, thread_ts, text)
        if ts:
            _send_set(key, bot["id"], channel, thread_ts, "done", ts)
            return "reconciled"
        _send_set(key, bot["id"], channel, thread_ts, "uncertain", error="outcome unknown; not re-posted")
        return "uncertain"
    r = slack(token, "chat.postMessage", {"channel": channel, "thread_ts": thread_ts, "text": text,
                                          "unfurl_links": "false", "unfurl_media": "false"})
    if r.get("ok"):
        _send_set(key, bot["id"], channel, thread_ts, "done", r.get("ts"))
        return "ok"
    err = str(r.get("error") or "unknown")
    if err.startswith("request_failed") or err.startswith("http_5") or err in AMBIGUOUS_ERRORS:
        ts = reconcile_send(bot, token, channel, thread_ts, text)
        if ts:
            _send_set(key, bot["id"], channel, thread_ts, "done", ts)
            return "reconciled"
        _send_set(key, bot["id"], channel, thread_ts, "uncertain", error=err)
        return "uncertain"
    if err in ("ratelimited", "http_429"):
        _send_set(key, bot["id"], channel, thread_ts, "retry", error=err)
        return "retry"
    _send_set(key, bot["id"], channel, thread_ts, "failed", error=err)
    return "failed:" + err


# Handoff chains. A chain is created ONLY by a human-origin message (chain_start). Bot->bot handoffs must
# find that chain unexpired and within its hop/job budgets (handoff_step). Expiry is fixed when the human
# starts the chain and is never extended. Expired/exhausted rows are kept as tombstones, so a late bot
# reply can never start a new chain; only a new human turn in the thread replaces the row.
def chain_start(thread_key: str, origin: str, ttl: int) -> str:
    """Start (or, for the same human message seen by several bots, re-use) the thread's chain -> corr."""
    now = time.time()
    with _state_lock:
        con = db()
        try:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute("SELECT corr, origin FROM handoffs WHERE thread_key = ?", (thread_key,)).fetchone()
            if row and row[1] == origin:
                con.execute("COMMIT")
                return row[0]
            corr = "h" + pysecrets.token_hex(5)
            con.execute("INSERT OR REPLACE INTO handoffs (thread_key, corr, hops, created, expires, last_from, "
                        "last_to, jobs, origin) VALUES (?, ?, 0, ?, ?, ?, NULL, 1, ?)",
                        (thread_key, corr, now, now + ttl, origin, origin))
            con.execute("COMMIT")
            return corr
        except Exception:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()


def chain_get(thread_key: str) -> dict | None:
    with _state_lock:
        con = db()
        try:
            row = con.execute("SELECT corr, hops, jobs, created, expires, origin FROM handoffs WHERE thread_key = ?",
                              (thread_key,)).fetchone()
        finally:
            con.close()
    if not row:
        return None
    return {"corr": row[0], "hops": int(row[1] or 0), "jobs": int(row[2] or 0), "created": row[3],
            "expires": float(row[4] or 0), "origin": row[5]}


def edge_allowed(src: str, dst: str) -> bool:
    edges = registry().get("handoff_edges")
    if edges is None:
        return True
    return [src, dst] in [list(e) for e in edges]


def _chain_verdict(row, now: float, msg_ts: float | None, budget: int, job_budget: int) -> str | None:
    if not row or not str(row["origin"] or "").startswith("human:"):
        return "no_human_chain"
    if now > row["expires"] or (msg_ts is not None and msg_ts > row["expires"]):
        return "chain_expired"
    if row["hops"] + 1 > budget:
        return "hop_budget_exhausted"
    if row["jobs"] + 1 > job_budget:
        return "job_budget_exhausted"
    return None


def _budgets() -> tuple[int, int]:
    reg = registry()
    budget = min(int(reg.get("handoff_hop_budget", HANDOFF_BUDGET)), 4)
    return budget, min(int(reg.get("handoff_job_budget", budget + 1)), 10)


def chain_peek(thread_key: str, src: str, dst: str) -> str | None:
    """Would a src->dst handoff in this thread be accepted right now? None = yes, else the reason."""
    if not edge_allowed(src, dst):
        return "edge_not_allowed"
    budget, job_budget = _budgets()
    return _chain_verdict(chain_get(thread_key), time.time(), None, budget, job_budget)


def handoff_step(thread_key: str, src: str, dst: str, budget: int | None = None, ttl: int | None = None,
                 msg_ts: str | float | None = None, job_budget: int | None = None) -> tuple[str | None, int | str]:
    """Count one bot->bot hop on the thread's ORIGINAL human chain. -> (corr, hop no.) or (None, reason).
    Never creates a chain and never extends its expiry (ttl is accepted for compatibility and ignored)."""
    dbud, djob = _budgets()
    budget = dbud if budget is None else budget
    job_budget = djob if job_budget is None else job_budget
    if not edge_allowed(src, dst):
        return None, "edge_not_allowed"
    now = time.time()
    try:
        mts = float(msg_ts) if msg_ts is not None else None
    except (TypeError, ValueError):
        mts = None
    with _state_lock:
        con = db()
        try:
            con.execute("BEGIN IMMEDIATE")
            r = con.execute("SELECT corr, hops, jobs, created, expires, origin FROM handoffs WHERE thread_key = ?",
                            (thread_key,)).fetchone()
            row = r and {"corr": r[0], "hops": int(r[1] or 0), "jobs": int(r[2] or 0), "created": r[3],
                         "expires": float(r[4] or 0), "origin": r[5]}
            why = _chain_verdict(row, now, mts, budget, job_budget)
            if why:
                con.execute("COMMIT")
                return None, why
            con.execute("UPDATE handoffs SET hops = hops + 1, jobs = jobs + 1, last_from = ?, last_to = ? "
                        "WHERE thread_key = ?", (src, dst, thread_key))
            con.execute("COMMIT")
            return row["corr"], row["hops"] + 1
        except Exception:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()


def channel_set(bot_id: str, channel: str, name: str | None, active: bool) -> bool:
    """Register/deregister a channel for a bot. Returns True if the state changed."""
    with _state_lock:
        con = db()
        try:
            row = con.execute("SELECT active FROM channels WHERE bot = ? AND channel = ?", (bot_id, channel)).fetchone()
            if row and bool(row[0]) == active:
                return False
            if active:
                con.execute("INSERT OR REPLACE INTO channels VALUES (?, ?, ?, ?, NULL, 1)", (bot_id, channel, name, time.time()))
            else:
                con.execute("UPDATE channels SET active = 0, left_at = ? WHERE bot = ? AND channel = ?",
                            (time.time(), bot_id, channel))
                if not row:
                    con.execute("INSERT INTO channels VALUES (?, ?, ?, NULL, ?, 0)", (bot_id, channel, name, time.time()))
            return True
        finally:
            con.close()


def channels_for(bot_id: str) -> list[dict]:
    con = db()
    try:
        return [{"channel": c, "name": n} for c, n in
                con.execute("SELECT channel, name FROM channels WHERE bot = ? AND active = 1", (bot_id,))]
    finally:
        con.close()


def make_ref(bot_id: str, channel: str, ts: str) -> str:
    return "s" + hashlib.sha1(f"{bot_id}:{channel}:{ts}".encode()).hexdigest()[:6]


def save_ref(rec: dict) -> None:
    with _state_lock:
        refs = read_json(STATE / "refs.json", {})
        refs[rec["ref"]] = rec
        if len(refs) > 1000:
            for k in sorted(refs, key=lambda k: refs[k].get("received_epoch", 0))[: len(refs) - 1000]:
                refs.pop(k, None)
        write_json(STATE / "refs.json", refs)


def get_ref(ref: str) -> dict | None:
    with _state_lock:
        return read_json(STATE / "refs.json", {}).get(ref)


# ----------------------------------------------------------------------------- slack lookups
_name_cache: dict[str, tuple[float, str]] = {}


def _cached(key: str, fn) -> str:
    hit = _name_cache.get(key)
    if hit and time.time() - hit[0] < 3600:
        return hit[1]
    val = fn()
    _name_cache[key] = (time.time(), val)
    return val


def user_name(token: str, uid: str) -> str:
    if not uid:
        return "someone"

    def f():
        r = slack(token, "users.info", {"user": uid})
        u = r.get("user") or {}
        p = u.get("profile") or {}
        return p.get("display_name") or u.get("real_name") or u.get("name") or uid

    return _cached("u:" + uid, f)


def channel_name(token: str, cid: str, is_im: bool) -> str:
    if is_im:
        return "DM"

    def f():
        r = slack(token, "conversations.info", {"channel": cid})
        c = r.get("channel") or {}
        return ("#" + c["name"]) if c.get("name") else cid

    return _cached("c:" + cid, f)


def readable(token: str, text: str) -> str:
    """<@U123> -> @name, <#C1|name> -> #name, <url|label> -> label (url)."""
    text = re.sub(r"<@([UW][A-Z0-9]+)(?:\|[^>]*)?>", lambda m: "@" + user_name(token, m.group(1)), text or "")
    text = re.sub(r"<#([CG][A-Z0-9]+)\|([^>]*)>", lambda m: "#" + (m.group(2) or m.group(1)), text)
    text = re.sub(r"<(https?://[^|>]+)\|([^>]+)>", r"\2 (\1)", text)
    text = re.sub(r"<(https?://[^>]+)>", r"\1", text)
    return text.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")


# ----------------------------------------------------------------------------- channel joins (auto-join)
# Every active bot joins every public, non-archived channel with its OWN token: a sweep at startup and every
# JOIN_SWEEP_SEC, plus channel_created / channel_unarchive events. State lives in SQLite `joins`:
#   member | removed (someone removed the bot -> never auto-rejoined; only a human /invite clears it)
#   skipped (archived/not joinable) | join_failed (retried next sweep).
# Welcomes: none on sweep joins of pre-existing channels; one brief line when the channel was created after
# auto-join was enabled for that bot; the normal welcome on a human /invite (member_joined_channel + inviter).
# Missing scopes (before John reinstalls) are logged once per bot+scope; the sweep just retries later.
_join_blocked: dict[str, str] = {}
SCOPE_ERRORS = ("missing_scope", "not_allowed_token_type", "invalid_auth", "account_inactive", "token_revoked")


def meta_get(k: str) -> str | None:
    with _state_lock:
        con = db()
        try:
            r = con.execute("SELECT v FROM meta WHERE k = ?", (k,)).fetchone()
            return r[0] if r else None
        finally:
            con.close()


def bot_since(bot_id: str) -> float:
    """When auto-join was first enabled for this bot (channels created later count as 'new')."""
    with _state_lock:
        con = db()
        try:
            con.execute("INSERT OR IGNORE INTO meta (k, v) VALUES (?, ?)", (f"autojoin_since:{bot_id}", str(time.time())))
            return float(con.execute("SELECT v FROM meta WHERE k = ?", (f"autojoin_since:{bot_id}",)).fetchone()[0])
        finally:
            con.close()


def join_state(bot_id: str, cid: str) -> str | None:
    with _state_lock:
        con = db()
        try:
            r = con.execute("SELECT state FROM joins WHERE bot = ? AND channel = ?", (bot_id, cid)).fetchone()
            return r[0] if r else None
        finally:
            con.close()


def join_record(bot_id: str, cid: str, state: str, why: str | None = None, name: str | None = None,
                removed_by: str | None = None, error: str | None = None) -> None:
    with _state_lock:
        con = db()
        try:
            con.execute("INSERT INTO joins (bot, channel, name, state, why, removed_by, error, updated) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(bot, channel) DO UPDATE SET "
                        "name = COALESCE(excluded.name, joins.name), state = excluded.state, why = excluded.why, "
                        "removed_by = excluded.removed_by, error = excluded.error, updated = excluded.updated",
                        (bot_id, cid, name, state, why, removed_by, error, time.time()))
        finally:
            con.close()


def _scope_blocked(bot: dict, r: dict, method: str) -> bool:
    err = str(r.get("error") or "")
    if err not in SCOPE_ERRORS:
        return False
    why = f"{err}{(' needs ' + str(r.get('needed'))) if r.get('needed') else ''} ({method})"
    if _join_blocked.get(bot["id"]) != why:  # log once per bot + problem, no crash, retry next sweep
        log.warning("%s: auto-join paused: %s - update the app manifest and reinstall; will retry automatically",
                    bot["id"], why)
    _join_blocked[bot["id"]] = why
    return True


def _scope_ok(bot: dict) -> None:
    if _join_blocked.pop(bot["id"], None):
        log.info("%s: auto-join scopes present now; resuming", bot["id"])


def welcome_text(bot: dict, brief: bool) -> str:
    inbound = bot.get("inbound") or {}
    if brief:
        return inbound.get("welcome_new_channel", f"Hi, I'm {bot_label(bot)}. Mention @{bot.get('handle') or bot['id']} for help.")
    return inbound.get("welcome", f"Hi, I'm {bot_label(bot)}. Mention @{bot.get('handle') or bot['id']} here and I'll answer in a thread.")


def do_join(bot: dict, token: str, c: dict, why: str) -> str:
    """Join one public channel as this bot. -> 'joined' | 'member' | 'removed' | 'skipped' | 'blocked' | 'failed'."""
    cid = c["id"]
    name = ("#" + c["name"]) if c.get("name") else None
    if join_state(bot["id"], cid) == "removed":
        return "removed"  # deliberately removed: never rejoin against John's wishes
    if c.get("is_member"):
        join_record(bot["id"], cid, "member", "already_member", name)
        channel_set(bot["id"], cid, name, True)
        return "member"
    if c.get("is_archived") or c.get("is_private") or c.get("is_im") or c.get("is_mpim"):
        return "skipped"
    r = slack(token, "conversations.join", {"channel": cid})
    if r.get("ok"):
        _scope_ok(bot)
        join_record(bot["id"], cid, "member", why, name)
        channel_set(bot["id"], cid, name, True)
        created = float(c.get("created") or (r.get("channel") or {}).get("created") or 0)
        new = created >= bot_since(bot["id"]) and time.time() - created < 6 * 3600
        log.info("%s: auto-joined %s (%s)%s", bot["id"], name or cid, why, " + brief welcome" if new else "")
        if new and (bot.get("inbound") or {}).get("welcome_new_channel", True) is not False:
            post_as_bot(bot, f"welcome:{bot['id']}:{cid}:new", cid, None, welcome_text(bot, brief=True))
        return "joined"
    if _scope_blocked(bot, r, "conversations.join"):
        return "blocked"
    err = str(r.get("error") or "unknown")
    if err in ("is_archived", "channel_not_found", "method_not_supported_for_channel_type"):
        join_record(bot["id"], cid, "skipped", why, name, error=err)
        return "skipped"
    join_record(bot["id"], cid, "join_failed", why, name, error=err)
    log.warning("%s: join %s failed: %s", bot["id"], name or cid, err)
    return "failed"


def join_channel(bot: dict, token: str, cid: str, why: str) -> str:
    """Event path (channel_created / channel_unarchive / explicit list): look the channel up, then join."""
    info = slack(token, "conversations.info", {"channel": cid})
    if not info.get("ok"):
        if not _scope_blocked(bot, info, "conversations.info"):
            log.info("join %s %s skipped: %s", bot["id"], cid, info.get("error"))
        return "blocked" if str(info.get("error")) in SCOPE_ERRORS else "failed"
    return do_join(bot, token, info.get("channel") or {"id": cid}, why)


def join_sweep(only_bot: str | None = None) -> dict:
    out = {}
    for bot in registry().get("bots", []):
        if only_bot and bot.get("id") != only_bot:
            continue
        aj, token = bot.get("auto_join") or {}, bot_token(bot)
        if not token or aj.get("enabled") is False:
            continue
        bot_since(bot["id"])
        exclude = set(aj.get("exclude") or [])
        res: dict[str, list] = {}
        budget = int(aj.get("max_joins_per_sweep", 100))
        for cid in aj.get("channels") or []:  # explicit list (works without channels:read listing)
            if cid not in exclude and join_state(bot["id"], cid) != "member":
                st = join_channel(bot, token, cid, "listed")
                res.setdefault(st, []).append(cid)
        if aj.get("all_public"):
            cursor, pages = None, 0
            while pages < 50:
                pages += 1
                r = slack(token, "conversations.list", {"types": "public_channel", "exclude_archived": "true",
                                                         "limit": 200, "cursor": cursor})
                if not r.get("ok"):
                    if not _scope_blocked(bot, r, "conversations.list"):
                        log.warning("%s: conversations.list failed: %s", bot["id"], r.get("error"))
                    res.setdefault("blocked" if str(r.get("error")) in SCOPE_ERRORS else "list_failed", []).append("*")
                    break
                for c in r.get("channels", []):
                    if c["id"] in exclude or c.get("is_archived"):
                        continue
                    if not c.get("is_member") and join_state(bot["id"], c["id"]) == "member":
                        # we were in it and no longer are, with no removal event seen: someone removed the bot
                        join_record(bot["id"], c["id"], "removed", "missing_from_channel",
                                    ("#" + c["name"]) if c.get("name") else None)
                        channel_set(bot["id"], c["id"], None, False)
                        log.info("%s: no longer in %s (removal event missed) -> marked removed; not rejoining",
                                 bot["id"], c.get("name") or c["id"])
                        res.setdefault("removed", []).append(c["id"])
                        continue
                    if not c.get("is_member") and join_state(bot["id"], c["id"]) != "removed":
                        if budget <= 0:
                            res.setdefault("deferred", []).append(c["id"])
                            continue
                        budget -= 1
                    st = do_join(bot, token, c, "sweep")
                    res.setdefault(st, []).append(c["id"])
                    if st == "blocked":
                        break
                    if st in ("joined", "failed"):
                        time.sleep(JOIN_PACE_SEC)
                if "blocked" in res:
                    break
                cursor = (r.get("response_metadata") or {}).get("next_cursor")
                if not cursor:
                    break
        out[bot["id"]] = {k: v for k, v in res.items() if k != "member"} | {"member_count": len(res.get("member", []))}
    return out


def join_summary() -> dict:
    with _state_lock:
        con = db()
        try:
            rows = con.execute("SELECT bot, state, count(*) FROM joins GROUP BY bot, state").fetchall()
        finally:
            con.close()
    out: dict[str, dict] = {}
    for b, st, n in rows:
        out.setdefault(b, {})[st] = n
    for b, why in _join_blocked.items():
        out.setdefault(b, {})["blocked"] = why
    return out


def _join_loop() -> None:
    while True:
        try:
            log.info("auto-join sweep: %s", json.dumps(join_sweep()))
        except Exception:
            log.exception("join sweep failed")
        time.sleep(JOIN_SWEEP_SEC)


# ----------------------------------------------------------------------------- brains (pluggable adapters)
# Each adapter: dispatch(bot, rec, cfg) -> status string. Adapters that can be "not ready" expose ready(cfg).
# A brain may name a `fallback` brain plus an `ack` text: when the primary isn't ready (or a job times out),
# the fallback runs and the ack is posted in the Slack thread as the bot.
def append_nullink(session: str, text: str) -> None:
    if session in FORBIDDEN_SESSIONS:
        raise ValueError(f"session {session!r} is reserved for its bridge")
    msg = {"role": "user", "text": text, "ts": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
           "session_id": session, "source": "slack"}
    line = (json.dumps(msg, ensure_ascii=False) + "\n").encode("utf-8")
    fd = os.open(NULLINK_MESSAGES, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    try:
        os.write(fd, line)  # single O_APPEND write, same as reply.py
    finally:
        os.close(fd)


def bot_label(bot: dict) -> str:
    return bot.get("display_name") or bot["id"]


def prompt_text(bot: dict, rec: dict) -> str:
    """Plain-text prompt for an AI brain: where, who, thread context, the message. No ids/tokens."""
    lines = [f"[Slack message for {bot_label(bot)} - {rec['channel_name']}"
             f"{', in a thread' if rec['reply_thread_ts'] != rec['ts'] else ''}]"]
    ctx = rec.get("context") or []
    if ctx:
        lines.append("Earlier in this thread (oldest first):")
        lines += [f"- {c['who']}: {c['text']}" for c in ctx]
        lines.append("")
    if rec.get("handoff"):
        h = rec["handoff"]
        lines.append(f"(Handoff from {h['from']} - correlation {h['corr']}, hop {h['hop']}/{h['budget']}. "
                     "Only @mention another bot again if you really need it.)")
    if (bot.get("brain") or {}).get("type") == "chatgpt_bridge" and handoff_targets(bot):
        lines.append(f"(Only if another bot is really needed: end your reply with one line `HANDOFF: <name>` "
                     f"({' or '.join(handoff_targets(bot))}); a plain @name does not notify it.)")
    lines.append(f"New message from {rec['user_name']}:")
    lines.append(rec["text"])
    lines.append("")
    if bot.get("id") == "jinx":
        hint = _isapi_persona_line()
        if hint:
            lines.append(hint)
    lines.append(f"Reply as {bot_label(bot)} with only the text to post back in that Slack thread "
                 "(Slack formatting, concise). Never include passwords, tokens or other secrets.")
    return "\n".join(lines)


class SlackWakeBrain:
    """Wake Morc's Grok Bot routine through the proven path: a Slack Incoming Webhook post into #general,
    where the 'Nullink Slack wake' keyword routine (nullink-wake) listens. The post is a bare marker
    `nullink-wake morc-mention kind=.. ch=.. ts=.. thread=.. job=..` - no message content, no secrets.
    Jobs are durable (SQLite `wakes`); _wake_post_loop debounces per thread, rate-limits, re-wakes once if
    nobody answered, and marks a job done when Morc replies in the thread (or reacts done_reaction on the
    mention, or POST localhost /slack/wake-done?job=<id>). Channels in `covered_channels` already have their
    own listener routine and get no #general wake (avoids double replies)."""

    @staticmethod
    def url(cfg) -> str | None:
        try:
            u = Path(cfg.get("webhook_url_file") or "/opt/nullink/secrets/slack-incoming-webhook.url").read_text().strip()
        except OSError:
            return None
        ok = u.startswith("https://hooks.slack.com/") or (os.environ.get("SLACK_WAKE_TEST_URLS") == "1" and u.startswith("http://127.0.0.1"))
        return u if ok else None

    @classmethod
    def ready(cls, bot, cfg):
        return cls.url(cfg) is not None

    @staticmethod
    def dispatch(bot, rec, cfg):
        covered = rec["channel"] in (cfg.get("covered_channels") or [])
        kind = "handoff" if rec.get("handoff") else ("dm" if rec.get("kind") == "slack_dm" else "mention")
        state = wake_enqueue(bot, rec, kind, "covered" if covered else "queued")
        if covered:
            return "wake:covered_by_channel_routine"
        _wake_kick.set()
        return f"wake:{state}:{rec['ref']}"


_wake_kick = threading.Event()


def wake_enqueue(bot: dict, rec: dict, kind: str, state: str) -> str:
    now = time.time()
    with _state_lock:
        con = db()
        try:
            con.execute("INSERT OR IGNORE INTO wakes (job, bot, channel, ts, thread_ts, kind, state, attempts, created, "
                        "next_at) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)",
                        (rec["ref"], bot["id"], rec["channel"], rec["ts"], rec["reply_thread_ts"], kind, state, now, now))
            return con.execute("SELECT state FROM wakes WHERE job = ?", (rec["ref"],)).fetchone()[0]
        finally:
            con.close()


def wake_set(job: str, **cols) -> None:
    cols["updated"] = time.time()
    with _state_lock:
        con = db()
        try:
            con.execute(f"UPDATE wakes SET {', '.join(k + ' = ?' for k in cols)} WHERE job = ?", (*cols.values(), job))
        finally:
            con.close()


def wake_marker(cfg: dict, w: dict) -> str:
    return (f"{cfg.get('marker') or 'nullink-wake morc-mention'} kind={w['kind']} ch={w['channel']} "
            f"ts={w['ts']} thread={w['thread_ts']} job={w['job']}")


def post_incoming(url: str, text: str) -> tuple[str, str]:
    """One attempt. -> ('ok'|'retry'|'failed', detail). A duplicate wake is harmless (jobs are idempotent)."""
    req = urllib.request.Request(url, data=json.dumps({"text": text}).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return ("ok", f"HTTP {r.status}") if 200 <= r.status < 300 else ("retry", f"HTTP {r.status}")
    except urllib.error.HTTPError as exc:
        return ("retry" if exc.code == 429 or exc.code >= 500 else "failed"), f"HTTP {exc.code}"
    except Exception as exc:
        return "retry", type(exc).__name__


def _wake_rows(sql: str, *a) -> list[dict]:
    with _state_lock:
        con = db()
        try:
            con.row_factory = sqlite3.Row
            return [dict(r) for r in con.execute(sql, a)]
        finally:
            con.close()


def wake_done_check(bot: dict, w: dict, cfg: dict) -> str | None:
    """Done when Morc (this bot) has replied in the thread after the mention, or reacted done_reaction on it."""
    token = bot_token(bot)
    if not token:
        return None
    r = slack(token, "conversations.replies", {"channel": w["channel"], "ts": w["thread_ts"], "limit": 200})
    if not r.get("ok"):
        return None
    me_u, me_b = bot.get("bot_user_id"), bot.get("bot_id")
    react = cfg.get("done_reaction") or "white_check_mark"
    for m in r.get("messages", []):
        if m.get("ts") == w["ts"] and any(x.get("name") == react and me_u in (x.get("users") or [])
                                          for x in m.get("reactions") or []):
            return "reaction"
        if float(m.get("ts") or 0) > float(w["ts"]) and (m.get("bot_id") == me_b or (me_u and m.get("user") == me_u)):
            return "reply"
    return None


def wake_tick(bot: dict, cfg: dict) -> None:
    now = time.time()
    # 1) closure: Morc answered (reply / reaction) -> done; give up after done_window_sec
    for w in _wake_rows("SELECT * FROM wakes WHERE bot = ? AND state IN ('queued', 'woken', 'covered') "
                        "AND COALESCE(checked_at, 0) < ? ORDER BY created LIMIT 20",
                        bot["id"], now - float(cfg.get("done_check_sec", 30))):
        how = wake_done_check(bot, w, cfg)
        if how:
            wake_set(w["job"], state="done", done_at=now, done_by=how, checked_at=now)
            log.info("%s: wake job %s done (%s)", bot["id"], w["job"], how)
        elif now - w["created"] > float(cfg.get("done_window_sec", 86400)):
            wake_set(w["job"], state="stale", checked_at=now)
        else:
            wake_set(w["job"], checked_at=now)
    # 2) (re)wake: queued jobs, and woken ones nobody answered within rewake_after_sec (max_wakes total)
    url = SlackWakeBrain.url(cfg)
    if not url:
        return
    due = _wake_rows("SELECT * FROM wakes WHERE bot = ? AND ((state = 'queued' AND next_at <= ?) OR "
                     "(state = 'woken' AND woken_at < ? AND attempts < ?)) ORDER BY created LIMIT 10",
                     bot["id"], now, now - float(cfg.get("rewake_after_sec", 900)), int(cfg.get("max_wakes", 2)))
    posted: set[tuple[str, str]] = set()
    for w in due:
        if (w["channel"], w["thread_ts"]) in posted:
            continue
        last = _wake_rows("SELECT MAX(woken_at) AS t FROM wakes WHERE bot = ? AND channel = ? AND thread_ts = ? "
                          "AND job != ? AND error IS NOT 'coalesced'", bot["id"], w["channel"], w["thread_ts"],
                          w["job"])[0]["t"] or 0
        deb = float(cfg.get("debounce_sec", 60))
        if w["state"] == "queued" and now - last < deb:
            wake_set(w["job"], next_at=last + deb)  # debounce: one wake per thread per window; stays queued
            continue
        glast = _wake_rows("SELECT MAX(woken_at) AS t FROM wakes WHERE bot = ? AND error IS NOT 'coalesced'",
                           bot["id"])[0]["t"] or 0
        if now - glast < float(cfg.get("min_gap_sec", 15)):
            return  # global spacing; stays queued (durable)
        if not _rate_ok(f"wake:{bot['id']}", int(cfg.get("max_per_10min", 10)), 600):
            log.warning("%s: wake rate limit reached; %s stays queued", bot["id"], w["job"])
            return
        st, detail = post_incoming(url, wake_marker(cfg, w))
        n = int(w["attempts"] or 0) + 1
        if st == "ok":
            t = time.time()
            wake_set(w["job"], state="woken", woken_at=t, attempts=n, error=None)
            posted.add((w["channel"], w["thread_ts"]))
            # every other queued job already in this thread is covered by this wake (routine reads the thread)
            with _state_lock:
                con = db()
                try:
                    con.execute("UPDATE wakes SET state='woken', woken_at=?, attempts=1, error='coalesced', updated=? "
                                "WHERE bot=? AND channel=? AND thread_ts=? AND state='queued' AND job != ?",
                                (t, t, bot["id"], w["channel"], w["thread_ts"], w["job"]))
                finally:
                    con.close()
            log.info("%s: wake posted for %s (%s, attempt %d)", bot["id"], w["job"], w["kind"], n)
        elif st == "retry" and n < 5:
            wake_set(w["job"], state="queued", attempts=n, next_at=now + 30 * n, error=detail)
            log.warning("%s: wake for %s failed (%s), will retry", bot["id"], w["job"], detail)
        else:
            wake_set(w["job"], state="failed", attempts=n, error=detail)
            log.error("%s: wake for %s failed permanently (%s)", bot["id"], w["job"], detail)


def _wake_post_loop() -> None:
    while True:
        try:
            for bot in registry().get("bots", []):
                br = bot.get("brain") or {}
                if br.get("type") == "slack_wake":
                    wake_tick(bot, br)
        except Exception:
            log.exception("wake loop failed")
        _wake_kick.wait(float(os.environ.get("SLACK_WAKE_POLL_SEC", "5")))
        _wake_kick.clear()


class RoomBrain:
    """Append to a Nullink room; replies there starting with `slack <ref>:` are relayed back (relay loop)."""

    @staticmethod
    def ready(bot, cfg):
        return True

    @staticmethod
    def dispatch(bot, rec, cfg):
        session = cfg.get("session") or bot["id"]
        note = cfg.get("note")
        text = (f"[Slack · @{bot_label(bot)} · ref {rec['ref']}]\n{prompt_text(bot, rec)}\n\n"
                f"To answer in Slack as {bot_label(bot)}, reply here starting with:\nslack {rec['ref']}: <your answer>"
                + (f"\n\n({note})" if note else ""))
        append_nullink(session, text)
        return f"nullink_room:{session}"


class BridgeBrain:
    """Browser bridge (e.g. ChatGPT web for Jinx) through a file spool:
       router writes <jobs_dir>/pending/<id>.json  ->  bridge answers into <jobs_dir>/results/<id>.json
       -> router posts the answer in the Slack thread as the bot (bridge never holds Slack tokens)."""

    @staticmethod
    def dirs(cfg):
        jobs = Path(cfg.get("jobs_dir") or "/opt/nullink/slack-events/jobs/jinx")
        for sub in ("pending", "results", "done", "posted", "cancelled", "failed", "rejected", "uncertain"):
            (jobs / sub).mkdir(parents=True, exist_ok=True)
        return jobs

    @staticmethod
    def bridge_state(cfg) -> dict:
        sd = Path(cfg.get("state_dir") or "/opt/nullink/bridges/chatgpt/state")
        st = read_json(sd / "state.json", {}) or {}
        try:
            hb_age = time.time() - (sd / "heartbeat").stat().st_mtime
        except OSError:
            hb_age = None
        st["_heartbeat_age"] = hb_age
        return st

    @classmethod
    def ready(cls, bot, cfg):
        st = cls.bridge_state(cfg)
        age = st.get("_heartbeat_age")
        return bool(age is not None and age < 90 and not st.get("blocked") and st.get("last_ok"))

    @classmethod
    def dispatch(cls, bot, rec, cfg):
        jobs = cls.dirs(cfg)
        iso = cfg.get("isolation", "thread")  # one dedicated ChatGPT chat per Slack channel+thread (or "channel")
        key = rec["channel"] if iso == "channel" else f"{rec['channel']}:{rec['reply_thread_ts']}"
        now = time.time()
        expires_at = now + 2 * float(cfg.get("job_timeout_sec", 600))
        ch = chain_get(rec.get("thread_key") or "") if rec.get("handoff") else None
        if ch:
            expires_at = min(expires_at, ch["expires"])  # a hop's job never outlives the original chain
        # Exactly Jinx's reference runtime contract (/opt/nullink/slack-integration README "Runtime contract").
        request = {"request_key": rec["ref"], "runtime_id": runtime_id_for(bot, cfg), "bot": bot["id"],
                   "channel": rec["channel"], "thread_ts": rec["reply_thread_ts"], "text": rec["text"],
                   "context": rec.get("context") or [], "expires_at": int(expires_at),
                   "correlation_id": rec.get("chain") or (rec.get("handoff") or {}).get("corr"),
                   "hop": int((rec.get("handoff") or {}).get("hop", 0))}
        if not job_register(bot, rec, request):
            return "bridge:duplicate_request_key"
        # meta: bridge-side presentation only (dedicated chat key/title, rendered prompt); never trusted back.
        job = {"version": 1, "method": "reply", "request": request,
               "meta": {"id": rec["ref"], "created": now, "conversation_key": key,
                        "conversation_title": f"Jinx Slack bridge - {rec['channel_name']}",
                        "handoff_targets": handoff_targets(bot),
                        "prompt": prompt_text(bot, rec)}}
        name = f"{int(now * 1000)}-{rec['ref']}.json"
        tmp = jobs / "pending" / ("." + name + ".tmp")
        tmp.write_text(json.dumps(job, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, jobs / "pending" / name)
        return "bridge:queued"


def runtime_id_for(bot: dict, cfg: dict) -> str:
    return str(cfg.get("runtime_id") or f"chatgpt-bridge:{bot['id']}")


def handoff_targets(bot: dict) -> list[str]:
    return [b["id"] for b in registry().get("bots", []) if b["id"] != bot["id"] and edge_allowed(bot["id"], b["id"])]


def job_register(bot: dict, rec: dict, request: dict) -> bool:
    """Persist the issued request (request_key -> runtime_id, thread, chain) before handing it to the runtime."""
    now = time.time()
    with _state_lock:
        con = db()
        try:
            cur = con.execute("INSERT OR IGNORE INTO jobs (request_key, bot, runtime_id, ref, channel, thread_ts, "
                              "thread_key, corr, hop, expires_at, state, created, updated) "
                              "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'issued', ?, ?)",
                              (request["request_key"], bot["id"], request["runtime_id"], rec["ref"], request["channel"],
                               request["thread_ts"], rec.get("thread_key") or f"{request['channel']}:{request['thread_ts']}",
                               request["correlation_id"], request["hop"], request["expires_at"], now, now))
            return cur.rowcount == 1
        finally:
            con.close()


def job_get(request_key: str) -> dict | None:
    with _state_lock:
        con = db()
        try:
            con.row_factory = sqlite3.Row
            r = con.execute("SELECT * FROM jobs WHERE request_key = ?", (request_key,)).fetchone()
            return dict(r) if r else None
        finally:
            con.close()


def job_finish(request_key: str, state: str, error: str | None = None) -> bool:
    """Move an issued job to a terminal state exactly once. False if it was already terminal."""
    with _state_lock:
        con = db()
        try:
            cur = con.execute("UPDATE jobs SET state = ?, error = ?, updated = ? WHERE request_key = ? AND state = 'issued'",
                              (state, error, time.time(), request_key))
            return cur.rowcount == 1
        finally:
            con.close()


_MENTION_RE = re.compile(r"<(?:@[UWB][A-Z0-9]+(?:\|[^>]*)?|![^>]*)>")


def scrub_mentions(text: str) -> str:
    """Runtime output may not create Slack mentions/broadcasts; only a validated handoff_to adds one."""
    return _MENTION_RE.sub("[mention removed]", text)


# InterServer read tools for Jinx: lines like `ISAPI: vps.list` in a bridge reply are executed by
# this router (caller "jinx") through the local broker. The ChatGPT browser never sees the key.
_ISAPI_PATH = Path("/opt/nullink-interserver")
try:
    import importlib.machinery
    import importlib.util
    if str(_ISAPI_PATH) not in sys.path:
        sys.path.insert(0, str(_ISAPI_PATH))
    import jinx_tools as _jinx_tools  # type: ignore
    # `isapi` is an extensionless executable on the VPS; load it explicitly.
    _isapi_loader = importlib.machinery.SourceFileLoader("isapi", str(_ISAPI_PATH / "isapi"))
    _isapi = importlib.util.module_from_spec(importlib.util.spec_from_loader("isapi", _isapi_loader))
    _isapi_loader.exec_module(_isapi)
except Exception as _e:  # pragma: no cover - soft dependency until broker is staged
    _jinx_tools = None  # type: ignore
    _isapi = None  # type: ignore
    log.warning("ISAPI tools unavailable: %s", _e)


def _apply_isapi_tools(text: str) -> str:
    """Strip ISAPI: lines, run up to MAX_CALLS through the broker, append compact results."""
    if not _jinx_tools or not _isapi:
        return text
    clean, reqs = _jinx_tools.extract(text)
    if not reqs:
        return text
    def _call(r):
        return _isapi.call({"op": r["op"], "args": r.get("args") or {}, "reason": r.get("reason") or "jinx slack tool request"})
    try:
        results = _jinx_tools.run(reqs, _call)
        formatted = _jinx_tools.format_results(results)
    except Exception as e:
        log.exception("ISAPI tool run failed")
        formatted = f"[InterServer error] {type(e).__name__}: {e}"
    return (clean + ("\n\n" + formatted if formatted else "")).strip()


def _isapi_persona_line() -> str | None:
    if not _jinx_tools or not _isapi:
        return None
    try:
        ops = _isapi.call({"op": "_ops"}).get("operations") or {}
        if not ops:
            return None
        return _jinx_tools.persona_hint(ops)
    except Exception:
        return None


def bind_result(bot: dict, data: dict) -> tuple[str, dict | None, str]:
    """Strictly bind a runtime result to the job the router issued (reference RuntimeSocket semantics).
    -> ('post'|'pending'|'failed'|'rejected'|'duplicate', job, reason).
    'rejected'/'duplicate' results are quarantined and never touch the issued job (a misbound or forged file
    cannot cancel or answer it); 'failed' finishes the job and runs the bot's fallback once."""
    if not isinstance(data, dict):
        return "rejected", None, "malformed"
    job = job_get(str(data.get("request_key") or ""))
    if not job or job["bot"] != bot["id"]:
        return "rejected", None, "unknown_request_key"
    if data.get("runtime_id") != job["runtime_id"] or data.get("request_key") != job["request_key"] \
            or data.get("idempotent") is not True:
        return "rejected", job, "runtime identity/idempotency mismatch"
    if job["state"] != "issued":
        return "duplicate", job, f"job already {job['state']}"
    state = data.get("state")
    if state in ("queued", "running"):
        return ("failed", job, "expired while pending") if time.time() > float(job["expires_at"]) else ("pending", job, state)
    if state != "succeeded":
        return "failed", job, f"runtime blocked or failed: {str(state)[:40]}"
    res = data.get("result")
    if not isinstance(res, dict) or not isinstance(res.get("text"), str) or not res["text"].strip():
        return "failed", job, "succeeded without result.text"
    if time.time() > float(job["expires_at"]) + 60:
        return "failed", job, "result after request expiry"
    return "post", job, "ok"


ADAPTERS = {"slack_wake": SlackWakeBrain, "nullink_room": RoomBrain, "chatgpt_bridge": BridgeBrain}
# Future adapters plug in here, e.g. "openai_api" (answer via API key) - same dispatch(bot, rec, cfg) contract.


def post_as_bot(bot: dict, key: str, channel: str, thread_ts: str | None, text: str) -> str:
    return send_once(bot, key, channel, thread_ts, text)


def run_fallback(bot: dict, rec: dict, brain: dict, why: str) -> str:
    fb = brain.get("fallback")
    if not fb:
        return f"not_ready:{why}"
    adapter = ADAPTERS.get(fb.get("type", ""))
    status = adapter.dispatch(bot, rec, fb) if adapter else "queued"
    ack = brain.get("ack") or fb.get("ack")
    if ack:
        status += ";ack:" + post_as_bot(bot, f"ack:{bot['id']}:{rec['ref']}", rec["channel"], rec["reply_thread_ts"], ack)
    return f"fallback({why}):{status}"


def route(bot: dict, rec: dict) -> str:
    brain = bot.get("brain") or {"type": "none"}
    adapter = ADAPTERS.get(brain.get("type", "none"))
    if not adapter:
        return "queued"
    if not adapter.ready(bot, brain):
        return run_fallback(bot, rec, brain, "primary_not_ready")
    return adapter.dispatch(bot, rec, brain)


def process_result(bot: dict, brain: dict, jobs: Path, res: Path) -> str:
    data = read_json(res, None)
    verdict, job, why = bind_result(bot, data)
    rec = get_ref(job["ref"]) if job else None
    dest = {"post": "posted", "failed": "failed", "rejected": "rejected", "duplicate": "rejected"}.get(verdict)
    if verdict == "pending":
        return verdict
    if verdict == "post":
        result = data["result"]
        text = scrub_mentions(result["text"].strip())
        if bot.get("id") == "jinx":
            text = _apply_isapi_tools(text)
        target = result.get("handoff_to")
        if target:
            tb = get_bot(str(target))
            why_not = ("unknown_bot" if not tb or not tb.get("bot_user_id")
                       else chain_peek(job["thread_key"], bot["id"], tb["id"]))
            if why_not:
                log.warning("bridge %s: handoff_to %s dropped (%s)", job["request_key"], target, why_not)
            else:
                text = f"<@{tb['bot_user_id']}> {text}"
        st = post_as_bot(bot, f"bridge:{bot['id']}:{job['request_key']}", job["channel"], job["thread_ts"],
                         text + str(brain.get("answer_suffix") or ""))
        log.info("bridge answer %s -> %s: %s", job["request_key"], job["channel"], st)
        if st == "retry":
            return "retry"  # definite non-send (rate limit) -> try next tick
        dest = "uncertain" if st == "uncertain" else ("failed" if st.startswith("failed") else "posted")
        job_finish(job["request_key"], dest, None if dest == "posted" else st)
    else:
        log.warning("bridge result %s %s: %s", res.name, verdict, why)
        if job and verdict == "failed":
            if job_finish(job["request_key"], verdict, why) and rec and not rec.get("fallback_done"):
                rec["fallback_done"] = True
                save_ref(rec)
                run_fallback(bot, rec, brain, "bridge_" + verdict)
    (jobs / dest).mkdir(exist_ok=True)
    os.replace(res, jobs / dest / res.name)
    return verdict


def expire_issued_jobs(bot: dict, brain: dict) -> None:
    """Issued jobs with no bound result by expires_at end as 'expired' (fallback once). Bounds everything,
    including jobs whose results were quarantined as misbound."""
    with _state_lock:
        con = db()
        try:
            keys = [r[0] for r in con.execute("SELECT request_key FROM jobs WHERE bot = ? AND state = 'issued' "
                                              "AND expires_at < ?", (bot["id"], time.time() - 5))]
        finally:
            con.close()
    for k in keys:
        if job_finish(k, "expired", "no bound result before expires_at"):
            rec = get_ref(k)
            log.warning("bridge job %s expired without a bound result", k)
            if rec and not rec.get("fallback_done"):
                rec["fallback_done"] = True
                save_ref(rec)
                run_fallback(bot, rec, brain, "bridge_expired")


def _bridge_loop() -> None:
    """Post bridge answers; time out / withdraw jobs when the bridge is blocked."""
    while True:
        try:
            for bot in registry().get("bots", []):
                brain = bot.get("brain") or {}
                if brain.get("type") != "chatgpt_bridge":
                    continue
                jobs = BridgeBrain.dirs(brain)
                for res in sorted((jobs / "results").glob("*.json")):
                    process_result(bot, brain, jobs, res)
                expire_issued_jobs(bot, brain)
                st = BridgeBrain.bridge_state(brain)
                inflight = str((st.get("inflight") or {}).get("key") or "")
                ready = BridgeBrain.ready(bot, brain)
                timeout = float(brain.get("job_timeout_sec", 600))
                for pend in sorted((jobs / "pending").glob("*.json")):
                    job = read_json(pend, {})
                    meta, req = job.get("meta") or {}, job.get("request") or {}
                    age = time.time() - float(meta.get("created") or job.get("created") or 0)
                    expired = time.time() > float(req.get("expires_at") or 9e18)
                    if not expired and meta.get("id", job.get("id")) == inflight and age < timeout * 2:
                        continue
                    if not expired and ready and age < timeout:
                        continue
                    try:  # withdraw: whoever renames first owns the job
                        os.replace(pend, jobs / "cancelled" / pend.name)
                    except OSError:
                        continue
                    rec = get_ref(str(req.get("request_key") or job.get("ref") or ""))
                    if req.get("request_key"):
                        job_finish(req["request_key"], "withdrawn", "expired" if expired else "bridge not ready/timeout")
                    if rec and not rec.get("fallback_done"):
                        rec["fallback_done"] = True
                        save_ref(rec)
                        why = "bridge_timeout" if ready else "bridge_not_ready"
                        log.info("bridge job %s withdrawn (%s)", rec["ref"], why)
                        run_fallback(bot, rec, brain, why)
        except Exception:
            log.exception("bridge loop failed")
        time.sleep(3)


# ----------------------------------------------------------------------------- rate limits / loop guard


def _rate_ok(key: str, limit: int, window: float) -> bool:
    """Sliding-window limit persisted in SQLite (rate_hits), so limits survive restarts."""
    now = time.time()
    with _state_lock:
        con = db()
        try:
            con.execute("BEGIN IMMEDIATE")
            con.execute("DELETE FROM rate_hits WHERE key = ? AND t <= ?", (key, now - window))
            n = con.execute("SELECT COUNT(*) FROM rate_hits WHERE key = ?", (key,)).fetchone()[0]
            if n >= limit:
                con.execute("COMMIT")
                return False
            con.execute("INSERT INTO rate_hits (key, t) VALUES (?, ?)", (key, now))
            con.execute("COMMIT")
            return True
        except Exception:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()


def outbound_allowed(bot: dict) -> bool:
    lim = (bot.get("limits") or {})
    return _rate_ok(f"out:{bot['id']}", int(lim.get("outbound_per_10min", 30)), 600)


def inbound_allowed(bot: dict, user: str) -> bool:
    lim = (bot.get("limits") or {})
    return (_rate_ok(f"in:{bot['id']}", int(lim.get("inbound_per_10min", 30)), 600)
            and _rate_ok(f"in:{bot['id']}:{user}", int(lim.get("inbound_per_user_per_min", 6)), 60))


def registered_bot_for(msg: dict) -> dict | None:
    """Source-bot identity check: Slack's bot_id must match a registered bot, and the user (if present)
    must be that same bot's user id. Payloads are signature-verified, so these fields are Slack's."""
    bid = msg.get("bot_id")
    if not bid:
        return None
    for b in registry().get("bots", []):
        if b.get("bot_id") and bid == b["bot_id"] and (not msg.get("user") or msg["user"] == b.get("bot_user_id")):
            return b
    return None


# ----------------------------------------------------------------------------- event handling
def thread_context(bot: dict, token: str, channel: str, thread_ts: str, upto_ts: str, limit: int = 15) -> list[dict]:
    r = slack(token, "conversations.replies", {"channel": channel, "ts": thread_ts, "limit": 50})
    if not r.get("ok"):
        return []
    out = []
    for m in r.get("messages", []):
        if m.get("ts") == upto_ts or float(m.get("ts") or 0) > float(upto_ts):
            continue
        src = registered_bot_for(m)
        who = (bot_label(src) + " (bot)") if src else (user_name(token, m["user"]) if m.get("user") else (m.get("username") or "bot"))
        out.append({"who": who, "text": readable(token, m.get("text") or "")[:600]})
    return out[-limit:]


def handle_membership(bot: dict, token: str, ev: dict) -> None:
    etype = ev.get("type")
    me = bot.get("bot_user_id")
    if etype == "member_joined_channel":
        if not me or ev.get("user") != me:
            return
        cid = ev.get("channel") or ""
        name = channel_name(token, cid, False)
        inviter = ev.get("inviter") or ""
        human_invite = bool(inviter) and not any(b.get("bot_user_id") == inviter for b in registry().get("bots", []))
        changed = channel_set(bot["id"], cid, name, True)
        join_record(bot["id"], cid, "member", "invited" if human_invite else "joined", name)  # clears 'removed'
        if human_invite:
            log.info("%s: invited to %s by %s -> registered", bot["id"], name, inviter)
            if ev.get("_event_key"):
                inbox_set(ev["_event_key"], phase="dispatching")
            welcome = welcome_text(bot, brief=False)
            if welcome:
                post_as_bot(bot, f"welcome:{bot['id']}:{cid}:{ev.get('event_ts') or ev.get('ts') or int(time.time())}",
                            cid, None, welcome)
        elif changed:
            log.info("%s: joined %s -> registered (no welcome: self-join)", bot["id"], name)
        return
    if etype in ("channel_left", "group_left") or (etype == "member_left_channel" and me and ev.get("user") == me):
        cid = ev.get("channel") or ""
        if isinstance(cid, dict):
            cid = cid.get("id") or ""
        if cid:
            channel_set(bot["id"], cid, None, False)
            join_record(bot["id"], cid, "removed", etype, removed_by=ev.get("actor_id") or ev.get("inviter"))
            log.info("%s: removed from %s (by %s) -> deregistered; will not auto-rejoin", bot["id"], cid,
                     ev.get("actor_id") or "?")


def handle_event(bot: dict, payload: dict, event_key: str = "") -> None:
    """Only called for signature-verified payloads."""
    ev = payload.get("event") or {}
    etype = ev.get("type")
    token = bot_token(bot)
    if not token:
        log.warning("%s: event %s but no token on server", bot["id"], etype)
        return
    if etype in ("member_joined_channel", "member_left_channel", "channel_left", "group_left"):
        return handle_membership(bot, token, dict(ev, _event_key=event_key))
    if etype in ("channel_created", "channel_unarchive"):
        ch = ev.get("channel")
        cid = ch.get("id") if isinstance(ch, dict) else ch
        aj = bot.get("auto_join") or {}
        if cid and aj.get("enabled", True) is not False and aj.get("new_channels", True) \
                and cid not in set(aj.get("exclude") or []):
            if etype == "channel_created" and isinstance(ch, dict) and ch.get("name"):
                do_join(bot, token, {"id": cid, "name": ch.get("name"), "created": ch.get("created") or time.time()},
                        "channel_created")
            else:
                join_channel(bot, token, cid, etype)
        return
    is_im = etype == "message" and ev.get("channel_type") == "im"
    if etype != "app_mention" and not is_im:
        return
    # bot_message must reach the allowlisted handoff check below (it is filtered there, not here)
    if ev.get("subtype") not in (None, "thread_broadcast", "file_share", "bot_message"):
        return
    channel, ts = ev.get("channel") or "", ev.get("ts") or ""
    if not channel or not ts:
        return
    if _seen_mark(f"msg:{bot['id']}:{channel}:{ts}", event_key or None):
        return
    if ev.get("client_msg_id") and _seen_mark(f"cmid:{bot['id']}:{ev['client_msg_id']}", event_key or None):
        return
    msg = ev
    me = bot.get("bot_user_id")
    author = msg.get("user") or ""
    if (me and author == me) or (msg.get("bot_id") and msg.get("bot_id") == bot.get("bot_id")):
        return  # our own message
    reply_ts = msg.get("thread_ts") or ts
    thread_key = f"{channel}:{reply_ts}"
    handoff = None
    if msg.get("bot_id") or msg.get("subtype") == "bot_message":
        # Bots are ignored (loop guard) except an explicit @mention handoff from another registered bot.
        src = registered_bot_for(msg)
        if not src or src["id"] == bot["id"] or etype != "app_mention":
            return
        budget, _jb = _budgets()
        corr, hop = handoff_step(thread_key, src["id"], bot["id"], budget, msg_ts=ts)
        if not corr:
            log.warning("%s: handoff from %s suppressed in %s (%s)", bot["id"], src["id"], thread_key, hop)
            return
        handoff = {"corr": corr, "hop": hop, "budget": budget, "from": src["id"]}
        chain_corr = corr
    else:
        if not inbound_allowed(bot, author):
            log.warning("%s: inbound rate limit hit (user %s)", bot["id"], author)
            return
        # a human turn starts the thread's (only) chain: fixed expiry, fresh hop/job budget
        chain_corr = chain_start(thread_key, f"human:{channel}:{ts}",
                                 min(int(registry().get("handoff_ttl_sec", HANDOFF_TTL_SEC)), 1800))
    src_bot = registered_bot_for(msg)
    rec = {
        "ref": make_ref(bot["id"], channel, ts),
        "bot": bot["id"],
        "kind": "slack_dm" if is_im else "slack_mention",
        "team": payload.get("team_id"),
        "channel": channel,
        "channel_name": channel_name(token, channel, is_im),
        "user": author,
        "user_name": (bot_label(src_bot) + " (bot)") if src_bot
                     else (user_name(token, author) if author else (msg.get("username") or "a bot")),
        "text": readable(token, msg.get("text") or ""),
        "ts": ts,
        "reply_thread_ts": reply_ts,
        "handoff": handoff,
        "chain": chain_corr,
        "thread_key": thread_key,
        "received": now_iso(),
        "received_epoch": time.time(),
    }
    if reply_ts != ts:
        rec["context"] = thread_context(bot, token, channel, reply_ts, ts)
    if not is_im:
        channel_set(bot["id"], channel, rec["channel_name"], True)  # e.g. joined before the router existed
    pl = slack(token, "chat.getPermalink", {"channel": channel, "message_ts": ts})
    if pl.get("ok"):
        rec["permalink"] = pl.get("permalink")
    if event_key:
        inbox_set(event_key, phase="dispatching")  # from here on a crash is 'uncertain', not re-run
    ack = (bot.get("inbound") or {}).get("ack_reaction", "eyes")
    if ack:
        slack(token, "reactions.add", {"channel": channel, "timestamp": ts, "name": ack})
    save_ref(rec)
    try:
        status = route(bot, rec)
    except Exception as exc:
        log.exception("%s: route failed", bot["id"])
        status = f"route_error:{type(exc).__name__}"
    rec["status"] = status
    save_ref(rec)
    append_jsonl(STATE / "inbox.jsonl", {"at": now_iso(), **{k: rec[k] for k in
                 ("ref", "bot", "kind", "channel", "channel_name", "user_name", "ts", "reply_thread_ts", "status",
                  "handoff")}, "text": rec["text"][:500]})
    log.info("%s: %s %s from %s -> %s", bot["id"], rec["kind"], rec["ref"], rec["user_name"], status)


def _worker() -> None:
    while True:
        item = inbox_claim()
        if not item:
            _wake.wait(2)
            _wake.clear()
            continue
        event_key, bot_id, payload, tkey = item
        try:
            bot = get_bot(bot_id)
            if not bot:
                inbox_set(event_key, state="failed", error="bot no longer registered")
                continue
            try:
                handle_event(bot, payload, event_key)
                inbox_set(event_key, state="done")
            except Exception as exc:
                log.exception("event handling failed")
                inbox_set(event_key, state="failed", error=type(exc).__name__)
        finally:
            inbox_release(tkey)


# ----------------------------------------------------------------------------- reply relay (rooms -> Slack)
RELAY_RE = re.compile(r"^[\s>*_`]*slack\s+(s[0-9a-f]{6})[*_`]*\s*[:：]\s*(.+)", re.I | re.M | re.S)


def _room_bots() -> dict[str, list[str]]:
    rooms: dict[str, list[str]] = {}
    for b in registry().get("bots", []):
        br = b.get("brain") or {}
        for cfg in (br, br.get("fallback") or {}):  # primary room brains and room fallbacks
            if cfg.get("type") == "nullink_room":
                rooms.setdefault(cfg.get("session") or b["id"], []).append(b["id"])
    return rooms


def relay_line(line: str, rooms: dict[str, list[str]]) -> None:
    try:
        m = json.loads(line)
    except json.JSONDecodeError:
        return
    sess = m.get("session_id") or "morc"
    if m.get("role") != "assistant" or sess not in rooms:
        return
    hit = RELAY_RE.search(m.get("text") or "")
    if not hit:
        return
    ref, body = hit.group(1).lower(), hit.group(2).strip()
    rec = get_ref(ref)
    if not rec or rec.get("bot") not in rooms[sess]:
        log.info("relay: unknown ref %s in %s", ref, sess)
        return
    bot = get_bot(rec["bot"])
    token = bot_token(bot) if bot else None
    if not token or not body:
        return
    st = post_as_bot(bot, "relay:" + hashlib.sha1(line.encode()).hexdigest(), rec["channel"], rec["reply_thread_ts"], body)
    log.info("relay %s -> %s %s: %s", ref, rec["bot"], rec["channel"], st)


def relay_once(offset: int) -> int:
    """Process complete lines appended to messages.jsonl after byte `offset`; return new offset."""
    try:
        size = NULLINK_MESSAGES.stat().st_size
    except OSError:
        return offset
    if size < offset:  # truncated/rotated
        offset = size
    if size == offset:
        return offset
    with NULLINK_MESSAGES.open("rb") as f:
        f.seek(offset)
        chunk = f.read(size - offset)
    end = chunk.rfind(b"\n")
    if end < 0:
        return offset
    rooms = _room_bots()
    if rooms:
        for raw in chunk[: end + 1].splitlines():
            relay_line(raw.decode("utf-8", "replace"), rooms)
    return offset + end + 1


def _relay_loop() -> None:
    offset = read_json(STATE / "relay.json", {}).get("byte_offset")
    if offset is None:  # first start: don't replay history
        try:
            offset = NULLINK_MESSAGES.stat().st_size
        except OSError:
            offset = 0
        write_json(STATE / "relay.json", {"byte_offset": offset})
    while True:
        try:
            new = relay_once(offset)
            if new != offset:
                offset = new
                write_json(STATE / "relay.json", {"byte_offset": offset})
        except Exception:
            log.exception("relay failed")
        time.sleep(RELAY_POLL_SEC)


# ----------------------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "nullverse-slack-events/1"

    def log_message(self, fmt, *args):  # quiet access log (no bodies, no headers)
        pass

    def _send(self, code: int, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else (json.dumps(body) if ctype == "application/json" else str(body)).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _local(self) -> bool:
        return self.client_address[0] in LOOPBACK and not self.headers.get("X-Forwarded-For")

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path.rstrip("/")
        if path == "/slack/health":
            if not self._local():
                return self._send(200, {"ok": True})
            bots = []
            for b in registry().get("bots", []):
                br = b.get("brain") or {}
                bots.append({
                    "id": b["id"], "token": bool(bot_token(b)), "signing_secret": bool(signing_secret(b)),
                    "brain": br.get("type", "none"),
                    "wake_ready": SlackWakeBrain.ready(b, br) if br.get("type") == "slack_wake" else None,
                    "covered_channels": br.get("covered_channels") if br.get("type") == "slack_wake" else None,
                    "session": br.get("session") if br.get("type") == "nullink_room" else None,
                    "bridge_ready": BridgeBrain.ready(b, br) if br.get("type") == "chatgpt_bridge" else None,
                    "fallback": (br.get("fallback") or {}).get("type"),
                    "channels": channels_for(b["id"]),
                })
            con = db()
            counts = dict(con.execute("SELECT state, count(*) FROM inbox GROUP BY state").fetchall())
            sends = dict(con.execute("SELECT state, count(*) FROM sends GROUP BY state").fetchall())
            jobs = dict(con.execute("SELECT state, count(*) FROM jobs GROUP BY state").fetchall())
            rate_rows = con.execute("SELECT count(*) FROM rate_hits").fetchone()[0]
            wakes = dict(con.execute("SELECT state, count(*) FROM wakes GROUP BY state").fetchall())
            con.close()
            return self._send(200, {"ok": True, "bots": bots, "inbox": counts, "sends": sends, "jobs": jobs,
                                    "rate_hits": rate_rows, "wakes": wakes, "joins": join_summary(),
                                    "handoff": {"hop_budget": _budgets()[0], "job_budget": _budgets()[1],
                                                "edges": registry().get("handoff_edges")}})
        if path in ("/slack/wake-done", "/slack/wake-test") and self._local():
            return self._send(405, {"error": "use POST"})
        if path == "/slack/join-sweep" and self._local():
            return self._send(200, {"ok": True, "joined": join_sweep()})
        return self._send(404, {"error": "not_found"})

    def _wake_admin(self, path: str, qs: dict):
        bot = next((b for b in registry().get("bots", []) if (b.get("brain") or {}).get("type") == "slack_wake"), None)
        if not bot:
            return self._send(404, {"error": "no slack_wake bot"})
        if path == "/slack/wake-done":
            job = (qs.get("job") or [""])[0]
            if not re.fullmatch(r"s[0-9a-f]{6}", job):
                return self._send(400, {"error": "bad job"})
            rows = _wake_rows("SELECT state FROM wakes WHERE job = ?", job)
            if not rows:
                return self._send(404, {"error": "unknown job"})
            if rows[0]["state"] != "done":
                wake_set(job, state="done", done_at=time.time(), done_by="endpoint")
            return self._send(200, {"ok": True, "job": job, "was": rows[0]["state"]})
        cfg = bot["brain"]
        url = SlackWakeBrain.url(cfg)
        if not url:
            return self._send(503, {"error": "wake not configured"})
        if not _rate_ok(f"wake:{bot['id']}", int(cfg.get("max_per_10min", 10)), 600):
            return self._send(429, {"error": "wake rate limit"})
        tid = "test-" + pysecrets.token_hex(3)
        text = f"{cfg.get('marker') or 'nullink-wake morc-mention'} kind=selftest ch=- ts=- thread=- job={tid}"
        st, detail = post_incoming(url, text)
        log.info("wake self-test %s: %s %s", tid, st, detail)
        return self._send(200 if st == "ok" else 502, {"ok": st == "ok", "job": tid, "detail": detail, "text": text})

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path.rstrip("/")
        if path in ("/slack/wake-done", "/slack/wake-test"):
            if not self._local():
                return self._send(404, {"error": "not_found"})
            return self._wake_admin(path, urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query))
        m = re.fullmatch(r"/slack/events/([a-z0-9][a-z0-9_-]{0,31})", path)
        if not m:
            return self._send(404, {"error": "not_found"})
        bot = get_bot(m.group(1))
        if not bot:
            return self._send(404, {"error": "unknown_bot"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            return self._send(413 if length > MAX_BODY else 400, {"error": "bad_length"})
        body = self.rfile.read(length)
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._send(400, {"error": "bad_json"})
        if not isinstance(payload, dict):
            return self._send(400, {"error": "bad_json"})
        secret = signing_secret(bot)
        if not secret:
            if payload.get("type") == "url_verification" and registry().get("allow_unsigned_url_verification") is True:
                # Bootstrap: Slack checks the Request URL while the app is being created, before its signing
                # secret can be installed here. Echoing the challenge has no side effects.
                log.info("%s: url_verification answered (bootstrap, no signing secret yet)", bot["id"])
                return self._send(200, str(payload.get("challenge") or "")[:200].encode(), "text/plain")
            log.warning("%s: %s refused - signing secret not installed yet (fail closed)", bot["id"], payload.get("type"))
            return self._send(401, {"error": "signing_secret_not_installed"})
        if not verify_signature(secret, self.headers, body):
            log.warning("%s: bad or stale signature", bot["id"])
            return self._send(401, {"error": "bad_signature"})
        ptype = payload.get("type")
        if ptype == "url_verification":
            log.info("%s: url_verification answered (signed) ua=%s", bot["id"],
                     re.sub(r"[^\w .:/()+;-]", "", str(self.headers.get("User-Agent") or ""))[:80])
            return self._send(200, str(payload.get("challenge") or "")[:200].encode(), "text/plain")
        if ptype != "event_callback":
            return self._send(200, {"ok": True})
        team = registry().get("team_id")
        if team and payload.get("team_id") != team:
            return self._send(403, {"error": "wrong_team"})
        if bot.get("app_id") and payload.get("api_app_id") != bot.get("app_id"):
            return self._send(403, {"error": "wrong_app"})
        eid = str(payload.get("event_id") or "") or ("sha:" + hashlib.sha256(body).hexdigest())
        try:
            res = inbox_put(f"{bot['id']}:{eid}", bot["id"], body)  # committed before the 200 (dedup = PK)
        except sqlite3.Error:
            log.exception("inbox write failed")
            return self._send(503, {"error": "store_unavailable"})  # Slack retries
        if res == "busy":
            return self._send(503, {"error": "busy"})
        if res == "dup":
            return self._send(200, {"ok": True, "dup": True})
        _wake.set()
        return self._send(200, {"ok": True})


def main() -> None:
    import signal
    faulthandler.register(signal.SIGUSR1, all_threads=True)
    db_init()
    registry()
    for target in (_worker, _worker, _join_loop, _relay_loop, _bridge_loop, _wake_post_loop):
        threading.Thread(target=target, daemon=True).start()
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    log.info("listening on %s:%s (registry %s)", HOST, PORT, REGISTRY)
    srv.serve_forever()


if __name__ == "__main__":
    main()
