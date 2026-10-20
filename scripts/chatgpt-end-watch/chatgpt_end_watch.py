#!/usr/bin/env python3
"""ChatGPT session stop → The End watcher for Nullink.

Polls GET /api/messages (Bearer). While armed:
  - idle/rate-limit stop without exact substring "The End" → POST keep building
  - stop with "The End" → disarm + notify (JSONL / webhook / stdout); never keep building

Control HTTP (loopback) + Start/Stop overlay for Nullink Apps proxy.
Stdlib only (urllib). Never logs token contents.
"""
from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import sys
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

ET = ZoneInfo("America/New_York")
KEEP_BUILDING_TEXT = "keep building"
THE_END = "The End"

# Case-sensitive / phrase heuristics for rate-limit stop (documented in README).
RATE_LIMIT_PHRASES = (
    "You've hit the free plan limit",
    "You've reached the limit",
    "rate limit",
    "Rate limit",
    "Too many requests",
    "try again later",
    "Try again later",
    "usage limit",
    "Usage limit",
    "temporarily rate-limited",
    "come back later",
)

SECRET_PATTERNS = [
    re.compile(r"BEGIN OPENSSH[\s\S]{0,200}"),
    re.compile(r"Bearer\s+\S+", re.IGNORECASE),
    re.compile(r"nlk_[A-Za-z0-9_\-]{8,}"),
    re.compile(r"-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]{0,200}"),
    re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*\S+"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
]


def now_et() -> datetime:
    return datetime.now(ET)


def iso_et(dt: datetime | None = None) -> str:
    d = dt or now_et()
    return d.isoformat(timespec="seconds")


def redact(text: str) -> str:
    out = text or ""
    for pat in SECRET_PATTERNS:
        out = pat.sub("[REDACTED]", out)
    return out


def preview(text: str, n: int = 200) -> str:
    return redact(text)[:n]


def load_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if k and k not in os.environ:
            os.environ[k] = v


def read_token(path: str) -> str:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"token file missing: {path}")
    return p.read_text(encoding="utf-8").strip()


class NullinkClient:
    def __init__(self, base_url: str, token: str, timeout: float = 30.0):
        self.base = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _request(self, method: str, path: str, body: dict | None = None) -> tuple[int, Any]:
        headers = {
            "Accept": "application/json",
            "User-Agent": "chatgpt-end-watch/1.0",
            "Authorization": f"Bearer {self.token}",
        }
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(
            self.base + path, data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                try:
                    parsed = json.loads(raw) if raw else None
                except json.JSONDecodeError:
                    parsed = raw
                return resp.status, parsed
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(raw) if raw else None
            except json.JSONDecodeError:
                parsed = raw
            return exc.code, parsed
        except urllib.error.URLError as exc:
            return 503, {"error": "connection_failed", "message": str(exc.reason)}

    def get_messages(self, session: str, after: int = 0, limit: int = 50) -> tuple[int, Any]:
        q = urllib.parse.urlencode(
            {"session": session, "after": str(after), "limit": str(limit)}
        )
        return self._request("GET", f"/api/messages?{q}")

    def post_message(self, session_id: str, text: str) -> tuple[int, Any]:
        return self._request(
            "POST", "/api/messages", {"session_id": session_id, "text": text}
        )


class StateStore:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.write(
                {
                    "armed": False,
                    "after_id": 0,
                    "last_msg_id": None,
                    "last_activity_ts": None,
                    "last_text_preview": "",
                    "seen_activity": False,
                    "last_stop_at": None,
                    "last_end_at": None,
                    "keep_building_count": 0,
                    "updated_at": iso_et(),
                }
            )

    def read(self) -> dict:
        with self._lock:
            try:
                return json.loads(self.path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                return {"armed": False, "after_id": 0}

    def write(self, data: dict) -> None:
        with self._lock:
            data = dict(data)
            data["updated_at"] = iso_et()
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            tmp.replace(self.path)

    def update(self, **kwargs: Any) -> dict:
        with self._lock:
            data = self.read()
            data.update(kwargs)
            self.write(data)
            return data


def match_rate_limit(text: str) -> bool:
    return any(p in (text or "") for p in RATE_LIMIT_PHRASES)


def build_notify_payload(
    *,
    stopped_reason: str,
    the_end_found: bool,
    last_message_text: str,
    session_id: str,
    last_msg_id: Any,
    armed: bool,
    keep_building_action: str | None = None,
) -> dict:
    return {
        "event": "chatgpt_end_watch",
        "stopped_reason": stopped_reason,
        "the_end_found": bool(the_end_found),
        "last_message_preview": preview(last_message_text, 200),
        "timestamp": iso_et(),
        "session_id": session_id,
        "last_msg_id": last_msg_id,
        "armed": armed,
        "keep_building_action": keep_building_action,
    }


def append_jsonl(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False) + "\n")


def post_webhook(url: str, payload: dict, dry_run: bool) -> dict:
    if not url:
        return {"skipped": True, "reason": "WEBHOOK_URL unset"}
    if dry_run:
        return {"skipped": True, "reason": "dry_run", "would_post": True}
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "chatgpt-end-watch/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return {"ok": True, "status": resp.status}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "status": exc.code}
    except urllib.error.URLError as exc:
        return {"ok": False, "error": str(exc.reason)}


def maybe_post_morc(client: NullinkClient, text: str, dry_run: bool) -> dict:
    """Optional notify to morc; never fail the watch on 403."""
    if dry_run:
        return {"skipped": True, "reason": "dry_run"}
    try:
        code, body = client.post_message("morc", text)
        if code == 403:
            return {"skipped": True, "reason": "403_session_not_allowed"}
        return {"ok": code == 200, "status": code}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": type(exc).__name__}


OVERLAY_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>ChatGPT End Watch</title>
<style>
  :root { color-scheme: dark; --bg:#0f1115; --card:#1a1f2a; --ok:#3dd68c; --stop:#f07178; --muted:#8b93a7; --fg:#e6eaf2; }
  * { box-sizing: border-box; }
  body { margin:0; font-family: ui-sans-serif, system-ui, sans-serif; background:var(--bg); color:var(--fg);
         display:flex; align-items:center; justify-content:center; min-height:100vh; }
  .card { background:var(--card); border-radius:16px; padding:28px 32px; width:min(420px,92vw);
          box-shadow:0 12px 40px rgba(0,0,0,.45); }
  h1 { margin:0 0 4px; font-size:1.25rem; }
  .sub { color:var(--muted); font-size:.85rem; margin-bottom:20px; }
  .status { font-size:1.1rem; margin:12px 0 20px; }
  .status .dot { display:inline-block; width:10px; height:10px; border-radius:50%; margin-right:8px; }
  .armed .dot { background:var(--ok); box-shadow:0 0 8px var(--ok); }
  .disarmed .dot { background:var(--stop); }
  .row { display:flex; gap:12px; }
  button { flex:1; border:0; border-radius:10px; padding:14px 12px; font-size:1rem; font-weight:600;
           cursor:pointer; color:#0b0d10; }
  button:disabled { opacity:.45; cursor:not-allowed; }
  #start { background:var(--ok); }
  #stop { background:var(--stop); color:#fff; }
  .meta { margin-top:18px; font-size:.75rem; color:var(--muted); line-height:1.45; white-space:pre-wrap; }
  .err { color:var(--stop); margin-top:10px; font-size:.85rem; }
</style>
</head>
<body>
  <div class="card">
    <h1>ChatGPT End Watch</h1>
    <div class="sub">Start arms the idle→keep-building loop. Stop / The End disarms.</div>
    <div id="st" class="status disarmed"><span class="dot"></span><span id="label">…</span></div>
    <div class="row">
      <button id="start" type="button">Start</button>
      <button id="stop" type="button">Stop</button>
    </div>
    <div id="err" class="err"></div>
    <div id="meta" class="meta"></div>
  </div>
<script>
async function api(path, method) {
  const r = await fetch(path, { method: method || 'GET', headers: { 'Accept': 'application/json' }});
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status));
  return j;
}
function render(s) {
  const armed = !!s.armed;
  const st = document.getElementById('st');
  st.className = 'status ' + (armed ? 'armed' : 'disarmed');
  document.getElementById('label').textContent = armed ? 'ARMED — watching chatgpt' : 'DISARMED';
  document.getElementById('start').disabled = armed;
  document.getElementById('stop').disabled = !armed;
  const lines = [
    'session: ' + (s.session_id || 'chatgpt'),
    'last_msg_id: ' + (s.last_msg_id ?? '—'),
    'keep_building_count: ' + (s.keep_building_count ?? 0),
    'last_end_at: ' + (s.last_end_at || '—'),
    'updated: ' + (s.updated_at || '—'),
  ];
  document.getElementById('meta').textContent = lines.join('\\n');
}
async function refresh() {
  try {
    const s = await api('/api/status');
    document.getElementById('err').textContent = '';
    render(s);
  } catch (e) {
    document.getElementById('err').textContent = String(e.message || e);
  }
}
document.getElementById('start').onclick = async () => {
  try { render(await api('/api/arm', 'POST')); } catch (e) {
    document.getElementById('err').textContent = String(e.message || e);
  }
};
document.getElementById('stop').onclick = async () => {
  try { render(await api('/api/disarm', 'POST')); } catch (e) {
    document.getElementById('err').textContent = String(e.message || e);
  }
};
refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
"""


class ControlHandler(BaseHTTPRequestHandler):
    watcher: "Watcher"  # set on class before serve
    control_token: str = ""

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("[control] " + (fmt % args) + "\n")

    def _client_is_loopback(self) -> bool:
        host = self.client_address[0]
        return host in ("127.0.0.1", "::1", "localhost")

    def _authorized(self) -> bool:
        """Loopback always OK; otherwise require CONTROL_TOKEN if configured."""
        tok = (ControlHandler.control_token or "").strip()
        if not tok:
            return True
        if self._client_is_loopback():
            return True
        auth = self.headers.get("Authorization") or ""
        x = self.headers.get("X-Control-Token") or ""
        if auth.lower().startswith("bearer "):
            got = auth[7:].strip()
        else:
            got = x.strip()
        return hmac.compare_digest(got, tok) if got else False

    def _json(self, code: int, obj: dict) -> None:
        raw = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _html(self, code: int, html: str) -> None:
        raw = html.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        path = urllib.parse.urlparse(self.path).path
        if path in ("/health", "/api/chatgpt-end-watch/health"):
            return self._json(200, {"ok": True, "service": "chatgpt-end-watch"})
        # Stub page only — primary Start/Stop is the Android SYSTEM_ALERT_WINDOW overlay.
        if path in ("/", "/index.html", "/overlay"):
            return self._html(200, OVERLAY_HTML)
        if path in (
            "/api/status",
            "/status",
            "/api/chatgpt-end-watch/status",
        ):
            if not self._authorized():
                return self._json(401, {"error": "unauthorized"})
            st = self.watcher.public_status()
            st["ok"] = True
            st["active"] = bool(st.get("armed"))
            return self._json(200, st)
        return self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urllib.parse.urlparse(self.path).path
        if path in (
            "/api/arm",
            "/api/start",
            "/start",
            "/api/chatgpt-end-watch/start",
            "/api/disarm",
            "/api/stop",
            "/stop",
            "/api/chatgpt-end-watch/stop",
        ):
            if not self._authorized():
                return self._json(401, {"error": "unauthorized"})
            if path in ("/api/arm", "/api/start", "/start", "/api/chatgpt-end-watch/start"):
                st = self.watcher.arm()
                st["ok"] = True
                st["action"] = "start"
                st["active"] = True
                return self._json(200, st)
            st = self.watcher.disarm(reason="manual_stop")
            st["ok"] = True
            st["action"] = "stop"
            st["active"] = False
            return self._json(200, st)
        return self._json(404, {"error": "not_found"})


class Watcher:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.session_id = args.session
        self.idle_secs = float(args.idle_secs)
        self.poll_secs = float(args.poll_secs)
        self.dry_run = bool(args.dry_run)
        self.alert_log = Path(args.alert_log)
        self.webhook_url = (args.webhook_url or "").strip()
        self.notify_morc = bool(args.notify_morc)
        self.state = StateStore(Path(args.state_file))
        token = ""
        if not args.no_token:
            token = read_token(args.token_file)
        self.client = NullinkClient(args.base_url, token) if token else None
        self._stop_event = threading.Event()

    def public_status(self) -> dict:
        s = self.state.read()
        return {
            "armed": bool(s.get("armed")),
            "session_id": self.session_id,
            "after_id": s.get("after_id", 0),
            "last_msg_id": s.get("last_msg_id"),
            "last_activity_ts": s.get("last_activity_ts"),
            "last_text_preview": s.get("last_text_preview") or "",
            "seen_activity": bool(s.get("seen_activity")),
            "last_stop_at": s.get("last_stop_at"),
            "last_end_at": s.get("last_end_at"),
            "keep_building_count": s.get("keep_building_count", 0),
            "updated_at": s.get("updated_at"),
            "idle_secs": self.idle_secs,
            "dry_run": self.dry_run,
        }

    def arm(self) -> dict:
        self.state.update(armed=True, seen_activity=False, last_stop_at=None)
        print(f"[watch] ARMED session={self.session_id} at {iso_et()}", flush=True)
        return self.public_status()

    def disarm(self, reason: str = "manual_stop") -> dict:
        self.state.update(armed=False)
        print(f"[watch] DISARMED reason={reason} at {iso_et()}", flush=True)
        return self.public_status()

    def notify(self, payload: dict) -> None:
        append_jsonl(self.alert_log, payload)
        wh = post_webhook(self.webhook_url, payload, self.dry_run)
        payload_out = dict(payload)
        payload_out["webhook"] = wh
        print("MORC_PULSE " + json.dumps(payload_out, ensure_ascii=False), flush=True)
        if self.notify_morc and self.client:
            summary = (
                f"[chatgpt-end-watch] reason={payload.get('stopped_reason')} "
                f"the_end={payload.get('the_end_found')} armed={payload.get('armed')} "
                f"preview={payload.get('last_message_preview')}"
            )
            morc = maybe_post_morc(self.client, summary[:8000], self.dry_run)
            print(f"[watch] morc_notify={json.dumps(morc)}", flush=True)

    def fetch_latest(self) -> tuple[list[dict], int]:
        assert self.client is not None
        s = self.state.read()
        after = int(s.get("after_id") or 0)
        all_new: list[dict] = []
        next_after = after
        # Page until has_more false (cap pages)
        for _ in range(20):
            code, body = self.client.get_messages(self.session_id, after=next_after, limit=100)
            if code != 200 or not isinstance(body, dict):
                raise RuntimeError(f"GET messages failed status={code} body={preview(str(body), 120)}")
            msgs = list(body.get("messages") or [])
            # Live Nullink: next_after + has_more
            if body.get("next_after") is not None:
                next_after = int(body["next_after"])
            has_more = bool(body.get("has_more", False))
            all_new.extend(msgs)
            if not has_more or not msgs:
                break
        return all_new, next_after

    def apply_messages(self, msgs: list[dict], next_after: int) -> dict:
        s = self.state.read()
        if msgs:
            last = msgs[-1]
            text = str(last.get("text") or "")
            mid = last.get("id")
            ts = last.get("created_at") or last.get("ts") or iso_et()
            self.state.update(
                after_id=next_after,
                last_msg_id=mid,
                last_activity_ts=ts if isinstance(ts, str) else iso_et(),
                last_text_preview=preview(text, 200),
                seen_activity=True,
                # wall clock for idle calc
                last_activity_monotonic=time.time(),
            )
            return self.state.read()
        # no new messages — still advance cursor if server gave next_after
        if next_after and next_after != int(s.get("after_id") or 0):
            self.state.update(after_id=next_after)
        return self.state.read()

    def detect_stop(self, s: dict, *, force: bool = False, force_reason: str | None = None) -> str | None:
        if force:
            return force_reason or "forced"
        if not s.get("seen_activity"):
            return None
        text = ""
        # use last preview only for rate-limit; idle uses monotonic
        # We store last_activity_monotonic when messages arrive
        mono = s.get("last_activity_monotonic")
        if mono is None:
            # bootstrap: set now so we don't immediately fire
            self.state.update(last_activity_monotonic=time.time())
            return None
        idle = time.time() - float(mono)
        # Re-read last text from state preview is redacted — keep raw in memory via fetch
        # Rate-limit check needs last raw text; caller passes via force or we check after fetch
        if idle >= self.idle_secs:
            return "idle"
        return None

    def handle_stop(
        self,
        *,
        reason: str,
        last_text: str,
        last_msg_id: Any,
    ) -> dict:
        the_end = THE_END in (last_text or "")
        result: dict[str, Any] = {
            "stopped_reason": reason,
            "the_end_found": the_end,
            "keep_building": None,
        }

        if the_end:
            # Disarm permanently until re-armed; never keep building
            self.state.update(
                armed=False,
                last_end_at=iso_et(),
                last_stop_at=iso_et(),
            )
            payload = build_notify_payload(
                stopped_reason=reason,
                the_end_found=True,
                last_message_text=last_text,
                session_id=self.session_id,
                last_msg_id=last_msg_id,
                armed=False,
                keep_building_action="skipped_the_end",
            )
            self.notify(payload)
            result["keep_building"] = {"action": "skipped_the_end"}
            result["disarmed"] = True
            print("[watch] The End → DISARMED; notify only", flush=True)
            return result

        # No The End → keep building (only while still armed)
        s = self.state.read()
        if not s.get("armed"):
            result["keep_building"] = {"action": "skipped_disarmed"}
            return result

        kb_action: dict[str, Any]
        if self.dry_run:
            kb_action = {"action": "would_post", "text": KEEP_BUILDING_TEXT, "session_id": self.session_id}
            print(f"[watch] dry-run would POST keep building to {self.session_id}", flush=True)
        else:
            assert self.client is not None
            code, body = self.client.post_message(self.session_id, KEEP_BUILDING_TEXT)
            kb_action = {"action": "posted", "status": code, "ok": code == 200}
            # body may contain message id — do not dump secrets
            if isinstance(body, dict) and isinstance(body.get("message"), dict):
                kb_action["msg_id"] = body["message"].get("id")
            print(f"[watch] POST keep building status={code}", flush=True)
            if code == 200:
                # Reset idle clock so we wait again for activity / next idle
                self.state.update(
                    last_activity_monotonic=time.time(),
                    keep_building_count=int(s.get("keep_building_count") or 0) + 1,
                    last_stop_at=iso_et(),
                    seen_activity=True,
                )
            else:
                self.state.update(last_stop_at=iso_et())

        payload = build_notify_payload(
            stopped_reason=reason,
            the_end_found=False,
            last_message_text=last_text,
            session_id=self.session_id,
            last_msg_id=last_msg_id,
            armed=True,
            keep_building_action=kb_action.get("action"),
        )
        payload["keep_building"] = kb_action
        self.notify(payload)
        result["keep_building"] = kb_action
        return result

    def one_cycle(
        self,
        *,
        force_stop: bool = False,
        fixture_text: str | None = None,
        require_armed: bool = True,
    ) -> dict:
        out: dict[str, Any] = {"ok": True}
        s = self.state.read()
        if require_armed and not s.get("armed") and not force_stop:
            out["skipped"] = "disarmed"
            return out

        last_text = ""
        last_msg_id = s.get("last_msg_id")

        if fixture_text is not None:
            last_text = fixture_text
            # fixture path for smoke — do not need live fetch for stop decision
            if force_stop:
                reason = "forced"
                if match_rate_limit(last_text):
                    reason = "rate_limit_heuristic"
                out["stop"] = self.handle_stop(
                    reason=reason, last_text=last_text, last_msg_id=last_msg_id
                )
                return out

        if self.client is None:
            out["ok"] = False
            out["error"] = "no_client"
            return out

        msgs, next_after = self.fetch_latest()
        s = self.apply_messages(msgs, next_after)
        if msgs:
            last_text = str(msgs[-1].get("text") or "")
            last_msg_id = msgs[-1].get("id")
        else:
            # need raw last text for The End / rate-limit — re-fetch last page from after-1 if needed
            # Use state preview only for display; for heuristics pull recent
            code, body = self.client.get_messages(
                self.session_id, after=max(0, int(s.get("after_id") or 0) - 5), limit=5
            )
            if code == 200 and isinstance(body, dict):
                recent = list(body.get("messages") or [])
                if recent:
                    last_text = str(recent[-1].get("text") or "")
                    last_msg_id = recent[-1].get("id")

        out["fetched"] = len(msgs)
        out["after_id"] = s.get("after_id")
        out["armed"] = bool(s.get("armed"))

        reason = None
        if force_stop:
            reason = "forced"
            if match_rate_limit(last_text):
                reason = "rate_limit_heuristic"
        else:
            # rate-limit heuristic can fire even before full idle if last msg matches
            if last_text and match_rate_limit(last_text) and s.get("seen_activity"):
                # only if no newer messages this cycle
                if not msgs:
                    reason = "rate_limit_heuristic"
            if reason is None:
                reason = self.detect_stop(s)

        if reason:
            # ensure armed for keep-building path unless The End
            if require_armed and not self.state.read().get("armed") and THE_END not in last_text:
                if not force_stop:
                    out["skipped"] = "disarmed_before_stop"
                    return out
            out["stop"] = self.handle_stop(
                reason=reason, last_text=last_text, last_msg_id=last_msg_id
            )
        else:
            out["idle_waiting"] = True
        return out

    def run_loop(self) -> None:
        print(
            f"[watch] loop start base={self.args.base_url} session={self.session_id} "
            f"idle={self.idle_secs}s poll={self.poll_secs}s dry_run={self.dry_run}",
            flush=True,
        )
        while not self._stop_event.is_set():
            try:
                s = self.state.read()
                if s.get("armed"):
                    result = self.one_cycle(require_armed=True)
                    # compact log — no secrets
                    print(
                        f"[watch] cycle armed={result.get('armed')} fetched={result.get('fetched')} "
                        f"stop={bool(result.get('stop'))} skip={result.get('skipped')}",
                        flush=True,
                    )
                else:
                    print(f"[watch] disarmed — no-op poll at {iso_et()}", flush=True)
            except Exception as exc:  # noqa: BLE001
                print(f"[watch] cycle error: {type(exc).__name__}: {exc}", flush=True)
                traceback.print_exc()
            self._stop_event.wait(self.poll_secs)

    def stop(self) -> None:
        self._stop_event.set()


def start_control_server(watcher: Watcher, host: str, port: int, control_token: str = "") -> ThreadingHTTPServer:
    ControlHandler.watcher = watcher
    ControlHandler.control_token = control_token or ""
    httpd = ThreadingHTTPServer((host, port), ControlHandler)
    t = threading.Thread(target=httpd.serve_forever, name="control-http", daemon=True)
    t.start()
    print(f"[control] listening http://{host}:{port}/", flush=True)
    return httpd


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Nullink ChatGPT end watcher")
    p.add_argument("--config", default="", help="Optional env file to load")
    p.add_argument("--base-url", default=os.environ.get("NULLINK_BASE_URL", "http://127.0.0.1:8766"))
    p.add_argument(
        "--token-file",
        default=os.environ.get(
            "NULLINK_TOKEN_FILE", "/opt/nullink/secrets/NULLINK_TOKEN_chatgpt.txt"
        ),
    )
    p.add_argument("--session", default=os.environ.get("SESSION_ID", "chatgpt"))
    p.add_argument("--idle-secs", type=float, default=float(os.environ.get("IDLE_SECS", "120")))
    p.add_argument("--poll-secs", type=float, default=float(os.environ.get("POLL_SECS", "15")))
    p.add_argument(
        "--state-file",
        default=os.environ.get(
            "STATE_FILE", "/opt/nullink/data/chatgpt-end-watch/state.json"
        ),
    )
    p.add_argument(
        "--alert-log",
        default=os.environ.get(
            "ALERT_LOG", "/opt/nullink/data/chatgpt-end-watch/alerts.jsonl"
        ),
    )
    p.add_argument("--webhook-url", default=os.environ.get("WEBHOOK_URL", ""))
    p.add_argument("--notify-morc", action="store_true", default=os.environ.get("NOTIFY_MORC", "").lower() in ("1", "true", "yes"))
    p.add_argument("--control-host", default=os.environ.get("CONTROL_HOST", "127.0.0.1"))
    p.add_argument("--control-port", type=int, default=int(os.environ.get("CONTROL_PORT", "8767")))
    p.add_argument("--control-token", default=os.environ.get("CONTROL_TOKEN", ""),
                        help="Token-gate non-loopback control API (Android overlay)")
    p.add_argument("--no-control", action="store_true", help="Do not start control HTTP")
    p.add_argument("--once", action="store_true", help="Single cycle then exit")
    p.add_argument("--force-stop", action="store_true", help="Treat as stop this cycle")
    p.add_argument("--fixture-text", default=None, help="Override last message text (smoke)")
    p.add_argument("--arm", action="store_true", help="Arm before running")
    p.add_argument("--disarm", action="store_true", help="Disarm and exit")
    p.add_argument("--dry-run", action="store_true", help="Do not POST keep building / webhook")
    p.add_argument("--no-token", action="store_true", help="Skip token load (fixture-only smoke)")
    p.add_argument("--status", action="store_true", help="Print status JSON and exit")
    return p


def main(argv: list[str] | None = None) -> int:
    # Pre-parse config path
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config", default="")
    pre_args, _ = pre.parse_known_args(argv)
    if pre_args.config:
        load_dotenv(Path(pre_args.config))
    else:
        # conventional env next to script / etc
        for cand in (
            Path("/opt/nullink/scripts/chatgpt-end-watch/config.env"),
            Path(__file__).resolve().parent / "config.env",
        ):
            load_dotenv(cand)

    args = build_arg_parser().parse_args(argv)
    # CLI (sys.argv) wins over dotenv; only fill from env when flag absent
    argv_list = list(argv) if argv is not None else sys.argv[1:]
    if "--base-url" not in argv_list:
        args.base_url = os.environ.get("NULLINK_BASE_URL", args.base_url)
    if "--webhook-url" not in argv_list:
        args.webhook_url = args.webhook_url or os.environ.get("WEBHOOK_URL", "")

    w = Watcher(args)

    if args.status:
        print(json.dumps(w.public_status(), indent=2))
        return 0
    if args.disarm:
        print(json.dumps(w.disarm(reason="cli_disarm"), indent=2))
        return 0
    if args.arm:
        w.arm()

    if args.once:
        # force-stop smoke may run while disarmed if fixture provided — allow via force
        require_armed = not args.force_stop
        if args.force_stop and not w.state.read().get("armed"):
            # temporarily arm for force-stop smoke paths that need keep-building,
            # unless fixture is The End (handle_stop disarms anyway).
            # For keep-building branch we need armed=True during handle_stop.
            w.state.update(armed=True, seen_activity=True, last_activity_monotonic=0)
        result = w.one_cycle(
            force_stop=args.force_stop,
            fixture_text=args.fixture_text,
            require_armed=require_armed and not args.force_stop,
        )
        # Redacted summary only
        safe = {
            "ok": result.get("ok"),
            "skipped": result.get("skipped"),
            "fetched": result.get("fetched"),
            "armed": w.state.read().get("armed"),
            "stop": None,
        }
        if result.get("stop"):
            st = result["stop"]
            safe["stop"] = {
                "stopped_reason": st.get("stopped_reason"),
                "the_end_found": st.get("the_end_found"),
                "disarmed": st.get("disarmed"),
                "keep_building": st.get("keep_building"),
            }
        print(json.dumps(safe, indent=2))
        return 0 if result.get("ok", True) else 1

    httpd = None
    if not args.no_control:
        httpd = start_control_server(w, args.control_host, args.control_port, args.control_token)
    try:
        w.run_loop()
    except KeyboardInterrupt:
        w.stop()
    finally:
        if httpd is not None:
            httpd.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
