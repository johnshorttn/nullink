#!/usr/bin/env python3
"""Nullink <-> chat.deepseek.com bridge.

Watches Nullink's messages.jsonl for new role=user messages in the `deepseek`
session, types each one into ONE persistent DeepSeek web conversation (a
logged-in Chromium profile driven by Playwright), waits for the answer to
finish streaming and posts it back with reply.py.

Modes:
  worker.py run      service loop (systemd: nullink-deepseek-bridge)
  worker.py status   print state / pending queue (no browser)
  worker.py check    one-shot login check in a hidden browser (service must be stopped)

Sign-in: John double-clicks "Sign in to DeepSeek" on the Nullink Desktop
(Guacamole XFCE, user `desk`). That writes login-req/request.json; this worker
then opens the SAME profile in a visible window on his desktop. The bridge never
sees or stores the DeepSeek password and never solves captchas.
All DOM selectors live in ds_selectors.py.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import logging
import logging.handlers
import os
import pwd
import re
import signal
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import ds_selectors as SEL  # noqa: E402
from page_js import DETECT_JS, SNAPSHOT_JS  # noqa: E402


def env(name: str, default: str) -> str:
    return os.environ.get(name, default)


NL_ROOT = Path(env("NL_ROOT", "/opt/nullink"))
MESSAGES = Path(env("NL_MESSAGES", str(NL_ROOT / "data" / "messages.jsonl")))
REPLY_PY = Path(env("NL_REPLY", str(NL_ROOT / "reply.py")))
SESSION = env("NL_SESSION", "deepseek")
LAST_HANDLED = Path(env("NL_LAST_HANDLED", str(NL_ROOT / "data" / ".last-handled")))
NL_PYTHON = env("NL_PYTHON", "/usr/bin/python3")
ADVANCE_LAST_HANDLED = env("NL_ADVANCE_LAST_HANDLED", "1") == "1"
BRIDGE_SESSIONS = {s.strip() for s in env("NL_BRIDGE_SESSIONS", "deepseek").split(",") if s.strip()} | {SESSION}

DS_HOME = Path(env("DS_HOME", str(HERE)))
STATE_DIR = Path(env("DS_STATE_DIR", str(DS_HOME / "state")))
PROFILE = Path(env("DS_PROFILE", str(DS_HOME / "profile")))
LOG_DIR = Path(env("DS_LOG_DIR", str(DS_HOME / "logs")))
LOGIN_REQ_DIR = Path(env("DS_LOGIN_REQ_DIR", str(DS_HOME / "login-req")))
LOGIN_USER = env("DS_LOGIN_USER", "desk")

POLL_SEC = float(env("DS_POLL_SEC", "2"))
IDLE_CLOSE_SEC = float(env("DS_IDLE_CLOSE_SEC", "900"))
PAGE_TIMEOUT_MS = int(env("DS_PAGE_TIMEOUT_MS", "60000"))
READY_WAIT_SEC = float(env("DS_READY_WAIT_SEC", "45"))
CAPTCHA_GRACE_SEC = float(env("DS_CAPTCHA_GRACE_SEC", "45"))
ANSWER_TIMEOUT = float(env("DS_ANSWER_TIMEOUT", "600"))
FIRST_TOKEN_TIMEOUT = float(env("DS_FIRST_TOKEN_TIMEOUT", "120"))
MIN_GAP_SEC = float(env("DS_MIN_GAP_SEC", "6"))
MAX_ATTEMPTS = int(env("DS_MAX_ATTEMPTS", "3"))
RETRY_BACKOFF = [60, 180, 600]
BLOCKED_RECHECK_SEC = float(env("DS_BLOCKED_RECHECK_SEC", "900"))
RATE_LIMIT_PAUSE_SEC = float(env("DS_RATE_LIMIT_PAUSE_SEC", "1800"))
LOGIN_TIMEOUT = float(env("DS_LOGIN_TIMEOUT", "1200"))
LOGIN_KEEP_OPEN_SEC = float(env("DS_LOGIN_KEEP_OPEN_SEC", "600"))
STARTUP_CHECK = env("DS_STARTUP_CHECK", "1") == "1"
PLAIN_LOGIN = env("DS_PLAIN_LOGIN", "1") == "1"  # sign-in window = plain Chrome, no automation attached
MAX_REPLY_CHARS = 100_000

STATE_FILE = STATE_DIR / "state.json"
LOCK_FILE = STATE_DIR / "worker.lock"

NOTICE_PREFIX = "⚠️ DeepSeek bridge: "
NOTICES = {
    "logged_out": NOTICE_PREFIX + "DeepSeek needs you to sign in again. In Nullink open the **Desktop** app, "
                  "double-click **“Sign in to DeepSeek”** on the desktop, and sign in in the DeepSeek window that opens "
                  "(if it shows a verification check, complete it yourself there). "
                  "Messages you send here are queued and answered after you sign in.",
    "captcha": NOTICE_PREFIX + "DeepSeek is showing a verification check (captcha). I won't try to solve it. "
               "In Nullink open the **Desktop** app, double-click **“Sign in to DeepSeek”** and complete it yourself; "
               "queued messages are answered afterwards.",
    "rate_limit": NOTICE_PREFIX + "DeepSeek says I've hit a usage/rate limit. I'm pausing and will retry your queued "
                  "message(s) in about {mins} minutes.",
    "unrecognized": NOTICE_PREFIX + "I can't find the DeepSeek chat box — the site may have changed. Selectors live in "
                    "/opt/nullink/bridges/deepseek/ds_selectors.py. Queued messages will be retried.",
}
CONNECTED_TEXT = "✅ DeepSeek bridge: signed in — I'm answering here again."
BLOCKING_KINDS = ("logged_out", "captcha", "unrecognized")

log = logging.getLogger("deepseek-bridge")
STOP = False


class Blocked(Exception):
    def __init__(self, kind: str, detail: str = ""):
        super().__init__(f"{kind}: {detail}")
        self.kind = kind


class Busy(Exception):
    pass


class RateLimited(Exception):
    pass


class ContextFull(Exception):
    pass


class Stopping(Exception):
    pass


# ---------------------------------------------------------------- utilities
def setup_logging(to_file: bool = True) -> None:
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    if to_file:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(LOG_DIR / "worker.log", maxBytes=2_000_000, backupCount=5, encoding="utf-8")
        fh.setFormatter(fmt)
        log.addHandler(fh)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    log.addHandler(sh)


def now_iso_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")


def msg_key(m: dict) -> str:
    raw = f"{m.get('session_id')}|{m.get('ts')}|{m.get('text')}"
    return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:20]


def sha(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()


def norm(s: str) -> str:
    return re.sub(r"[\W_]+", "", (s or "").lower())


def sleep_interruptible(sec: float) -> None:
    end = time.time() + sec
    while not STOP and time.time() < end:
        time.sleep(min(0.5, max(0.0, end - time.time())))


def read_messages() -> list[tuple[int, dict]]:
    out: list[tuple[int, dict]] = []
    try:
        with MESSAGES.open("r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(d, dict):
                    out.append((i, d))
    except FileNotFoundError:
        pass
    return out


def count_lines() -> int:
    try:
        with MESSAGES.open("rb") as f:
            return sum(1 for _ in f)
    except FileNotFoundError:
        return 0


class State:
    def __init__(self) -> None:
        self.d: dict = {}
        self.load()

    def load(self) -> None:
        try:
            self.d = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            self.d = {}
        self.d.setdefault("handled", [])
        self.d.setdefault("attempts", {})

    def save(self) -> None:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.d, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, STATE_FILE)

    def __getitem__(self, k):
        return self.d.get(k)

    def __setitem__(self, k, v):
        self.d[k] = v


# ---------------------------------------------------------------- browser
class Browser:
    def __init__(self) -> None:
        self.pw = None
        self.ctx = None
        self.page = None
        self.xvfb: subprocess.Popen | None = None
        self.display: str | None = None
        self.visible = False
        self.last_used = 0.0

    @property
    def is_open(self) -> bool:
        return self.ctx is not None

    def _start_xvfb(self) -> str:
        r, w = os.pipe()
        self.xvfb = subprocess.Popen(
            ["Xvfb", "-displayfd", str(w), "-screen", "0", "1280x900x24", "-nolisten", "tcp", "-nocursor"],
            pass_fds=(w,), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        os.close(w)
        buf = b""
        deadline = time.time() + 15
        while time.time() < deadline and not buf.endswith(b"\n"):
            chunk = os.read(r, 16)
            if not chunk:
                break
            buf += chunk
        os.close(r)
        num = buf.strip().decode() if buf.strip() else ""
        if not num.isdigit():
            raise RuntimeError("Xvfb failed to start")
        return ":" + num

    def start(self, display: str | None = None) -> None:
        """display=None -> private hidden Xvfb display; else a real desktop display (sign-in)."""
        from playwright.sync_api import sync_playwright

        self.stop()
        PROFILE.mkdir(parents=True, exist_ok=True)
        os.chmod(PROFILE, 0o700)
        for stale in ("SingletonLock", "SingletonSocket", "SingletonCookie"):
            p = PROFILE / stale
            if p.is_symlink() or p.exists():
                try:
                    p.unlink()
                except OSError:
                    pass
        self.visible = display is not None
        self.display = display or self._start_xvfb()
        envv = dict(os.environ)
        envv["DISPLAY"] = self.display
        envv.pop("WAYLAND_DISPLAY", None)
        self.pw = sync_playwright().start()
        kwargs = dict(
            headless=False,
            env=envv,
            args=[
                "--no-first-run", "--no-default-browser-check", "--disable-dev-shm-usage",
                "--disable-gpu", "--renderer-process-limit=2", "--lang=en-US",
                "--disable-features=Translate,MediaRouter,OptimizationHints",
                "--js-flags=--max-old-space-size=384",
            ],
            locale="en-US",
            timeout=PAGE_TIMEOUT_MS,
        )
        # Use real Google Chrome when installed (Google sign-in rejects the Playwright test Chromium),
        # and drop the automation flag. Set DS_BROWSER_CHANNEL= (empty) in bridge.env to go back.
        channel = (os.environ.get("DS_BROWSER_CHANNEL") or "chrome")  # Chrome only: John said never use Chromium (2026-10-08)
        if channel:
            kwargs["channel"] = channel
        kwargs["ignore_default_args"] = ["--enable-automation"]
        kwargs["args"] = kwargs["args"] + ["--disable-blink-features=AutomationControlled"]
        if self.visible:
            kwargs["no_viewport"] = True
            kwargs["args"] = kwargs["args"] + ["--start-maximized", "--window-name=DeepSeek sign-in (Nullink bridge)"]
        else:
            kwargs["viewport"] = {"width": 1280, "height": 860}
        self.ctx = self.pw.chromium.launch_persistent_context(str(PROFILE), **kwargs)
        self.ctx.set_default_timeout(PAGE_TIMEOUT_MS)
        mock = os.environ.get("DS_TEST_MOCK_HTML")
        if mock:  # test harness only: serve a fake DeepSeek page instead of the real site
            body = Path(mock).read_text(encoding="utf-8")
            self.ctx.route("https://chat.deepseek.com/**", lambda route: route.fulfill(status=200, body=body, content_type="text/html"))
            log.warning("TEST MODE: chat.deepseek.com is mocked from %s", mock)
        pages = self.ctx.pages
        self.page = pages[0] if pages else self.ctx.new_page()
        for extra in pages[1:]:
            try:
                extra.close()
            except Exception:
                pass
        self.last_used = time.time()
        log.info("browser started (%s display %s)", "visible" if self.visible else "hidden", self.display)

    def stop(self) -> None:
        if self.ctx is not None:
            try:
                self.ctx.close()
            except Exception:
                pass
        if self.pw is not None:
            try:
                self.pw.stop()
            except Exception:
                pass
        if self.xvfb is not None:
            try:
                self.xvfb.terminate()
                self.xvfb.wait(timeout=5)
            except Exception:
                try:
                    self.xvfb.kill()
                except Exception:
                    pass
        if self.ctx is not None:
            log.info("browser stopped")
        self.ctx = self.pw = self.page = self.xvfb = None
        self.display = None
        self.visible = False

    def ensure(self) -> None:
        if self.ctx is None or self.page is None or self.page.is_closed():
            self.start()
        # one tab only
        for p in list(self.ctx.pages):
            if p is not self.page:
                try:
                    p.close()
                except Exception:
                    pass
        self.last_used = time.time()

    # -- page helpers --------------------------------------------------
    def detect(self) -> dict:
        cfg = {"input": SEL.INPUT_SELECTORS, "loginForm": SEL.LOGIN_FORM_SELECTORS, "toasts": SEL.TOAST_SELECTORS}
        return self.page.evaluate(DETECT_JS, cfg)

    def snapshot(self) -> dict:
        cfg = {
            "message": SEL.MESSAGE_SELECTORS, "answer": SEL.ANSWER_SELECTORS, "thinking": SEL.THINKING_SELECTORS,
            "iconButton": SEL.ICON_BUTTON_SELECTOR, "mdProps": SEL.MARKDOWN_PROP_NAMES,
            "codeBlock": SEL.CODE_BLOCK_SELECTOR, "codeLang": SEL.CODE_LANG_SELECTORS,
        }
        return self.page.evaluate(SNAPSHOT_JS, cfg)


def classify(st: dict) -> str:
    """-> 'ok' | 'logged_out' | 'captcha' | 'loading'"""
    url = st.get("url") or ""
    if any(src and any(part in src.lower() for part in SEL.CAPTCHA_IFRAME_SRC_PARTS) for src in st.get("iframes") or []):
        return "captcha"
    if re.search(SEL.CAPTCHA_TITLE_RE, st.get("title") or "", re.I):
        return "captcha"
    short = " ".join([st.get("dialogs") or "", st.get("toasts") or "", st.get("body") or ""])
    if re.search(SEL.CAPTCHA_TEXT_RE, short, re.I):
        return "captcha"
    if any(part in url for part in SEL.LOGIN_URL_PARTS):
        return "logged_out"
    if st.get("loginForm") and not st.get("hasInput"):
        return "logged_out"
    if st.get("hasInput") and url.startswith("https://chat.deepseek.com"):
        return "ok"
    return "loading"


# ---------------------------------------------------------------- bridge
class Bridge:
    def __init__(self) -> None:
        self.state = State()
        self.browser = Browser()
        self.next_try_at = 0.0
        self.last_block_check = 0.0
        self.last_msg_done = 0.0
        self.advanced_ts = ""
        self.advance_tried = 0.0
        try:
            self.login_uid = pwd.getpwnam(LOGIN_USER).pw_uid
        except KeyError:
            self.login_uid = None

    # -- Nullink side --------------------------------------------------
    def post(self, text: str) -> None:
        text = text.strip()
        if len(text) > MAX_REPLY_CHARS:
            text = text[:MAX_REPLY_CHARS] + "\n\n…(truncated by the DeepSeek bridge)"
        r = subprocess.run([NL_PYTHON, str(REPLY_PY), "--session", SESSION, text],
                           cwd=str(REPLY_PY.parent), capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            raise RuntimeError(f"reply.py failed: {r.stderr.strip()[:300]}")
        log.info("posted to %s (%d chars)", SESSION, len(text))

    def notice(self, kind: str, **fmt) -> None:
        cur = self.state["notice"] or {}
        same_family = cur.get("kind") in BLOCKING_KINDS and kind in BLOCKING_KINDS
        if cur.get("kind") == kind or same_family:
            # one notice per outage: signed-out / verification / unrecognised all need the same fix
            log.info("notice %s already posted at %s (now %s); not repeating", cur.get("kind"), cur.get("ts"), kind)
            return
        self.post(NOTICES[kind].format(**fmt))
        self.state["notice"] = {"kind": kind, "ts": now_iso_utc()}
        self.state.save()

    def mark_ok(self) -> None:
        cur = self.state["notice"] or {}
        changed = False
        if self.state["blocked"]:
            self.state["blocked"] = None
            changed = True
        if cur.get("kind") in BLOCKING_KINDS:
            self.post(CONNECTED_TEXT)
            self.state["notice"] = None
            changed = True
        elif cur.get("kind") == "rate_limit":
            self.state["notice"] = None
            changed = True
        self.state["last_ok"] = now_iso_utc()
        if changed:
            self.state.save()

    def block(self, kind: str, detail: str = "") -> None:
        log.warning("blocked: %s %s", kind, detail)
        until = time.time() + RATE_LIMIT_PAUSE_SEC if kind == "rate_limit" else None
        self.state["blocked"] = {"kind": kind, "since": now_iso_utc(), "until": until}
        self.state.save()
        self.last_block_check = time.time()
        if kind == "rate_limit":
            self.notice("rate_limit", mins=int(RATE_LIMIT_PAUSE_SEC // 60))
        else:
            self.notice(kind)

    def init_cursor(self) -> None:
        if self.state["cursor_line"] is None:
            self.state["cursor_line"] = count_lines()
            self.state["cursor_ts"] = now_iso_utc()
            self.state.save()
            log.info("cursor initialised at line %s (history is NOT answered)", self.state["cursor_line"])

    def pending(self) -> list[tuple[int, dict, str]]:
        msgs = read_messages()
        cursor = int(self.state["cursor_line"] or 0)
        if msgs and msgs[-1][0] < cursor:
            log.warning("messages.jsonl shrank (%s < cursor %s); falling back to ts/key dedupe", msgs[-1][0], cursor)
            cursor = 0
            self.state["cursor_line"] = 0
            self.state.save()
        handled = set(self.state["handled"])
        floor_ts = self.state["cursor_ts"] or ""
        out = []
        for line, m in msgs:
            if line <= cursor or m.get("role") != "user" or str(m.get("session_id") or "morc") != SESSION:
                continue
            if not str(m.get("text") or "").strip():
                continue
            k = msg_key(m)
            if k in handled or str(m.get("ts") or "") < floor_ts:
                continue
            out.append((line, m, k))
        return out

    def finish(self, line: int, m: dict, key: str) -> None:
        handled = self.state["handled"]
        handled.append(key)
        self.state["handled"] = handled[-500:]
        self.state["cursor_line"] = max(int(self.state["cursor_line"] or 0), line)
        ts = str(m.get("ts") or "")
        if ts > (self.state["cursor_ts"] or ""):
            self.state["cursor_ts"] = ts
        self.state["inflight"] = None
        self.state["attempts"].pop(key, None)
        self.state.save()
        self.last_msg_done = time.time()

    def advance_last_handled(self, ts: str) -> bool:
        """Keep the box-side Morc inbox routine from answering bridge-owned rooms.

        Only moves .last-handled forward to this message's ts, and only if no
        non-bridge user message is still newer than the current marker (so a
        real message in another room is never hidden)."""
        if not ADVANCE_LAST_HANDLED or not ts:
            return True
        try:
            cur = LAST_HANDLED.read_text(encoding="utf-8").strip() if LAST_HANDLED.exists() else ""
            if cur and ts <= cur:
                return True
            try:  # let same-second messages from other rooms land first (ts has 1 s resolution)
                if time.time() - datetime.fromisoformat(ts).timestamp() < 3:
                    return False
            except ValueError:
                pass
            newest_other = ""
            for _, d in read_messages():
                if d.get("role") != "user" or str(d.get("session_id") or "morc") in BRIDGE_SESSIONS:
                    continue
                if str(d.get("source") or "").lower() in ("mirror", "grok-bot", "grokbot"):
                    continue
                newest_other = max(newest_other, str(d.get("ts") or ""))
            if newest_other and (not cur or newest_other > cur):
                log.info(".last-handled not advanced yet: other rooms have unhandled messages (%s > %s)", newest_other, cur)
                return False
            tmp = LAST_HANDLED.with_name(".last-handled.deepseek-tmp")
            tmp.write_text(ts + "\n", encoding="utf-8")
            os.replace(tmp, LAST_HANDLED)
            log.info(".last-handled advanced %s -> %s", cur or "(none)", ts)
            return True
        except OSError as exc:
            log.warning("could not advance .last-handled: %s", exc)
            return True

    # -- DeepSeek side -------------------------------------------------
    def wait_ready(self) -> str:
        deadline = time.time() + READY_WAIT_SEC
        kind, last, captcha_since = "loading", None, None
        while time.time() < deadline:
            if STOP:
                raise Stopping()
            try:
                last = self.browser.detect()
                kind = classify(last)
            except Exception as exc:  # navigation in progress
                last = f"{type(exc).__name__}: {str(exc)[:160]}"
                kind = "loading"
            if kind == "captcha":
                # Never touch the challenge. Only wait passively in case the site's own
                # check completes by itself; otherwise report it.
                if captcha_since is None:
                    captcha_since = time.time()
                    log.info("verification page shown; waiting passively up to %ss", int(CAPTCHA_GRACE_SEC))
                if time.time() - captcha_since >= CAPTCHA_GRACE_SEC:
                    return "captcha"
                deadline = max(deadline, captcha_since + CAPTCHA_GRACE_SEC + 1)
            elif kind != "loading":
                return kind
            time.sleep(1)
        if captcha_since is not None and kind == "captcha":
            return "captcha"
        if isinstance(last, dict):
            last = {k: (v[:120] if isinstance(v, str) else v) for k, v in last.items()}
        log.info("page not ready after %ss; last detect: %s", int(READY_WAIT_SEC), last)
        return kind

    def open_conversation(self) -> list[str]:
        notes: list[str] = []
        page = self.browser.page
        conv = self.state["conversation_url"]
        target = conv or SEL.BASE_URL
        if conv and page.url.split("?")[0] == conv:
            pass
        elif not conv and page.url.rstrip("/") == SEL.BASE_URL.rstrip("/"):
            pass
        else:
            page.goto(target, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
        kind = self.wait_ready()
        if kind == "loading":
            raise Blocked("unrecognized", f"no chat input at {page.url}")
        if kind != "ok":
            raise Blocked(kind, page.url)
        if conv:
            uid = conv.rstrip("/").rsplit("/", 1)[-1]
            if uid not in page.url:
                log.warning("stored conversation %s not reachable (now %s); starting a new one", conv, page.url)
                self.state["conversation_url"] = None
                self.state.save()
                notes.append("_(The previous DeepSeek conversation was unavailable, so I started a new one — earlier context is gone.)_")
                page.goto(SEL.BASE_URL, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
                kind = self.wait_ready()
                if kind != "ok":
                    raise Blocked(kind if kind != "loading" else "unrecognized", page.url)
        return notes

    def find_input(self):
        page = self.browser.page
        try:
            loc = page.get_by_role("textbox").first
            if loc.count() and loc.is_visible():
                tag = loc.evaluate("e => e.tagName.toLowerCase() + '|' + (e.getAttribute('contenteditable')||'')")
                if tag.startswith("textarea") or "true" in tag:
                    return loc
        except Exception:
            pass
        for s in SEL.INPUT_SELECTORS:
            loc = page.locator(s).first
            try:
                if loc.count() and loc.is_visible():
                    return loc
            except Exception:
                continue
        raise Blocked("unrecognized", "chat input not found")

    def input_value(self, loc) -> str:
        try:
            return loc.evaluate("e => (e.value !== undefined ? e.value : e.innerText) || ''")
        except Exception:
            return ""

    def send(self, text: str, snap0: dict) -> None:
        page = self.browser.page
        loc = self.find_input()
        loc.click()
        loc.fill(text)
        time.sleep(0.5)
        if norm(self.input_value(loc))[:40] != norm(text)[:40]:
            # fallback typing (slow but reliable)
            loc.fill("")
            loc.press_sequentially(text, delay=5)
        loc.press("Enter")
        if self._sent(loc, snap0, 8):
            return
        # fallback: click the last enabled icon button in the composer
        log.info("Enter did not send; trying composer send button")
        clicked = loc.evaluate(
            """(e, sel) => {
                let box = e.parentElement;
                for (let i = 0; box && i < 6; i++, box = box.parentElement) {
                  const btns = Array.from(box.querySelectorAll(sel)).filter(b => (b.offsetWidth || b.offsetHeight) && b.getAttribute('aria-disabled') !== 'true' && !(b.innerText||'').trim());
                  if (btns.length) { btns[btns.length - 1].click(); return true; }
                }
                return false;
            }""",
            SEL.COMPOSER_BUTTON_SELECTOR,
        )
        if clicked and self._sent(loc, snap0, 8):
            return
        raise RuntimeError("could not submit the message (input not cleared)")

    def _sent(self, loc, snap0: dict, sec: float) -> bool:
        end = time.time() + sec
        while time.time() < end:
            if not norm(self.input_value(loc)):
                return True
            try:
                s = self.browser.snapshot()
                if s["turns"] > snap0["turns"]:
                    return True
            except Exception:
                pass
            time.sleep(0.5)
        return False

    def check_errors(self, snap: dict | None) -> None:
        try:
            st = self.browser.detect()
        except Exception:
            return
        kind = classify(st)
        if kind in ("captcha", "logged_out"):
            raise Blocked(kind, st.get("url", ""))
        short = (st.get("toasts") or "")
        if snap and snap.get("text") and len(snap["text"]) < 300:
            short += " | " + snap["text"]
        if re.search(SEL.RATE_LIMIT_RE, short, re.I):
            raise RateLimited(short[:200])
        if re.search(SEL.CONTEXT_FULL_RE, short, re.I):
            raise ContextFull(short[:200])
        if re.search(SEL.BUSY_RE, short, re.I):
            raise Busy(short[:200])

    def wait_answer(self, text: str, snap0: dict) -> tuple[str, bool]:
        """-> (answer_markdown, complete)"""
        start = time.time()
        deadline = start + ANSWER_TIMEOUT
        last_text, stable_since, best = None, time.time(), None
        n = 0
        want = norm(text)[:60]
        while time.time() < deadline:
            if STOP:
                raise Stopping()
            n += 1
            snap = self.browser.snapshot()
            if n % 4 == 0:
                self.check_errors(snap)
            matched = bool(want) and norm(snap.get("lastUserText", "")).startswith(want[:40])
            new_turn = snap["turns"] >= snap0["turns"] + 2 or snap["answersCount"] > snap0["answersCount"] or (matched and snap["asstFound"])
            if new_turn and snap.get("text"):
                best = snap
                if snap["text"] != last_text:
                    last_text, stable_since = snap["text"], time.time()
                stable = time.time() - stable_since
                if (snap["hasActions"] and stable >= 2.5) or stable >= 25:
                    self.check_errors(snap)
                    return self.pick_markdown(snap), True
            elif time.time() - start > FIRST_TOKEN_TIMEOUT and not (new_turn and snap.get("thinking")):
                self.check_errors(snap)
                raise RuntimeError("no answer started within %ss" % int(FIRST_TOKEN_TIMEOUT))
            time.sleep(1)
        if best and best.get("text"):
            return self.pick_markdown(best), False
        raise RuntimeError("answer timed out")

    @staticmethod
    def pick_markdown(snap: dict) -> str:
        md, conv, txt = snap.get("md"), snap.get("conv") or "", snap.get("text") or ""
        ref = norm(conv or txt)
        if md and ref:
            mdn = norm(md)
            step = max(1, len(ref) // 12)
            shingles = [ref[i:i + 12] for i in range(0, max(1, len(ref) - 12), step)][:12] or [ref]
            hit = sum(1 for s in shingles if s in mdn) / len(shingles)
            if hit >= 0.6 and 0.4 <= len(mdn) / max(1, len(ref)) <= 2.5:
                return md.strip()
            log.info("react markdown rejected (hit=%.2f); using converted HTML", hit)
        return (conv or txt).strip()

    def remember_conversation(self) -> None:
        url = (self.browser.page.url or "").split("?")[0]
        if re.match(SEL.CONVERSATION_URL_RE, url) and url != self.state["conversation_url"]:
            self.state["conversation_url"] = url
            self.state.save()
            log.info("conversation url stored: %s", url)

    # -- processing ----------------------------------------------------
    def process(self, line: int, m: dict, key: str) -> None:
        text = str(m.get("text") or "").strip()
        infl = self.state["inflight"] or {}
        if infl.get("key") != key:
            infl = {"key": key, "line": line, "phase": "picked", "started": now_iso_utc()}
            self.state["inflight"] = infl
            self.state.save()
        # crash after DeepSeek answered but before cursor moved -> never double-post
        if infl.get("phase") == "replying":
            if self.already_posted(line, infl.get("answer_sha", "")):
                log.info("reply for %s was already posted before restart; finishing", key)
                return self.finish(line, m, key)
            self.post(infl.get("answer", ""))
            return self.finish(line, m, key)

        self.browser.ensure()
        notes = self.open_conversation()
        self.mark_ok()
        snap0 = self.browser.snapshot()
        resume = infl.get("phase") == "submitted" and norm(snap0.get("lastUserText", "")).startswith(norm(text)[:40])
        if resume:
            log.info("resuming %s: prompt already in DeepSeek, waiting for its answer", key)
            snap0 = {"turns": 0, "answersCount": 0}
        else:
            log.info("sending %s (%d chars) to DeepSeek", key, len(text))
            self.send(text, snap0)
            infl["phase"] = "submitted"
            self.state["inflight"] = infl
            self.state.save()
        try:
            answer, complete = self.wait_answer(text, snap0)
        except ContextFull:
            if infl.get("context_reset"):
                raise
            log.warning("conversation full; starting a new DeepSeek conversation")
            self.state["conversation_url"] = None
            infl.update({"phase": "picked", "context_reset": True})
            self.state["inflight"] = infl
            self.state.save()
            self.browser.page.goto(SEL.BASE_URL, wait_until="domcontentloaded")
            if self.wait_ready() != "ok":
                raise
            snap0 = self.browser.snapshot()
            self.send(text, snap0)
            infl["phase"] = "submitted"
            self.state.save()
            notes.append("_(The DeepSeek conversation got too long, so I started a new one — earlier context is gone.)_")
            answer, complete = self.wait_answer(text, snap0)
        self.remember_conversation()
        if not answer:
            raise RuntimeError("empty answer")
        if not complete:
            notes.append("_(DeepSeek was still writing after %d min; this answer may be cut off.)_" % int(ANSWER_TIMEOUT // 60))
        final = answer + ("\n\n" + "\n".join(notes) if notes else "")
        infl.update({"phase": "replying", "answer": final, "answer_sha": sha(final.strip())})
        self.state["inflight"] = infl
        self.state.save()
        self.post(final)
        self.finish(line, m, key)

    def already_posted(self, after_line: int, answer_sha: str) -> bool:
        for line, d in read_messages():
            if line > after_line and d.get("role") == "assistant" and d.get("session_id") == SESSION:
                if sha(str(d.get("text") or "").strip()) == answer_sha:
                    return True
        return False

    def handle_one(self, line: int, m: dict, key: str) -> None:
        try:
            self.process(line, m, key)
        except Blocked as b:
            if b.kind == "unrecognized":
                n = int(self.state["attempts"].get(key, 0)) + 1
                self.state["attempts"][key] = n
                self.state.save()
                log.warning("page not recognised (attempt %d/%d): %s", n, MAX_ATTEMPTS, b)
                if n >= MAX_ATTEMPTS:
                    self.state["attempts"].pop(key, None)
                    self.block("unrecognized", str(b))
                else:
                    self.next_try_at = time.time() + RETRY_BACKOFF[min(n - 1, len(RETRY_BACKOFF) - 1)]
                    self.browser.stop()
            else:
                self.block(b.kind, str(b))
        except RateLimited as r:
            self.block("rate_limit", str(r))
        except Stopping:
            raise
        except Exception as exc:  # Busy, timeouts, playwright errors
            n = int(self.state["attempts"].get(key, 0)) + 1
            self.state["attempts"][key] = n
            infl = self.state["inflight"] or {}
            if isinstance(exc, Busy) and infl.get("key") == key and infl.get("phase") == "submitted":
                infl["phase"] = "picked"  # DeepSeek errored on this turn -> resend next time
                self.state["inflight"] = infl
            self.state.save()
            log.warning("attempt %d/%d for %s failed: %s: %s", n, MAX_ATTEMPTS, key, type(exc).__name__, str(exc)[:300])
            if n >= MAX_ATTEMPTS:
                why = "DeepSeek is busy" if isinstance(exc, Busy) else f"{type(exc).__name__}: {str(exc)[:160]}"
                self.post(NOTICE_PREFIX + f"I couldn't get an answer to your message after {n} tries ({why}). Please resend it later.")
                self.finish(line, m, key)
            else:
                self.next_try_at = time.time() + RETRY_BACKOFF[min(n - 1, len(RETRY_BACKOFF) - 1)]
                # a fresh browser often fixes a wedged page
                self.browser.stop()

    def check_login_state(self) -> str:
        self.browser.ensure()
        page = self.browser.page
        page.goto(self.state["conversation_url"] or SEL.BASE_URL, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
        kind = self.wait_ready()
        if kind == "loading":
            log.info("login check inconclusive; reloading once")
            page.reload(wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
            kind = self.wait_ready()
        log.info("login check: %s (%s)", kind, page.url)
        return "unrecognized" if kind == "loading" else kind

    def recheck(self) -> None:
        self.last_block_check = time.time()
        try:
            kind = self.check_login_state()
        except Stopping:
            return
        except Exception as exc:
            log.warning("login check failed: %s", exc)
            self.browser.stop()
            return
        if STOP:
            return
        if kind == "ok":
            self.mark_ok()
        else:
            self.browser.stop()  # don't hold ~400 MB while waiting for John
            self.block(kind)

    # -- sign-in on John's desktop ------------------------------------
    def login_status(self, status: str, message: str = "") -> None:
        try:
            p = LOGIN_REQ_DIR / "status.json"
            tmp = LOGIN_REQ_DIR / ".status.tmp"
            tmp.write_text(json.dumps({"status": status, "message": message, "ts": time.time()}), encoding="utf-8")
            os.chmod(tmp, 0o644)
            os.replace(tmp, p)
        except OSError as exc:
            log.warning("cannot write login status: %s", exc)

    def take_login_request(self) -> str | None:
        req = LOGIN_REQ_DIR / "request.json"
        try:
            st = req.lstat()
        except FileNotFoundError:
            return None
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            try:
                req.unlink()
            except OSError:
                pass
            log.warning("ignoring non-regular login request file")
            return None
        try:
            data = json.loads(req.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
        try:
            req.unlink()
        except OSError:
            pass
        if self.login_uid is not None and st.st_uid != self.login_uid:
            log.warning("ignoring login request owned by uid %s (expected %s)", st.st_uid, self.login_uid)
            return None
        display = str(data.get("display") or "")
        if not re.fullmatch(r":\d{1,3}(\.\d)?", display) or time.time() - float(data.get("ts") or 0) > 900:
            log.warning("ignoring invalid/stale login request %r", data)
            self.login_status("error", "Invalid or stale request — double-click the icon again.")
            return None
        return display

    def display_ok(self, display: str) -> bool:
        r = subprocess.run(["xdpyinfo", "-display", display], capture_output=True, timeout=10)
        return r.returncode == 0

    def plain_login_window(self, display: str, was_blocked: bool) -> str:
        """Open the bridge profile in a PLAIN Google Chrome window (no Playwright/CDP, no automation
        flags) so Google sign-in and hCaptcha treat it like a normal browser. John signs in, then
        closes the window; the bridge then verifies with a hidden check."""
        exe = env("DS_CHROME_EXE", "/opt/google/chrome/chrome")
        url = self.state["conversation_url"] or SEL.BASE_URL
        PROFILE.mkdir(parents=True, exist_ok=True)
        for stale in ("SingletonLock", "SingletonSocket", "SingletonCookie"):
            sp = PROFILE / stale
            if sp.is_symlink() or sp.exists():
                try:
                    sp.unlink()
                except OSError:
                    pass
        envv = {**os.environ, "DISPLAY": display}
        envv.pop("WAYLAND_DISPLAY", None)
        base = [exe, f"--user-data-dir={PROFILE}", "--no-first-run", "--no-default-browser-check",
                "--start-maximized", "--lang=en-US", "--class=DeepSeekSignIn", "--new-window", url]
        logf = open(LOG_DIR / "plain-chrome.log", "ab")
        limit = LOGIN_TIMEOUT if was_blocked else LOGIN_KEEP_OPEN_SEC
        proc = None
        for extra in ([], ["--no-sandbox"]):
            cmd = base[:1] + extra + base[1:]
            proc = subprocess.Popen(cmd, env=envv, stdin=subprocess.DEVNULL, stdout=logf, stderr=logf,
                                    start_new_session=True)
            t0 = time.time()
            while time.time() - t0 < 6 and proc.poll() is None:
                time.sleep(0.5)
            if proc.poll() is None:
                break
            log.warning("plain Chrome exited early (rc=%s, extra=%s)", proc.returncode, extra)
        else:
            self.login_status("error", "Chrome could not open on your desktop.")
            return "error"
        log.info("plain Chrome sign-in window open (pid %s, display %s)", proc.pid, display)
        self.login_status("open", "DeepSeek window is open on your desktop.")
        start = time.time()
        outcome = "closed"
        while proc.poll() is None:
            if STOP or time.time() - start >= limit:
                outcome = "timeout"
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                    proc.wait(timeout=15)
                except Exception:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except Exception:
                        pass
                break
            time.sleep(2)
        time.sleep(2)  # let Chrome flush cookies to the profile
        return outcome

    def login_flow(self, display: str) -> None:
        was_blocked = bool(self.state["blocked"]) and (self.state["blocked"] or {}).get("kind") != "rate_limit"
        log.info("sign-in requested on display %s (blocked=%s)", display, was_blocked)
        self.browser.stop()
        if not self.display_ok(display):
            self.login_status("error", "The bridge could not open a window on your desktop (display access denied).")
            log.warning("cannot open display %s", display)
            return
        outcome = "closed"
        if PLAIN_LOGIN:
            try:
                outcome = self.plain_login_window(display, was_blocked)
            except Exception as exc:
                log.warning("plain sign-in window error: %s", exc)
                outcome = "error"
            finally:
                subprocess.run(["xhost", "-SI:localuser:" + pwd.getpwuid(os.getuid()).pw_name],
                               env={**os.environ, "DISPLAY": display}, capture_output=True, timeout=10)
            log.info("plain sign-in window finished: %s", outcome)
            self.login_status("done", outcome)
            if STOP:
                return
            # No automation was attached to that window, so verify the result with a hidden check.
            self.recheck()
            return
        try:
            self.browser.start(display=display)
            page = self.browser.page
            page.goto(self.state["conversation_url"] or SEL.BASE_URL, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
            try:
                page.bring_to_front()
            except Exception:
                pass
            self.login_status("open", "DeepSeek window is open on your desktop.")
            start = time.time()
            limit = LOGIN_TIMEOUT if was_blocked else LOGIN_KEEP_OPEN_SEC
            ok_since = None
            while not STOP and time.time() - start < limit:
                try:
                    closed = page.is_closed() or not self.browser.ctx.pages
                except Exception:
                    closed = True
                if closed:
                    outcome = "closed"
                    break
                try:
                    kind = classify(self.browser.detect())
                except Exception:
                    kind = "loading"
                if kind == "ok":
                    ok_since = ok_since or time.time()
                    if was_blocked and time.time() - ok_since >= 8:
                        outcome = "signed_in"
                        break
                    outcome = "signed_in"
                else:
                    ok_since = None
                    outcome = "not_signed_in"
                time.sleep(2)
            else:
                if outcome != "signed_in":
                    outcome = "timeout"
        except Exception as exc:
            log.warning("sign-in window error: %s", exc)
        finally:
            self.browser.stop()
            subprocess.run(["xhost", "-SI:localuser:" + pwd.getpwuid(os.getuid()).pw_name],
                           env={**os.environ, "DISPLAY": display}, capture_output=True, timeout=10)
        log.info("sign-in window finished: %s", outcome)
        self.login_status("done", outcome)
        if STOP:
            return
        if outcome == "signed_in":
            self.mark_ok()
            self.next_try_at = 0
        elif was_blocked:
            # window closed/timed out without a confirmed sign-in -> verify once (no new notice if unchanged)
            self.recheck()

    # -- main loop -----------------------------------------------------
    def run(self) -> None:
        self.init_cursor()
        log.info("bridge running: session=%s messages=%s profile=%s", SESSION, MESSAGES, PROFILE)
        if STARTUP_CHECK:
            if self.state["inflight"] or self.pending():
                log.info("startup: queued work present; checking login while processing")
            self.recheck()
        while not STOP:
            try:
                disp = self.take_login_request()
                if disp:
                    self.login_flow(disp)
                    continue
                blocked = self.state["blocked"]
                queue = self.pending()
                if queue:
                    newest = max(str(m.get("ts") or "") for _, m, _ in queue)
                    if newest > self.advanced_ts and time.time() - self.advance_tried >= 5:
                        self.advance_tried = time.time()
                        if self.advance_last_handled(newest):
                            self.advanced_ts = newest
                if blocked:
                    if blocked.get("kind") == "rate_limit" and time.time() >= float(blocked.get("until") or 0):
                        self.state["blocked"] = None
                        self.state.save()
                        blocked = None
                    elif queue and time.time() - self.last_block_check >= BLOCKED_RECHECK_SEC and blocked.get("kind") != "rate_limit":
                        self.recheck()
                        blocked = self.state["blocked"]
                if queue and not blocked and time.time() >= self.next_try_at:
                    gap = MIN_GAP_SEC - (time.time() - self.last_msg_done)
                    if gap > 0:
                        sleep_interruptible(gap)
                    line, m, key = queue[0]
                    self.handle_one(line, m, key)
                    continue
                if self.browser.is_open and time.time() - self.browser.last_used > IDLE_CLOSE_SEC:
                    log.info("idle for %ss; closing browser to save memory", int(IDLE_CLOSE_SEC))
                    self.browser.stop()
            except Stopping:
                break
            except Exception as exc:
                log.exception("loop error: %s", exc)
                self.browser.stop()
                sleep_interruptible(30)
            sleep_interruptible(POLL_SEC)
        self.browser.stop()
        log.info("bridge stopped")


def acquire_lock():
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    fh = open(LOCK_FILE, "w")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return None
    return fh


def main() -> int:
    global STOP
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", nargs="?", default="run", choices=["run", "status", "check"])
    a = ap.parse_args()

    def _stop(*_):
        global STOP
        STOP = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    if a.mode == "status":
        s = State()
        b = Bridge.__new__(Bridge)
        b.state = s
        q = Bridge.pending(b) if s["cursor_line"] is not None else []
        print(json.dumps({k: v for k, v in s.d.items() if k not in ("handled",)} | {"handled_count": len(s["handled"]), "pending": [(l, m.get("ts"), str(m.get("text"))[:80]) for l, m, _ in q]}, indent=2, ensure_ascii=False))
        return 0

    lock = acquire_lock()
    if lock is None:
        print("another worker instance holds the lock (stop the service first for 'check')", file=sys.stderr)
        return 2
    setup_logging(to_file=(a.mode == "run"))
    br = Bridge()
    if a.mode == "check":
        try:
            print(br.check_login_state())
        finally:
            br.browser.stop()
        return 0
    br.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
