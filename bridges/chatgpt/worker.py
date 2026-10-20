#!/usr/bin/env python3
"""Jinx ChatGPT web bridge (Slack router <-> chatgpt.com), modeled on the DeepSeek bridge.

The Nullverse Slack router writes one job per Jinx @mention/DM into
<jobs>/pending/<ts>-<ref>.json ({"id","ref","prompt",...}). This worker types each prompt into ONE
dedicated ChatGPT conversation (a logged-in Chromium profile driven by Playwright on a hidden Xvfb
display), waits for the answer to finish and writes <jobs>/results/<same name> ({"status":"answered",
"text":...}). The router posts it in the Slack thread as the Jinx bot. This process never sees Slack tokens.

Modes:
  worker.py run      service loop (systemd: nullink-chatgpt-bridge)
  worker.py status   print state / pending jobs (no browser)
  worker.py check    one-shot login check in a hidden browser (service must be stopped)

Sign-in: John double-clicks "Sign in to ChatGPT (Jinx)" on the Nullink Desktop (Guacamole XFCE, user
`desk`). That writes login-req/request.json; this worker opens the SAME profile in a visible window on his
desktop. The bridge never sees or stores the password and never solves captchas.
While signed out, state.json has "blocked" set and the router uses its fallback (Nullink `chatgpt` room +
a short ack in Slack). All DOM selectors live in cg_selectors.py.
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
import cg_selectors as SEL  # noqa: E402
from page_js import DETECT_JS, SNAPSHOT_JS  # noqa: E402


def env(name: str, default: str) -> str:
    return os.environ.get(name, default)


CG_HOME = Path(env("CG_HOME", str(HERE)))
JOBS_DIR = Path(env("CG_JOBS_DIR", "/opt/nullink/slack-events/jobs/jinx"))
PENDING_DIR = JOBS_DIR / "pending"
RESULTS_DIR = JOBS_DIR / "results"
DONE_DIR = JOBS_DIR / "done"
STATE_DIR = Path(env("CG_STATE_DIR", str(CG_HOME / "state")))
PROFILE = Path(env("CG_PROFILE", str(CG_HOME / "profile")))
LOG_DIR = Path(env("CG_LOG_DIR", str(CG_HOME / "logs")))
LOGIN_REQ_DIR = Path(env("CG_LOGIN_REQ_DIR", str(CG_HOME / "login-req")))
LOGIN_USER = env("CG_LOGIN_USER", "desk")
PERSONA_FILE = Path(env("CG_PERSONA_FILE", str(CG_HOME / "persona.md")))
# Optional pin for jobs without a conversation_key (normally every Slack channel gets its own dedicated chat).
PINNED_CONVERSATION = env("CG_CONVERSATION_URL", "").strip() or None
# This bridge's verified runtime identity (reference contract). Jobs addressed to another runtime are refused.
RUNTIME_ID = env("CG_RUNTIME_ID", "chatgpt-bridge:jinx")
HANDOFF_LINE_RE = re.compile(r"^\s*[*_`]*HANDOFF\s*:\s*@?([A-Za-z0-9_-]+)[*_`.]*\s*$")
HEARTBEAT = STATE_DIR / "heartbeat"

POLL_SEC = float(env("CG_POLL_SEC", "2"))
IDLE_CLOSE_SEC = float(env("CG_IDLE_CLOSE_SEC", "900"))
PAGE_TIMEOUT_MS = int(env("CG_PAGE_TIMEOUT_MS", "60000"))
READY_WAIT_SEC = float(env("CG_READY_WAIT_SEC", "45"))
CAPTCHA_GRACE_SEC = float(env("CG_CAPTCHA_GRACE_SEC", "45"))
ANSWER_TIMEOUT = float(env("CG_ANSWER_TIMEOUT", "600"))
FIRST_TOKEN_TIMEOUT = float(env("CG_FIRST_TOKEN_TIMEOUT", "120"))
MIN_GAP_SEC = float(env("CG_MIN_GAP_SEC", "6"))
MAX_ATTEMPTS = int(env("CG_MAX_ATTEMPTS", "3"))
RETRY_BACKOFF = [60, 180, 600]
BLOCKED_RECHECK_SEC = float(env("CG_BLOCKED_RECHECK_SEC", "900"))
RATE_LIMIT_PAUSE_SEC = float(env("CG_RATE_LIMIT_PAUSE_SEC", "1800"))
LOGIN_TIMEOUT = float(env("CG_LOGIN_TIMEOUT", "1200"))
LOGIN_KEEP_OPEN_SEC = float(env("CG_LOGIN_KEEP_OPEN_SEC", "600"))
STARTUP_CHECK = env("CG_STARTUP_CHECK", "1") == "1"
MAX_REPLY_CHARS = 100_000

STATE_FILE = STATE_DIR / "state.json"
LOCK_FILE = STATE_DIR / "worker.lock"

BLOCKING_KINDS = ("logged_out", "captcha", "unrecognized")

log = logging.getLogger("chatgpt-bridge")
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


VIS_ANY_JS = r"""
(sels) => { const vis = (e) => !!e && !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length);
  for (const s of sels) { try { for (const e of document.querySelectorAll(s)) if (vis(e)) return true; } catch (err) {} }
  return false; }
"""
# True if the last assistant turn's container (article/turn) shows a "done" action (copy button).
LAST_TURN_HAS_JS = r"""
(cfg) => { let msgs = []; for (const s of cfg.msg) { try { msgs = Array.from(document.querySelectorAll(s)); if (msgs.length) break; } catch (e) {} }
  const asst = msgs.filter((m) => m.getAttribute('data-message-author-role') === 'assistant');
  if (!asst.length) return false;
  const last = asst[asst.length - 1];
  const turn = last.closest('article') || last.closest('[data-testid^="conversation-turn"]') || (last.parentElement && last.parentElement.parentElement);
  if (!turn) return false;
  for (const s of cfg.done) { try { if (turn.querySelector(s)) return true; } catch (e) {} }
  return false; }
"""


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
        # and drop the automation flag. Set CG_BROWSER_CHANNEL= (empty) in bridge.env to go back.
        channel = (os.environ.get("CG_BROWSER_CHANNEL") or "chrome")  # Chrome only: John said never use Chromium (2026-10-08)
        if channel:
            kwargs["channel"] = channel
        kwargs["ignore_default_args"] = ["--enable-automation"]
        kwargs["args"] = kwargs["args"] + ["--disable-blink-features=AutomationControlled"]
        if self.visible:
            kwargs["no_viewport"] = True
            kwargs["args"] = kwargs["args"] + ["--start-maximized", "--window-name=ChatGPT sign-in (Jinx bridge)"]
        else:
            kwargs["viewport"] = {"width": 1280, "height": 860}
        self.ctx = self.pw.chromium.launch_persistent_context(str(PROFILE), **kwargs)
        self.ctx.set_default_timeout(PAGE_TIMEOUT_MS)
        mock = os.environ.get("CG_TEST_MOCK_HTML")
        if mock:  # test harness only: serve a fake ChatGPT page instead of the real site
            body = Path(mock).read_text(encoding="utf-8")
            self.ctx.route("https://chatgpt.com/**", lambda route: route.fulfill(status=200, body=body, content_type="text/html"))
            log.warning("TEST MODE: chatgpt.com is mocked from %s", mock)
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
        st = self.page.evaluate(DETECT_JS, cfg)
        st["signedIn"] = self.page.evaluate(VIS_ANY_JS, SEL.SIGNED_IN_SELECTORS)
        return st

    def snapshot(self) -> dict:
        cfg = {
            "message": SEL.MESSAGE_SELECTORS, "answer": SEL.ANSWER_SELECTORS, "thinking": SEL.THINKING_SELECTORS,
            "iconButton": SEL.ICON_BUTTON_SELECTOR, "mdProps": SEL.MARKDOWN_PROP_NAMES,
            "codeBlock": SEL.CODE_BLOCK_SELECTOR, "codeLang": SEL.CODE_LANG_SELECTORS,
        }
        snap = self.page.evaluate(SNAPSHOT_JS, cfg)
        streaming = self.page.evaluate(VIS_ANY_JS, SEL.STOP_BUTTON_SELECTORS)
        done_btn = self.page.evaluate(LAST_TURN_HAS_JS, {"msg": SEL.MESSAGE_SELECTORS, "done": SEL.DONE_ACTION_SELECTORS})
        snap["streaming"] = bool(streaming)
        snap["hasActions"] = bool(done_btn) and not streaming
        return snap


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
    if st.get("loginForm"):  # chatgpt.com shows a composer to anonymous visitors too
        return "logged_out"
    if st.get("hasInput") and url.startswith("https://chatgpt.com") and st.get("signedIn"):
        return "ok"
    if st.get("hasInput") and url.startswith("https://chatgpt.com") and not st.get("signedIn"):
        return "loading"  # composer up, account hooks not rendered yet (or UI changed -> 'unrecognized')
    return "loading"


# ---------------------------------------------------------------- bridge
class Bridge:
    def __init__(self) -> None:
        self.state = State()
        self.browser = Browser()
        self.next_try_at = 0.0
        self.last_block_check = 0.0
        self.last_msg_done = 0.0
        self.cur_key = "default"
        try:
            self.login_uid = pwd.getpwnam(LOGIN_USER).pw_uid
        except KeyError:
            self.login_uid = None

    # -- job spool (router side) ---------------------------------------
    def write_result(self, job: dict, status: str, text: str) -> None:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        text = (text or "").strip()
        if len(text) > MAX_REPLY_CHARS:
            text = text[:MAX_REPLY_CHARS] + "\n\n...(truncated)"
        name = job["_file"]
        result = {"text": text}
        if status == "answered":
            lines = text.rstrip().splitlines()
            hit = HANDOFF_LINE_RE.match(lines[-1]) if lines else None
            if hit:  # structured handoff directive on the last line -> result.handoff_to (router validates it)
                text = "\n".join(lines[:-1]).rstrip()
                result = {"text": text}
                tgt = hit.group(1).lower()
                if tgt in [str(t).lower() for t in (job.get("_meta") or {}).get("handoff_targets") or []]:
                    result["handoff_to"] = tgt
                    if not text:
                        text = result["text"] = "Over to you."
        # Exactly the reference runtime contract; diagnostics go in a separate "meta" object.
        out = {"runtime_id": RUNTIME_ID, "request_key": job.get("request_key"), "idempotent": True,
               "state": "succeeded" if status == "answered" and text else "failed", "result": result,
               "meta": {"conversation_key": self.cur_key, "conversation_url": self.conv_url(), "ts": now_iso_utc()}}
        tmp = RESULTS_DIR / ("." + name + ".tmp")
        tmp.write_text(json.dumps(out, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, RESULTS_DIR / name)
        log.info("result %s for %s (%d chars)", status, job.get("ref"), len(text))

    def notice(self, kind: str, **fmt) -> None:
        cur = self.state["notice"] or {}
        if cur.get("kind") == kind:
            return
        self.state["notice"] = {"kind": kind, "ts": now_iso_utc()}
        self.state.save()

    def mark_ok(self) -> None:
        changed = bool(self.state["blocked"]) or bool(self.state["notice"])
        self.state["blocked"] = None
        self.state["notice"] = None
        self.state["last_ok"] = now_iso_utc()
        self.state.save()
        if changed:
            log.info("ChatGPT reachable and signed in")

    def block(self, kind: str, detail: str = "") -> None:
        log.warning("blocked: %s %s", kind, detail)
        until = time.time() + RATE_LIMIT_PAUSE_SEC if kind == "rate_limit" else None
        self.state["blocked"] = {"kind": kind, "since": now_iso_utc(), "until": until}
        self.state.save()
        self.last_block_check = time.time()
        self.notice(kind)

    def heartbeat(self) -> None:
        try:
            STATE_DIR.mkdir(parents=True, exist_ok=True)
            HEARTBEAT.touch()
        except OSError:
            pass

    def pending(self) -> list[tuple[int, dict, str]]:
        out = []
        try:
            files = sorted(PENDING_DIR.glob("*.json"))
        except OSError:
            return out
        for i, f in enumerate(files):
            try:
                job = json.loads(f.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(job, dict) or job.get("version") != 1 or job.get("method") != "reply" \
                    or not isinstance(job.get("request"), dict):
                continue
            if (RESULTS_DIR / f.name).exists():
                continue
            req, meta = job["request"], (job.get("meta") if isinstance(job.get("meta"), dict) else {})
            m = {"_file": f.name, "_meta": meta, "request_key": str(req.get("request_key") or ""),
                 "id": str(req.get("request_key") or f.stem), "ref": str(req.get("request_key") or ""),
                 "conversation_key": meta.get("conversation_key") or f"{req.get('channel')}:{req.get('thread_ts')}",
                 "conversation_title": meta.get("conversation_title"),
                 "text": str(meta.get("prompt") or req.get("text") or "")}
            refuse = None
            if not m["request_key"] or not m["text"].strip():
                refuse = "malformed request"
            elif req.get("runtime_id") != RUNTIME_ID:
                refuse = "runtime_id mismatch"
            elif time.time() > float(req.get("expires_at") or 0) and (self.state["inflight"] or {}).get("key") != m["id"]:
                refuse = "request expired"
            if refuse:
                log.warning("refusing job %s: %s", f.name, refuse)
                self.write_result(m, "failed", refuse)
                self.finish(i, m, m["id"]) if (self.state["inflight"] or {}).get("key") == m["id"] else self._done(m)
                continue
            out.append((i, m, m["id"]))
        return out

    def _done(self, m: dict) -> None:
        DONE_DIR.mkdir(parents=True, exist_ok=True)
        try:
            os.replace(PENDING_DIR / m["_file"], DONE_DIR / m["_file"])
        except OSError:
            pass

    def finish(self, line: int, m: dict, key: str) -> None:
        DONE_DIR.mkdir(parents=True, exist_ok=True)
        try:
            os.replace(PENDING_DIR / m["_file"], DONE_DIR / m["_file"])
        except OSError:
            pass  # withdrawn by the router meanwhile
        self.state["inflight"] = None
        self.state["attempts"].pop(key, None)
        self.state.save()
        self.last_msg_done = time.time()

    # one dedicated ChatGPT chat per conversation_key (Slack channel), never Jinx's main chat
    def conv_url(self) -> str | None:
        convs = self.state["conversations"] or {}
        return convs.get(self.cur_key) or (PINNED_CONVERSATION if self.cur_key == "default" else None)

    def set_conv_url(self, url: str | None) -> None:
        convs = dict(self.state["conversations"] or {})
        if url:
            convs[self.cur_key] = url
        else:
            convs.pop(self.cur_key, None)
        self.state["conversations"] = convs
        self.state.save()

    def persona(self) -> str:
        try:
            return PERSONA_FILE.read_text(encoding="utf-8").strip()
        except OSError:
            return ""

    # -- ChatGPT side --------------------------------------------------
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
        conv = self.conv_url()
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
                self.set_conv_url(None)
                notes.append("_(My previous ChatGPT conversation was unavailable, so I started a new one.)_")
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
        log.info("Enter did not send; trying send button")
        for sel in SEL.SEND_BUTTON_SELECTORS:
            try:
                b = page.locator(sel).first
                if b.count() and b.is_visible() and b.is_enabled():
                    b.click()
                    if self._sent(loc, snap0, 8):
                        return
            except Exception:
                continue
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
                if (snap["hasActions"] and stable >= 2.0) or (stable >= 25 and not snap.get("streaming")) or stable >= 90:
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
        if re.match(SEL.CONVERSATION_URL_RE, url) and url != self.conv_url():
            self.set_conv_url(url)
            log.info("conversation url stored: %s", url)

    # -- processing ----------------------------------------------------
    def process(self, line: int, m: dict, key: str) -> None:
        self.cur_key = str(m.get("conversation_key") or "default")
        text = str(m.get("text") or "").strip()
        if not self.conv_url() and self.persona():
            title = str(m.get("conversation_title") or "Jinx Slack bridge")
            text = self.persona().replace("{title}", title) + "\n\n---\n\n" + text
        infl = self.state["inflight"] or {}
        if infl.get("key") != key:
            infl = {"key": key, "line": line, "phase": "picked", "started": now_iso_utc()}
            self.state["inflight"] = infl
            self.state.save()
        # crash after ChatGPT answered but before cursor moved -> never double-post
        if infl.get("phase") == "replying":
            if not (RESULTS_DIR / m["_file"]).exists():
                self.write_result(m, "answered", infl.get("answer", ""))
            return self.finish(line, m, key)

        self.browser.ensure()
        notes = self.open_conversation()
        self.mark_ok()
        snap0 = self.browser.snapshot()
        resume = infl.get("phase") == "submitted" and norm(snap0.get("lastUserText", "")).startswith(norm(text)[:40])
        if resume:
            log.info("resuming %s: prompt already in ChatGPT, waiting for its answer", key)
            snap0 = {"turns": 0, "answersCount": 0}
        else:
            log.info("sending %s (%d chars) to ChatGPT", key, len(text))
            self.send(text, snap0)
            infl["phase"] = "submitted"
            self.state["inflight"] = infl
            self.state.save()
        try:
            answer, complete = self.wait_answer(text, snap0)
        except ContextFull:
            if infl.get("context_reset"):
                raise
            log.warning("conversation full; starting a new ChatGPT conversation")
            self.set_conv_url(None)
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
            notes.append("_(My ChatGPT conversation got too long, so I started a new one.)_")
            answer, complete = self.wait_answer(text, snap0)
        self.remember_conversation()
        if not answer:
            raise RuntimeError("empty answer")
        if not complete:
            notes.append("_(ChatGPT was still writing after %d min; this answer may be cut off.)_" % int(ANSWER_TIMEOUT // 60))
        final = answer + ("\n\n" + "\n".join(notes) if notes else "")
        infl.update({"phase": "replying", "answer": final, "answer_sha": sha(final.strip())})
        self.state["inflight"] = infl
        self.state.save()
        self.write_result(m, "answered", final)
        self.finish(line, m, key)

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
                infl["phase"] = "picked"  # ChatGPT errored on this turn -> resend next time
                self.state["inflight"] = infl
            self.state.save()
            log.warning("attempt %d/%d for %s failed: %s: %s", n, MAX_ATTEMPTS, key, type(exc).__name__, str(exc)[:300])
            if n >= MAX_ATTEMPTS:
                why = "ChatGPT is busy" if isinstance(exc, Busy) else f"{type(exc).__name__}: {str(exc)[:160]}"
                self.write_result(m, "failed", f"no answer after {n} tries ({why})")
                self.finish(line, m, key)
            else:
                self.next_try_at = time.time() + RETRY_BACKOFF[min(n - 1, len(RETRY_BACKOFF) - 1)]
                # a fresh browser often fixes a wedged page
                self.browser.stop()

    def check_login_state(self) -> str:
        self.browser.ensure()
        page = self.browser.page
        page.goto(self.conv_url() or SEL.BASE_URL, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
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

    def login_flow(self, display: str) -> None:
        was_blocked = bool(self.state["blocked"]) and (self.state["blocked"] or {}).get("kind") != "rate_limit"
        log.info("sign-in requested on display %s (blocked=%s)", display, was_blocked)
        self.browser.stop()
        if not self.display_ok(display):
            self.login_status("error", "The bridge could not open a window on your desktop (display access denied).")
            log.warning("cannot open display %s", display)
            return
        outcome = "closed"
        try:
            self.browser.start(display=display)
            page = self.browser.page
            page.goto(self.conv_url() or SEL.BASE_URL, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
            try:
                page.bring_to_front()
            except Exception:
                pass
            self.login_status("open", "ChatGPT window is open on your desktop.")
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
        for d in (PENDING_DIR, RESULTS_DIR, DONE_DIR):
            d.mkdir(parents=True, exist_ok=True)
        self.heartbeat()
        log.info("bridge running: jobs=%s profile=%s pinned=%s", JOBS_DIR, PROFILE, bool(PINNED_CONVERSATION))
        if STARTUP_CHECK:
            if self.state["inflight"] or self.pending():
                log.info("startup: queued work present; checking login while processing")
            self.recheck()
        while not STOP:
            try:
                self.heartbeat()
                disp = self.take_login_request()
                if disp:
                    self.login_flow(disp)
                    continue
                blocked = self.state["blocked"]
                queue = self.pending()
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
                    infl = self.state["inflight"] or {}
                    if infl.get("key") and infl.get("key") not in {k for _, _, k in queue}:
                        self.state["inflight"] = None
                        self.state.save()
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
        q = Bridge.pending(b)
        print(json.dumps({k: v for k, v in s.d.items() if k not in ("handled",)} | {"pending": [(m.get("_file"), str(m.get("text"))[:80]) for _, m, _ in q]}, indent=2, ensure_ascii=False))
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
