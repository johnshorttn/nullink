"""Unit checks that need no browser: .last-handled guard, replay-safe reply, classify()."""
import json, os, sys, tempfile, importlib
from pathlib import Path
T = Path(tempfile.mkdtemp(prefix="dsunit-"))
(T / "data").mkdir()
import shutil; shutil.copy("/opt/nullink/reply.py", T / "reply.py")
os.environ.update(NL_ROOT=str(T), NL_SESSION="deepseek-test", NL_LAST_HANDLED=str(T / "data/.last-handled"),
                  NL_BRIDGE_SESSIONS="deepseek,deepseek-test", DS_STATE_DIR=str(T / "state"), DS_LOG_DIR=str(T / "logs"))
sys.path.insert(0, "/opt/nullink/bridges/deepseek")
w = importlib.import_module("worker")
M = T / "data/messages.jsonl"
def write(rows): M.write_text("".join(json.dumps(r) + "\n" for r in rows))
ok = lambda c, msg: print(("PASS " if c else "FAIL ") + msg)

b = w.Bridge()
# 1) .last-handled advances when other rooms are all handled
(T / "data/.last-handled").write_text("2026-10-06T01:00:00+00:00\n")
write([{"role": "user", "text": "old morc", "ts": "2026-10-06T00:30:00+00:00", "session_id": "morc"},
       {"role": "user", "text": "ds q", "ts": "2026-10-06T02:00:00+00:00", "session_id": "deepseek-test"}])
b.advance_last_handled("2026-10-06T02:00:00+00:00")
ok((T / "data/.last-handled").read_text().strip() == "2026-10-06T02:00:00+00:00", "advance when other rooms quiet")
# 2) does NOT advance past an unhandled message in another room
(T / "data/.last-handled").write_text("2026-10-06T01:00:00+00:00\n")
write([{"role": "user", "text": "new morc", "ts": "2026-10-06T01:30:00+00:00", "session_id": "morc"},
       {"role": "user", "text": "ds q", "ts": "2026-10-06T02:00:00+00:00", "session_id": "deepseek-test"}])
b.advance_last_handled("2026-10-06T02:00:00+00:00")
ok((T / "data/.last-handled").read_text().strip() == "2026-10-06T01:00:00+00:00", "no advance when another room has unhandled msg")
# 3) crash after posting, before cursor moved -> no double post
write([{"role": "user", "text": "ds q", "ts": "2026-10-06T02:00:00+00:00", "session_id": "deepseek-test"}])
b.state["cursor_line"] = 0; b.state["cursor_ts"] = ""
line, m, key = b.pending()[0]
b.post("the answer")
b.state["inflight"] = {"key": key, "line": line, "phase": "replying", "answer": "the answer", "answer_sha": w.sha("the answer")}
b.process(line, m, key)
n = sum(1 for l in M.read_text().splitlines() if json.loads(l)["role"] == "assistant")
ok(n == 1 and not b.pending(), "replying-phase recovery does not double-post (assistant msgs=%d)" % n)
# 4) crash before posting -> posts exactly once
write([{"role": "user", "text": "ds q2", "ts": "2026-10-06T03:00:00+00:00", "session_id": "deepseek-test"}])
b.state["cursor_line"] = 0; b.state["cursor_ts"] = ""; b.state["handled"] = []
line, m, key = b.pending()[0]
b.state["inflight"] = {"key": key, "line": line, "phase": "replying", "answer": "answer2", "answer_sha": w.sha("answer2")}
b.process(line, m, key)
n = sum(1 for l in M.read_text().splitlines() if json.loads(l)["role"] == "assistant")
ok(n == 1 and not b.pending(), "replying-phase recovery posts once when missing")
# 5) classify
C = w.classify
ok(C({"url": "https://chat.deepseek.com/sign_in", "iframes": []}) == "logged_out", "classify sign_in url")
ok(C({"url": "https://chat.deepseek.com/", "iframes": ["https://challenges.cloudflare.com/x"], "hasInput": True}) == "captcha", "classify cloudflare iframe")
ok(C({"url": "https://chat.deepseek.com/", "title": "Just a moment...", "iframes": []}) == "captcha", "classify CF title")
ok(C({"url": "https://chat.deepseek.com/a/chat/s/x", "iframes": [], "hasInput": True}) == "ok", "classify ok")
ok(C({"url": "https://chat.deepseek.com/", "iframes": [], "hasInput": False}) == "loading", "classify loading")
ok(C({"url": "https://chat.deepseek.com/sign_in", "iframes": [], "body": "Enter verification code"}) == "logged_out", "sms 'verification code' is not a captcha")
ok(C({"url": "https://chat.deepseek.com/", "title": "Human Verification", "iframes": [], "body": "Let's confirm you are human"}) == "captcha", "classify DeepSeek 'Human Verification' page")
# 6) one notice per outage even if the block kind flips logged_out <-> captcha
write([])
b.state["notice"] = None
for k in ["logged_out", "captcha", "logged_out", "unrecognized", "captcha"]:
    b.block(k)
n = sum(1 for l in M.read_text().splitlines() if "DeepSeek bridge" in l)
ok(n == 1, "flipping block kinds posts one notice (got %d)" % n)
b.mark_ok()
n2 = sum(1 for l in M.read_text().splitlines() if "signed in" in l)
b.block("logged_out")
n3 = sum(1 for l in M.read_text().splitlines() if "needs you to sign in" in l)
ok(n2 == 1 and n3 == 2, "after recovery a new outage notifies again (connected=%d, notices=%d)" % (n2, n3))
shutil.rmtree(T)
