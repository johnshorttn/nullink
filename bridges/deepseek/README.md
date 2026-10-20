# Nullink ⇄ DeepSeek web bridge

Answers the Nullink **DeepSeek** room (`session_id=deepseek`) with the real DeepSeek web chat
(chat.deepseek.com) by driving a signed-in Chromium profile with Playwright. No API key.
Unofficial: it can break whenever DeepSeek changes its site, and DeepSeek's terms may not allow it.

| What | Where |
|---|---|
| Service | `nullink-deepseek-bridge.service` (user `morc`, MemoryMax 1400M, OOMScoreAdjust 700) |
| Worker | `/opt/nullink/bridges/deepseek/worker.py` (`run` / `status` / `check`) |
| **Selectors (patch here)** | `/opt/nullink/bridges/deepseek/ds_selectors.py` |
| In-page JS (extraction / md converter) | `page_js.py` |
| Browser profile (cookies; never the password) | `profile/` (mode 700, morc) |
| State: cursor, handled keys, conversation URL, notice/blocked | `state/state.json` |
| Log (rotating 2 MB × 5) | `logs/worker.log` (+ `journalctl -u nullink-deepseek-bridge`) |
| Sign-in hand-off | `deepseek-signin.sh` + `/home/desk/Desktop/Sign in to DeepSeek.desktop`, `login-req/` (desk:morc 2770) |
| Overrides | `bridge.env` |
| Tests | `tests/` (mock DeepSeek page, logged-out test, sign-in chain test, unit tests) |

## How it works
1. Polls `/opt/nullink/data/messages.jsonl` every 2 s for new `role=user` lines in session `deepseek`
   (cursor = line number + ts floor + last 500 message hashes, so restarts never re-answer; history before
   the first start is ignored).
2. One message at a time: opens the stored DeepSeek conversation (`conversation_url` in state; first
   message starts a new chat and its `/a/chat/s/<uuid>` URL is saved), types the text, presses Enter,
   waits until the answer stops changing and the copy/regenerate row appears, then posts the answer with
   `reply.py --session deepseek`. Markdown is taken from DeepSeek's own React `markdown` prop when it
   matches the rendered text, otherwise rebuilt from HTML (code blocks with language, lists, tables,
   links, KaTeX). DeepThink reasoning is excluded.
3. Chromium runs headful on a private hidden Xvfb display (no "HeadlessChrome" UA, no stealth tricks)
   and is closed after `DS_IDLE_CLOSE_SEC` idle (bridge.env: 1 h).
4. Signed out / verification page / unrecognised page / usage limit → ONE notice in the room, queue
   held, no loops. Busy/timeouts → retried 3× (60 s, 180 s), then one "couldn't answer" note.
   Captchas are never solved or bypassed: on a verification page ("Human Verification / confirm you are
   human / security check", Cloudflare/Turnstile/GeeTest iframes) the bridge only waits passively 45 s in
   case the site's own check finishes, then reports it. Signed-out / verification / unrecognised share
   ONE notice per outage; after recovery it posts "✅ … signed in" once.
5. Crash-safe: an `inflight` record prevents double replies (checked against messages.jsonl) and avoids
   re-sending a prompt DeepSeek already received.

## Sign-in (John)
Nullink → **Desktop** app → double-click **"Sign in to DeepSeek"** on the XFCE desktop → a Chromium
window titled *DeepSeek sign-in (Nullink bridge)* opens (shows "Chrome is being controlled by automated
test software" – that's expected) → sign in → it closes by itself ~8 s after the chat page appears and
the room gets "✅ DeepSeek bridge: signed in". The icon grants the bridge's user (`morc`) access to the
desktop display only for that window (`xhost -SI:localuser:morc` is run afterwards).
If already signed in, the icon opens the window for up to 10 min (e.g. to toggle DeepThink/Search,
which the bridge leaves as-is); queued messages wait until it is closed.

## Operate
```
sudo systemctl status nullink-deepseek-bridge
sudo systemctl stop nullink-deepseek-bridge        # stop now
sudo systemctl disable --now nullink-deepseek-bridge   # stop + don't start at boot
sudo systemctl restart nullink-deepseek-bridge     # after editing ds_selectors.py
/opt/nullink/bridges/deepseek/venv/bin/python /opt/nullink/bridges/deepseek/worker.py status
tail -f /opt/nullink/bridges/deepseek/logs/worker.log
```
Start a fresh DeepSeek conversation: stop the service, set `"conversation_url": null` in
`state/state.json`, start it. Forget the DeepSeek login: stop the service and delete `profile/`.

Server/UI changes made for this (backups `*.bak-deepseek-20261006101512`): see `nullink-server-ui.patch`.

## Interaction with Morc's inbox routine
`server.py` has `BRIDGE_SESSIONS = {"deepseek"}`: posts in that room no longer write `pending.notify`,
fire the webhook, or count for `/api/ping`. The worker also moves `data/.last-handled` forward to a
picked-up DeepSeek message's ts, but only when no other room has a newer unhandled user message.
