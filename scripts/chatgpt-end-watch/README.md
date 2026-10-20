# ChatGPT End Watch (Nullink)

Watches Nullink session `chatgpt` via Bearer REST. While **armed**:

| Condition | Action |
|-----------|--------|
| Idle (`IDLE_SECS`=120) or rate-limit phrase, last text **lacks** exact `The End` | `POST /api/messages` `{"session_id":"chatgpt","text":"keep building"}` |
| Last text contains exact **`The End`** | **Disarm** (`armed=false`) + notify JSONL/webhook/stdout; **never** keep-building; polls no-op until Start |

**Start/Stop UI:** Kotlin Android `SYSTEM_ALERT_WINDOW` floating overlay — [`android/`](android/).
Companion control API on VPS (`control_api.py`, port **8788**), Caddy: `/api/chatgpt-end-watch/*`.

## Paths

| Where | Path |
|-------|------|
| Box SoT | `/workspace/forge/nullink/chatgpt-end-watch/` |
| Android scaffold | `/workspace/forge/nullink/chatgpt-end-watch/android` (see `SCAFFOLD-PATH.txt`) |
| Debug APK | `android/dist/chatgpt-end-watch-debug.apk` |
| VPS scripts | `/opt/nullink/scripts/chatgpt-end-watch/` |
| State | `/opt/nullink/data/chatgpt-end-watch/state.json` |
| Alerts | `/opt/nullink/data/chatgpt-end-watch/alerts.jsonl` |
| Token | `/opt/nullink/secrets/NULLINK_TOKEN_chatgpt.txt` (mode 600; never logged) |

## systemd

```bash
sudo systemctl enable --now chatgpt-end-watch.service chatgpt-end-watch-control.service
sudo systemctl status chatgpt-end-watch.service chatgpt-end-watch-control.service
sudo systemctl stop chatgpt-end-watch.service chatgpt-end-watch-control.service
```

Watcher uses `Restart=always` polling loop (`--no-control`; control is the sibling unit).

## Control API (Android)

```
GET  /api/chatgpt-end-watch/health
GET  /api/chatgpt-end-watch/status
POST /api/chatgpt-end-watch/start   # arm
POST /api/chatgpt-end-watch/stop    # disarm
```

Auth (non-loopback): `Authorization: Bearer <token>` or `X-Control-Token`
(token = `CONTROL_TOKEN` or chatgpt bearer file). Loopback may skip auth (`CONTROL_ALLOW_LOOPBACK_NOAUTH=1`).

Public base: `https://nullink.216.158.238.236.sslip.io`

## Rate-limit phrases

`You've hit the free plan limit`, `You've reached the limit`, `rate limit`, `Rate limit`, `Too many requests`, `try again later`, `Try again later`, `usage limit`, `Usage limit`, `temporarily rate-limited`, `come back later`.

## Smoke

```bash
# A) no The End → would POST keep building
python3 chatgpt_end_watch.py --once --force-stop --dry-run --fixture-text "still working" --no-token --no-control \
  --state-file /tmp/a.json --alert-log /tmp/a.jsonl

# B) The End → disarm + notify
python3 chatgpt_end_watch.py --once --force-stop --dry-run --fixture-text "Done. The End" --no-token --no-control \
  --state-file /tmp/b.json --alert-log /tmp/b.jsonl

# Control Start/Stop
curl -sS -X POST http://127.0.0.1:8788/start
curl -sS http://127.0.0.1:8788/status
curl -sS -X POST http://127.0.0.1:8788/stop
```

## Android

See [`android/README.md`](android/README.md). `assembleDebug` → APK under `android/dist/`.
