# ChatGPT End Watch — Android overlay (Kotlin)

Floating **SYSTEM_ALERT_WINDOW** Start / Stop panel.

Package: `io.nullink.jinxendwatch`

| Button | Request |
|--------|---------|
| Start | `POST {base}/api/chatgpt-end-watch/start` |
| Stop | `POST {base}/api/chatgpt-end-watch/stop` |
| Status | `GET {base}/api/chatgpt-end-watch/status` |

Auth: `Authorization: Bearer <token>` or `X-Control-Token` (same token as VPS `CONTROL_TOKEN` / chatgpt bearer file).

Default base: `https://nullink.216.158.238.236.sslip.io` (Caddy proxies `/api/chatgpt-end-watch/*` → `127.0.0.1:8788`).

## Build

```bash
cd /workspace/forge/nullink/chatgpt-end-watch/android
echo "sdk.dir=/workspace/android-sdk" > local.properties
./gradlew :app:assembleDebug
# APK: app/build/outputs/apk/debug/app-debug.apk
```

## Smoke

1. Grant overlay permission → show floating panel
2. Start → status `armed/active=true`
3. Stop → `armed=false`
4. Backend `The End` path also disarms
