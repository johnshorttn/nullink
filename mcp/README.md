# Nullink ChatGPT / MCP adapter

Separate **stdio MCP** process. Nullink core stays REST + cookie UI; this adapter
talks HTTPS Bearer to Nullink and is **not** part of `nullink.service`.

## Layout

| Path | Role |
|------|------|
| `/workspace/nullink-chatgpt-build/mcp_server.py` | Source on the box |
| `/workspace/chat-bridge/mcp/mcp_server.py` | Mirror next to chat-bridge |
| `/opt/nullink/mcp/mcp_server.py` | On VPS (deployed copy) |

## Mint a scoped token (admin cookie)

1. Log into https://nullink.216.158.238.236.sslip.io with the OTP PIN (sets `morc_session`).
2. Create a ChatGPT-scoped token:

```bash
curl -sS -X POST 'https://nullink.216.158.238.236.sslip.io/api/auth/tokens' \
  -H 'Content-Type: application/json' \
  -b 'morc_session=YOUR_COOKIE' \
  -d '{
    "name": "chatgpt-mcp",
    "scopes": [
      "health:read",
      "sessions:read",
      "messages:read",
      "messages:write",
      "ping:read"
    ],
    "sessions": ["chatgpt"],
    "expires_in": 2592000
  }'
```

Plaintext `token` (`nlk_…`) is returned **once**. Store it as `NULLINK_TOKEN`.

List / revoke (metadata only on list):

```bash
curl -sS -b 'morc_session=…' https://nullink.216.158.238.236.sslip.io/api/auth/tokens
curl -sS -X DELETE -b 'morc_session=…' \
  https://nullink.216.158.238.236.sslip.io/api/auth/tokens/TOKEN_ID
```

## Run the MCP adapter (stdio)

```bash
export NULLINK_URL='https://nullink.216.158.238.236.sslip.io'
export NULLINK_TOKEN='nlk_…'
python3 /opt/nullink/mcp/mcp_server.py
# or: python3 /workspace/nullink-chatgpt-build/mcp_server.py
```

Speaks JSON-RPC MCP over stdin/stdout. Tools:

- `nullink_health`
- `nullink_sessions`
- `nullink_pull_messages`
- `nullink_send_message`
- `nullink_watch_once`
- `nullink_ping`

## Curl smoke (Bearer) before MCP

```bash
BASE=https://nullink.216.158.238.236.sslip.io
AUTH="Authorization: Bearer $NULLINK_TOKEN"

curl -sS "$BASE/health"
curl -sS -H "$AUTH" "$BASE/api/me"
curl -sS -H "$AUTH" "$BASE/api/sessions"
curl -sS -H "$AUTH" "$BASE/api/messages?session=chatgpt&after=0&limit=10"
curl -sS -H "$AUTH" "$BASE/api/messages?session=morc&after=0"   # expect 403
curl -sS -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"text":"hello from bearer","session_id":"chatgpt"}' "$BASE/api/messages"
curl -sS -H "$AUTH" "$BASE/api/ping?change=0"
```

## Locks

- Do **not** run this inside Nullink core / convert Nullink into MCP.
- Keep `/api/ping` as the wake detector (no long-lived `/api/watch`).
- Human UI continues to use `morc_session` OTP cookie.
