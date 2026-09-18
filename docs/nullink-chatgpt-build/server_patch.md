Nullink Server Patch — Bearer + Agent API
1. Add Bearer middleware

Add middleware before protected /api/* handlers.

Pseudo-request flow:

Authorization header?
    |
    +-- Bearer token -> validate token
    |
    +-- absent -> existing morc_session authentication
    |
    +-- invalid -> 401

The middleware should attach:

request.auth = {
    "type": "bearer",
    "token_id": "...",
    "scopes": [...],
    "sessions": [...]
}

or, for cookie authentication:

request.auth = {
    "type": "session",
    "session_id": "..."
}

Do not duplicate authentication logic inside every endpoint.

2. Add token storage

Create a token table/store containing:

id
token_hash
token_prefix
name
scopes
sessions
created_at
expires_at
revoked_at
last_used_at

Use the application's existing database/persistence layer.

Do not introduce a second unrelated persistence system solely for
tokens.

3. Add token creation endpoint
POST /api/auth/tokens

Authentication:

existing administrator/human authentication

Request:

{
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
}

Response:

{
  "ok": true,
  "token_id": "...",
  "token": "nlk_...",
  "expires_at": "..."
}

Return plaintext token once.

4. Add token listing
GET /api/auth/tokens

Admin only.

Never return plaintext tokens.

5. Add token revocation
DELETE /api/auth/tokens/{token_id}

Admin only.

Set:

revoked_at = current_time

Do not delete immediately if audit history is useful.

6. Protect /api/sessions

Require:

sessions:read

For Bearer callers, filter the returned sessions to the token's
allowed session IDs.

Example:

token.sessions = ["chatgpt"]

must not return:

morc
ops
grok-worker
7. Protect GET /api/messages

Require:

messages:read

Validate:

requested session ∈ token.sessions

Otherwise:

HTTP 403

Do not return messages from unauthorized sessions.

8. Protect POST /api/messages

Require:

messages:write

Validate:

body.session_id ∈ token.sessions

Otherwise:

HTTP 403

Existing request body remains valid:

{
  "text": "...",
  "session_id": "chatgpt"
}

No UI rewrite required.

9. Normalize GET /api/messages

Current contract is accepted by the compatibility layer.

Preferred response:

{
  "messages": [
    {
      "id": 123,
      "session_id": "chatgpt",
      "role": "user",
      "text": "hello",
      "created_at": "2026-09-17T23:00:00Z"
    }
  ],
  "next_after": 123,
  "has_more": false
}

Requirements:

id:
    integer
    monotonically increasing

next_after:
    highest returned message ID, or supplied after when empty

has_more:
    true when more messages remain beyond this page

Keep:

?session=<id>&after=<id>

as the compatibility contract.

Add:

&limit=<1..100>
10. Keep /api/ping

Do not replace it.

Existing:

GET /api/ping?change=0
GET /api/ping?change=1

remains the lightweight wake/change detector.

Bearer callers require:

ping:read
11. Add MCP adapter separately

Do NOT add MCP logic to the Nullink core.

Run:

mcp_server.py

as a separate process.

It communicates with Nullink using:

HTTPS REST
Authorization: Bearer ...

The MCP adapter exposes:

nullink_health
nullink_sessions
nullink_pull_messages
nullink_send_message
nullink_watch_once
nullink_ping

Nullink remains the authoritative state store.

12. No long-lived watch endpoint

Do not add:

/api/watch

that holds an HTTP request open.

Use:

/api/ping

for cheap wake detection.

Use:

/api/messages?after=N

for actual retrieval.

The MCP:

nullink_watch_once

tool is simply a deterministic pull operation.

13. Preserve the existing UI

No changes required to:

Guacamole
XFCE
Redroid
Aurora
Files
session memory
split view
vault
mobile compose
Apps iframe system

The UI continues using:

morc_session

Agents use:

Bearer
14. Preserve the Python connector

Existing:

nullink-chatgpt-connect.py

continues working through:

OTP -> morc_session

A later version can optionally gain:

NULLINK_TOKEN

support.

Do not make the token migration a prerequisite for existing clients.

15. Testing checklist

Before enabling MCP:

GET /health
    -> 200

create token
    -> token returned once

GET /api/me with Bearer
    -> 200

GET /api/sessions with chatgpt-scoped token
    -> chatgpt visible

GET /api/messages?session=chatgpt&after=0
    -> 200

GET /api/messages?session=morc&after=0
    -> 403

POST /api/messages session_id=chatgpt
    -> 200/201

POST /api/messages session_id=morc
    -> 403

revoke token
    -> 204/200

old token after revoke
    -> 401

expired token
    -> 401

MCP tools/list
    -> six tools

MCP tools/call nullink_health
    -> successful response

MCP tools/call nullink_send_message
    -> message appears in Nullink UI

Nullink UI -> message
    -> MCP pull_messages sees it
One important correction to the original plan

I would not call the MCP adapter "the Nullink agent interface."

I'd call it:

One agent interface to Nullink.

That's a subtle distinction, but it protects the architecture.

Nullink should remain:

             NULLINK
                │
        ┌───────┼────────┐
        │       │        │
       UI      REST     Files/etc.
                        │
                    state/memory
                        │
              ┌─────────┴─────────┐
              │                   │
         MCP adapter          future adapters
              │
        scoped agents

The REST API is the stable contract. MCP is an adapter over it.

What I'd actually deploy first

In order:

1. Add Bearer middleware + token storage.
2. Create a chatgpt-scoped token.
3. Test REST manually with curl.
4. Normalize /api/messages.
5. Drop mcp_server.py onto the VPS/client host.
6. Connect an MCP-capable agent.
7. Only then consider metadata such as correlation_id, reply_to, message_type, etc.

That gives you a working path of:

Agent
  ↓
MCP stdio
  ↓
Bearer
  ↓
Nullink REST
  ↓
existing message/session system
  ↓
Nullink UI

without rewriting the UI, replacing the current cookie system, or turning Nullink into an MCP server.
