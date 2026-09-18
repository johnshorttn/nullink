Morc, given the architecture lock and the current wake reality, I’d optimize for reliable agent-to-agent work, not more UI features. The key is making Nullink a dependable message/work coordination layer while leaving the UI untouched.

1. Top 5 improvements for the next 2 weeks
Rank	Improvement	Why	Smallest shippable slice	Risk
1	Scoped Bearer auth	Removes the PIN/cookie bottleneck and enables reliable agents	/api/tokens admin-side creation/revocation + Authorization: Bearer <token> middleware; scope token to sessions/actions	Medium — credential leakage becomes the main concern
2	Agent-grade message API	Agents need deterministic pull/send/cursor semantics	Standardize pull_messages(session, after, limit) response as {messages, next_after, has_more}; make IDs strictly monotonic	Low
3	Reliable wake/claim loop	Agents need to know something changed without hammering the inbox	Keep `/api/ping?change=0	1; add watch_once(session, after, timeout=0)` semantics that returns immediately; document 15–30s watcher as canonical
4	MCP adapter	Gives MCP-capable agents a clean interface without changing Nullink itself	Separate adapter process/service translating MCP calls → existing REST endpoints	Medium
5	Message/work metadata	Plain text eventually becomes limiting for multi-agent work	Add optional fields such as from, to/session, message_type, correlation_id, reply_to, created_at; preserve existing text clients	Medium
The sequence I'd actually ship
Week 1
──────
Bearer tokens
     ↓
normalized message/cursor API
     ↓
reliable wake/watch semantics

Week 2
──────
MCP adapter
     ↓
message metadata/correlation

I would not wait for the metadata system before shipping the first four.

2. Concrete Bearer + MCP design

I'd keep the existing REST API as the source of truth.

Authentication
http
Authorization: Bearer nlk_xxxxxxxxx

Token should have:

JSON
{
  "scope": ["messages:read", "messages:write"],
  "sessions": ["chatgpt"],
  "expires_at": "..."
}

For example, a ChatGPT integration token should not automatically have access to morc, ops, or every worker.

I'd support:

create

revoke

expiration

session restrictions

read/write restrictions

Don't expose raw token values after creation.

MCP tools
nullink_health

No parameters.

Returns:

JSON
{
  "ok": true,
  "service": "nullink"
}
nullink_sessions

Parameters:

JSON
{
  "include_status": true
}

Returns the sessions the token is authorized to see.

nullink_pull_messages

Parameters:

JSON
{
  "session": "chatgpt",
  "after": 0,
  "limit": 50
}

Returns:

JSON
{
  "messages": [],
  "next_after": 123,
  "has_more": false
}

This should be the core primitive.

nullink_send_message

Parameters:

JSON
{
  "session": "chatgpt",
  "text": "Hello"
}

Optional later:

JSON
{
  "correlation_id": "...",
  "reply_to": 123
}
nullink_watch_once

Parameters:

JSON
{
  "session": "chatgpt",
  "after": 123
}

Returns immediately:

JSON
{
  "messages": [],
  "next_after": 123,
  "changed": false
}

I would not make MCP itself hold a long-lived connection waiting for a message. The existing /api/ping watcher remains the reliable wake mechanism.

nullink_ping

Parameters:

JSON
{
  "change": 0
}

Returns whether the bridge has changed.

This gives agents a cheap wake check without pulling the entire inbox.

3. One API change I'd make now

Normalize message retrieval.

Instead of making clients guess whether the response is:

JSON
[ ... ]

or:

JSON
{"messages":[ ... ]}

make it permanently:

JSON
{
  "messages": [
    {
      "id": 124,
      "session_id": "chatgpt",
      "role": "user",
      "text": "..."
    }
  ],
  "next_after": 124,
  "has_more": false
}

That makes every client—including MCP—much simpler.

4. What I would NOT build
❌ Don't convert Nullink into MCP

Your architecture lock is correct here.

MCP should be an adapter, not the underlying architecture.

                 ┌── Web UI
                 │
Nullink core ────┼── REST API
                 │
                 └── MCP adapter
                         │
                    MCP agents
❌ Don't build another authentication mechanism around PINs

Don't try to make Custom GPT cookie persistence cleverer.

PIN = human bootstrap authentication.

Bearer = machine/agent authentication.

Keep those roles separate.

❌ Don't build long-polling/WebSocket infrastructure yet

Your /api/ping watcher already gives you a workable wake primitive.

Don't spend the two-week window replacing something that is currently functional.

❌ Don't build a giant task/job queue yet

First establish:

send → wake → pull → process → respond

Only add jobs/claims/retries when actual workflows demonstrate the need.

❌ Don't make the ChatGPT iframe pretend to be an autonomous agent

The distinction you've established matters:

ChatGPT roster slot ≠ live bot.

Keep it that way. The MCP/Bearer adapter can provide machine access without confusing the UI's role.

❌ Don't add 30 MCP tools

Five or six excellent primitives are preferable to a giant abstraction layer.

The initial MCP surface should essentially be:

health
sessions
pull_messages
send_message
watch_once
ping

That is enough to prove the architecture.

The end-state I'd aim for
                     NULLINK
                ┌───────────────┐
                │     Core      │
                │ messages      │
                │ sessions      │
                │ wake state    │
                └───────┬───────┘
                        │
          ┌─────────────┼─────────────┐
          │             │             │
       Web UI       REST API      MCP Adapter
          │             │             │
      Humans       scripts/apps     Agents
                        │             │
                    Bearer       scoped Bearer

The important architectural principle is:

Nullink owns state and transport; adapters expose it to whatever agent/interface needs it.

That gives John a path from today's PIN + Python connector to genuine agent interoperability without throwing away the UI or rewriting the existing API.