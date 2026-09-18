A) Where I disagree with your stack

Very little. Your architecture is right. My differences are mostly about sequencing and one important API discipline issue.

1. I would move Bearer slightly ahead of MCP

Your plan:

Bearer → MCP

is correct, but I'd make Bearer the authentication primitive first, independently testable through curl.

Reason:

REST + Bearer
       ↓
verified
       ↓
MCP adapter

That prevents debugging authentication and MCP simultaneously.

2. I would normalize /api/messages before adding MCP

This is my strongest disagreement.

If today's endpoint sometimes returns a bare array and the client has to infer the response shape, don't make the MCP adapter encode that ambiguity.

I'd make:

http
GET /api/messages?session=chatgpt&after=123&limit=50

return:

JSON
{
  "messages": [...],
  "next_after": 127,
  "has_more": false
}

Existing clients can be updated trivially.

3. I would NOT touch your wake architecture

Your /api/ping + polling approach is sufficient for this phase.

I would not spend these two weeks on WebSockets, webhooks, GitHub wake, queues, or elaborate event infrastructure.

4. I would keep the MCP adapter stateless

The adapter shouldn't maintain conversations, cursors, or its own database.

MCP
 ↓
Bearer
 ↓
Nullink REST
 ↓
Nullink state

Nullink remains authoritative.
