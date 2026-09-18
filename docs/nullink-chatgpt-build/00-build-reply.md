Morc — head-to-head first, then the drop-in artifacts.

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

B1 — openapi.yaml

This is deliberately small. I included Bearer as the preferred security mechanism and the existing cookie as legacy compatibility.

Once Bearer is deployed, this becomes genuinely useful to Actions. Cookie-only Actions remain inherently unreliable because the Action runtime may not retain morc_session.

openapi.yaml — Nullink minimal Actions API
openapi: 3.0.3

info:
  title: Nullink API
  version: 1.1.0
  description: Minimal agent/message API for the private Nullink workspace.

servers:
  - url: https://nullink.216.158.238.236.sslip.io

security:
  - bearerAuth: []
  - nullinkSessionCookie: []

paths:

  /health:
    get:
      operationId: health
      summary: Check Nullink health
      security: []
      responses:
        "200":
          description: Nullink health
          content:
            application/json:
              schema:
                type: object
                properties:
                  ok:
                    type: boolean
                  service:
                    type: string

  /api/me:
    get:
      operationId: whoami
      summary: Return the authenticated identity
      responses:
        "200":
          description: Authenticated identity
          content:
            application/json:
              schema:
                type: object
                additionalProperties: true
        "401":
          $ref: "#/components/responses/Unauthorized"

  /api/sessions:
    get:
      operationId: listSessions
      summary: List sessions visible to the authenticated identity
      responses:
        "200":
          description: Session list
          content:
            application/json:
              schema:
                type: object
                additionalProperties: true
        "401":
          $ref: "#/components/responses/Unauthorized"

  /api/messages:
    get:
      operationId: pullMessages
      summary: Pull messages after a message ID
      parameters:
        - name: session
          in: query
          required: true
          schema:
            type: string
          description: Nullink session/roster slot.
        - name: after
          in: query
          required: false
          schema:
            type: integer
            minimum: 0
            default: 0
        - name: limit
          in: query
          required: false
          schema:
            type: integer
            minimum: 1
            maximum: 100
            default: 50
      responses:
        "200":
          description: Messages
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/MessagePage"
        "401":
          $ref: "#/components/responses/Unauthorized"
        "403":
          $ref: "#/components/responses/Forbidden"

    post:
      operationId: sendMessage
      summary: Send a message to a Nullink session
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "#/components/schemas/SendMessage"
      responses:
        "200":
          description: Message accepted
          content:
            application/json:
              schema:
                type: object
                additionalProperties: true
        "201":
          description: Message created
          content:
            application/json:
              schema:
                type: object
                additionalProperties: true
        "401":
          $ref: "#/components/responses/Unauthorized"
        "403":
          $ref: "#/components/responses/Forbidden"

  /api/ping:
    get:
      operationId: ping
      summary: Check the Nullink change detector
      parameters:
        - name: change
          in: query
          required: false
          schema:
            type: integer
            enum: [0, 1]
            default: 0
      responses:
        "200":
          description: Change detector state
          content:
            application/json:
              schema:
                type: object
                additionalProperties: true
        "401":
          $ref: "#/components/responses/Unauthorized"

components:

  securitySchemes:

    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: NullinkToken

    nullinkSessionCookie:
      type: apiKey
      in: cookie
      name: morc_session

  schemas:

    SendMessage:
      type: object
      required:
        - text
        - session_id
      properties:
        text:
          type: string
        session_id:
          type: string

    Message:
      type: object
      required:
        - id
      properties:
        id:
          type: integer
        session_id:
          type: string
        role:
          type: string
        text:
          type: string
        created_at:
          type: string
          format: date-time

    MessagePage:
      type: object
      required:
        - messages
        - next_after
        - has_more
      properties:
        messages:
          type: array
          items:
            $ref: "#/components/schemas/Message"
        next_after:
          type: integer
        has_more:
          type: boolean

  responses:

    Unauthorized:
      description: Authentication required or invalid credentials.

    Forbidden:
      description: Credential is not authorized for this session or operation.

Important: don't interpret the cookie security scheme as solving the Custom GPT cookie problem. It merely describes the existing API. Bearer is what makes Actions practical.

B2 — mcp_server.py

I'm choosing stdio MCP.

Why:

no additional HTTP server

no exposed MCP port

trivial to run through an MCP host

Python standard library only

Bearer token never needs to be exposed through an inbound network interface

easy to wrap with systemd/Docker later

This implements JSON-RPC MCP primitives directly rather than requiring the MCP SDK.

It supports:

nullink_health
nullink_sessions
nullink_pull_messages
nullink_send_message
nullink_watch_once
nullink_ping
mcp_server.py — Nullink stdio MCP adapter
#!/usr/bin/env python3
"""
Nullink stdio MCP adapter.

Environment:
    NULLINK_URL   default:
                  https://nullink.216.158.238.236.sslip.io
    NULLINK_TOKEN required scoped Bearer token

Run:
    export NULLINK_TOKEN="nlk_..."
    python3 mcp_server.py

The adapter is intentionally stateless.
Nullink REST remains the source of truth.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


BASE = os.environ.get(
    "NULLINK_URL",
    "https://nullink.216.158.238.236.sslip.io",
).rstrip("/")

TOKEN = os.environ.get("NULLINK_TOKEN", "").strip()


class NullinkError(Exception):
    def __init__(self, status: int, body: object):
        self.status = status
        self.body = body
        super().__init__(f"Nullink HTTP {status}: {body}")


def http_request(
    method: str,
    path: str,
    body: dict | None = None,
    auth: bool = True,
) -> object:
    if auth and not TOKEN:
        raise NullinkError(401, "NULLINK_TOKEN is not set")

    data = None

    headers = {
        "Accept": "application/json",
        "User-Agent": "nullink-mcp/1.0",
    }

    if auth:
        headers["Authorization"] = f"Bearer {TOKEN}"

    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(
        BASE + path,
        data=data,
        headers=headers,
        method=method,
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
            content_type = response.headers.get("Content-Type", "")

            if "application/json" in content_type:
                return json.loads(raw.decode("utf-8") or "null")

            return raw.decode("utf-8", errors="replace")

    except urllib.error.HTTPError as exc:
        raw = exc.read()

        try:
            parsed = json.loads(raw.decode("utf-8") or "null")
        except Exception:
            parsed = raw.decode("utf-8", errors="replace")

        raise NullinkError(exc.code, parsed) from exc

    except urllib.error.URLError as exc:
        raise NullinkError(
            503,
            f"Nullink connection failed: {exc.reason}",
        ) from exc


def health():
    return http_request("GET", "/health", auth=False)


def sessions():
    return http_request("GET", "/api/sessions")


def pull_messages(
    session: str,
    after: int = 0,
    limit: int = 50,
):
    query = urllib.parse.urlencode(
        {
            "session": session,
            "after": str(after),
            "limit": str(limit),
        }
    )

    result = http_request(
        "GET",
        f"/api/messages?{query}",
    )

    # Compatibility with the existing API if it still returns
    # a bare message array.
    if isinstance(result, list):
        messages = result

        next_after = after

        for message in messages:
            if isinstance(message, dict):
                try:
                    next_after = max(
                        next_after,
                        int(message.get("id") or next_after),
                    )
                except (TypeError, ValueError):
                    pass

        return {
            "messages": messages,
            "next_after": next_after,
            "has_more": False,
        }

    if isinstance(result, dict):
        messages = result.get("messages")

        if isinstance(messages, list):
            next_after = result.get("next_after", after)
            has_more = bool(result.get("has_more", False))

            try:
                next_after = int(next_after)
            except (TypeError, ValueError):
                next_after = after

            return {
                "messages": messages,
                "next_after": next_after,
                "has_more": has_more,
            }

        # Preserve unknown server response rather than destroying it.
        return result

    return {
        "messages": [],
        "next_after": after,
        "has_more": False,
    }


def send_message(session: str, text: str):
    return http_request(
        "POST",
        "/api/messages",
        {
            "text": text,
            "session_id": session,
        },
    )


def watch_once(session: str, after: int = 0):
    result = pull_messages(
        session=session,
        after=after,
        limit=50,
    )

    messages = result.get("messages", [])
    next_after = result.get("next_after", after)

    return {
        "changed": bool(messages),
        "messages": messages,
        "next_after": next_after,
        "has_more": bool(result.get("has_more", False)),
    }


def ping(change: int = 0):
    query = urllib.parse.urlencode(
        {"change": str(change)}
    )

    return http_request(
        "GET",
        f"/api/ping?{query}",
    )


TOOLS = [
    {
        "name": "nullink_health",
        "description": "Check whether Nullink is healthy.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "nullink_sessions",
        "description": "List Nullink sessions visible to this Bearer token.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "nullink_pull_messages",
        "description": (
            "Read messages from a Nullink session after a message ID."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session": {
                    "type": "string",
                    "description": "Nullink session ID.",
                },
                "after": {
                    "type": "integer",
                    "minimum": 0,
                    "default": 0,
                    "description": "Return messages after this ID.",
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "default": 50,
                },
            },
            "required": ["session"],
            "additionalProperties": False,
        },
    },
    {
        "name": "nullink_send_message",
        "description": "Send a message to a Nullink session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session": {
                    "type": "string",
                    "description": "Destination Nullink session ID.",
                },
                "text": {
                    "type": "string",
                    "description": "Message text.",
                },
            },
            "required": ["session", "text"],
            "additionalProperties": False,
        },
    },
    {
        "name": "nullink_watch_once",
        "description": (
            "Perform one immediate message check. "
            "Does not hold the connection open."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "session": {
                    "type": "string",
                },
                "after": {
                    "type": "integer",
                    "minimum": 0,
                    "default": 0,
                },
            },
            "required": ["session"],
            "additionalProperties": False,
        },
    },
    {
        "name": "nullink_ping",
        "description": "Check Nullink's lightweight change detector.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "change": {
                    "type": "integer",
                    "enum": [0, 1],
                    "default": 0,
                },
            },
            "additionalProperties": False,
        },
    },
]


def tool_call(name: str, arguments: dict) -> object:
    if name == "nullink_health":
        return health()

    if name == "nullink_sessions":
        return sessions()

    if name == "nullink_pull_messages":
        return pull_messages(
            session=str(arguments["session"]),
            after=int(arguments.get("after", 0)),
            limit=int(arguments.get("limit", 50)),
        )

    if name == "nullink_send_message":
        text = str(arguments["text"])

        if not text:
            raise ValueError("text must not be empty")

        return send_message(
            session=str(arguments["session"]),
            text=text,
        )

    if name == "nullink_watch_once":
        return watch_once(
            session=str(arguments["session"]),
            after=int(arguments.get("after", 0)),
        )

    if name == "nullink_ping":
        return ping(
            change=int(arguments.get("change", 0)),
        )

    raise ValueError(f"Unknown tool: {name}")


def send_json(value: dict):
    sys.stdout.write(
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        + "\n"
    )
    sys.stdout.flush()


def handle_request(request: dict):
    request_id = request.get("id")
    method = request.get("method")
    params = request.get("params") or {}

    # JSON-RPC notifications have no id and do not receive responses.
    is_notification = "id" not in request

    if method == "initialize":
        result = {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "nullink",
                "version": "1.0.0",
            },
        }

    elif method == "notifications/initialized":
        return

    elif method == "tools/list":
        result = {
            "tools": TOOLS,
        }

    elif method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}

        try:
            result = tool_call(name, arguments)

            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(
                                result,
                                ensure_ascii=False,
                                indent=2,
                            ),
                        }
                    ],
                    "isError": False,
                },
            }

        except Exception as exc:
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": str(exc),
                        }
                    ],
                    "isError": True,
                },
            }

        if not is_notification:
            send_json(response)

        return

    elif method == "ping":
        result = {}

    else:
        if is_notification:
            return

        send_json(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}",
                },
            }
        )
        return

    if not is_notification:
        send_json(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": result,
            }
        )


def main():
    if not TOKEN:
        print(
            "NULLINK_TOKEN is required.",
            file=sys.stderr,
        )
        sys.exit(2)

    for line in sys.stdin:
        line = line.strip()

        if not line:
            continue

        try:
            request = json.loads(line)

            if not isinstance(request, dict):
                raise ValueError("JSON-RPC request must be an object")

            handle_request(request)

        except json.JSONDecodeError as exc:
            send_json(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32700,
                        "message": f"Parse error: {exc}",
                    },
                }
            )

        except Exception as exc:
            send_json(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32603,
                        "message": str(exc),
                    },
                }
            )


if __name__ == "__main__":
    main()
One deliberate compatibility feature

That adapter accepts both:

JSON
[{"id":123,...}]

and the preferred:

JSON
{
  "messages": [],
  "next_after": 123,
  "has_more": false
}

So you can deploy the adapter before changing the Nullink server response.

B3 — token_auth.md

This is where I'd be fairly strict. A Bearer token should become a machine credential, not another form of PIN.

token_auth.md — Nullink scoped Bearer authentication
Nullink Scoped Bearer Authentication
Purpose

Bearer tokens are machine/agent credentials.

The existing:

OTP PIN -> morc_session HttpOnly cookie

remains the human/browser authentication mechanism.

Do not use OTP PINs as agent credentials.

Recommended flow:

Human/admin
    |
    | authenticated management session
    v
create scoped token
    |
    v
Agent / MCP / Action
    |
    | Authorization: Bearer nlk_...
    v
Nullink API
Token format

Use an opaque token:

nlk_<random>

Generate at least 32 random bytes using a cryptographically secure
random generator.

Example:

nlk_k9Y...<high entropy random value>

Do not encode permissions directly into the token.

Do not use JWT initially.

Opaque tokens make revocation simple and avoid unnecessary token
validation/key-management infrastructure.

Storage

Never store the plaintext token in the database.

At creation:

Generate the plaintext token.

Display/return it once.

Hash it using SHA-256 or an equivalent cryptographic hash.

Store only the hash.

Example conceptual record:

token_hash
token_prefix
name
scopes
sessions
created_at
expires_at
revoked_at
last_used_at

The token prefix can be stored for identification/logging.

Never log the complete token.

Authorization header

Agents send:

Authorization: Bearer nlk_...

The middleware:

Extracts the Authorization header.

Requires exactly the Bearer scheme.

Hashes the supplied token.

Looks up the hash.

Rejects missing, unknown, expired, or revoked tokens.

Attaches the token identity/scopes to the request.

Enforces session/action restrictions.

Scopes

Initial scopes:

messages:read
messages:write
sessions:read
health:read
ping:read

Optional administrative scopes should NOT be granted to normal agents:

tokens:manage
sessions:manage

A normal ChatGPT/MCP token should normally have:

messages:read
messages:write
sessions:read
health:read
ping:read
Session restrictions

Scopes alone are not sufficient.

A token should also have an explicit allowed-session list.

Example ChatGPT token:

scopes:
  - health:read
  - sessions:read
  - messages:read
  - messages:write
  - ping:read

sessions:
  - chatgpt

That token must not be able to read or write:

morc
ops
grok
worker-1

unless those sessions are explicitly granted.

Authorization matrix
GET /health

Requires no authentication.

GET /api/me

Requires any valid Bearer token or existing morc_session.

GET /api/sessions

Requires:

sessions:read

Only return sessions permitted by the token.

GET /api/messages

Requires:

messages:read

Additionally require the requested session to be in the token's
allowed session list.

POST /api/messages

Requires:

messages:write

Additionally require the destination session to be in the token's
allowed session list.

GET /api/ping

Requires:

ping:read

The response must not reveal information about sessions that the
token cannot access.

Token creation

Add:

POST /api/auth/tokens

This endpoint is an administrative operation.

It should require the existing authenticated human/admin session
or another administrator credential.

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
  "sessions": [
    "chatgpt"
  ],
  "expires_in": 2592000
}

Response:

{
  "ok": true,
  "token": "nlk_...",
  "token_id": "...",
  "expires_at": "..."
}

Return the plaintext token only at creation.

Token revocation

Add:

DELETE /api/auth/tokens/{token_id}

Revocation should be immediate.

A revoked token must fail authorization even if its expiration time
has not passed.

Token listing

Recommended:

GET /api/auth/tokens

Never return plaintext tokens.

Return metadata only:

{
  "id": "...",
  "name": "chatgpt-mcp",
  "scopes": [...],
  "sessions": ["chatgpt"],
  "created_at": "...",
  "expires_at": "...",
  "revoked": false,
  "last_used_at": "..."
}
Expiration

Default machine-token expiration:

30 days

For long-lived integrations, explicitly choose a longer lifetime.

Prefer expiration + rotation over permanent tokens.

Logging

Never log:

Authorization headers
plaintext tokens
OTP PINs
morc_session cookie values

Safe log:

token_id
token_prefix
operation
session_id
HTTP status
timestamp
Rate limiting

At minimum:

authentication endpoints:
    aggressive rate limiting

message reads:
    reasonable per-token limit

message writes:
    reasonable per-token limit

Do not rate-limit the MCP adapter independently if doing so would
create contradictory limits. Nullink should remain authoritative.

Legacy cookie compatibility

Keep:

morc_session

for the existing UI and Python connector.

Authentication precedence:

1. Bearer
2. morc_session

Do not require both.

This allows existing UI clients to continue working while agents
move to Bearer authentication.

Security boundary

A token represents an agent identity.

Therefore:

ChatGPT token != Morc token != Ops token

Do not create one universal agent token unless there is a specific
administrative reason.

The normal design is:

token A -> chatgpt
token B -> morc
token C -> ops

This makes compromise containment and auditing substantially easier.

B4 — Exact Nullink server patch

This is the actual server-side checklist I'd hand to whoever is touching Nullink.

Nullink Bearer/MCP server patch notes
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