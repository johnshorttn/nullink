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
