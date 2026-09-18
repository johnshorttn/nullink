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

_TOKEN_FILE = os.environ.get("NULLINK_TOKEN_FILE", "/workspace/server/secrets/NULLINK_TOKEN_chatgpt.txt")
TOKEN = os.environ.get("NULLINK_TOKEN", "").strip()
if (not TOKEN) or TOKEN == "PLACEHOLDER":
    try:
        with open(_TOKEN_FILE, encoding="utf-8") as _f:
            TOKEN = _f.read().strip()
    except OSError:
        TOKEN = ""


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
