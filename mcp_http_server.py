#!/usr/bin/env python3
"""Stateless Streamable HTTP transport for the Nullink MCP adapter.

Environment:
    NULLINK_MCP_HOST       Bind address (default: 127.0.0.1)
    NULLINK_MCP_PORT       Bind port (default: 8767)
    NULLINK_MCP_PATH       MCP endpoint (default: /mcp)
    NULLINK_MCP_MAX_BODY   Maximum request bytes (default: 1048576)
    NULLINK_TOKEN          Scoped nlk_ token (also used by mcp_server.py)
    NULLINK_TOKEN_FILE     Token file fallback used by mcp_server.py
"""

from __future__ import annotations

import hmac
import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import mcp_server as adapter


HOST = os.environ.get("NULLINK_MCP_HOST", "127.0.0.1")
PORT = int(os.environ.get("NULLINK_MCP_PORT", "8767"))
MCP_PATH = os.environ.get("NULLINK_MCP_PATH", "/mcp")
MAX_BODY = int(os.environ.get("NULLINK_MCP_MAX_BODY", str(1024 * 1024)))
SUPPORTED_PROTOCOLS = ("2025-03-26", "2024-11-05")


def jsonrpc_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def handle_message(message: Any) -> dict[str, Any] | None:
    if not isinstance(message, dict):
        return jsonrpc_error(None, -32600, "Invalid Request")

    request_id = message.get("id")
    is_notification = "id" not in message
    method = message.get("method")
    params = message.get("params") or {}

    if message.get("jsonrpc") != "2.0" or not isinstance(method, str):
        return None if is_notification else jsonrpc_error(request_id, -32600, "Invalid Request")
    if method == "notifications/initialized":
        return None

    if method == "initialize":
        requested = params.get("protocolVersion")
        protocol = requested if requested in SUPPORTED_PROTOCOLS else SUPPORTED_PROTOCOLS[0]
        result = {
            "protocolVersion": protocol,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "nullink", "version": "1.1.0"},
        }
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": adapter.TOOLS}
    elif method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(name, str) or not isinstance(arguments, dict):
            return jsonrpc_error(request_id, -32602, "Invalid params")
        try:
            value = adapter.tool_call(name, arguments)
            result = {
                "content": [{"type": "text", "text": json.dumps(value, ensure_ascii=False, indent=2)}],
                "isError": False,
            }
        except Exception as exc:
            result = {"content": [{"type": "text", "text": str(exc)}], "isError": True}
    else:
        return None if is_notification else jsonrpc_error(request_id, -32601, f"Method not found: {method}")

    if is_notification:
        return None
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def handle_payload(payload: Any) -> dict[str, Any] | list[dict[str, Any]] | None:
    if isinstance(payload, list):
        if not payload:
            return jsonrpc_error(None, -32600, "Invalid Request")
        responses = [response for item in payload if (response := handle_message(item)) is not None]
        return responses or None
    return handle_message(payload)


class MCPHandler(BaseHTTPRequestHandler):
    server_version = "NullinkMCP/1.1"

    def _send_empty(self, status: HTTPStatus, **headers: str) -> None:
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name.replace("_", "-"), value)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _authorized(self) -> bool:
        expected = adapter.TOKEN
        supplied = self.headers.get("Authorization", "")
        return bool(expected and supplied.startswith("Bearer ") and hmac.compare_digest(supplied[7:].strip(), expected))

    def _send_json(self, status: HTTPStatus, value: Any) -> None:
        data = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_sse(self, value: Any) -> None:
        encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        data = f"event: message\ndata: {encoded}\n\n".encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send_json(HTTPStatus.OK, {"ok": True, "service": "nullink-mcp"})
            return
        if self.path != MCP_PATH:
            self._send_empty(HTTPStatus.NOT_FOUND)
            return
        if not self._authorized():
            self._send_empty(HTTPStatus.UNAUTHORIZED, WWW_Authenticate='Bearer realm="nullink-mcp"')
            return
        self._send_empty(HTTPStatus.METHOD_NOT_ALLOWED, Allow="POST")

    def do_DELETE(self) -> None:
        if self.path != MCP_PATH:
            self._send_empty(HTTPStatus.NOT_FOUND)
            return
        if not self._authorized():
            self._send_empty(HTTPStatus.UNAUTHORIZED, WWW_Authenticate='Bearer realm="nullink-mcp"')
            return
        self._send_empty(HTTPStatus.METHOD_NOT_ALLOWED, Allow="POST")

    def do_POST(self) -> None:
        if self.path != MCP_PATH:
            self._send_empty(HTTPStatus.NOT_FOUND)
            return
        if not self._authorized():
            self._send_empty(HTTPStatus.UNAUTHORIZED, WWW_Authenticate='Bearer realm="nullink-mcp"')
            return
        if "application/json" not in self.headers.get("Content-Type", "").lower():
            self._send_json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, jsonrpc_error(None, -32600, "Content-Type must be application/json"))
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_empty(HTTPStatus.BAD_REQUEST)
            return
        if length <= 0 or length > MAX_BODY:
            status = HTTPStatus.REQUEST_ENTITY_TOO_LARGE if length > MAX_BODY else HTTPStatus.BAD_REQUEST
            self._send_empty(status)
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(HTTPStatus.BAD_REQUEST, jsonrpc_error(None, -32700, "Parse error"))
            return

        response = handle_payload(payload)
        if response is None:
            self._send_empty(HTTPStatus.ACCEPTED)
            return
        accept = self.headers.get("Accept", "application/json").lower()
        if "text/event-stream" in accept and "application/json" not in accept:
            self._send_sse(response)
        else:
            self._send_json(HTTPStatus.OK, response)


def main() -> None:
    if not adapter.TOKEN:
        raise SystemExit("NULLINK_TOKEN or NULLINK_TOKEN_FILE is required")
    server = ThreadingHTTPServer((HOST, PORT), MCPHandler)
    print(f"Nullink MCP listening on http://{HOST}:{PORT}{MCP_PATH}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
