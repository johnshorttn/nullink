#!/usr/bin/env python3
"""Opt-in admin MCP endpoint; legacy messaging endpoint remains unchanged."""
import hmac
import json
import os
import socket
from pathlib import Path
import mcp_http_server as transport


def tool(name, description, properties=None, required=None, write=False):
    return {'name': name, 'description': description,
            'inputSchema': {'type': 'object', 'properties': properties or {},
                            'required': required or [], 'additionalProperties': False},
            'annotations': {'readOnlyHint': not write, 'destructiveHint': write,
                            'idempotentHint': not write, 'openWorldHint': True}}


S = {'type': 'string', 'minLength': 1, 'maxLength': 128}
PROMPT = {'type': 'string', 'minLength': 1, 'maxLength': 24000}
TOOLS = [
    tool('master_capabilities', 'Get enabled projects, services, worker privileges and limits.'),
    tool('server_status', 'Inspect hostname, disk, load and Codex binary availability.'),
    tool('repo_status', 'Read Git branch and working tree status; never modifies files.', {'project': S}, ['project']),
    tool('service_status', 'Read an allowlisted systemd service state.', {'service': S}, ['service']),
    tool('agent_start_task', 'Queue a Codex task. May change production and install software according to worker privileges. Reuse request_key only for retries of the identical task.',
         {'project': S, 'prompt': PROMPT, 'request_key': S}, ['project', 'prompt', 'request_key'], True),
    tool('agent_task_status', 'Get task state and the latest 32,768 characters of output. Output may contain sensitive server data.', {'job_id': S}, ['job_id']),
    tool('agent_list_tasks', 'List the latest 50 jobs and their output.'),
    tool('agent_reply', 'Continue a finished Codex session as a new queued job. Does not steer a running process.',
         {'job_id': S, 'prompt': PROMPT, 'request_key': S}, ['job_id', 'prompt', 'request_key'], True),
    tool('agent_cancel_task', 'Cancel queued work or kill the active job process group. Does not undo completed changes.', {'job_id': S}, ['job_id'], True),
    tool('master_audit', 'Read the latest 100 job lifecycle audit entries; prompts are excluded.'),
]


def call_worker(name, arguments):
    spec = next((t for t in TOOLS if t['name'] == name), None)
    if spec is None: raise ValueError('Unknown master tool')
    schema = spec['inputSchema']
    if not isinstance(arguments, dict) or set(arguments) - set(schema['properties']):
        raise ValueError('Invalid arguments')
    if set(schema['required']) - set(arguments): raise ValueError('Missing required arguments')
    for key, value in arguments.items():
        field = schema['properties'][key]
        if not isinstance(value, str) or not field['minLength'] <= len(value) <= field['maxLength']:
            raise ValueError('Invalid ' + key)
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(15)
        client.connect(os.environ.get('MASTER_SOCKET', '/run/nullink-master/worker.sock'))
        client.sendall(json.dumps({'name': name, 'arguments': arguments}).encode() + b'\n')
        with client.makefile('rb') as stream:
            data = stream.readline(4 * 1024 * 1024)
        if not data.endswith(b'\n'): raise ValueError('Invalid worker response')
        result = json.loads(data)
        if 'error' in result: raise ValueError(result['error'])
        return result['result']


class MasterHandler(transport.MCPHandler):
    def _authorized(self):
        auth = self.headers.get('Authorization', '')
        return auth.startswith('Bearer ') and hmac.compare_digest(auth[7:].strip(), self.server.admin_token)

    def do_POST(self):
        # Reject browser origins unless explicitly allowlisted by the administrator.
        origin = self.headers.get('Origin')
        allowed = os.environ.get('MASTER_ALLOWED_ORIGINS', '').split(',')
        if origin and origin not in allowed:
            self._send_empty(transport.HTTPStatus.FORBIDDEN)
            return
        super().do_POST()


def main():
    token = Path(os.environ.get('MASTER_TOKEN_FILE', '/etc/nullink-master/admin-token')).read_text().strip()
    if len(token) < 32: raise SystemExit('Admin token must contain at least 32 characters')
    if hmac.compare_digest(token, transport.adapter.TOKEN):
        raise SystemExit('Admin token must differ from the messaging token')
    old_call = transport.adapter.tool_call
    master_names = {t['name'] for t in TOOLS}
    transport.adapter.TOOLS = transport.adapter.TOOLS + TOOLS
    transport.adapter.tool_call = lambda name, args: call_worker(name, args) if name in master_names else old_call(name, args)
    with transport.ThreadingHTTPServer(('127.0.0.1', int(os.environ.get('MASTER_PORT', '8768'))), MasterHandler) as server:
        server.admin_token = token
        server.serve_forever()


if __name__ == '__main__': main()
