#!/usr/bin/env python3
"""OAuth-only MCP endpoint, separate from the deployed static Bearer gateway."""
import html
from collections import deque
from http import HTTPStatus
from http.cookies import SimpleCookie
import json
import os
import threading
import time
from urllib.parse import parse_qs, urlsplit

import master_gateway as master
from oauth_store import Store, OAuthError, SCOPE, load_config


def fields(raw):
    parsed = parse_qs(raw, keep_blank_values=True, max_num_fields=30, strict_parsing=True)
    if any(len(v) != 1 for v in parsed.values()): raise OAuthError('invalid_request')
    return {k: v[0] for k, v in parsed.items()}


class Handler(master.MasterHandler):
    def log_message(self, fmt, *args):
        # No URLs, query strings, codes, cookies, headers, or tokens in access logs.
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def _authorized(self):
        value = self.headers.get('Authorization', '')
        return value.startswith('Bearer ') and self.server.oauth.valid(value[7:].strip())

    def _send_empty(self, status, **headers):
        if status == HTTPStatus.UNAUTHORIZED:
            headers['WWW_Authenticate'] = 'Bearer resource_metadata="' + self.server.metadata_url + '", scope="' + SCOPE + '"'
        super()._send_empty(status, **headers)

    def reply(self, status, data, content_type='application/json', headers=None):
        body = json.dumps(data).encode() if content_type == 'application/json' else data.encode()
        self.send_response(status)
        for key, value in (headers or {}).items(): self.send_header(key, value)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, url, cookie=None):
        headers = {'Location': url}
        if cookie: headers['Set-Cookie'] = cookie
        self.reply(303, '', 'text/plain', headers)

    def route(self):
        if len(self.path) > 8192: raise OAuthError('invalid_request')
        return urlsplit(self.path)

    def limited(self, operation, limit):
        with self.server.rate_lock:
            now = time.monotonic()
            bucket = self.server.rates.setdefault(operation, deque())
            while bucket and bucket[0] < now - 60: bucket.popleft()
            if len(bucket) >= limit:
                self.reply(429, {"error":"temporarily_unavailable"}, headers={"Retry-After":"60"})
                return True
            bucket.append(now)
            return False

    def do_GET(self):
        try:
            url = self.route()
            oauth = self.server.oauth
            if url.path in self.server.discovery:
                self.reply(200, self.server.discovery[url.path])
            elif url.path == self.server.auth_path + '/authorize':
                if self.limited('authorize', 30): return
                request, browser = oauth.authorize(fields(url.query))
                cookie = '__Secure-nullink-oauth=' + browser + '; Secure; HttpOnly; SameSite=Lax; Max-Age=600; Path=' + self.server.auth_path
                self.redirect(self.server.auth_path + '/pending?request=' + request, cookie)
            elif url.path == self.server.auth_path + '/pending':
                params = fields(url.query)
                request = params.get('request', '')
                cookie = SimpleCookie(self.headers.get('Cookie', ''))
                browser = cookie.get('__Secure-nullink-oauth')
                if not browser: raise OAuthError('invalid_request')
                target = oauth.poll(request, browser.value)
                if target:
                    self.redirect(target, '__Secure-nullink-oauth=; Secure; HttpOnly; SameSite=Lax; Max-Age=0; Path=' + self.server.auth_path)
                else:
                    page = ('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
                            '<meta http-equiv="refresh" content="3"><title>Connect Nullink</title>'
                            '<h1>Approve your Nullink connection</h1><p>This connection grants full server administration through Codex.</p>'
                            '<p>On your VPS root console, inspect the pending request and approve this exact ID:</p><pre>'
                            + html.escape(request) + '</pre><p>Run <code>python3 /opt/nullink-master/oauth_store.py pending</code>, then '
                            '<code>python3 /opt/nullink-master/oauth_store.py approve REQUEST_ID</code>.</p>'
                            '<p>Approve only a connection you initiated. Do not send the request ID to an AI agent. This page returns to ChatGPT after approval.</p></html>')
                    self.reply(200, page, 'text/html; charset=utf-8')
            else:
                super().do_GET()
        except (OAuthError, ValueError, TypeError, UnicodeError):
            self.reply(400, {'error': 'invalid_request'})

    def do_POST(self):
        try:
            path = self.route().path
            oauth = self.server.oauth
            if path not in [self.server.auth_path + suffix for suffix in ['/register', '/token', '/revoke']]:
                return super().do_POST()
            if self.limited(path, 120): return
            # Back-channel OAuth endpoints are not browser form endpoints.
            if self.headers.get('Origin'): return self.reply(403, {'error': 'invalid_request'})
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 16384 or self.headers.get('Transfer-Encoding'):
                return self.reply(400, {'error': 'invalid_request'})
            raw = self.rfile.read(size)
            content_type = self.headers.get('Content-Type', '').split(';')[0].strip()
            if path.endswith('/register'):
                if content_type != 'application/json': return self.reply(415, {'error':'invalid_request'})
                args = json.loads(raw)
                if not isinstance(args, dict): raise OAuthError('invalid_request')
                result = oauth.register(args)
                return self.reply(201, result)
            if content_type != 'application/x-www-form-urlencoded': return self.reply(415, {'error':'invalid_request'})
            args = fields(raw.decode())
            if path.endswith('/token'): return self.reply(200, oauth.token(args))
            oauth.revoke(args.get('token', ''), args.get('client_id'))
            return self.reply(200, {})
        except OAuthError as exc:
            self.reply(400, {'error': exc.code})
        except (ValueError, TypeError, UnicodeError):
            self.reply(400, {'error': 'invalid_request'})


def configure(server, oauth):
    server.oauth = oauth
    server.rate_lock = threading.Lock()
    server.rates = {}
    issuer, resource = urlsplit(oauth.issuer), urlsplit(oauth.resource)
    server.auth_path = issuer.path
    origin = issuer.scheme + '://' + issuer.netloc
    protected_path = '/.well-known/oauth-protected-resource' + resource.path
    server.metadata_url = origin + protected_path
    server.discovery = {
        protected_path: oauth.protected(),
        '/.well-known/oauth-authorization-server' + issuer.path: oauth.metadata(),
        issuer.path + '/.well-known/oauth-authorization-server': oauth.metadata(),
    }


def main():
    os.umask(0o077)
    oauth = Store(load_config())
    master.transport.MCP_PATH = urlsplit(oauth.resource).path
    old_call = master.transport.adapter.tool_call
    names = {t['name'] for t in master.TOOLS}
    master.transport.adapter.TOOLS += master.TOOLS
    # OAuth applies to every tool on this endpoint, including legacy messaging.
    for tool in master.transport.adapter.TOOLS:
        tool['securitySchemes'] = [{'type':'oauth2', 'scopes':[SCOPE]}]
    master.transport.adapter.tool_call = lambda name, args: master.call_worker(name, args) if name in names else old_call(name, args)
    with master.transport.ThreadingHTTPServer(('127.0.0.1', int(os.environ.get('MASTER_OAUTH_PORT', '8769'))), Handler) as server:
        configure(server, oauth)
        server.serve_forever()


if __name__ == '__main__': main()
