"""Exercise the real HTTP auth flow against isolated credentials and state."""
import http.client
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
import server


class PortalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        cls.patches = [patch.object(server, name, root / filename) for name, filename in
                       [('OTP_FILE', 'otp.json'), ('TOTP_FILE', 'totp.json'),
                        ('RATE_FILE', 'rate.json'), ('SESSION_SECRET_FILE', 'session.txt'),
                        ('SESSIONS_FILE', 'sessions.json')]]
        for item in cls.patches:
            item.start()
        server.SESSION_SECRET_FILE.write_text('isolated-test-secret')
        server.write_otp('123456', 60)
        cls.httpd = server.ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join()
        for item in reversed(cls.patches):
            item.stop()
        cls.tmp.cleanup()

    @staticmethod
    def session_cookie(expired=False):
        value, rec = server.create_session('203.0.113.9', 'test', 'pin')
        if expired:
            sessions = server.load_sessions()
            for key, item in sessions.items():
                if item['id'] == rec['id']:
                    item['expires_at'] = time.time() - 1
            server.save_sessions(sessions)
        return value

    def request(self, path, method='GET', cookie=None, host='nullverse.cloud', body=None, extra_headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.httpd.server_port)
        headers = {'Host': host}
        headers.update(extra_headers or {})
        if cookie:
            headers['Cookie'] = cookie
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        conn.close()
        return result

    def test_login_session_expiry_logout_and_hosts(self):
        self.assertIn(b'id="pin-form"', self.request('/')[2])
        self.assertEqual(self.request('/projects')[0], 302)
        self.assertEqual(self.request('/projects', cookie='morc_session=forged')[0], 302)
        self.assertEqual(self.request('/projects', cookie=server.COOKIE_NAME + '=forged')[0], 302)
        status, headers, _ = self.request('/api/auth/verify', 'POST', body=json.dumps({'code': '123456'}))
        self.assertEqual(status, 200)
        cookie = headers['Set-Cookie'].split(';')[0]
        self.assertTrue(cookie.startswith('__Host-nullink_session='))
        for flag in ['Secure', 'HttpOnly', 'SameSite=Lax', 'Path=/']:
            self.assertIn(flag, headers['Set-Cookie'])
        self.assertNotIn('Domain=', headers['Set-Cookie'])
        self.assertEqual(self.request('/', cookie=cookie)[1]['Location'], '/projects')
        self.assertIn(b'Coming soon', self.request('/projects', cookie=cookie)[2])
        expired = server.COOKIE_NAME + '=' + self.session_cookie(expired=True)
        self.assertEqual(self.request('/projects', cookie=expired)[1]['Location'], '/')
        status, headers, _ = self.request('/api/auth/logout', 'POST', cookie=cookie)
        self.assertEqual(status, 200)
        self.assertIn('Max-Age=0', headers['Set-Cookie'])
        self.assertEqual(self.request('/projects', cookie=headers['Set-Cookie'].split(';')[0])[0], 302)
        # The copied pre-logout cookie is revoked server-side.
        self.assertEqual(self.request('/projects', cookie=cookie)[0], 302)
        cookie = server.COOKIE_NAME + '=' + self.session_cookie()
        self.assertEqual(self.request('/', host='evil.example')[0], 421)
        self.assertEqual(self.request('/api/sessions')[0], 404)
        self.assertEqual(self.request('/portal.html')[0], 404)
        for host in ['nullink.nullverse.cloud', 'nullink.216.158.238.236.sslip.io']:
            self.assertEqual(self.request('/', host=host, cookie=cookie)[0], 200)
        for path in ['/app.js', '/style.css', '/tokens.css', '/portal.js', '/portal.css']:
            self.assertEqual(self.request(path)[0], 200)

    def test_status_rejects_bearer_and_forwarded_host(self):
        token = self.session_cookie()
        with patch.object(server, 'collect_portal_status') as collect:
            self.assertEqual(self.request('/api/portal/status', extra_headers={
                'Authorization': 'Bearer ' + token})[0], 401)
            self.assertEqual(self.request('/api/portal/status', host='nullink.nullverse.cloud',
                cookie=server.COOKIE_NAME + '=' + token,
                extra_headers={'X-Forwarded-Host': 'nullverse.cloud'})[0], 404)
            collect.assert_not_called()

    def test_status_auth_host_guard_and_failure(self):
        valid = server.COOKIE_NAME + '=' + self.session_cookie()
        expired = server.COOKIE_NAME + '=' + self.session_cookie(expired=True)
        with patch.object(server, 'collect_portal_status', return_value={'timestamp': 123}) as collect:
            for cookie in [None, 'morc_session=forged', expired]:
                status, headers, _ = self.request('/api/portal/status', cookie=cookie)
                self.assertEqual(status, 401)
                self.assertEqual(headers['Cache-Control'], 'no-store')
            for host in ['nullink.nullverse.cloud', 'nullink.216.158.238.236.sslip.io', 'localhost']:
                self.assertEqual(self.request('/api/portal/status', host=host, cookie=valid)[0], 404)
            self.assertEqual(self.request('/api/portal/status', host='evil.example', cookie=valid)[0], 421)
            self.assertEqual(self.request('/api/portal/status', 'POST', cookie=valid)[0], 404)
            collect.assert_not_called()
            status, headers, body = self.request('/api/portal/status', cookie=valid)
            self.assertEqual(status, 200)
            self.assertEqual(headers['Cache-Control'], 'no-store')
            self.assertEqual(json.loads(body), {'timestamp': 123})
        with patch.object(server, 'collect_portal_status', side_effect=OSError('private detail')):
            status, headers, body = self.request('/api/portal/status', cookie=valid)
            self.assertEqual(status, 503)
            self.assertEqual(json.loads(body), {'error': 'status_unavailable'})
            self.assertEqual(headers['Cache-Control'], 'no-store')
            self.assertEqual(self.request('/projects', cookie=valid)[0], 200)


class PortalMetricTests(unittest.TestCase):
    def test_physical_memory_and_filesystem_capacity(self):
        from collections import namedtuple
        usage = namedtuple('usage', 'total used free')(1000, 650, 300)
        with patch.object(Path, 'read_text', return_value='MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 400 kB\n'), \
             patch.object(server.shutil, 'disk_usage', return_value=usage) as disk, \
             patch.object(server.time, 'time', return_value=1234.5):
            result = server.collect_portal_status()
        disk.assert_called_once_with(server.DATA)
        self.assertEqual(result, {
            'ram': {'used_bytes': 614400, 'total_bytes': 1024000, 'percent': 60.0},
            'storage': {'used_bytes': 650, 'total_bytes': 1000, 'percent': 65.0},
            'timestamp': 1234.5})

    def test_missing_or_invalid_memory_is_unavailable(self):
        for contents in ['MemTotal: 0 kB\nMemAvailable: 0 kB',
                         'MemTotal: 10 kB', 'MemTotal: 10 kB\nMemAvailable: 11 kB']:
            with patch.object(Path, 'read_text', return_value=contents):
                with self.assertRaises((ValueError, KeyError)):
                    server.collect_portal_status()
