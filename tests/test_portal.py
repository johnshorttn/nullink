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
                        ('RATE_FILE', 'rate.json'), ('SESSION_SECRET_FILE', 'session.txt')]]
        for item in cls.patches:
            item.start()
        server.SESSION_SECRET_FILE.write_text('isolated-test-secret')
        server.OTP_FILE.write_text(json.dumps({'salt': 'test', 'pin_hash': server.hash_pin('123456', 'test'),
                                               'expires_at': time.time() + 60}))
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

    def request(self, path, method='GET', cookie=None, host='nullverse.cloud', body=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.httpd.server_port)
        headers = {'Host': host}
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
        status, headers, _ = self.request('/api/auth/verify', 'POST', body=json.dumps({'code': '123456'}))
        self.assertEqual(status, 200)
        cookie = headers['Set-Cookie'].split(';')[0]
        for flag in ['Secure', 'HttpOnly', 'SameSite=Lax']:
            self.assertIn(flag, headers['Set-Cookie'])
        self.assertNotIn('Domain=', headers['Set-Cookie'])
        self.assertEqual(self.request('/', cookie=cookie)[1]['Location'], '/projects')
        self.assertIn(b'Coming soon', self.request('/projects', cookie=cookie)[2])
        expired = server.COOKIE_NAME + '=' + server.sign_session(int(time.time()) - 1)
        self.assertEqual(self.request('/projects', cookie=expired)[1]['Location'], '/')
        status, headers, _ = self.request('/api/auth/logout', 'POST', cookie=cookie)
        self.assertEqual(status, 200)
        self.assertIn('Max-Age=0', headers['Set-Cookie'])
        self.assertEqual(self.request('/projects', cookie=headers['Set-Cookie'].split(';')[0])[0], 302)
        self.assertEqual(self.request('/', host='evil.example')[0], 421)
        self.assertEqual(self.request('/api/sessions')[0], 404)
        self.assertEqual(self.request('/portal.html')[0], 404)
        for host in ['nullink.nullverse.cloud', 'nullink.216.158.238.236.sslip.io']:
            self.assertEqual(self.request('/', host=host, cookie=cookie)[0], 200)
        for path in ['/app.js', '/style.css', '/tokens.css', '/portal.js', '/portal.css']:
            self.assertEqual(self.request(path)[0], 200)
