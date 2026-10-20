"""Portal short paths, sslip portal host, and the forward_auth gate (2026-10-07)."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import server
from tests.test_portal import PortalTests as _Base

SSLIP = 'nullverse.216.158.238.236.sslip.io'


class PortalLinkTests(_Base):
    def setUp(self):
        self.links_tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.links_tmp.cleanup)
        links = {}
        for path, app in [('/link', 'nullink'), ('/mail', 'nullmail'),
                          ('/nullmail', 'nullmail'), ('/story', 'storycast'),
                          ('/storycast', 'storycast')]:
            links[path] = {'cloud': f'https://{app}.nullverse.cloud',
                           'sslip': f'https://{app}.216.158.238.236.sslip.io'}
        links['/story-admin'] = {
            'cloud': 'https://storycast.nullverse.cloud/admin',
            'sslip': 'https://storycast.216.158.238.236.sslip.io/admin'}
        links['/cockpit'] = {'cloud': 'https://cockpit.216.158.238.236.sslip.io',
                             'sslip': 'https://cockpit.216.158.238.236.sslip.io'}
        links['/recovery'] = {'cloud': 'https://recovery.216.158.238.236.sslip.io',
                              'sslip': 'https://recovery.216.158.238.236.sslip.io',
                              'public': True}
        links['/axis'] = {'status': 'coming_soon'}
        config = Path(self.links_tmp.name) / 'links.json'
        config.write_text(json.dumps({'links': links}))
        for name, value in [('PORTAL_LINKS_FILE', config),
                            ('_portal_links_cache', {'mtime': None, 'links': {}})]:
            patcher = patch.object(server, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def cookie(self):
        return server.COOKIE_NAME + '=' + self.session_cookie()

    def test_signed_out_paths_redirect_to_sign_in_with_next(self):
        for host in ['nullverse.cloud', SSLIP]:
            for path in ['/link', '/mail', '/axis', '/story', '/cockpit', '/story-admin', '/projects']:
                status, headers, _ = self.request(path, host=host)
                self.assertEqual(status, 302, (host, path))
                self.assertTrue(headers['Location'] in ('/', '/?next=' + path), headers['Location'])
            self.assertIn(b'id="pin-form"', self.request('/', host=host)[2])
            # Recovery shortcut is public: it must work while locked out.
            status, headers, _ = self.request('/recovery', host=host)
            self.assertEqual((status, headers['Location']), (302, 'https://recovery.216.158.238.236.sslip.io'))

    def test_signed_in_targets_per_host(self):
        c = self.cookie()
        expect = {
            'nullverse.cloud': {'/link': 'https://nullink.nullverse.cloud', '/story': 'https://storycast.nullverse.cloud',
                                '/storycast': 'https://storycast.nullverse.cloud', '/mail': 'https://nullmail.nullverse.cloud',
                                '/nullmail': 'https://nullmail.nullverse.cloud',
                                '/cockpit': 'https://cockpit.216.158.238.236.sslip.io',
                                '/story-admin': 'https://storycast.nullverse.cloud/admin'},
            SSLIP: {'/link': 'https://nullink.216.158.238.236.sslip.io', '/story': 'https://storycast.216.158.238.236.sslip.io',
                    '/mail': 'https://nullmail.216.158.238.236.sslip.io',
                    '/nullmail': 'https://nullmail.216.158.238.236.sslip.io',
                    '/story-admin': 'https://storycast.216.158.238.236.sslip.io/admin'},
        }
        for host, paths in expect.items():
            for path, target in paths.items():
                status, headers, _ = self.request(path, host=host, cookie=c)
                self.assertEqual((status, headers['Location']), (302, target), (host, path))
            status, headers, body = self.request('/axis', host=host, cookie=c)
            self.assertEqual(status, 200)
            self.assertIn(b'Coming soon', body)
            self.assertIn("default-src 'none'", headers['Content-Security-Policy'])
            self.assertEqual(self.request('/projects', host=host, cookie=c)[0], 200)
            self.assertIn(b'href="/link"', self.request('/projects', host=host, cookie=c)[2])
            self.assertEqual(self.request('/nope', host=host, cookie=c)[0], 404)
            self.assertEqual(self.request('/api/messages', host=host, cookie=c)[0], 404)

    def test_next_is_not_an_open_redirect(self):
        c = self.cookie()
        for host in ['nullverse.cloud', SSLIP]:
            self.assertEqual(self.request('/?next=/mail', host=host, cookie=c)[1]['Location'], '/mail')
            for bad in ['//evil.example', 'https://evil.example', '/%2F%2Fevil.example', '/unknown', '/api/me',
                        '/link/../x', '\\\\evil.example']:
                loc = self.request('/?next=' + bad, host=host, cookie=c)[1]['Location']
                self.assertEqual(loc, '/projects', bad)

    def test_map_validation_rejects_offsite_targets(self):
        links = server._parse_portal_links({'links': {
            '/ok': {'cloud': 'https://x.nullverse.cloud'},
            '/evil': {'cloud': 'https://evil.example'},
            '/evil2': {'cloud': 'https://nullverse.cloud.evil.example'},
            '/http': {'cloud': 'http://nullink.nullverse.cloud'},
            '/userinfo': {'cloud': 'https://a@nullink.nullverse.cloud'},
            '/projects': {'cloud': 'https://nullink.nullverse.cloud'},
            '/UPPER': {'cloud': 'https://nullink.nullverse.cloud'},
            '/soon': {'name': 'Soon'},
        }})
        self.assertEqual(sorted(links), ['/ok', '/soon'])
        self.assertTrue(links['/soon']['coming_soon'])

    def test_gate_endpoint(self):
        c = self.cookie()
        for host in ['nullink.nullverse.cloud', 'nullink.216.158.238.236.sslip.io']:
            self.assertEqual(self.request('/api/auth/gate', host=host, cookie=c)[0], 204)
            self.assertEqual(self.request('/api/auth/gate', host=host)[0], 401)
            status, headers, _ = self.request('/api/auth/gate', host=host,
                                              extra_headers={'Sec-Fetch-Mode': 'navigate'})
            self.assertEqual((status, headers['Location']), (302, '/'))
            token = self.session_cookie()
            self.assertEqual(self.request('/api/auth/gate', host=host,
                                          extra_headers={'Authorization': 'Bearer ' + token})[0], 401)
        self.assertEqual(self.request('/api/auth/gate', host='nullverse.cloud', cookie=c)[0], 404)

    def test_api_apps_requires_session(self):
        self.assertEqual(self.request('/api/apps', host='nullink.nullverse.cloud')[0], 401)
        self.assertEqual(self.request('/api/apps', host='nullink.nullverse.cloud', cookie=self.cookie())[0], 200)

    def test_sslip_portal_cookie_is_host_prefixed(self):
        self.assertIn(SSLIP, server.PUBLIC_HTTPS_HOSTS)


if __name__ == '__main__':
    unittest.main()
