import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlencode, parse_qs, urlsplit
from urllib.request import Request, urlopen, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError

from oauth_store import Store, OAuthError, challenge, SCOPE
from oauth_gateway import Handler, configure
from http.server import ThreadingHTTPServer


class OAuthFixture:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.config = {'issuer':'https://nullink.example/connect/oauth',
                       'resource':'https://nullink.example/connect/mcp',
                       'redirect_uris':['https://chatgpt.com/connector_platform_oauth_redirect'],
                       'database':str(Path(self.tmp.name)/'oauth.sqlite3')}
        self.store = Store(self.config)
        self.redirect = self.config['redirect_uris'][0]
        self.client = self.store.register({'redirect_uris':[self.redirect]})['client_id']
        self.verifier = 'a'*43
    def tearDown(self): self.tmp.cleanup()
    def args(self):
        return {'client_id':self.client, 'redirect_uri':self.redirect, 'state':'opaque-state',
                'code_challenge':challenge(self.verifier), 'code_challenge_method':'S256',
                'response_type':'code', 'resource':self.store.resource, 'scope':SCOPE}
    def code(self):
        request, browser = self.store.authorize(self.args())
        self.assertIsNone(self.store.poll(request, browser))
        self.store.decide(request, True)
        target = self.store.poll(request, browser)
        params = parse_qs(urlsplit(target).query)
        self.assertEqual(params['iss'], [self.store.issuer])
        self.assertEqual(params['state'], ['opaque-state'])
        return params['code'][0]
    def token_args(self, code=None):
        return {'grant_type':'authorization_code', 'code':code or self.code(),
                'client_id':self.client, 'redirect_uri':self.redirect,
                'code_verifier':self.verifier, 'resource':self.store.resource}

class OAuthTests(OAuthFixture, unittest.TestCase):
    def test_full_flow(self):
        tokens = self.store.token(self.token_args())
        self.assertTrue(self.store.valid(tokens['access_token']))
        self.assertFalse(self.store.valid(tokens['refresh_token']))
        self.assertFalse(self.store.valid('legacy-token'))
    def test_unapproved_cannot_get_code(self):
        request, browser = self.store.authorize(self.args())
        self.assertIsNone(self.store.poll(request, browser))
        with self.assertRaises(OAuthError): self.store.poll(request, 'wrong-browser')
    def test_deny_returns_issuer(self):
        request, browser = self.store.authorize(self.args())
        self.store.decide(request, False)
        params = parse_qs(urlsplit(self.store.poll(request, browser)).query)
        self.assertEqual(params['error'], ['access_denied'])
        self.assertEqual(params['iss'], [self.store.issuer])
    def test_pkce_wrong_verifier(self):
        args = self.token_args()
        args['code_verifier'] = 'b'*43
        with self.assertRaises(OAuthError): self.store.token(args)
    def test_code_replay_revokes_grant(self):
        args = self.token_args()
        token = self.store.token(args)['access_token']
        with self.assertRaises(OAuthError): self.store.token(args)
        self.assertFalse(self.store.valid(token))
    def test_refresh_rotation_and_replay(self):
        token = self.store.token(self.token_args())
        args = {'grant_type':'refresh_token', 'refresh_token':token['refresh_token'],
                'client_id':self.client, 'resource':self.store.resource}
        newer = self.store.token(args)
        self.assertTrue(self.store.valid(newer['access_token']))
        with self.assertRaises(OAuthError): self.store.token(args)
        self.assertFalse(self.store.valid(newer['access_token']))
        self.assertFalse(self.store.valid(token['access_token']))
    def test_expired_access(self):
        token = self.store.token(self.token_args())['access_token']
        with patch('oauth_store.time.time', return_value=time.time()+700):
            self.assertFalse(self.store.valid(token))
    def test_expired_code(self):
        args = self.token_args()
        with patch('oauth_store.time.time', return_value=time.time()+100):
            with self.assertRaises(OAuthError): self.store.token(args)
    def test_expired_request(self):
        request, browser = self.store.authorize(self.args())
        with patch('oauth_store.time.time', return_value=time.time()+700):
            with self.assertRaises(OAuthError): self.store.decide(request, True)
            with self.assertRaises(OAuthError): self.store.poll(request, browser)
    def test_wrong_resource_or_scope(self):
        for key, value in [('resource','https://other.example'), ('scope','other'), ('code_challenge_method','plain')]:
            args=self.args(); args[key]=value
            with self.assertRaises(OAuthError): self.store.authorize(args)
        args=self.token_args(); args['resource']='https://other.example'
        with self.assertRaises(OAuthError): self.store.token(args)
    def test_wrong_client_or_redirect(self):
        for key in ['client_id','redirect_uri']:
            args=self.token_args(); args[key]='wrong'
            with self.assertRaises(OAuthError): self.store.token(args)
    def test_redirect_registration(self):
        with self.assertRaises(OAuthError): self.store.register({'redirect_uris':['https://evil.example']})
        # Registrations for the same fixed public callback are idempotent.
        self.assertEqual(self.store.register({'redirect_uris':[self.redirect]})['client_id'],self.client)
    def test_tokens_hashed_at_rest(self):
        token=self.store.token(self.token_args())
        data=Path(self.config['database']).read_bytes()
        self.assertNotIn(token['access_token'].encode(),data)
        self.assertNotIn(token['refresh_token'].encode(),data)
    def test_revoke(self):
        token=self.store.token(self.token_args())
        self.store.revoke(token['refresh_token'],self.client)
        self.assertFalse(self.store.valid(token['access_token']))
    def test_revoke_all(self):
        token=self.store.token(self.token_args())
        self.store.revoke_all()
        self.assertFalse(self.store.valid(token['access_token']))
    def test_database_resource_binding(self):
        with self.assertRaises(ValueError): Store({**self.config,'resource':'https://nullink.example/other'})
    def test_concurrent_code_redemption(self):
        args=self.token_args()
        outcomes=[]
        def exchange():
            try: outcomes.append(self.store.token(args))
            except OAuthError: outcomes.append(None)
        threads=[threading.Thread(target=exchange) for _ in range(2)]
        for t in threads:t.start()
        for t in threads:t.join()
        self.assertEqual(sum(r is not None for r in outcomes),1)
    def test_browser_poll_one_time(self):
        request,browser=self.store.authorize(self.args())
        self.store.decide(request,True)
        self.store.poll(request,browser)
        with self.assertRaises(OAuthError): self.store.poll(request,browser)


class HTTPTests(OAuthFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        configure(self.server,self.store)
        self.thread=threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.base='http://127.0.0.1:'+str(self.server.server_port)
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join()
        super().tearDown()
    def test_browser_approval_http_roundtrip(self):
        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs): return None
        opener=build_opener(NoRedirect)
        with self.assertRaises(HTTPError) as response:
            opener.open(self.base+'/connect/oauth/authorize?'+urlencode(self.args()))
        self.assertEqual(response.exception.code,303)
        cookie=response.exception.headers['Set-Cookie']
        self.assertIn('Secure; HttpOnly; SameSite=Lax',cookie)
        pending=response.exception.headers['Location']
        request=parse_qs(urlsplit(pending).query)['request'][0]
        req=Request(self.base+pending,headers={'Cookie':cookie.split(';')[0]})
        with opener.open(req) as page:
            self.assertIn(request,page.read().decode())
        self.store.decide(request,True)
        with self.assertRaises(HTTPError) as approved: opener.open(req)
        target=approved.exception.headers['Location']
        self.assertTrue(target.startswith(self.redirect+'?'))
        code=parse_qs(urlsplit(target).query)['code'][0]
        token=self.store.token(self.token_args(code))
        self.assertTrue(self.store.valid(token['access_token']))
    def test_browser_origin_blocked_on_token(self):
        req=Request(self.base+'/connect/oauth/token',data=b'grant_type=x',
                    headers={'Content-Type':'application/x-www-form-urlencoded','Origin':'https://evil.example'})
        with self.assertRaises(HTTPError) as result:urlopen(req)
        self.assertEqual(result.exception.code,403)
    def test_rate_limit(self):
        for _ in range(30):
            self.server.rates.setdefault('authorize', __import__('collections').deque()).append(time.monotonic())
        with self.assertRaises(HTTPError) as result:
            urlopen(self.base+'/connect/oauth/authorize?'+urlencode(self.args()))
        self.assertEqual(result.exception.code,429)
    def test_discovery(self):
        with urlopen(self.base+'/.well-known/oauth-protected-resource/connect/mcp') as r:
            self.assertEqual(json.load(r)['resource'],self.store.resource)
        with urlopen(self.base+'/.well-known/oauth-authorization-server/connect/oauth') as r:
            self.assertEqual(json.load(r)['code_challenge_methods_supported'],['S256'])
    def test_mcp_401_challenge(self):
        # Shared transport uses /mcp until application startup configures public path.
        for token in ['', 'old-admin-token']:
            req=Request(self.base+'/mcp', data=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
                        headers={'Content-Type':'application/json','Authorization':'Bearer '+token})
            with self.assertRaises(HTTPError) as e: urlopen(req)
            self.assertEqual(e.exception.code,401)
            self.assertIn('oauth-protected-resource/connect/mcp',e.exception.headers['WWW-Authenticate'])
    def test_valid_oauth_mcp(self):
        token=self.store.token(self.token_args())['access_token']
        req=Request(self.base+'/mcp',data=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
                    headers={'Content-Type':'application/json','Authorization':'Bearer '+token})
        with urlopen(req) as r:self.assertEqual(json.load(r)['result'],{})
    def test_registration_http(self):
        req=Request(self.base+'/connect/oauth/register',data=json.dumps({'redirect_uris':[self.redirect]}).encode(),headers={'Content-Type':'application/json'})
        with urlopen(req) as r:self.assertEqual(r.status,201)
    def test_token_http_and_duplicate_fields(self):
        args=self.token_args()
        req=Request(self.base+'/connect/oauth/token',data=urlencode(args).encode(),headers={'Content-Type':'application/x-www-form-urlencoded'})
        with urlopen(req) as r:self.assertTrue(self.store.valid(json.load(r)['access_token']))
        req=Request(self.base+'/connect/oauth/token',data=b'grant_type=x&grant_type=y',headers={'Content-Type':'application/x-www-form-urlencoded'})
        with self.assertRaises(HTTPError) as e:urlopen(req)
        self.assertEqual(e.exception.code,400)

class ProcessTests(OAuthFixture, unittest.TestCase):
    def test_real_gateway_startup_and_tools(self):
        import os, socket, subprocess, sys
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0))
            port=sock.getsockname()[1]
        config_path=Path(self.tmp.name)/'oauth.json'
        config_path.write_text(json.dumps(self.config))
        env={**os.environ,'MASTER_OAUTH_CONFIG':str(config_path),'MASTER_OAUTH_PORT':str(port)}
        proc=subprocess.Popen([sys.executable,'oauth_gateway.py'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        try:
            base='http://127.0.0.1:'+str(port)
            deadline=time.monotonic()+5
            while True:
                try:
                    with urlopen(base+'/.well-known/oauth-protected-resource/connect/mcp',timeout=1) as r:
                        self.assertEqual(json.load(r)['resource'],self.store.resource)
                    break
                except OSError:
                    if proc.poll() is not None or time.monotonic()>deadline:
                        self.fail('OAuth gateway did not start')
                    time.sleep(.02)
            token=self.store.token(self.token_args())['access_token']
            req=Request(base+'/connect/mcp',data=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
                        headers={'Content-Type':'application/json','Authorization':'Bearer '+token})
            with urlopen(req) as r: tools=json.load(r)['result']['tools']
            self.assertEqual(len(tools),16)
            self.assertTrue(all(t['securitySchemes']==[{'type':'oauth2','scopes':[SCOPE]}] for t in tools))
        finally:
            proc.terminate()
            proc.wait(timeout=5)
            proc.stderr.close()

if __name__=='__main__':unittest.main()
