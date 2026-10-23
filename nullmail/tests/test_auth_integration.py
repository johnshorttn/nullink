"""Exercise the live integration contract with isolated real Nullink auth state."""
import http.client,json,pathlib,sys,tempfile,threading,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[2]))
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import server as nullink
import app

class AuthIntegration(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();root=pathlib.Path(self.tmp.name);self.patches=[]
        for name in dir(nullink):
            value=getattr(nullink,name)
            if isinstance(value,pathlib.Path) and name not in ('BASE','STATIC'):
                try:rel=value.resolve().relative_to(nullink.BASE.resolve())
                except ValueError:continue
                self.patches.append(patch.object(nullink,name,root/rel))
        for p in self.patches:p.start()
        nullink.SECRETS.mkdir(parents=True);nullink.DATA.mkdir(parents=True);nullink.SESSION_SECRET_FILE.write_text('fixture-only-key')
        self.server=nullink.ThreadingHTTPServer(('127.0.0.1',0),nullink.Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.port=patch.object(app,'AUTH_PORT',self.server.server_port);self.port.start()
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join();self.port.stop()
        for p in reversed(self.patches):p.stop()
        self.tmp.cleanup()
    def test_pin_cookie_validation_and_revocation(self):
        nullink.write_otp('123456')
        status,_,cookie=app.nullink('/api/auth/verify',body=b'{"code":"123456"}',client_ip='198.51.100.20')
        self.assertEqual(status,200);self.assertTrue(cookie.startswith('__Host-nullink_session='))
        self.assertIn('Secure',cookie);self.assertIn('HttpOnly',cookie);self.assertNotIn('Domain=',cookie)
        cookie=cookie.split(';',1)[0]
        self.assertEqual(app.nullink('/api/me',cookie)[0],200)
        self.assertEqual(app.nullink('/api/auth/logout',cookie,b'{}')[0],200)
        self.assertEqual(app.nullink('/api/me',cookie)[0],401)
        self.assertIn(app.nullink('/api/auth/verify',body=b'{"code":"123456"}')[0],(401,503))
    def test_totp_and_per_client_rate_limit(self):
        import time
        secret='GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
        nullink.save_totp({'enabled':True,'secret':secret})
        code=nullink._totp_value(secret,int(time.time()//nullink.TOTP_STEP_SEC))
        status,_,cookie=app.nullink('/api/auth/verify',body=json.dumps({'code':code}).encode(),client_ip='198.51.100.21')
        self.assertEqual(status,200);self.assertIsNotNone(cookie)
        for i in range(5):status,_,_=app.nullink('/api/auth/verify',body=b'{"code":"invalid"}',client_ip='198.51.100.22')
        self.assertEqual(status,429)
        status,_,_=app.nullink('/api/auth/verify',body=b'{"code":"invalid"}',client_ip='198.51.100.23')
        self.assertEqual(status,401)

if __name__=='__main__':unittest.main()

class PixelSessionCheck(AuthIntegration):
    """owner_session_live against real Nullink auth state: valid, fake, expired, none; never touches."""
    def _token(self):
        token,_=nullink.create_session('127.0.0.1','pixel test','test');return token
    def test_valid_session_is_live_and_untouched(self):
        token=self._token();before=nullink.load_sessions()
        self.assertTrue(app.owner_session_live(app.COOKIE_NAME+'='+token))
        self.assertEqual(nullink.load_sessions(),before)
    def test_fake_cookie_is_not_live(self):
        token=self._token();v,sid,sig=token.split('.')
        self.assertFalse(app.owner_session_live(app.COOKIE_NAME+'='+'.'.join([v,sid,'0'*len(sig)])))
        self.assertFalse(app.owner_session_live(app.COOKIE_NAME+'=forged'))
    def test_expired_session_is_not_live(self):
        token=self._token();s=nullink.load_sessions()
        for r in s.values():r['expires_at']=1
        nullink.save_sessions(s)
        self.assertFalse(app.owner_session_live(app.COOKIE_NAME+'='+token))
    def test_no_cookie_is_not_live(self):
        self.assertFalse(app.owner_session_live(''))
