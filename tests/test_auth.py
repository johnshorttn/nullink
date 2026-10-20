"""Auth hardening tests (2026-10-06): single-use PIN, per-client lockout with
backoff + global ceiling, server-side sessions, step-up, proxy-aware localhost
checks, bearer tokens, desktop credentials removal.

Runs the real Handler on an ephemeral loopback port with every BASE-relative
state path redirected into a temp dir (never touches real secrets/data).
"""
import hashlib
import hmac
import http.client
import json
import os
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import server

TOTP_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # RFC 6238 test key, test-only
HTTPS_HOST = "nullink.216.158.238.236.sslip.io"


def totp_code(offset_steps=0, now=None):
    counter = int((time.time() if now is None else now) // server.TOTP_STEP_SEC) + offset_steps
    return server._totp_value(TOTP_SECRET, counter)


class AuthBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        base = server.BASE.resolve()
        cls.patches = []
        for name in dir(server):
            val = getattr(server, name)
            if isinstance(val, Path) and name != "STATIC" and name != "BASE":
                try:
                    rel = val.resolve().relative_to(base)
                except ValueError:
                    continue
                cls.patches.append(patch.object(server, name, cls.root / rel))
        for p in cls.patches:
            p.start()
        server.SECRETS.mkdir(parents=True, exist_ok=True)
        server.DATA.mkdir(parents=True, exist_ok=True)
        server.SESSION_SECRET_FILE.write_text("isolated-auth-test-secret")
        server.MESSAGES_FILE.write_text("")
        cls.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join()
        for p in reversed(cls.patches):
            p.stop()
        cls.tmp.cleanup()

    def setUp(self):
        for f in (server.OTP_FILE, server.TOTP_FILE, server.RATE_FILE, server.SESSIONS_FILE):
            try:
                f.unlink()
            except FileNotFoundError:
                pass

    # --- helpers ---
    def req(self, path, method="GET", body=None, cookie=None, host=HTTPS_HOST, xff="198.51.100.10",
            proto="https", headers=None, raw_headers=False):
        conn = http.client.HTTPConnection("127.0.0.1", self.httpd.server_port, timeout=10)
        h = {"Host": host}
        if xff is not None:
            h["X-Forwarded-For"] = xff
        if proto is not None:
            h["X-Forwarded-Proto"] = proto
        if cookie:
            h["Cookie"] = cookie
        if body is not None:
            h["Content-Type"] = "application/json"
            body = json.dumps(body)
        h.update(headers or {})
        conn.request(method, path, body=body, headers=h)
        r = conn.getresponse()
        data = r.read()
        hdrs = r.getheaders()
        conn.close()
        try:
            js = json.loads(data) if data else {}
        except ValueError:
            js = {}
        return r.status, hdrs, js, data

    @staticmethod
    def cookies(hdrs):
        return [v for k, v in hdrs if k.lower() == "set-cookie"]

    def login(self, code, xff="198.51.100.10", host=HTTPS_HOST, proto="https"):
        st, hdrs, js, _ = self.req("/api/auth/verify", "POST", {"code": code}, xff=xff, host=host, proto=proto)
        cookie = None
        for c in self.cookies(hdrs):
            name_val = c.split(";")[0]
            if name_val.split("=", 1)[1]:
                cookie = name_val
        return st, js, cookie

    def enable_totp(self, recovery=("ABCDE-23456",)):
        server.save_totp({
            "enabled": True, "secret": TOTP_SECRET, "account": "owner", "last_counter": -1,
            "recovery_hashes": [server._recovery_hash(c) for c in recovery],
        })

    def age_stepup(self, seconds=600):
        sessions = server.load_sessions()
        for rec in sessions.values():
            rec["stepup_at"] = time.time() - seconds
        server.save_sessions(sessions)


class PinTests(AuthBase):
    def test_generate_pin_uses_secrets_and_format(self):
        pins = {server.generate_pin() for _ in range(200)}
        self.assertTrue(all(len(p) == 6 and p.isdigit() for p in pins))
        self.assertGreater(len(pins), 150)
        src = Path(server.__file__).with_name("set_otp.py").read_text()
        self.assertNotIn("import random", src)
        self.assertNotIn("random.randint", Path(server.__file__).read_text())

    def test_write_otp_no_cleartext_and_mode_600(self):
        legacy = server.SECRETS / "CURRENT_PIN.txt"
        legacy.write_text("111111\n")
        server.write_otp("246810")
        self.assertFalse(legacy.exists(), "legacy clear-text PIN copy must be removed")
        raw = server.OTP_FILE.read_text()
        self.assertNotIn("246810", raw)
        data = json.loads(raw)
        self.assertEqual(data["kdf"], "pbkdf2-sha256")
        self.assertEqual(stat.S_IMODE(os.stat(server.OTP_FILE).st_mode), 0o600)
        self.assertAlmostEqual(data["expires_at"] - data["created_at"], 24 * 3600, delta=2)
        self.assertEqual([p.name for p in server.SECRETS.iterdir() if "PIN" in p.name.upper()], [])

    def test_pin_works_once_then_fails(self):
        server.write_otp("135790")
        st, js, cookie = self.login("135790")
        self.assertEqual(st, 200, js)
        self.assertEqual(js["method"], "pin")
        self.assertIsNotNone(cookie)
        self.assertFalse(server.OTP_FILE.exists(), "PIN must be consumed")
        st, js, _ = self.login("135790")
        self.assertEqual(st, 503)
        self.assertEqual(js["error"], "no_otp")

    def test_pin_single_use_in_totp_mode_too(self):
        self.enable_totp()
        server.write_otp("864209")
        self.assertEqual(self.login("864209")[0], 200)
        st, js, _ = self.login("864209")
        self.assertEqual(st, 401)

    def test_expired_pin_fails(self):
        server.write_otp("102938", 60)
        data = json.loads(server.OTP_FILE.read_text())
        data["expires_at"] = time.time() - 1
        server.OTP_FILE.write_text(json.dumps(data))
        st, js, _ = self.login("102938")
        self.assertEqual(st, 401)
        self.assertEqual(js["error"], "expired")

    def test_legacy_sha256_pin_record_still_verifies(self):
        server.OTP_FILE.write_text(json.dumps({"salt": "s", "pin_hash": server.hash_pin("777333", "s"),
                                               "expires_at": time.time() + 60}))
        self.assertEqual(self.login("777333")[0], 200)

    def test_set_otp_script_prints_once_and_stores_hash_only(self):
        import subprocess, sys
        script = Path(server.__file__).with_name("set_otp.py")
        # run in-process to honour patched paths
        import importlib.util
        spec = importlib.util.spec_from_file_location("set_otp_mod", script)
        mod = importlib.util.module_from_spec(spec)
        import io, contextlib
        buf = io.StringIO()
        with patch.object(sys, "argv", ["set_otp.py", "--ttl-hours", "1"]), contextlib.redirect_stdout(buf):
            spec.loader.exec_module(mod)
            mod.main()
        out = buf.getvalue()
        pin = out.split("PIN: ")[1].split()[0]
        self.assertRegex(pin, r"^\d{6}$")
        self.assertNotIn(pin, server.OTP_FILE.read_text())
        data = json.loads(server.OTP_FILE.read_text())
        self.assertAlmostEqual(data["expires_at"] - data["created_at"], 3600, delta=2)
        self.assertEqual(self.login(pin)[0], 200)


class TotpHttpTests(AuthBase):
    def test_totp_valid_replay_and_window(self):
        self.enable_totp()
        now = time.time()
        # avoid step boundary flakiness
        if now % 30 > 27:
            time.sleep(3.2)
        self.assertEqual(self.login(totp_code(-1))[0], 200)       # previous step accepted
        self.assertEqual(self.login(totp_code(-1))[0], 401)       # replay rejected
        self.assertEqual(self.login(totp_code(0))[0], 200)        # current step
        self.assertEqual(self.login(totp_code(0))[0], 401)        # replay rejected
        self.assertEqual(self.login(totp_code(+2), xff="198.51.100.11")[0], 401)  # outside window
        self.assertEqual(self.login(totp_code(+1), xff="198.51.100.11")[0], 200)  # next step ok

    def test_recovery_code_single_use(self):
        self.enable_totp(recovery=("ABCDE-23456", "QRSTU-76543"))
        self.assertEqual(self.login("abcde-23456")[0], 200)
        self.assertEqual(self.login("ABCDE-23456")[0], 401)
        self.assertEqual(len(server.load_totp()["recovery_hashes"]), 1)


class LockoutTests(AuthBase):
    def test_per_ip_lockout_backoff_and_other_ip_unaffected(self):
        server.write_otp("555111")
        a, b = "203.0.113.1", "203.0.113.2"
        for i in range(4):
            st, js, _ = self.login("000000", xff=a)
            self.assertEqual(st, 401)
            self.assertEqual(js["attempts_left"], 4 - i)
        st, js, _ = self.login("000000", xff=a)
        self.assertEqual(st, 429)
        self.assertEqual(js["retry_after_sec"], 15 * 60)
        # even the right PIN is refused while locked
        self.assertEqual(self.login("555111", xff=a)[0], 429)
        # other client unaffected and can log in
        st, js, _ = self.login("000000", xff=b)
        self.assertEqual((st, js.get("attempts_left")), (401, 4))
        self.assertEqual(self.login("555111", xff=b)[0], 200)
        self.assertNotIn(b, server.load_rate()["ips"], "success resets that client")
        # expire A's lock -> next lockout doubles (exponential backoff)
        rate = server.load_rate()
        rate["ips"][a]["locked_until"] = time.time() - 1
        server.write_otp("555222")  # B consumed the PIN; new PIN (this resets limits)...
        server.save_rate(rate)      # ...so restore A's escalation state
        for _ in range(4):
            self.assertEqual(self.login("000000", xff=a)[0], 401)
        st, js, _ = self.login("000000", xff=a)
        self.assertEqual(st, 429)
        self.assertEqual(js["retry_after_sec"], 30 * 60)

    def test_success_resets_client_counter(self):
        server.write_otp("424242")
        ip = "203.0.113.5"
        for _ in range(3):
            self.login("000001", xff=ip)
        self.assertEqual(server.load_rate()["ips"][ip]["fails"], 3)
        self.assertEqual(self.login("424242", xff=ip)[0], 200)
        self.assertNotIn(ip, server.load_rate()["ips"])

    def test_spoofed_xff_cannot_bypass(self):
        server.write_otp("909090")
        real = "192.0.2.77"
        lefts = []
        for i in range(5):
            spoof = f"10.0.0.{i}, 8.8.{i}.{i}"
            st, js, _ = self.login("000002", xff=f"{spoof}, {real}")
            lefts.append(js.get("attempts_left") if st == 401 else st)
        self.assertEqual(lefts, [4, 3, 2, 1, 429])
        rate = server.load_rate()
        self.assertIn(real, rate["ips"])
        self.assertFalse(any(k.startswith("10.") or k.startswith("8.8") for k in rate["ips"]))
        # Multiple XFF header lines: still the rightmost (Caddy-appended) hop
        conn = http.client.HTTPConnection("127.0.0.1", self.httpd.server_port, timeout=10)
        conn.putrequest("POST", "/api/auth/verify", skip_host=True)
        conn.putheader("Host", HTTPS_HOST)
        conn.putheader("X-Forwarded-For", "1.1.1.1")
        conn.putheader("X-Forwarded-For", real)
        body = json.dumps({"code": "909090"}).encode()
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", str(len(body)))
        conn.endheaders(body)
        self.assertEqual(conn.getresponse().status, 429)
        conn.close()

    def test_global_ceiling(self):
        server.write_otp("373737")
        n = 0
        for i in range(server.GLOBAL_MAX_FAILS // server.IP_MAX_FAILS):
            for _ in range(server.IP_MAX_FAILS):
                st, js, _ = self.login("000003", xff=f"198.18.{i}.1")
                n += 1
        self.assertEqual(n, server.GLOBAL_MAX_FAILS)
        st, js, _ = self.login("373737", xff="198.18.200.200")
        self.assertEqual(st, 429)
        self.assertEqual(js["scope"], "global")
        # Morc setting a new PIN clears all lockouts
        server.write_otp("383838")
        self.assertEqual(self.login("383838", xff="198.18.200.200")[0], 200)

    def test_ceiling_not_reachable_by_single_ip(self):
        server.write_otp("494949")
        for _ in range(12):
            self.login("000004", xff="198.19.0.1")
        g = server.load_rate()["global"]
        self.assertEqual(g["locked_until"], 0)
        self.assertEqual(self.login("494949", xff="198.19.0.2")[0], 200)


class SessionTests(AuthBase):
    def test_cookie_flags_https_and_local(self):
        server.write_otp("121212")
        st, hdrs, js, _ = self.req("/api/auth/verify", "POST", {"code": "121212"})
        sc = [c for c in self.cookies(hdrs) if c.startswith("__Host-")][0]
        for flag in ("Path=/", "Secure", "HttpOnly", "SameSite=Lax", "Max-Age=86400"):
            self.assertIn(flag, sc)
        self.assertNotIn("Domain", sc)
        # plain http localhost: non-prefixed cookie without Secure
        server.write_otp("131313")
        st, hdrs, js, _ = self.req("/api/auth/verify", "POST", {"code": "131313"}, host="127.0.0.1",
                                    xff=None, proto=None)
        self.assertEqual(st, 200)
        lc = self.cookies(hdrs)[-1]
        self.assertTrue(lc.startswith("nullink_session="))
        self.assertNotIn("Secure", lc)
        # a local cookie is not accepted on the HTTPS host and vice versa
        local_cookie = lc.split(";")[0]
        self.assertEqual(self.req("/api/me", cookie=local_cookie)[0], 401)
        self.assertEqual(self.req("/api/me", cookie=local_cookie, host="127.0.0.1", xff=None, proto=None)[0], 200)

    def test_store_holds_hash_not_raw_session_id(self):
        server.write_otp("141414")
        _, _, cookie = self.login("141414")
        sid = cookie.split("=", 1)[1].split(".")[1]
        raw = server.SESSIONS_FILE.read_text()
        self.assertNotIn(sid, raw)
        self.assertIn(hashlib.sha256(sid.encode()).hexdigest(), raw)
        self.assertEqual(stat.S_IMODE(os.stat(server.SESSIONS_FILE).st_mode), 0o600)
        rec = list(json.loads(raw)["sessions"].values())[0]
        self.assertEqual(rec["ip"], "198.51.100.10")

    def test_logout_revokes_copied_cookie(self):
        server.write_otp("151515")
        _, _, cookie = self.login("151515")
        self.assertEqual(self.req("/api/me", cookie=cookie)[0], 200)
        st, hdrs, _, _ = self.req("/api/auth/logout", "POST", cookie=cookie)
        self.assertEqual(st, 200)
        self.assertTrue(all("Max-Age=0" in c for c in self.cookies(hdrs)))
        self.assertEqual(self.req("/api/me", cookie=cookie)[0], 401)  # copied cookie dead

    def test_sign_out_everywhere(self):
        self.enable_totp(recovery=("AAAAA-22222", "BBBBB-33333"))
        _, _, c1 = self.login("AAAAA-22222", xff="198.51.100.20")
        _, _, c2 = self.login("BBBBB-33333", xff="198.51.100.21")
        st, _, js, _ = self.req("/api/auth/sessions", cookie=c1)
        self.assertEqual((st, js["count"]), (200, 2))
        self.assertEqual(self.req("/api/auth/logout-all", "POST")[0], 401)  # needs auth
        st, _, js, _ = self.req("/api/auth/logout-all", "POST", cookie=c1)
        self.assertEqual((st, js["revoked"]), (200, 2))
        self.assertEqual(self.req("/api/me", cookie=c1)[0], 401)
        self.assertEqual(self.req("/api/me", cookie=c2)[0], 401)

    def test_old_cookie_formats_rejected(self):
        exp = int(time.time()) + 3600
        payload = f"ok:{exp}"
        sig = hmac.new(server.session_secret(), payload.encode(), hashlib.sha256).hexdigest()
        old = f"{payload}.{sig}"
        self.assertEqual(self.req("/api/me", cookie=f"morc_session={old}")[0], 401)
        self.assertEqual(self.req("/api/me", cookie=f"{server.COOKIE_NAME}={old}")[0], 401)
        # forged v2 with bad signature / unknown id
        self.assertEqual(self.req("/api/me", cookie=f"{server.COOKIE_NAME}=v2.{'A'*43}.{'0'*64}")[0], 401)
        sid = "B" * 43
        good_sig = server._session_sig(sid)
        self.assertEqual(self.req("/api/me", cookie=f"{server.COOKIE_NAME}=v2.{sid}.{good_sig}")[0], 401)

    def test_expired_session_rejected(self):
        value, rec = server.create_session("x", "ua", "pin")
        sessions = server.load_sessions()
        for r in sessions.values():
            r["expires_at"] = time.time() - 1
        server.save_sessions(sessions)
        self.assertEqual(self.req("/api/me", cookie=f"{server.COOKIE_NAME}={value}")[0], 401)


class StepUpTests(AuthBase):
    def _session(self):
        self.enable_totp(recovery=("CCCCC-44444", "DDDDD-55555", "EEEEE-66666"))
        _, _, cookie = self.login("CCCCC-44444")
        return cookie

    def test_fresh_login_counts_as_stepup(self):
        cookie = self._session()
        st, _, js, _ = self.req("/api/auth/tokens", "POST",
                                {"name": "t", "sessions": ["chatgpt"]}, cookie=cookie)
        self.assertEqual(st, 200, js)

    def test_stale_session_needs_stepup_for_sensitive_ops(self):
        cookie = self._session()
        rec, _ = server.create_api_token("victim", list(server.AGENT_SCOPES), ["chatgpt"])
        self.age_stepup()
        checks = [
            ("/api/auth/totp/setup", "POST", {"account": "owner"}),
            ("/api/auth/totp/confirm", "POST", {"code": "123456"}),
            ("/api/auth/totp/disable", "POST", {"code": "123456"}),
            ("/api/auth/tokens", "POST", {"name": "x", "sessions": ["chatgpt"]}),
            (f"/api/auth/tokens/{rec['id']}", "DELETE", None),
        ]
        for path, method, body in checks:
            st, _, js, _ = self.req(path, method, body, cookie=cookie)
            self.assertEqual((st, js.get("error")), (403, "step_up_required"), path)
        # listing tokens / sessions does not need step-up
        self.assertEqual(self.req("/api/auth/tokens", cookie=cookie)[0], 200)
        # wrong step-up code counts toward lockout
        st, _, js, _ = self.req("/api/auth/stepup", "POST", {"code": "ZZZZZ-ZZZZZ"}, cookie=cookie)
        self.assertEqual((st, js.get("attempts_left")), (401, 4))
        # valid step-up (recovery code) unlocks sensitive ops for 5 minutes
        st, _, js, _ = self.req("/api/auth/stepup", "POST", {"code": "DDDDD-55555"}, cookie=cookie)
        self.assertEqual(st, 200, js)
        st, _, js, _ = self.req(f"/api/auth/tokens/{rec['id']}", "DELETE", cookie=cookie)
        self.assertEqual(st, 200, js)
        # TOTP disable after step-up still requires a valid current code
        st, _, js, _ = self.req("/api/auth/totp/disable", "POST", {"code": "000000"}, cookie=cookie)
        self.assertEqual(st, 401)

    def test_stepup_with_totp_code_then_disable_and_setup(self):
        cookie = self._session()
        self.age_stepup()
        if time.time() % 30 > 27:
            time.sleep(3.2)
        code = totp_code(0)
        self.assertEqual(self.req("/api/auth/stepup", "POST", {"code": code}, cookie=cookie)[0], 200)
        st, _, js, _ = self.req("/api/auth/totp/disable", "POST", {"code": code}, cookie=cookie)
        self.assertEqual(st, 200, js)
        st, _, js, _ = self.req("/api/auth/totp/setup", "POST", {"account": "owner"}, cookie=cookie)
        self.assertEqual(st, 200, js)
        self.assertIn("otpauth://", js["uri"])

    def test_stepup_requires_session(self):
        self.assertEqual(self.req("/api/auth/stepup", "POST", {"code": "123456"})[0], 401)

    def test_bearer_cannot_use_cookie_only_auth_ops(self):
        _, token = server.create_api_token("bot", list(server.AGENT_SCOPES), ["chatgpt"])
        h = {"Authorization": f"Bearer {token}"}
        self.assertEqual(self.req("/api/auth/tokens", "POST", {"name": "x", "sessions": ["chatgpt"]}, headers=h)[0], 403)
        self.assertEqual(self.req("/api/auth/totp/setup", "POST", {}, headers=h)[0], 403)
        self.assertEqual(self.req("/api/auth/stepup", "POST", {"code": "1"}, headers=h)[0], 403)


class BearerTests(AuthBase):
    def test_bearer_token_messages_sse_and_scopes(self):
        _, token = server.create_api_token("chatgpt-mcp", list(server.AGENT_SCOPES), ["chatgpt"])
        h = {"Authorization": f"Bearer {token}"}
        st, _, js, _ = self.req("/api/me", headers=h)
        self.assertEqual((st, js.get("auth_type")), (200, "bearer"))
        self.assertEqual(self.req("/api/messages?session=chatgpt", headers=h)[0], 200)
        self.assertEqual(self.req("/api/messages?session=morc", headers=h)[0], 403)
        st, _, js, _ = self.req("/api/messages", "POST", {"text": "hi", "session_id": "chatgpt"}, headers=h)
        self.assertEqual(st, 200, js)
        self.assertEqual(self.req("/api/sessions", headers=h)[0], 200)
        self.assertEqual(self.req("/api/ping", headers=h)[0], 200)
        self.assertEqual(self.req("/api/me", headers={"Authorization": "Bearer nlk_invalid"})[0], 401)
        # SSE stream accepts the bearer token
        conn = http.client.HTTPConnection("127.0.0.1", self.httpd.server_port, timeout=10)
        conn.request("GET", "/api/messages/stream?session=chatgpt&after=0",
                     headers={"Host": HTTPS_HOST, "Authorization": f"Bearer {token}"})
        r = conn.getresponse()
        self.assertEqual(r.status, 200)
        self.assertIn("text/event-stream", r.getheader("Content-Type"))
        conn.close()


class LocalhostTests(AuthBase):
    def test_admin_local_only_and_proxy_headers_rejected(self):
        for path, body in (("/api/admin/set-otp", {"pin": "x"}), ("/api/admin/reply", {}),
                           ("/api/files/register", {})):
            st, _, js, _ = self.req(path, "POST", body, host="127.0.0.1", xff=None, proto=None)
            self.assertEqual(st, 400, (path, js))
            for hdr in ({"X-Forwarded-For": "127.0.0.1"}, {"X-Forwarded-Host": "localhost"},
                        {"X-Forwarded-Proto": "https"}, {"Forwarded": "for=127.0.0.1"}):
                st, _, js, _ = self.req(path, "POST", body, host="127.0.0.1", xff=None, proto=None, headers=hdr)
                if path == "/api/files/register":
                    self.assertEqual(st, 403, (path, hdr))
                else:
                    self.assertEqual((st, js.get("error")), (403, "localhost_only"), (path, hdr))

    def test_admin_set_otp_local_sets_single_use_pin_no_cleartext(self):
        st, _, js, _ = self.req("/api/admin/set-otp", "POST", {"pin": "616161", "ttl_sec": 3600},
                                host="127.0.0.1", xff=None, proto=None)
        self.assertEqual((st, js.get("single_use")), (200, True))
        self.assertFalse((server.SECRETS / "CURRENT_PIN.txt").exists())
        self.assertEqual(self.login("616161")[0], 200)
        self.assertNotEqual(self.login("616161")[0], 200)


class DesktopAndUiTests(AuthBase):
    def test_desktop_credentials_removed_and_launch_works(self):
        server.write_otp("717171")
        _, _, cookie = self.login("717171")
        self.assertEqual(self.req("/api/desktop/credentials")[0], 401)
        st, _, js, _ = self.req("/api/desktop/credentials", cookie=cookie)
        self.assertEqual(st, 410)
        self.assertNotIn("password", js)
        fake = {"embedUrl": "/desktop/#/client/x?token=t", "username": "desk"}
        with patch.object(server, "guacamole_desktop_launch", return_value=fake):
            st, _, js, _ = self.req("/api/desktop/launch", cookie=cookie)
        self.assertEqual((st, js.get("embedUrl")), (200, fake["embedUrl"]))
        self.assertEqual(self.req("/api/desktop/launch")[0], 401)

    def test_ui_assets(self):
        st, _, _, html = self.req("/")
        self.assertEqual(st, 200)
        for marker in (b'id="pin-form"', b'id="auth-method-totp"', b'id="auth-method-pin"',
                       b'id="logout-all-btn"', b'id="security-btn"'):
            self.assertIn(marker, html)
        self.assertNotIn(b"btn-apps-fill", html)
        st, _, _, js = self.req("/app.js")
        self.assertEqual(st, 200)
        self.assertNotIn(b"/api/desktop/credentials", js)
        for marker in (b"stepUpFetch", b"/api/auth/logout-all", b"/api/auth/stepup"):
            self.assertIn(marker, js)
        st, _, js_, _ = self.req("/api/auth/method")
        self.assertEqual(st, 200)
        self.enable_totp()
        self.assertEqual(self.req("/api/auth/method")[2]["method"], "both")

    def test_portal_login_flow(self):
        server.write_otp("818181")
        st, hdrs, js, _ = self.req("/api/auth/verify", "POST", {"code": "818181"}, host="nullverse.cloud")
        self.assertEqual(st, 200)
        cookie = [c for c in self.cookies(hdrs) if c.startswith("__Host-")][0].split(";")[0]
        st, hdrs, _, _ = self.req("/", host="nullverse.cloud", cookie=cookie)
        self.assertEqual((st, dict(hdrs).get("Location")), (302, "/projects"))
        self.assertEqual(self.req("/projects", host="nullverse.cloud", cookie=cookie)[0], 200)
        self.assertEqual(self.req("/projects", host="nullverse.cloud")[0], 302)
        self.assertEqual(self.req("/api/auth/stepup", "POST", {"code": "1"}, host="nullverse.cloud", cookie=cookie)[0], 404)


if __name__ == "__main__":
    unittest.main()
