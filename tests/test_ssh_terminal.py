"""SSH terminal (2026-10-19): Nullink side. TOTP-only step-up for the terminal (/api/ssh/stepup)
and the loopback-only owner check (/api/admin/ssh-session) used by the nullink-ssh service."""
import json
import time
import unittest

import server
from tests.test_auth import AuthBase, totp_code
from tests import test_guest as _tg  # module import: keeps GuestTests out of this module's discovery

ORIGIN = "https://nullink.216.158.238.236.sslip.io"


class SshTerminalTests(AuthBase):
    # reuse the guest helpers without re-running GuestTests' own tests
    request, approve, redeem, guest = (_tg.GuestTests.request, _tg.GuestTests.approve,
                                       _tg.GuestTests.redeem, _tg.GuestTests.guest)

    def setUp(self):
        super().setUp()
        for f in (server.GUEST_FILE, server.GUEST_AUDIT_FILE):
            try:
                f.unlink()
            except FileNotFoundError:
                pass
        self.enable_totp()
        st, _, self.owner = self.login(totp_code())
        self.assertEqual(st, 200)
        try:
            server.SSH_AUDIT_FILE.unlink()
        except FileNotFoundError:
            pass

    def token_of(self, cookie):
        return cookie.split("=", 1)[1]

    def stepup(self, code, cookie=None, origin=ORIGIN, headers=None):
        h = {"Origin": origin} if origin else {}
        h.update(headers or {})
        return self.req("/api/ssh/stepup", "POST", {"code": code}, cookie=cookie or self.owner, headers=h)

    def check(self, token, local=True, headers=None):
        # nullink-ssh calls straight to loopback: no proxy headers
        if local:
            return self.req("/api/admin/ssh-session", "POST", {"token": token}, xff=None, proto=None,
                            host="127.0.0.1", headers=headers)
        return self.req("/api/admin/ssh-session", "POST", {"token": token}, headers=headers)

    def audit(self):
        if not server.SSH_AUDIT_FILE.exists():
            return []
        return [json.loads(x) for x in server.SSH_AUDIT_FILE.read_text().splitlines() if x]

    def test_owner_stepup_marks_session(self):
        st, _, js, _ = self.check(self.token_of(self.owner))
        self.assertTrue(js["ok"])
        self.assertEqual(js["ssh_stepup_at"], 0)  # login alone does not unlock the terminal
        st, _, js, _ = self.stepup(totp_code(1))
        self.assertEqual(st, 200, js)
        self.assertEqual(js["valid_for_sec"], 600)
        st, _, js, _ = self.check(self.token_of(self.owner))
        self.assertTrue(js["ok"])
        self.assertLess(time.time() - js["ssh_stepup_at"], 5)
        self.assertIn("stepup_ok", [e["event"] for e in self.audit()])

    def test_stepup_code_cannot_be_replayed_and_wrong_code_fails(self):
        st, _, _, _ = self.stepup(totp_code(1))
        self.assertEqual(st, 200)
        st, _, js, _ = self.stepup(totp_code(1))
        self.assertEqual(st, 401)
        st, _, js, _ = self.stepup("000000" if totp_code(1) != "000000" else "111111")
        self.assertEqual(st, 401)
        self.assertIn("stepup_failed", [e["event"] for e in self.audit()])

    def test_stepup_is_totp_only_no_recovery_or_pin(self):
        st, _, _, _ = self.stepup("ABCDE-23456")
        self.assertEqual(st, 401)
        cfg = server.load_totp()
        self.assertEqual(len(cfg["recovery_hashes"]), 1, "recovery code must not be consumed")

    def test_stepup_requires_origin(self):
        for origin in (None, "https://evil.example"):
            st, _, js, _ = self.stepup(totp_code(1), origin=origin)
            self.assertEqual(st, 403)
            self.assertEqual(js["error"], "bad_origin")

    def test_stepup_refuses_bearer_and_anonymous(self):
        _rec, plain = server.create_api_token("ai-connector", ["read"], ["*"])
        st, _, _, _ = self.req("/api/ssh/stepup", "POST", {"code": totp_code(1)},
                               headers={"Origin": ORIGIN, "Authorization": f"Bearer {plain}"})
        self.assertEqual(st, 403)
        st, _, _, _ = self.req("/api/ssh/stepup", "POST", {"code": totp_code(1)}, headers={"Origin": ORIGIN})
        self.assertEqual(st, 401)

    def test_guest_refused_everywhere(self):
        gck, _ = self.guest("full")
        st, _, js, _ = self.stepup(totp_code(1), cookie=gck)
        self.assertEqual(st, 403)
        st, _, js, _ = self.check(self.token_of(gck))
        self.assertEqual(st, 200)
        self.assertFalse(js["ok"])
        self.assertEqual(js["reason"], "guest")
        # guests can't pass the Caddy forward_auth gate for /ssh either
        st, _, _, _ = self.req("/api/auth/gate", cookie=gck)
        self.assertNotIn(st, (200, 204))

    def test_check_is_loopback_only(self):
        st, _, js, _ = self.check(self.token_of(self.owner), local=False)
        self.assertEqual(st, 403)
        st, _, js, _ = self.check("v2.bogus.sig")
        self.assertFalse(js["ok"])

    def test_owner_passes_gate(self):
        st, _, _, _ = self.req("/api/auth/gate", cookie=self.owner)
        self.assertEqual(st, 204)


if __name__ == "__main__":
    unittest.main()
