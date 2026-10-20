"""Guest access tests (2026-10-14): request, rate limit, approve/deny, single-use 60 s PIN,
10-minute blocks with extend/close, warning tick, read-only enforcement, owner-only gating."""
import time
import unittest
import unittest.mock
from unittest.mock import patch

import server
from tests.test_auth import AuthBase, totp_code


class GuestTests(AuthBase):
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

    def request(self, xff="203.0.113.5", name="Replit AI"):
        return self.req("/api/guest/request", "POST", {"name": name, "reason": "examine layout"}, xff=xff)

    def approve(self, rid, scope="read"):
        return self.req(f"/api/guest/requests/{rid}/approve", "POST", {"scope": scope}, cookie=self.owner)

    def redeem(self, pin, xff="203.0.113.5"):
        st, hdrs, js, _ = self.req("/api/auth/guest/redeem", "POST", {"pin": pin}, xff=xff)
        ck = None
        for c in self.cookies(hdrs):
            nv = c.split(";")[0]
            if nv.split("=", 1)[1]:
                ck = nv
        return st, js, ck

    def guest(self, scope="read"):
        st, _, js, _ = self.request()
        self.assertEqual(st, 201)
        st, _, a, _ = self.approve(js["request_id"], scope)
        self.assertEqual(st, 200)
        st, r, ck = self.redeem(a["pin"])
        self.assertEqual(st, 200)
        return ck, a

    def test_request_and_owner_sees_it(self):
        st, _, js, _ = self.request()
        self.assertEqual(st, 201)
        self.assertRegex(js["request_id"], r"^GR-[A-Z0-9]{6}$")
        st, _, lst, _ = self.req("/api/guest/requests", cookie=self.owner)
        self.assertEqual([p["id"] for p in lst["pending"]], [js["request_id"]])
        self.assertNotIn("poll_hash", lst["pending"][0])
        st, _, s, _ = self.req(f"/api/guest/request/{js['request_id']}?poll={js['poll_token']}")
        self.assertEqual(s["status"], "pending")
        st, _, _, _ = self.req(f"/api/guest/request/{js['request_id']}?poll=wrong")
        self.assertEqual(st, 404)

    def test_unauthenticated_cannot_list_or_approve(self):
        st, _, js, _ = self.request()
        self.assertEqual(self.req("/api/guest/requests")[0], 401)
        self.assertEqual(self.req(f"/api/guest/requests/{js['request_id']}/approve", "POST", {})[0], 401)
        self.assertEqual(self.req("/api/guest/mint", "POST", {})[0], 401)

    def test_rate_limit_per_ip_and_max_pending(self):
        for i in range(3):
            self.assertEqual(self.request(xff=f"203.0.113.{i + 10}")[0], 201)
        st, _, js, _ = self.request(xff="203.0.113.99")
        self.assertEqual((st, js["error"]), (429, "too_many_pending"))
        server.save_guest({"requests": {}, "rate": {}})
        for _ in range(5):
            self.assertEqual(self.request(xff="203.0.113.50")[0], 201)
            server.save_guest({"requests": {}, "rate": server.load_guest()["rate"]})
        st, _, js, _ = self.request(xff="203.0.113.50")
        self.assertEqual((st, js["error"]), (429, "rate_limited"))

    def test_pin_single_use_and_hashed(self):
        st, _, js, _ = self.request()
        _, _, a, _ = self.approve(js["request_id"])
        self.assertRegex(a["pin"], r"^[A-Z0-9]{5}-[A-Z0-9]{5}$")
        self.assertNotIn(a["pin"], server.GUEST_FILE.read_text())
        self.assertNotIn(a["pin"].replace("-", ""), server.GUEST_FILE.read_text())
        st, r, ck = self.redeem(a["pin"])
        self.assertEqual(st, 200)
        self.assertIn(r["expires_in"], (599, 600))  # 10-minute block
        st, _, _ = self.redeem(a["pin"])
        self.assertEqual(st, 401)
        _, _, me, _ = self.req("/api/me", cookie=ck)
        self.assertEqual((me["auth_type"], me["guest"]["scope"], me["guest"]["label"]), ("guest", "read", "guest"))

    def test_pin_expires_after_60_seconds(self):
        st, _, js, _ = self.request()
        _, _, a, _ = self.approve(js["request_id"])
        real = time.time
        with patch.object(server.time, "time", lambda: real() + 61):
            st, _, _ = self.redeem(a["pin"])
        self.assertEqual(st, 401)

    def test_deny(self):
        st, _, js, _ = self.request()
        st, _, d, _ = self.req(f"/api/guest/requests/{js['request_id']}/deny", "POST", {}, cookie=self.owner)
        self.assertEqual(d["status"], "denied")
        self.assertEqual(self.approve(js["request_id"])[0], 409)
        _, _, s, _ = self.req(f"/api/guest/request/{js['request_id']}?poll={js['poll_token']}")
        self.assertEqual(s["status"], "denied")

    def test_read_only_blocks_mutations_and_secrets(self):
        ck, _ = self.guest("read")
        self.assertEqual(self.req("/api/me", cookie=ck)[0], 200)
        self.assertEqual(self.req("/api/sessions", cookie=ck)[0], 200)
        self.assertEqual(self.req("/", cookie=ck)[0], 200)
        for method, path in [("POST", "/api/messages"), ("POST", "/api/files/upload"), ("DELETE", "/api/files/x"),
                             ("PATCH", "/api/labels/x"), ("PUT", "/api/files/save"), ("POST", "/api/vault"),
                             ("POST", "/api/admin/set-otp"), ("POST", "/api/auth/logout-all"),
                             ("GET", "/api/vault"), ("GET", "/api/auth/tokens"), ("GET", "/api/auth/sessions"),
                             ("GET", "/api/desktop/credentials"), ("GET", "/api/auth/gate"),
                             ("GET", "/api/guest/requests"), ("POST", "/api/guest/mint")]:
            st, _, js, _ = self.req(path, method, {} if method != "GET" else None, cookie=ck)
            self.assertEqual((path, st), (path, 403))
            self.assertIn(js.get("error"), ("guest_forbidden", "guest_history_hidden"))
        self.assertEqual(self.req("/api/auth/logout", "POST", {}, cookie=ck)[0], 200)

    def test_history_hidden_for_guests(self):
        self.assertTrue(server.GUEST_HIDE_HISTORY)
        for scope in ("read", "full"):
            ck, _ = self.guest(scope)
            for path in ("/api/messages?session=morc", "/api/messages/stream?session=morc", "/api/files",
                         "/api/files/abc/download", "/api/files/abc/content", "/api/inbox",
                         "/api/session-memory/morc", "/api/tasks", "/api/playground/chatgpt"):
                st, _, js, _ = self.req(path, cookie=ck)
                self.assertEqual((path, st, js.get("error")), (path, 403, "guest_history_hidden"))
            self.assertEqual(self.req("/api/me", cookie=ck)[0], 200)
            server.save_guest({"requests": {}, "rate": {}})
        # owner unaffected
        self.assertNotEqual(self.req("/api/files", cookie=self.owner)[0], 403)
        self.assertNotEqual(self.req("/api/messages?session=morc", cookie=self.owner)[0], 403)

    def test_history_flag_off_allows_reads(self):
        ck, _ = self.guest("read")
        with unittest.mock.patch.object(server, "GUEST_HIDE_HISTORY", False):
            self.assertNotEqual(self.req("/api/files", cookie=ck)[0], 403)
            self.assertEqual(self.req("/api/files/upload", "POST", {}, cookie=ck)[2].get("error"), "guest_forbidden")

    def test_full_guest_cannot_approve_or_see_secrets(self):
        ck, _ = self.guest("full")
        st, _, js, _ = self.request(xff="203.0.113.77")
        self.assertEqual(self.req(f"/api/guest/requests/{js['request_id']}/approve", "POST", {}, cookie=ck)[0], 403)
        self.assertEqual(self.req("/api/auth/tokens", cookie=ck)[0], 403)
        self.assertEqual(self.req("/api/vault", cookie=ck)[0], 403)

    def test_extend_warn_and_auto_end(self):
        ck, _ = self.guest()
        sess = server.list_guest_sessions()
        sid, exp = sess[0]["id"], sess[0]["expires_at"]
        self.assertEqual(server.guest_watch_tick(now=exp - 120, notify=False), [])
        self.assertEqual(server.guest_watch_tick(now=exp - 50, notify=False), [sid])
        self.assertEqual(server.guest_watch_tick(now=exp - 40, notify=False), [])  # warn once per block
        st, _, js, _ = self.req(f"/api/guest/sessions/{sid}/extend", "POST", {}, cookie=self.owner)
        self.assertEqual(st, 200)
        self.assertAlmostEqual(js["expires_at"], exp + 600, delta=1)
        self.assertIn("session_extended", server.GUEST_AUDIT_FILE.read_text())
        self.assertEqual(self.req(f"/api/guest/sessions/{sid}/extend", "POST", {}, cookie=ck)[0], 403)
        server.guest_watch_tick(now=exp + 601, notify=False)
        self.assertEqual(server.list_guest_sessions(now=time.time()), [])

    def test_close_and_end_all_and_mint(self):
        ck, _ = self.guest()
        sid = server.list_guest_sessions()[0]["id"]
        self.assertEqual(self.req(f"/api/guest/sessions/{sid}/end", "POST", {}, cookie=self.owner)[0], 200)
        self.assertEqual(self.req("/api/me", cookie=ck)[0], 401)
        _, _, m, _ = self.req("/api/guest/mint", "POST", {"name": "Replit", "scope": "read"}, cookie=self.owner)
        st, _, ck2 = self.redeem(m["pin"])
        self.assertEqual(st, 200)
        _, _, e, _ = self.req("/api/guest/sessions/end-all", "POST", {}, cookie=self.owner)
        self.assertEqual(e["ended"], 1)
        self.assertEqual(self.req("/api/me", cookie=ck2)[0], 401)
        # owner session survives
        self.assertEqual(self.req("/api/me", cookie=self.owner)[2]["auth_type"], "session")
        audit = server.GUEST_AUDIT_FILE.read_text()
        for ev in ("request_created", "request_approved", "redeemed", "session_ended", "pin_minted", "sessions_ended_all"):
            self.assertIn(ev, audit)


if __name__ == "__main__":
    unittest.main()
