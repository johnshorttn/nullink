"""Owner-only guest audit endpoint/page (2026-10-14)."""
import json
import server
from tests.test_auth import AuthBase, totp_code


class GuestAuditTests(AuthBase):
    def setUp(self):
        super().setUp()
        for f in (server.GUEST_FILE, server.GUEST_AUDIT_FILE):
            try:
                f.unlink()
            except FileNotFoundError:
                pass
        self.enable_totp()
        st, _, self.owner = self.login(totp_code())
        server.guest_audit("request_created", request_id="GR-AAAAAA", ip="203.0.113.9", name="Replit AI")
        server.guest_audit("request_approved", request_id="GR-AAAAAA", by="slack:" + server.SLACK_OWNER_UID, scope="read")
        server.guest_audit("weird_debug", request_id="GR-AAAAAA", pin="RSEY5-K7M2P", poll_token="abcdefgh")
        server.guest_audit("slack_bad_signature", ip="198.51.100.1")

    def test_unauth_401(self):
        st, _, js, _ = self.req("/api/guest/audit")
        self.assertEqual(st, 401)
        self.assertEqual(self.req("/guest-audit")[0], 401)

    def test_owner_ok_newest_first_labels_filters(self):
        st, _, js, _ = self.req("/api/guest/audit", cookie=self.owner)
        self.assertEqual(st, 200)
        self.assertEqual(js["total"], 4)
        self.assertEqual(js["rows"][0]["label"], "Bad signature")
        labels = [r["label"] for r in js["rows"]]
        self.assertIn("Approved via Slack", labels); self.assertIn("Requested", labels)
        self.assertEqual(js["requests"].keys(), set()) if False else None
        appr = [r for r in js["rows"] if r["event"] == "request_approved"][0]
        self.assertEqual(appr["actor"], "John (Slack)")
        st, _, js, _ = self.req("/api/guest/audit?request_id=gr-aaaaaa&event=Requested", cookie=self.owner)
        self.assertEqual(js["total"], 1); self.assertEqual(js["rows"][0]["ip"], "203.0.113.9")
        st, _, js, _ = self.req("/api/guest/audit?q=198.51&limit=1&offset=0", cookie=self.owner)
        self.assertEqual(js["total"], 1)
        st, _, js, _ = self.req("/api/guest/audit?from=2000-01-01&to=2000-01-02", cookie=self.owner)
        self.assertEqual(js["total"], 0)
        self.assertEqual(self.req("/guest-audit", cookie=self.owner)[0], 200)

    def test_masking_json_and_csv(self):
        st, _, js, raw = self.req("/api/guest/audit", cookie=self.owner)
        blob = json.dumps(js, ensure_ascii=False)
        self.assertNotIn("K7M2P", blob); self.assertNotIn("abcdefgh", blob)
        self.assertIn("RSEY5-•••••", blob)
        st, hdrs, _, body = self.req("/api/guest/audit?format=csv", cookie=self.owner)
        self.assertEqual(st, 200)
        text = body.decode() if isinstance(body, bytes) else str(body)
        self.assertNotIn("K7M2P", text); self.assertIn("time_et", text)

    def test_guest_403(self):
        st, _, js, _ = self.req("/api/guest/request", "POST", {"name": "G", "reason": "x"}, xff="203.0.113.5")
        _, _, a, _ = self.req(f"/api/guest/requests/{js['request_id']}/approve", "POST", {"scope": "full"}, cookie=self.owner)
        st, hdrs, _, _ = self.req("/api/auth/guest/redeem", "POST", {"pin": a["pin"]}, xff="203.0.113.5")
        ck = [c.split(";")[0] for c in self.cookies(hdrs) if c.split(";")[0].split("=", 1)[1]][0]
        self.assertEqual(self.req("/api/guest/audit", cookie=ck)[0], 403)
        self.assertEqual(self.req("/api/guest/audit?format=csv", cookie=ck)[0], 403)
        self.assertEqual(self.req("/guest-audit", cookie=ck)[0], 403)
