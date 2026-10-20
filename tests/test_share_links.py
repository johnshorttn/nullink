"""Report share links (2026-10-14): owner-only PDF, token scope, first-device binding, expiry,
other-device rejection, request validation/rate limit, Slack approve."""
import json, time, urllib.parse
from pathlib import Path
from unittest.mock import patch
import server, share_links
from tests.test_slack_guest import SlackGuestTests as _SG

PORTAL = "nullverse.cloud"


class ShareTests(_SG):
    def setUp(self):
        super().setUp()
        self.rdir = self.root / "reports"; self.rdir.mkdir(exist_ok=True)
        (self.rdir / "demo.html").write_text("<html><head><title>Demo</title></head><body><h1>Hi</h1></body></html>")
        self.rp = patch.object(server, "PORTAL_REPORTS_DIR", self.rdir); self.rp.start()
        for f in ("share_links.json", "share_audit.jsonl"):
            (server.DATA / f).unlink(missing_ok=True)
        share_links._ip_hits.clear()

    def tearDown(self):
        self.rp.stop(); super().tearDown()

    def pg(self, path, method="GET", body=None, cookie=None, xff="198.51.100.20", ua="DevA"):
        return self.req(path, method, body, cookie=cookie, host=PORTAL, xff=xff, headers={"User-Agent": ua})

    def mklink(self):
        st, _, js, _ = self.pg("/api/share/links", "POST", {"report": "demo.html"}, cookie=self.owner)
        self.assertEqual(st, 201)
        return js["id"], urllib.parse.urlsplit(js["url"]).path

    def devcookie(self, hdrs):
        for c in self.cookies(hdrs):
            if "nvs_" in c:
                return c.split(";")[0]

    def test_owner_toolbar_and_pdf_owner_only(self):
        st, _, _, raw = self.pg("/reports/demo.html", cookie=self.owner)
        self.assertEqual(st, 200); self.assertIn(b"Download PDF", raw); self.assertIn(b"Share link", raw)
        self.assertNotIn(b"Privacy filter", raw); self.assertNotIn(b"nvwm", raw); self.assertNotIn(b"nvscroll", raw)
        st, _, _, _ = self.pg("/reports/demo.html"); self.assertEqual(st, 302)
        st, _, _, _ = self.pg("/api/share/pdf/demo.html"); self.assertEqual(st, 401)
        with patch.object(share_links, "render_pdf", return_value=self.root / "x.pdf"):
            (self.root / "x.pdf").write_bytes(b"%PDF-1.4 x")
            st, _, _, raw = self.pg("/api/share/pdf/demo.html", cookie=self.owner)
            self.assertEqual(st, 200); self.assertTrue(raw.startswith(b"%PDF"))
        _, path = self.mklink()
        st, hdrs, _, raw = self.pg(path)
        self.assertEqual(st, 200); self.assertNotIn(b"Download PDF", raw); self.assertNotIn(b"nv-share", raw)
        for marker in (b"nvscroll", b"nvcb-top", b"Nullfinity", b"-webkit-scrollbar-track:vertical", b"Privacy filter", b"Printing disabled", b"MutationObserver", b"contextmenu", b"nvwm"):
            self.assertIn(marker, raw)
        ck = self.devcookie(hdrs)
        st, _, _, _ = self.pg(path + "/pdf", cookie=ck); self.assertEqual(st, 403)
        st, _, _, _ = self.pg("/api/share/pdf/demo.html", cookie=ck); self.assertEqual(st, 401)

    def test_pdf_and_toolbar_blocked_for_guest(self):
        gck = self.guest()[0]
        st, _, _, raw = self.pg("/reports/demo.html", cookie=gck)
        if st == 200:
            self.assertNotIn(b"Download PDF", raw)
        st, _, _, _ = self.pg("/api/share/pdf/demo.html", cookie=gck); self.assertEqual(st, 403)

    def test_first_device_binding_scope_expiry(self):
        lid, path = self.mklink()
        st, hdrs, _, raw = self.pg(path)
        self.assertEqual(st, 200); self.assertIn(b"expires 24 hours", raw); self.assertIn(b"Request 24h extension", raw)
        h = dict((k.lower(), v) for k, v in hdrs)
        self.assertIn("noindex", h["x-robots-tag"])
        ck = self.devcookie(hdrs)
        self.assertIn("HttpOnly", [c for c in self.cookies(hdrs) if "nvs_" in c][0])
        self.assertFalse(any("nullink_session" in c for c in self.cookies(hdrs)))
        st, _, _, _ = self.pg(path, cookie=ck); self.assertEqual(st, 200)
        st, _, _, raw = self.pg(path, xff="203.0.113.9", ua="DevB"); self.assertEqual(st, 403)
        self.assertIn(b"registered to another device", raw)
        st, _, _, _ = self.pg(path, cookie=ck.split(".")[0] + ".deadbeef"); self.assertEqual(st, 403)
        # scope: device cookie grants nothing else
        for other in ("/reports/demo.html", "/api/portal/reports", "/api/share/links", "/projects"):
            st, _, _, _ = self.pg(other, cookie=ck); self.assertIn(st, (302, 401, 404), other)
        st, _, _, _ = self.pg(path + "/../reports/demo.html", cookie=ck); self.assertNotEqual(st, 200)
        st, _, _, _ = self.pg("/s/" + "A" * 43); self.assertEqual(st, 404)
        # expiry
        d = share_links.load(); d["links"][lid]["expires_at"] = time.time() - 1; share_links.save(d)
        st, _, _, raw = self.pg(path, cookie=ck); self.assertEqual(st, 410); self.assertIn(b"expired", raw)
        # revoke
        st, _, _, _ = self.pg(f"/api/share/links/{lid}/revoke", "POST", {}, cookie=self.owner); self.assertEqual(st, 200)
        st, _, _, raw = self.pg(path, cookie=ck); self.assertEqual(st, 410); self.assertIn(b"revoked", raw)

    def test_request_validation_and_slack_approve(self):
        lid, path = self.mklink()
        st, hdrs, _, _ = self.pg(path); ck = self.devcookie(hdrs)
        st, _, js, _ = self.pg(path + "/request", "POST", {"kind": "extend", "name": "A", "email": "bad", "reason": ""}, cookie=ck)
        self.assertEqual(st, 400); self.assertEqual(set(js["fields"]), {"name", "email", "reason"})
        st, _, js, _ = self.pg(path + "/request", "POST", {"kind": "teammate", "name": "Ann", "email": "a@x.io", "reason": "review"}, cookie=ck)
        self.assertEqual(st, 400); self.assertIn("teammate_email", js["fields"])
        st, _, _, _ = self.pg(path + "/request", "POST", {"kind": "extend", "name": "Ann", "email": "a@x.io", "reason": "need more"})
        self.assertEqual(st, 403)  # other device can't extend
        st, _, js, _ = self.pg(path + "/request", "POST", {"kind": "extend", "name": "Ann", "email": "a@x.io", "reason": "need more time"}, cookie=ck)
        self.assertEqual(st, 201); rid, key = js["request_id"], js["poll_key"]
        time.sleep(0.3)
        self.assertTrue(any(m == "chat.postMessage" and "share_approve" in json.dumps(p) for m, p in self.calls))
        old = share_links.load()["links"][lid]["expires_at"]
        # wrong user rejected
        self.assertEqual(self.post_interact(self.body(self.payload_for("share_approve", rid, "UOTHER"))), 200)
        time.sleep(0.2)
        self.assertEqual(share_links.load()["requests"][rid]["status"], "pending")
        st, _, _, _ = self.pg(f"{path}/request/{rid}?key=wrong", cookie=ck); self.assertEqual(st, 404)
        self.assertEqual(self.post_interact(self.body(self.payload_for("share_approve", rid))), 200)
        time.sleep(0.4)
        st, _, js, _ = self.pg(f"{path}/request/{rid}?key={key}", cookie=ck)
        self.assertEqual(js["status"], "approved"); self.assertGreater(js["expires_at"], old + 23 * 3600)
        # teammate
        st, _, js, _ = self.pg(path + "/request", "POST", {"kind": "teammate", "name": "Ann", "email": "a@x.io",
                              "reason": "for my lead", "teammate_name": "Bob", "teammate_email": "b@x.io"}, cookie=ck)
        self.assertEqual(st, 201); rid2, key2 = js["request_id"], js["poll_key"]
        time.sleep(0.2)
        self.post_interact(self.body(self.payload_for("share_approve", rid2))); time.sleep(0.4)
        st, _, js, _ = self.pg(f"{path}/request/{rid2}?key={key2}", cookie=ck)
        self.assertEqual(js["status"], "approved"); self.assertIn("/s/", js["url"])
        self.assertTrue(any(m == "chat.update" and js["url"] in json.dumps(p) for m, p in self.calls))
        st, _, _, _ = self.pg(urllib.parse.urlsplit(js["url"]).path, xff="192.0.2.77", ua="Bob"); self.assertEqual(st, 200)
        # bad signature
        self.assertEqual(self.post_interact(self.body(self.payload_for("share_deny", rid2)), sig="v0=bad"), 401)
        # rate limit
        share_links._ip_hits.clear()
        codes = [self.pg(path + "/request", "POST", {"kind": "extend", "name": "Ann", "email": "a@x.io",
                        "reason": "again please"}, cookie=ck)[0] for _ in range(7)]
        self.assertIn(429, codes)
        ev = (server.DATA / "share_audit.jsonl").read_text()
        for e in ("link_created", "link_registered", "request_created", "request_approved"):
            self.assertIn(e, ev)

    def test_ai_links(self):
        st, _, js, _ = self.pg("/api/share/links", "POST", {"report": "demo.html", "type": "ai", "ttl": "1h", "max_opens": 3}, cookie=self.owner)
        self.assertEqual(st, 201); self.assertEqual(js["type"], "ai")
        path = urllib.parse.urlsplit(js["url"]).path; self.assertTrue(path.startswith("/a/"))
        self.assertEqual(self.pg("/api/share/links", "POST", {"report": "demo.html", "type": "ai", "ttl": "9y"}, cookie=self.owner)[0], 400)
        self.assertEqual(self.pg("/api/share/links", "POST", {"report": "demo.html", "type": "ai"})[0], 401)
        st, hdrs, _, raw = self.pg(path, ua="GPTBot")
        self.assertEqual(st, 200); self.assertIn("Nullfinity".encode(), raw)
        for m in (b"nvscroll", b"nvwm", b"Privacy filter", b"contextmenu", b"Download PDF"):
            self.assertNotIn(m, raw)
        self.assertFalse(self.cookies(hdrs))
        self.assertIn("noindex", dict((k.lower(), v) for k, v in hdrs)["x-robots-tag"])
        st, hdrs, _, raw = self.pg(path + ".md", xff="192.0.2.9")
        self.assertEqual(st, 200); self.assertTrue(raw.decode().startswith("\u00a9 Nullfinity \u2014 shared for review, do not redistribute"))
        self.assertIn("# Hi", raw.decode()); self.assertIn("markdown", dict((k.lower(), v) for k, v in hdrs)["content-type"])
        st, hdrs, _, raw = self.pg(path + "?format=text"); self.assertEqual(st, 200)
        self.assertIn("text/plain", dict((k.lower(), v) for k, v in hdrs)["content-type"])
        self.assertEqual(self.pg(path)[0], 410)  # 4th fetch > cap 3
        lid = js["id"]
        d = share_links.load(); self.assertEqual(d["links"][lid]["opens"], 3)
        # token scope: /a/ token not valid as /s/, not elsewhere
        tok = path[3:]
        self.assertEqual(self.pg("/s/" + tok)[0], 404)
        self.assertEqual(self.pg("/a/" + tok + "/../reports/demo.html")[0], 404)
        # extend raises expiry, revoke kills it
        d["links"][lid]["max_opens"] = 100; d["links"][lid]["expires_at"] = time.time() - 1; share_links.save(d)
        self.assertEqual(self.pg(path)[0], 410)
        self.assertEqual(self.pg(f"/api/share/links/{lid}/extend", "POST", {}, cookie=self.owner)[0], 200)
        self.assertEqual(self.pg(path)[0], 200)
        self.assertEqual(self.pg(f"/api/share/links/{lid}/revoke", "POST", {}, cookie=self.owner)[0], 200)
        self.assertEqual(self.pg(path)[0], 410)
        ev = (server.DATA / "share_audit.jsonl").read_text()
        self.assertIn('"ai_fetch"', ev); self.assertIn("GPTBot", ev); self.assertIn("ai_fetch_rejected", ev)
        # person token isn't valid on /a/
        _, ppath = self.mklink()
        self.assertEqual(self.pg("/a/" + ppath[3:])[0], 404)

    def payload_for(self, a, v, user=server.SLACK_OWNER_UID):
        from tests.test_slack_guest import payload
        return payload(a, v, user)
