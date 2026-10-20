"""Slack DM approve/deny for guest access: signature, replay, wrong user, idempotency (2026-10-14)."""
import hashlib, hmac, json, time, urllib.parse
from unittest.mock import patch
import server
from tests.test_guest import GuestTests as _G

SECRET = "testsecret0123456789abcdef012345"


def sign(body: bytes, ts=None, secret=SECRET):
    ts = str(int(time.time()) if ts is None else ts)
    return ts, "v0=" + hmac.new(secret.encode(), b"v0:" + ts.encode() + b":" + body, hashlib.sha256).hexdigest()


def payload(action, value, user=server.SLACK_OWNER_UID):
    return {"type": "block_actions", "user": {"id": user}, "channel": {"id": "D123"},
            "container": {"channel_id": "D123", "message_ts": "1.1"},
            "actions": [{"action_id": action, "value": value}]}


class SlackGuestTests(_G):
    def setUp(self):
        super().setUp()
        self.calls = []
        self.p = [patch.object(server, "slack_call", side_effect=self.fake),
                  patch.object(server, "_slack_cred", side_effect=lambda k: SECRET if k == "signing_secret" else "x")]
        for x in self.p:
            x.start()

    def tearDown(self):
        for x in self.p:
            x.stop()
        super().tearDown() if hasattr(super(), "tearDown") else None

    def fake(self, method, params):
        self.calls.append((method, params))
        if method == "conversations.open":
            return {"ok": True, "channel": {"id": "D123"}}
        return {"ok": True, "channel": params.get("channel"), "ts": f"9.{len(self.calls)}"}

    def new_req(self):
        st, _, js, _ = self.request()
        self.assertEqual(st, 201)
        return js["request_id"]

    def post_interact(self, body: bytes, ts=None, sig=None):
        t, s = sign(body, ts)
        import http.client
        c = http.client.HTTPConnection("127.0.0.1", self.httpd.server_port, timeout=10)
        c.request("POST", "/api/slack/interact", body=body, headers={
            "Content-Type": "application/x-www-form-urlencoded", "X-Slack-Request-Timestamp": t,
            "X-Slack-Signature": sig or s, "Host": "nullink.nullverse.cloud"})
        r = c.getresponse(); r.read(); return r.status

    def body(self, pl):
        return urllib.parse.urlencode({"payload": json.dumps(pl)}).encode()

    def test_verify_good_bad_replay(self):
        b = b"payload=x"
        t, s = sign(b)
        self.assertTrue(server.slack_verify(SECRET, t, s, b))
        self.assertFalse(server.slack_verify(SECRET, t, s, b + b"y"))
        self.assertFalse(server.slack_verify("other", t, s, b))
        old = int(time.time()) - 400
        t2, s2 = sign(b, old)
        self.assertFalse(server.slack_verify(SECRET, t2, s2, b))
        self.assertFalse(server.slack_verify(None, t, s, b))

    def test_endpoint_rejects_bad_signature_and_replay(self):
        rid = self.new_req()
        b = self.body(payload("guest_approve", rid))
        self.assertEqual(self.post_interact(b, sig="v0=deadbeef"), 401)
        self.assertEqual(self.post_interact(b, ts=int(time.time()) - 600), 401)
        self.assertEqual(server.load_guest()["requests"][rid]["status"], "pending")

    def test_endpoint_no_cookie_needed_and_acks(self):
        rid = self.new_req()
        self.assertEqual(self.post_interact(self.body(payload("guest_deny", rid))), 200)
        for _ in range(50):
            if server.load_guest()["requests"][rid]["status"] == "denied":
                break
            time.sleep(0.05)
        self.assertEqual(server.load_guest()["requests"][rid]["status"], "denied")

    def test_wrong_user_rejected(self):
        rid = self.new_req()
        out = server.slack_handle_interaction(payload("guest_approve", rid, user="U0SOMEONE"))
        self.assertEqual(out["error"], "wrong_user")
        self.assertEqual(server.load_guest()["requests"][rid]["status"], "pending")
        self.assertEqual(self.post_interact(self.body(payload("guest_approve", rid, user="U0SOMEONE"))), 200)
        time.sleep(0.2)
        self.assertEqual(server.load_guest()["requests"][rid]["status"], "pending")

    def test_approve_idempotent_pin_dm_only(self):
        rid = self.new_req()
        a = server.slack_handle_interaction(payload("guest_approve", rid))
        b = server.slack_handle_interaction(payload("guest_approve", rid))
        c = server.slack_handle_interaction(payload("guest_deny", rid))
        self.assertTrue(a["ok"]); self.assertFalse(b["ok"]); self.assertEqual(b["code"], 409)
        posts = [p for m, p in self.calls if m == "chat.postMessage"]
        import re as _re
        pins = [p for p in posts if _re.fullmatch(r"[A-Z0-9]{5}-[A-Z0-9]{5}", p.get("text", ""))]
        self.assertEqual(len(pins), 1)
        self.assertEqual(pins[0]["channel"], "D123")
        self.assertNotIn("blocks", pins[0]); self.assertIs(pins[0].get("mrkdwn"), False)
        ctx = posts[posts.index(pins[0]) - 1]
        self.assertIn("Expires in 0:", ctx["text"]); self.assertNotIn(pins[0]["text"], ctx["text"])
        audit = server.GUEST_AUDIT_FILE.read_text()
        self.assertIn("slack_approved", audit)
        # deny after approve kills the unredeemed PIN (same as Nullink path)
        self.assertTrue(c["ok"])

    def test_expired_request_updates_message(self):
        rid = self.new_req()
        server._guest_set_fields(rid, slack_channel="D123", slack_ts="5.5", slack_state="pending",
                                 created_at=time.time() - 3600)
        out = server.slack_handle_interaction(payload("guest_approve", rid))
        self.assertFalse(out["ok"]); self.assertEqual(out["status"], "expired")
        ups = [p for m, p in self.calls if m == "chat.update" and p.get("ts") == "5.5"]
        self.assertTrue(ups and "actions" not in json.dumps(ups[-1]["blocks"]))

    def test_alert_goes_to_dm_not_webhook(self):
        with patch.object(server, "_guest_slack") as wh:
            rid = self.new_req()
            time.sleep(0.3)
            wh.assert_not_called()
        posts = [p for m, p in self.calls if m == "chat.postMessage"]
        self.assertTrue(posts and posts[0]["channel"] == "D123")
        self.assertIn("guest_approve", json.dumps(posts[0]["blocks"]))

    def test_extend_close_buttons(self):
        st, js, ck = self.guest() if False else (None, None, None)
        rid = self.new_req()
        _, _, js, _ = self.approve(rid)
        st, js2, ck = self.redeem(js["pin"])
        sid = server.list_guest_sessions()[0]["id"]
        before = server.list_guest_sessions()[0]["expires_at"]
        self.assertTrue(server.slack_handle_interaction(payload("guest_extend", sid))["ok"])
        self.assertGreater(server.list_guest_sessions()[0]["expires_at"], before)
        self.assertFalse(server.slack_handle_interaction(payload("guest_close", sid, user="U0X"))["ok"])
        self.assertTrue(server.slack_handle_interaction(payload("guest_close", sid))["ok"])
        self.assertEqual(server.list_guest_sessions(), [])


del _G


class SlackPinFinalizeTests(SlackGuestTests):
    def test_redeem_edits_pin_dm_immediately_with_ip(self):
        rid = self.new_req()
        server.slack_handle_interaction(payload("guest_approve", rid))
        r = server.load_guest()["requests"][rid]
        self.assertTrue(r["slack_pin_ts"] and r["slack_pin_channel"] == "D123")
        pin = [p for m, p in self.calls if m == "chat.postMessage" and "-" in p["text"] and len(p["text"]) == 11][0]["text"]
        st, js, ck = self.redeem(pin, xff="1.2.3.4, 203.0.113.77")  # spoofed left hop ignored
        self.assertEqual(st, 200)
        for _ in range(60):
            if server.load_guest()["requests"][rid].get("slack_state") == "redeemed":
                break
            time.sleep(0.05)
        ups = [p for m, p in self.calls if m == "chat.update" and p.get("ts") == r["slack_pin_ts"]]
        self.assertTrue(ups)
        t = ups[-1]["text"]
        self.assertTrue(t.startswith("Used at ") and t.endswith(" by Replit AI from 203.0.113.77"), t)
        self.assertIn(" ET by ", t); self.assertNotIn("1.2.3.4", t)
        self.assertIn('"ip": "203.0.113.77"', server.GUEST_AUDIT_FILE.read_text())
        alert = [p for m, p in self.calls if m == "chat.update" and p.get("ts") == r["slack_ts"]]
        self.assertIn("203.0.113.77", json.dumps(alert[-1]["blocks"]))
        n = len(self.calls); server.slack_guest_sweep(); server.slack_pin_finalize(rid)
        self.assertFalse([1 for m, p in self.calls[n:] if p.get("ts") == r["slack_pin_ts"]])  # idempotent

    def test_expiry_via_sweep_persisted(self):
        rid = self.new_req()
        server.slack_handle_interaction(payload("guest_approve", rid))
        r = server.load_guest()["requests"][rid]
        server._guest_set_fields(rid, pin_expires_at=time.time() - 1)
        server.slack_guest_sweep()  # simulates post-restart sweep; no in-memory timer needed
        ups = [p for m, p in self.calls if m == "chat.update" and p.get("ts") == r["slack_pin_ts"]]
        self.assertEqual(ups[-1]["text"], "expired")
        self.assertTrue(server.load_guest()["requests"][rid]["slack_pin_final"])


class SlackCountdownTests(SlackGuestTests):
    def _approve(self):
        rid = self.new_req()
        server.slack_handle_interaction(payload("guest_approve", rid))
        return rid, server.load_guest()["requests"][rid]

    def test_ctx_countdown_and_pin_only(self):
        rid, r = self._approve()
        self.assertTrue(r.get("slack_ctx_ts"))
        server._guest_set_fields(rid, slack_ctx_at=time.time() - 20)
        server.slack_ctx_countdown_tick()
        ups = [p for m, p in self.calls if m == "chat.update" and p.get("ts") == r["slack_ctx_ts"]]
        self.assertIn("Expires in 0:", ups[-1]["text"])
        n = len(self.calls); server.slack_ctx_countdown_tick()  # <10 s since last: no update
        self.assertEqual(len(self.calls), n)
        server._guest_set_fields(rid, pin_expires_at=time.time() - 1)
        server.slack_guest_sweep()
        ups = [p for m, p in self.calls if m == "chat.update" and p.get("ts") == r["slack_ctx_ts"]]
        self.assertIn("expired unused", ups[-1]["text"])

    def test_session_status_message_lifecycle(self):
        rid, r = self._approve()
        pin = [p for m, p in self.calls if m == "chat.postMessage" and len(p["text"]) == 11 and "-" in p["text"]][0]["text"]
        self.assertEqual(self.redeem(pin)[0], 200)
        time.sleep(0.3)
        server.slack_session_status_tick()
        sid = server.list_guest_sessions()[0]["id"]
        tr = server.load_guest()["slack_sessions"][sid]
        self.assertTrue(tr["ts"])
        posts = [p for m, p in self.calls if m == "chat.postMessage" and "Guest session (read-only)" in p["text"]]
        self.assertEqual(len(posts), 1)  # one status message, not repeated
        self.assertIn("guest_extend", json.dumps(posts[0]["blocks"]))
        n = len(self.calls); server.slack_session_status_tick()
        self.assertEqual(len(self.calls), n)  # <60 s: no update
        server._sess_track(sid, {"last": time.time() - 61})  # simulates restart / 60 s later
        server.slack_session_status_tick()
        self.assertEqual(self.calls[-1][0], "chat.update")
        self.assertIn("min left", self.calls[-1][1]["text"])
        server.slack_handle_interaction(payload("guest_close", sid))
        server.slack_session_status_tick()
        last = [p for m, p in self.calls if m == "chat.update" and p.get("ts") == tr["ts"]][-1]
        self.assertIn("closed by John", last["text"]); self.assertNotIn("guest_extend", json.dumps(last["blocks"]))
        self.assertTrue(server.load_guest()["slack_sessions"][sid]["final"])
        n = len(self.calls); server.slack_session_status_tick()
        self.assertEqual(len(self.calls), n)  # stops after end

    def test_backoff_on_429(self):
        import io, urllib.error
        for x in self.p:
            x.stop()
        self.p = [patch.object(server, "_slack_cred", side_effect=lambda k: "x")]
        self.p[0].start()
        err = urllib.error.HTTPError("u", 429, "rl", {"Retry-After": "30"}, io.BytesIO(b""))
        with patch.object(server.urllib.request, "urlopen", side_effect=err) as uo:
            self.assertEqual(server.slack_call("chat.update", {})["error"], "ratelimited")
            self.assertEqual(server.slack_call("chat.update", {})["error"], "ratelimited_backoff")
            self.assertEqual(uo.call_count, 1)
        server._SLACK_BACKOFF_UNTIL = 0.0
