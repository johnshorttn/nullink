"""2026-11-14 (John 3:49 AM ET, "Add revoke all to batch revoke"): POST /api/vault/devices/revoke-batch.
Same gate as the single revoke (no Authorization, allowed Origin, owner session not guest, TOTP + lockout), ONE code
per request, per-device registry entry + audit + alert + result."""
import json

import nullvault
import server
from tests.test_auth import totp_code
from tests.test_nullvault import NullVaultBase, ORIGIN

PATH = "/api/vault/devices/revoke-batch"


class RevokeBatchTests(NullVaultBase):
    def batch(self, body, cookie="owner", headers=None, fresh=True):
        if fresh:
            self.fresh_codes()
        hd = {"Origin": ORIGIN}
        hd.update(headers or {})
        return self.req(PATH, "POST", body, cookie=self.owner if cookie == "owner" else cookie, headers=hd)

    def audit(self):
        f = server.VAULT_AUDIT_FILE
        return [json.loads(l) for l in f.read_text().splitlines()] if f.exists() else []

    def test_all_revokes_every_active_device_with_one_code(self):
        a = self.register(); b = self.register()
        code = (self.fresh_codes(), totp_code())[1]
        st, _, js, _ = self.batch({"code": code, "all": True}, fresh=False)
        self.assertEqual(st, 200, js)
        self.assertEqual(js["revoked"], 2)
        self.assertEqual({r["device_id"]: r["status"] for r in js["results"]},
                         {a["js"]["device_id"]: "revoked", b["js"]["device_id"]: "revoked"})
        for d in (a, b):
            self.assertEqual(nullvault.devices()[d["js"]["device_id"]]["status"], "revoked")
            st, _, j, _ = self.sync_challenge(d)
            self.assertEqual((st, j["error"]), (403, "revoked"))
        self.assertEqual(sum("revoked" in x for x in self.alerts), 2)           # one alert per device
        ev = [e for e in self.audit() if e.get("event") == "device_revoke"]
        self.assertEqual(len(ev), 2)
        self.assertTrue(all(e.get("batch") for e in ev))
        self.assertEqual(sum(1 for r in self.registry() if r.get("kind") == "revoke"), 2)
        # the code was consumed once: replaying it is refused
        st, _, js, _ = self.batch({"code": code, "all": True}, fresh=False)
        self.assertIn(st, (401, 409))

    def test_selected_ids_and_per_device_results(self):
        a = self.register(); b = self.register()
        aid, bid = a["js"]["device_id"], b["js"]["device_id"]
        self.assertEqual(self.revoke(aid)[0], 200)
        st, _, js, _ = self.batch({"code": totp_code(), "device_ids": [aid, bid, "dev_ffffffffffffffff", bid]})
        self.assertEqual(st, 200, js)
        self.assertEqual(js["results"], [{"device_id": aid, "status": "already_revoked"},
                                         {"device_id": bid, "status": "revoked"},
                                         {"device_id": "dev_ffffffffffffffff", "status": "not_found"}])
        self.assertEqual(js["revoked"], 1)

    def test_same_gate_as_single_revoke(self):
        dev = self.register(); did = dev["js"]["device_id"]
        body = lambda: {"code": totp_code(), "all": True}
        st, _, js, _ = self.batch(body(), headers=self.bearer(dev))                 # Authorization header
        self.assertEqual((st, js.get("message")), (403, "Owner browser session only."))
        self.fresh_codes()
        st, *_ = self.req(PATH, "POST", body(), cookie=self.owner)                  # no Origin
        self.assertEqual(st, 403)
        st, _, js, _ = self.batch(body(), headers={"Origin": "https://evil.example"})
        self.assertEqual((st, js["error"]), (403, "bad_origin"))
        st, *_ = self.batch(body(), cookie=None)                                    # no session
        self.assertEqual(st, 401)
        guest, _ = server.create_session("198.51.100.10", "t", "guest")
        st, _, js, _ = self.batch(body(), cookie=f"{server.COOKIE_NAME}={guest}")
        self.assertIn(st, (401, 403))
        self.assertEqual(nullvault.devices()[did]["status"], "active")

    def test_wrong_code_counts_toward_the_lockout(self):
        dev = self.register()
        st, _, js, _ = self.batch({"code": "000000", "all": True})
        if st == 200:  # 1-in-a-million collision with the real code
            return
        self.assertEqual((st, js["error"]), (401, "wrong_code"))
        self.assertIn("attempts_left", js)
        for _ in range(10):
            st, _, js, _ = self.batch({"code": "000001", "all": True})
            if st == 429:
                break
        self.assertEqual((st, js["error"]), (429, "locked"))
        self.assertIn("retry_after_sec", js)
        self.assertEqual(nullvault.devices()[dev["js"]["device_id"]]["status"], "active")

    def test_bad_requests_do_not_spend_the_code(self):
        self.register()
        self.fresh_codes(); code = totp_code()
        for b in ({"code": code}, {"code": code, "device_ids": []}, {"code": code, "device_ids": ["nope"]},
                  {"code": code, "device_ids": ["dev_0123456789abcdef"] * 51},
                  {"code": code, "all": True, "device_ids": ["dev_0123456789abcdef"]}):
            st, _, js, _ = self.batch(b, fresh=False)
            self.assertEqual((st, js["error"]), (400, "bad_request"), b)
        st, _, js, _ = self.batch({"code": code, "all": True}, fresh=False)   # still valid
        self.assertEqual(st, 200, js)
        st, _, js, _ = self.batch({"code": totp_code(), "all": True})          # nothing left
        self.assertEqual((st, js["error"]), (409, "no_devices"))

    def test_flag_off_is_404(self):
        import os
        os.environ["NULLVAULT_ENABLED"] = "0"
        st, _, js, _ = self.batch({"code": totp_code(), "all": True})
        self.assertEqual((st, js.get("error")), (404, "not_found"))
