"""Vault encryption at rest (2026-10-19): AES-256-GCM bodies, TOTP step-up to view, masked list,
guests / AI tokens refused, tamper detection, loopback admin read, audit without content."""
import base64
import json
import os
import secrets
import tempfile
import time
import unittest
from pathlib import Path

import server
from tests.test_auth import AuthBase, totp_code
from tests import test_guest as _tg

ORIGIN = "https://nullink.216.158.238.236.sslip.io"
SECRET_BODY = "backup codes: ABCD-1234 EFGH-5678 hunter2-test-only"


class VaultCryptoTests(AuthBase):
    request, approve, redeem, guest = (_tg.GuestTests.request, _tg.GuestTests.approve,
                                       _tg.GuestTests.redeem, _tg.GuestTests.guest)

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.keydir = tempfile.TemporaryDirectory()
        cls.keyfile = Path(cls.keydir.name) / "data.key"
        cls.keyfile.write_text(base64.b64encode(secrets.token_bytes(32)).decode())
        cls._old_env = os.environ.get("NULLINK_VAULT_KEY_FILE")
        os.environ["NULLINK_VAULT_KEY_FILE"] = str(cls.keyfile)

    @classmethod
    def tearDownClass(cls):
        if cls._old_env is None:
            os.environ.pop("NULLINK_VAULT_KEY_FILE", None)
        else:
            os.environ["NULLINK_VAULT_KEY_FILE"] = cls._old_env
        cls.keydir.cleanup()
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        for f in (server.GUEST_FILE, server.GUEST_AUDIT_FILE, server.VAULT_AUDIT_FILE):
            try:
                f.unlink()
            except FileNotFoundError:
                pass
        server.ensure_dirs()
        for f in server.VAULT_DIR.glob("*.json"):
            f.unlink()
        self.enable_totp()
        st, _, self.owner = self.login(totp_code())
        self.assertEqual(st, 200)
        self.entry = server.save_vault_snippet({"title": "Auth Backup codes", "body": SECRET_BODY, "tags": ["Auth"]})

    def stepup(self, cookie=None):
        st, _, js, _ = self.req("/api/ssh/stepup", "POST", {"code": totp_code(1)}, cookie=cookie or self.owner,
                                headers={"Origin": ORIGIN})
        self.assertEqual(st, 200, js)

    def raw(self, vid):
        return (server.VAULT_DIR / f"{vid}.json").read_text()

    def test_round_trip_and_no_plaintext_at_rest(self):
        raw = self.raw(self.entry["id"])
        self.assertNotIn("hunter2", raw)
        self.assertNotIn("ABCD-1234", raw)
        d = json.loads(raw)
        self.assertNotIn("body", d)
        self.assertEqual(d["enc"]["alg"], "AES-256-GCM")
        self.assertEqual(d["title"], "Auth Backup codes")  # titles/tags stay plaintext
        self.assertEqual(server.load_vault_snippet(self.entry["id"])["body"], SECRET_BODY)
        self.assertEqual(oct((server.VAULT_DIR / f"{self.entry['id']}.json").stat().st_mode & 0o777), "0o600")

    def test_fresh_nonce_per_write(self):
        n1 = json.loads(self.raw(self.entry["id"]))["enc"]["n"]
        server.save_vault_snippet(server.load_vault_snippet(self.entry["id"]))
        d2 = json.loads(self.raw(self.entry["id"]))["enc"]
        self.assertNotEqual(n1, d2["n"])

    def test_tamper_detected(self):
        fp = server.VAULT_DIR / f"{self.entry['id']}.json"
        d = json.loads(fp.read_text())
        ct = bytearray(base64.b64decode(d["enc"]["c"]))
        ct[0] ^= 1
        d["enc"]["c"] = base64.b64encode(bytes(ct)).decode()
        fp.write_text(json.dumps(d))
        with self.assertRaises(server.VaultIntegrityError):
            server.load_vault_snippet(self.entry["id"])
        self.stepup()
        st, _, js, _ = self.req(f"/api/vault/{self.entry['id']}", cookie=self.owner)
        self.assertEqual(st, 500)
        self.assertEqual(js["error"], "vault_integrity")

    def test_ciphertext_bound_to_entry_id(self):
        other = server.save_vault_snippet({"title": "x", "body": "other", "tags": []})
        a = json.loads(self.raw(self.entry["id"]))
        b = json.loads(self.raw(other["id"]))
        b["enc"] = a["enc"]  # swap ciphertext into another entry
        (server.VAULT_DIR / f"{other['id']}.json").write_text(json.dumps(b))
        with self.assertRaises(server.VaultIntegrityError):
            server.load_vault_snippet(other["id"])

    def test_wrong_key_fails_closed(self):
        old = os.environ["NULLINK_VAULT_KEY_FILE"]
        with tempfile.TemporaryDirectory() as t:
            k = Path(t) / "k"
            k.write_text(base64.b64encode(secrets.token_bytes(32)).decode())
            os.environ["NULLINK_VAULT_KEY_FILE"] = str(k)
            try:
                with self.assertRaises(server.VaultIntegrityError):
                    server.load_vault_snippet(self.entry["id"])
                os.environ["NULLINK_VAULT_KEY_FILE"] = str(Path(t) / "missing")
                with self.assertRaises(server.VaultKeyUnavailable):
                    server.load_vault_snippet(self.entry["id"])
            finally:
                os.environ["NULLINK_VAULT_KEY_FILE"] = old

    def test_step_up_required_to_view(self):
        st, _, js, data = self.req(f"/api/vault/{self.entry['id']}", cookie=self.owner)
        self.assertEqual(st, 200)
        self.assertTrue(js["locked"])
        self.assertEqual(js["item"]["title"], "Auth Backup codes")
        self.assertNotIn(b"hunter2", data)
        self.stepup()
        st, _, js, _ = self.req(f"/api/vault/{self.entry['id']}", cookie=self.owner,
                                headers={"User-Agent": "VaultTest/1"})
        self.assertEqual(st, 200)
        self.assertFalse(js["locked"])
        self.assertEqual(js["item"]["body"], SECRET_BODY)
        audit = server.VAULT_AUDIT_FILE.read_text()
        self.assertNotIn("hunter2", audit)
        ev = [json.loads(x) for x in audit.splitlines()]
        view = [e for e in ev if e["event"] == "decrypt_view"][-1]
        self.assertEqual((view["id"], view["ip"], view["ua"]), (self.entry["id"], "198.51.100.10", "VaultTest/1"))
        self.assertIn("view_masked", [e["event"] for e in ev])

    def test_stale_step_up_locks_again(self):
        self.stepup()
        sessions = server.load_sessions()
        for rec in sessions.values():
            rec["ssh_stepup_at"] = time.time() - 601
        server.save_sessions(sessions)
        st, _, js, _ = self.req(f"/api/vault/{self.entry['id']}", cookie=self.owner)
        self.assertTrue(js["locked"])

    def test_masked_list_and_title_tag_search(self):
        st, _, js, data = self.req("/api/vault", cookie=self.owner)
        self.assertEqual(st, 200)
        self.assertNotIn(b"hunter2", data)
        self.assertTrue(all(i["locked"] for i in js["items"]))
        self.assertEqual(self.req("/api/vault?q=hunter2", cookie=self.owner)[2]["count"], 0)
        self.assertEqual(self.req("/api/vault?q=backup", cookie=self.owner)[2]["count"], 1)
        self.assertEqual(self.req("/api/vault?q=auth", cookie=self.owner)[2]["count"], 1)

    def test_body_write_and_delete_need_step_up(self):
        vid = self.entry["id"]
        st, _, js, _ = self.req(f"/api/vault/{vid}", "PATCH", {"body": "overwrite"}, cookie=self.owner)
        self.assertEqual(st, 403)
        self.assertEqual(js["error"], "step_up_required")
        st, _, js, _ = self.req(f"/api/vault/{vid}", "PATCH", {"title": "Renamed", "tags": ["Auth"]}, cookie=self.owner)
        self.assertEqual(st, 200)
        self.assertEqual(server.load_vault_snippet(vid)["body"], SECRET_BODY)  # body kept, re-encrypted
        self.assertEqual(self.req(f"/api/vault/{vid}", "DELETE", cookie=self.owner)[0], 403)
        self.stepup()
        self.assertEqual(self.req(f"/api/vault/{vid}", "PATCH", {"body": "new body"}, cookie=self.owner)[0], 200)
        self.assertEqual(server.load_vault_snippet(vid)["body"], "new body")

    def test_guest_refused(self):
        gck, _ = self.guest("full")
        for path in ("/api/vault", f"/api/vault/{self.entry['id']}"):
            st, _, _, data = self.req(path, cookie=gck)
            self.assertEqual(st, 403)
            self.assertNotIn(b"hunter2", data)

    def test_ai_token_refused(self):
        _rec, plain = server.create_api_token("ai-connector", ["read", "write"], ["*"])
        for path in ("/api/vault", f"/api/vault/{self.entry['id']}"):
            st, _, _, data = self.req(path, headers={"Authorization": f"Bearer {plain}"})
            self.assertEqual(st, 403)
            self.assertNotIn(b"hunter2", data)

    def test_share_and_anonymous_refused(self):
        st, _, _, data = self.req(f"/api/vault/{self.entry['id']}", cookie="__Host-nl_share_x=dev.sig")
        self.assertEqual(st, 401)
        self.assertNotIn(b"hunter2", data)

    def test_admin_loopback_read_for_morc(self):
        st, _, js, _ = self.req(f"/api/admin/vault/{self.entry['id']}", xff=None, proto=None, host="127.0.0.1")
        self.assertEqual(st, 200)
        self.assertEqual(js["item"]["body"], SECRET_BODY)
        st, _, _, data = self.req(f"/api/admin/vault/{self.entry['id']}")  # via proxy headers
        self.assertEqual(st, 403)
        self.assertNotIn(b"hunter2", data)


if __name__ == "__main__":
    unittest.main()
