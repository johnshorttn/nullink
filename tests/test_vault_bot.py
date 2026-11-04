"""Scoped bot vault access (2026-11-04): add-only deposit token + per-read TOTP code."""
import json
import secrets

import server
import vault_bot
from tests import test_vault_crypto as _vc
from tests.test_auth import totp_code
from tests.test_vault_crypto import ORIGIN, SECRET_BODY

TOKEN = "nlvb_" + secrets.token_urlsafe(32)


class VaultBotTests(_vc.VaultCryptoTests):
    def setUp(self):
        super().setUp()
        vault_bot.server = server
        for f in (vault_bot.tokens_file(), vault_bot.rate_file()):
            f.unlink(missing_ok=True)
        vault_bot.add_token("morc", vault_bot.hash_token(TOKEN))
        self.bot = {"Authorization": f"Bearer {TOKEN}"}

    def fresh_codes_allowed(self):
        cfg = server.load_totp(); cfg["last_counter"] = -1; server.save_totp(cfg)

    def deposit(self, payload, headers=None):
        return self.req("/api/vault/deposit", "POST", payload, headers=headers or self.bot)

    def audit(self):
        return [json.loads(l) for l in server.VAULT_AUDIT_FILE.read_text().splitlines()]

    def test_deposit_creates_new_entry_no_body_echo(self):
        st, _, js, data = self.deposit({"title": "Gemini API key", "body": "sk-gemini-secret", "tags": ["api"]})
        self.assertEqual(st, 201, js)
        self.assertNotIn(b"sk-gemini-secret", data)
        self.assertEqual(server.load_vault_snippet(js["id"])["body"], "sk-gemini-secret")
        self.assertIn("from-morc", server.load_vault_snippet(js["id"])["tags"])
        ev = [a for a in self.audit() if a["event"] == "deposit"][-1]
        self.assertEqual((ev["source"], ev["id"]), ("morc", js["id"]))
        self.assertNotIn("sk-gemini-secret", server.VAULT_AUDIT_FILE.read_text())

    def test_deposit_cannot_overwrite(self):
        st, _, js, _ = self.deposit({"id": self.entry["id"], "title": "x", "body": "evil"})
        self.assertEqual(st, 201)
        self.assertNotEqual(js["id"], self.entry["id"])
        self.assertEqual(server.load_vault_snippet(self.entry["id"])["body"], SECRET_BODY)

    def test_bot_token_cannot_list_read_edit_delete(self):
        vid = self.entry["id"]
        for url, m, body in (("/api/vault", "GET", None), ("/api/vault/labels", "GET", None),
                             (f"/api/vault/{vid}", "GET", None), ("/api/vault", "POST", {"title": "t", "body": "b"}),
                             (f"/api/vault/{vid}", "POST", {"body": "x"}), (f"/api/vault/{vid}", "PUT", {"body": "x"}),
                             (f"/api/vault/{vid}", "DELETE", None),
                             ("/api/vault/labels/rename", "POST", {"from": "auth", "to": "x"})):
            st, _, _, data = self.req(url, m, body, headers={**self.bot, "Origin": ORIGIN})
            self.assertIn(st, (401, 403, 404, 405), (url, m, st))
            self.assertNotIn(b"hunter2", data)
        self.assertEqual(server.load_vault_snippet(vid)["body"], SECRET_BODY)
        self.assertEqual(server.load_vault_snippet(vid)["tags"], ["Auth"])

    def test_bad_or_missing_token(self):
        st, *_ = self.deposit({"title": "t", "body": "b"}, headers={"Authorization": "Bearer nlvb_wrong"})
        self.assertEqual(st, 401)
        st, *_ = self.deposit({"title": "t", "body": "b"}, headers={"X-None": "1"})
        self.assertEqual(st, 401)
        st, *_ = self.req("/api/vault/bot-read", "POST", {"id": self.entry["id"], "code": totp_code(1)}, cookie=self.owner)
        self.assertEqual(st, 401)  # owner cookie is not a bot credential either

    def read(self, code, vid=None):
        return self.req("/api/vault/bot-read", "POST", {"id": vid or self.entry["id"], "code": code}, headers=self.bot)

    def test_read_needs_valid_code_and_is_single_use(self):
        self.fresh_codes_allowed()
        st, _, js, _ = self.read("000000" if totp_code() != "000000" else "111111")
        self.assertEqual(st, 403)
        st, _, js, _ = self.read(None)
        self.assertEqual(st, 403)
        code = totp_code()
        st, _, js, _ = self.read(code)
        self.assertEqual(st, 200, js)
        self.assertEqual(js["item"]["body"], SECRET_BODY)
        st, _, js, _ = self.read(code)  # replay of the same code
        self.assertEqual(st, 403)
        st, _, js, _ = self.read(totp_code(-1))  # earlier time step also dead
        self.assertEqual(st, 403)
        a = self.audit()
        self.assertEqual([x["source"] for x in a if x["event"] == "bot_read"], ["morc"])
        self.assertTrue(any(x["event"] == "bot_read_denied" for x in a))
        self.assertNotIn("hunter2", server.VAULT_AUDIT_FILE.read_text())

    def test_one_code_one_entry(self):
        self.fresh_codes_allowed()
        other = server.save_vault_snippet({"title": "o", "body": "other-secret"})
        code = totp_code()
        self.assertEqual(self.read(code)[0], 200)
        st, _, _, data = self.read(code, other["id"])
        self.assertEqual(st, 403)
        self.assertNotIn(b"other-secret", data)

    def test_expired_code_rejected(self):
        self.fresh_codes_allowed()
        self.assertEqual(self.read(totp_code(-4))[0], 403)

    def test_lockout_after_bad_codes(self):
        self.fresh_codes_allowed()
        for _ in range(vault_bot.READ_FAIL_MAX):
            self.read("000000" if totp_code() != "000000" else "111111")
        st, _, js, _ = self.read(totp_code())
        self.assertEqual(st, 429)

    def test_revoke(self):
        vault_bot.revoke_token("morc")
        self.assertEqual(self.deposit({"title": "t", "body": "b"})[0], 401)

    def test_tokens_stored_hashed(self):
        raw = vault_bot.tokens_file().read_text()
        self.assertNotIn(TOKEN, raw)
        self.assertEqual(oct(vault_bot.tokens_file().stat().st_mode & 0o777), "0o600")


for _n in [n for n in vars(_vc.VaultCryptoTests) if n.startswith("test")]:
    setattr(VaultBotTests, _n, None)
