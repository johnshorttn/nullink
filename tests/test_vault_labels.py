"""Vault searchable labels (2026-10-21): title+label search, label filter with counts,
rename/remove labels without touching the encrypted body, no secret in responses or audit."""
import json

import server
from tests import test_vault_crypto as _vc
from tests.test_vault_crypto import ORIGIN, SECRET_BODY


class VaultLabelTests(_vc.VaultCryptoTests):
    def setUp(self):
        super().setUp()
        self.gh = server.save_vault_snippet({"title": "GitHub 2FA setup key", "body": "JBSWY3DPEHPK3PXP-test",
                                             "tags": ["Auth", "GitHub"]})
        self.wifi = server.save_vault_snippet({"title": "Home wifi", "body": "pw-wifi-secret", "tags": ["home"]})

    def get(self, url):
        st, _, js, data = self.req(url, cookie=self.owner)
        self.assertEqual(st, 200, js)
        self.assertNotIn(b"hunter2", data)
        self.assertNotIn(b"JBSWY3DPEHPK3PXP", data)
        self.assertNotIn(b"pw-wifi-secret", data)
        return js

    def ids(self, js):
        return {i["id"] for i in js["items"]}

    def test_search_title_and_label_case_insensitive(self):
        self.assertEqual(self.ids(self.get("/api/vault?q=github")), {self.gh["id"]})
        self.assertEqual(self.ids(self.get("/api/vault?q=AUTH")), {self.entry["id"], self.gh["id"]})
        self.assertEqual(self.ids(self.get("/api/vault?q=auth%20key")), {self.gh["id"]})  # all tokens must hit
        self.assertEqual(self.ids(self.get("/api/vault?q=tag:home")), {self.wifi["id"]})
        self.assertEqual(self.ids(self.get("/api/vault?q=hunter2")), set())  # body never searched

    def test_label_filter_and_counts(self):
        js = self.get("/api/vault")
        self.assertEqual(js["labels"][0], {"name": "Auth", "count": 2})
        self.assertIn({"name": "home", "count": 1}, js["labels"])
        self.assertEqual(self.ids(self.get("/api/vault?label=auth")), {self.entry["id"], self.gh["id"]})
        self.assertEqual(self.ids(self.get("/api/vault?label=Auth&label=GitHub")), {self.gh["id"]})
        self.assertEqual(self.get("/api/vault/labels")["labels"], js["labels"])

    def test_rename_and_remove_preserve_ciphertext(self):
        before = json.loads(self.raw(self.gh["id"]))["enc"]
        st, _, js, _ = self.req("/api/vault/labels/rename", "POST", {"from": "auth", "to": "2FA"},
                                cookie=self.owner, headers={"Origin": ORIGIN})
        self.assertEqual(st, 200, js)
        self.assertEqual(js["changed"], 2)
        after = json.loads(self.raw(self.gh["id"]))
        self.assertEqual(after["enc"], before)
        self.assertEqual(after["tags"], ["2FA", "GitHub"])
        self.assertEqual(server.load_vault_snippet(self.entry["id"])["body"], SECRET_BODY)
        st, _, js, _ = self.req("/api/vault/labels/rename", "POST", {"from": "github", "to": ""},
                                cookie=self.owner, headers={"Origin": ORIGIN})
        self.assertEqual(js["changed"], 1)
        self.assertEqual(server.load_vault_snippet(self.gh["id"], decrypt=False)["tags"], ["2FA"])
        audit = server.VAULT_AUDIT_FILE.read_text()
        self.assertNotIn("JBSWY3DPEHPK3PXP", audit)
        self.assertIn("label_rename", audit)

    def test_labels_require_owner(self):
        st, _, _, _ = self.req("/api/vault/labels")
        self.assertIn(st, (401, 403))
        st, _, _, _ = self.req("/api/vault/labels/rename", "POST", {"from": "auth", "to": "x"},
                               headers={"Origin": ORIGIN})
        self.assertIn(st, (401, 403))
        self.assertEqual(server.load_vault_snippet(self.gh["id"], decrypt=False)["tags"], ["Auth", "GitHub"])


# Reuse the crypto fixture only; don't re-run its tests here (extra entries would skew their counts).
for _n in [n for n in vars(_vc.VaultCryptoTests) if n.startswith("test")]:
    setattr(VaultLabelTests, _n, None)
