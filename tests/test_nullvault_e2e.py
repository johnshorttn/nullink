"""0.6.0 end-to-end encryption: the server keeps ciphertext + metadata only, migrates per item only after the device
confirms a read-back, refuses old clients without wiping, and never retires the legacy key on its own."""
import base64
import json
import os
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import nullvault
import nullvault_e2e as e2e
import nullvault_ext as ext
import server
from tests.test_nullvault import APK, CERT, ORIGIN, SECRET_BODY, NullVaultBase

b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
PLAIN_MARK = "E2E-PLAINTEXT-MUST-NOT-REACH-DISK-7c1f"


def wrap(kind):
    w = {"salt": b64(secrets.token_bytes(16)), "n": b64(secrets.token_bytes(12)), "c": b64(secrets.token_bytes(48))}
    if kind == "passphrase":
        return {"kdf": "argon2id", "m": 65536, "t": 3, "p": 1, **w}
    return {"kdf": "hkdf-sha256", **w}


def header(vk_id=None):
    return {"v": 1, "vk_id": vk_id or secrets.token_hex(8), "passphrase": wrap("passphrase"), "recovery": wrap("recovery")}


def seal(vk, kid, kind, iid, ver, payload, extra=""):
    """Same AEAD and AAD as the app (core/E2e.kt): AES-256-GCM, AAD = nullvault-item-v1|kind|id|ver|kid[|project]."""
    n = secrets.token_bytes(12)
    aad = f"nullvault-item-v1|{kind}|{iid}|{ver}|{kid}" + (f"|{extra}" if extra else "")
    c = AESGCM(vk).encrypt(n, json.dumps(payload).encode(), aad.encode())
    return {"v": 1, "alg": "A256GCM", "kid": kid, "ver": ver, "n": b64(n), "c": b64(c)}


class E2EBase(NullVaultBase):
    # the attested app version must match the reported versionCode
    def signed_call(self, dev, path, purpose="sync", extra=None, kd_kw=None, apk=None, **kw):
        if apk is not None and kd_kw is None:
            kd_kw = {"version": apk["version_code"]}
        return super().signed_call(dev, path, purpose, extra=extra, kd_kw=kd_kw, apk=apk, **kw)

    def register(self, kd_kw=None, apk=None, **kw):
        if apk is not None and kd_kw is None:
            kd_kw = {"version": apk["version_code"]}
        return super().register(kd_kw=kd_kw, apk=apk, **kw)

    def setUp(self):
        super().setUp()
        for k, v in (("NULLVAULT_LINKS", "1"), ("NULLVAULT_NOTES", "1"), ("NULLVAULT_DISCOVERY_CADDY", "0")):
            os.environ[k] = v
            self.addCleanup(os.environ.pop, k, None)
        ext.nv, ext.server = nullvault, server
        e2e.bind(nullvault, server)
        rel = {"version_name": "x", "channel": "test", "signing_cert_sha256": [CERT], "apk_sha256": [APK], "revoked": False}
        pins = nullvault.load_pins()
        for vc in (8, 10, 11):
            pins["releases"][str(vc)] = dict(rel)
        server._atomic_write_json(nullvault.pins_file(), pins)
        self.v11 = self.apk(version_code=11, version_name="0.6.0-test")
        self.dev = self.register(apk=self.v11)
        self.vk = secrets.token_bytes(32)

    def w(self, op, kind="entry", rec=None, apk=None, **extra):
        x = {"op": op, "kind": kind, **extra}
        if rec is not None:
            x[kind if kind != "e2e" else "_"] = rec
        return self.signed_call(self.dev, "/api/vault/device/write", "write", extra=x, apk=apk or self.v11)

    def init(self, hd=None):
        hd = hd or header()
        st, js, _, _ = self.w("init", "e2e", e2e_header=hd)
        self.assertEqual(st, 200, js)
        return hd

    def sync11(self):
        return self.sync(self.dev, apk=self.v11)

    def disk(self) -> str:
        parts = [f.read_text() for f in server.VAULT_DIR.glob("*.json")]
        nf = nullvault.nv_dir() / "notes.json"
        if nf.exists():
            parts.append(nf.read_text())
        return "\n".join(parts)


class HeaderTests(E2EBase):
    def test_init_once_then_rewrap_by_generation(self):
        hd = self.init()
        st, js, _, _ = self.w("init", "e2e", e2e_header=header())
        self.assertEqual((st, js["error"]), (409, "e2e_exists"))
        new = {**hd, "passphrase": wrap("passphrase")}
        st, js, _, _ = self.w("rewrap", "e2e", e2e_header=new, base_gen=5)
        self.assertEqual((st, js["error"]), (409, "conflict"))
        st, js, _, _ = self.w("rewrap", "e2e", e2e_header=new, base_gen=1)
        self.assertEqual(st, 200, js)
        self.assertEqual(js["e2e"]["gen"], 2)
        self.assertEqual(json.loads(e2e.header_file().read_text())["passphrase"], new["passphrase"])
        st, js, _, _ = self.w("rewrap", "e2e", e2e_header=header(), base_gen=2)
        self.assertEqual((st, js["error"]), (409, "rotation_not_supported"))

    def test_header_shapes_and_weak_kdf_refused(self):
        for bad in ({**header(), "extra": 1}, {**header(), "passphrase": {**wrap("passphrase"), "m": 1024}},
                    {**header(), "passphrase": {**wrap("passphrase"), "t": 1}}, {**header(), "vk_id": "XYZ"},
                    {**header(), "recovery": {**wrap("recovery"), "kdf": "none"}},
                    {**header(), "recovery": {**wrap("recovery"), "c": b64(b"x" * 10)}}):
            st, js, _, _ = self.w("init", "e2e", e2e_header=bad)
            self.assertEqual((st, js["error"]), (400, "bad_header"))
        self.assertIsNone(e2e.header())

    def test_header_needs_fingerprint_key_not_window_key(self):
        st, body = e2e.header_write({"signed_by": "session", "op": "init", "e2e_header": header()})
        self.assertEqual((st, body["error"]), (403, "fingerprint_required"))

    def test_sync_carries_header_and_min_version(self):
        hd = self.init()
        st, js, _, _ = self.sync11()
        self.assertEqual(st, 200, js)
        self.assertEqual(js["e2e"]["vk_id"], hd["vk_id"])
        self.assertEqual(js["e2e"]["passphrase"], hd["passphrase"])
        self.assertEqual(js["e2e_min_version_code"], 11)


class OldClientTests(E2EBase):
    def test_v8_v10_v11_upgrade_and_old_client_refused_without_wipe(self):
        dev = self.register(apk=self.apk(version_code=8))
        st, js, _, _ = self.sync(dev, apk=self.apk(version_code=8))
        self.assertEqual(st, 200, js)                                   # v8 before E2E: unchanged
        st, js, _, _ = self.sync(dev, apk=self.apk(version_code=10))
        self.assertEqual(st, 200, js)                                   # v10 before E2E: unchanged
        self.assertIsNone(js["e2e"])
        self.init()                                                     # a v11 phone turns on E2E
        for vc in (8, 10):
            st, js, _, _ = self.sync(dev, apk=self.apk(version_code=vc))
            self.assertEqual(st, 426, js)
            self.assertEqual(js["error"], "e2e_client_required")
            self.assertNotIn("wipe", js)
            st, js, _, _ = self.signed_call(dev, "/api/vault/device/write", "write", apk=self.apk(version_code=vc),
                                            extra={"op": "update", "entry": {"id": self.entry["id"], "title": "x", "body": "y"}})
            self.assertEqual(st, 426, js)
            self.assertNotIn("wipe", js)
        d = nullvault.devices()[dev["js"]["device_id"]]
        self.assertEqual(d["status"], "active")                         # not flagged, not revoked
        st, js, _, _ = self.sync(dev, apk=self.v11)                     # same phone after updating to v11
        self.assertEqual(st, 200, js)
        self.assertEqual(server.load_vault_snippet(self.entry["id"])["body"], SECRET_BODY)  # nothing rewritten


class EntryTests(E2EBase):
    def test_server_never_stores_plaintext_for_e2e_items(self):
        hd = self.init()
        iid = secrets.token_hex(6)
        blob = seal(self.vk, hd["vk_id"], "entry", iid, 1, {"title": PLAIN_MARK, "tags": [PLAIN_MARK], "body": PLAIN_MARK})
        st, js, _, _ = self.w("create", rec={"id": iid, "e2e": blob})
        self.assertEqual(st, 200, js)
        self.assertEqual(js["entry"]["ver"], 1)
        # plaintext writes are refused once E2E is on, so no plaintext copy can be created by a device
        st, js, _, _ = self.w("create", rec={"title": PLAIN_MARK, "body": PLAIN_MARK})
        self.assertEqual((st, js["error"]), (409, "e2e_required"))
        st, js, _, _ = self.w("update", rec={"id": iid, "title": PLAIN_MARK, "body": PLAIN_MARK})
        self.assertEqual((st, js["error"]), (409, "e2e_required"))
        raw = json.loads((server.VAULT_DIR / f"{iid}.json").read_text())
        self.assertNotIn("enc", raw); self.assertEqual(raw["title"], ""); self.assertEqual(raw["tags"], [])
        self.assertNotIn(PLAIN_MARK, self.disk())
        self.assertNotIn(PLAIN_MARK, server.VAULT_AUDIT_FILE.read_text())
        self.assertNotIn(PLAIN_MARK, nullvault.registry_file().read_text())
        # the server's own read paths can only produce ciphertext / a mask
        item = server.load_vault_snippet(iid, decrypt=True)
        self.assertTrue(item["e2e"]); self.assertEqual(item["body"], server.VAULT_MASK)
        st, js, _, _ = self.sync11()
        row = next(x for x in js["entries"] if x["id"] == iid)
        self.assertEqual(row["e2e"], blob); self.assertNotIn("body", row); self.assertNotIn("title", row)
        # and the device can decrypt what it gets back
        got = AESGCM(self.vk).decrypt(base64.b64decode(row["e2e"]["n"]), base64.b64decode(row["e2e"]["c"]),
                                      f"nullvault-item-v1|entry|{iid}|1|{hd['vk_id']}".encode())
        self.assertEqual(json.loads(got)["body"], PLAIN_MARK)

    def test_versions_ids_and_kid_enforced(self):
        hd = self.init()
        iid = secrets.token_hex(6)
        mk = lambda ver, kid=hd["vk_id"]: seal(self.vk, kid, "entry", iid, ver, {"title": "t", "tags": [], "body": "b"})  # noqa: E731
        self.assertEqual(self.w("create", rec={"id": iid, "e2e": mk(2)})[0], 400)            # create must be ver 1
        self.assertEqual(self.w("create", rec={"id": iid, "e2e": mk(1, "ff" * 8)})[0], 400)   # unknown kid
        self.assertEqual(self.w("create", rec={"id": "BAD!", "e2e": mk(1)})[0], 409)
        self.assertEqual(self.w("create", rec={"id": iid, "e2e": mk(1)})[0], 200)
        self.assertEqual(self.w("create", rec={"id": iid, "e2e": mk(1)})[1]["error"], "bad_id")  # no overwrite
        st, js, _, _ = self.w("update", rec={"id": iid, "e2e": mk(3)})
        self.assertEqual((st, js["expected_ver"]), (409, 2))
        st, js, _, _ = self.w("update", rec={"id": iid, "e2e": mk(2)})
        self.assertEqual((st, js["entry"]["ver"]), (200, 2))
        self.assertEqual(self.w("delete", rec={"id": iid})[0], 200)
        self.assertFalse((server.VAULT_DIR / f"{iid}.json").exists())

    def test_web_and_bot_cannot_read_or_overwrite_e2e_items(self):
        hd = self.init()
        iid = secrets.token_hex(6)
        self.w("create", rec={"id": iid, "e2e": seal(self.vk, hd["vk_id"], "entry", iid, 1, {"title": "t", "tags": [], "body": "b"})})
        with self.assertRaises(server.VaultE2EItem):
            server.save_vault_snippet({"id": iid, "title": "x", "body": "server copy"})
        listed = next(x for x in server.list_vault_snippets() if x["id"] == iid)
        self.assertEqual(listed["title"], server.VAULT_E2E_TITLE)


class MigrationTests(E2EBase):
    def legacy_payload(self):
        return {"title": "Bank", "tags": ["money"], "body": SECRET_BODY}

    def test_migrate_readback_confirm_then_legacy_copy_gone(self):
        hd = self.init()
        iid = self.entry["id"]
        st, js, _, _ = self.sync11()
        row = next(x for x in js["entries"] if x["id"] == iid)
        self.assertEqual(row["body"], SECRET_BODY)                       # legacy: server-decrypted for the device
        blob = seal(self.vk, hd["vk_id"], "entry", iid, 1, self.legacy_payload())
        st, js, _, _ = self.w("migrate", rec={"id": iid, "e2e": blob})
        self.assertEqual(st, 200, js)
        self.assertEqual(js["entry"]["e2e_pending"], blob)               # read back from disk
        raw = json.loads((server.VAULT_DIR / f"{iid}.json").read_text())
        self.assertIn("enc", raw)                                        # nothing deleted before the confirm
        st, js, _, _ = self.w("migrate_confirm", rec={"id": iid, "sha256": "00" * 32})
        self.assertEqual((st, js["error"]), (409, "verify_mismatch"))
        self.assertIn("enc", json.loads((server.VAULT_DIR / f"{iid}.json").read_text()))
        st, js, _, _ = self.w("migrate_confirm", rec={"id": iid, "sha256": e2e.blob_sha(blob)})
        self.assertEqual(st, 200, js)
        raw = json.loads((server.VAULT_DIR / f"{iid}.json").read_text())
        self.assertNotIn("enc", raw); self.assertNotIn("e2e_pending", raw); self.assertEqual(raw["e2e"], blob)
        self.assertNotIn(SECRET_BODY, self.disk()); self.assertNotIn("Bank", self.disk())
        # confirm is idempotent (a lost response is retried safely)
        self.assertTrue(self.w("migrate_confirm", rec={"id": iid, "sha256": e2e.blob_sha(blob)})[1]["already"])
        # the legacy server key is untouched by migration (retiring it is a separate, refused-by-default command)
        self.assertTrue(server.vault_key_available()); self.assertFalse(e2e.retired_marker().exists())

    def test_partial_failure_and_resume(self):
        hd = self.init()
        second = server.save_vault_snippet({"title": "Mail", "body": "second secret", "tags": []})
        a, b = self.entry["id"], second["id"]
        ba = seal(self.vk, hd["vk_id"], "entry", a, 1, self.legacy_payload())
        self.assertEqual(self.w("migrate", rec={"id": a, "e2e": ba})[0], 200)
        # ... the phone dies before confirming a, and before touching b
        st, js, _, _ = self.sync11()
        rows = {x["id"]: x for x in js["entries"]}
        self.assertEqual(rows[a]["e2e_pending"], ba)                    # resume: pending is offered back
        self.assertEqual(rows[a]["body"], SECRET_BODY)                  # legacy copy still there
        self.assertNotIn("e2e_pending", rows[b])
        inv = e2e.legacy_inventory(ext)
        self.assertEqual(sorted(inv["legacy_entries"]), sorted([a, b])); self.assertEqual(inv["pending_confirm"], [a])
        # resume: re-upload replaces a stale pending; then both confirm
        ba2 = seal(self.vk, hd["vk_id"], "entry", a, 1, self.legacy_payload())
        self.assertEqual(self.w("migrate", rec={"id": a, "e2e": ba2})[0], 200)
        self.assertEqual(self.w("migrate_confirm", rec={"id": a, "sha256": e2e.blob_sha(ba)})[0], 409)   # stale hash
        self.assertEqual(self.w("migrate_confirm", rec={"id": a, "sha256": e2e.blob_sha(ba2)})[0], 200)
        bb = seal(self.vk, hd["vk_id"], "entry", b, 1, {"title": "Mail", "tags": [], "body": "second secret"})
        self.assertEqual(self.w("migrate", rec={"id": b, "e2e": bb})[0], 200)
        self.assertEqual(self.w("migrate_confirm", rec={"id": b, "sha256": e2e.blob_sha(bb)})[0], 200)
        self.assertEqual(self.w("migrate", rec={"id": b, "e2e": bb})[1]["error"], "not_legacy")
        self.assertEqual(e2e.legacy_inventory(ext)["legacy_entries"], [])

    def test_notes_migrate_and_e2e_create(self):
        st, js, _, _ = self.w("create", "project", {"name": "NullKey"})
        pid = js["project"]["id"]
        st, js, _, _ = self.w("create", "note", {"project_id": pid, "title": "ssh", "body": SECRET_BODY})
        self.assertEqual(st, 200, js)
        nid = js["note"]["id"]
        hd = self.init()
        st, js, _, _ = self.w("update", "note", {"id": nid, "title": "x", "body": "y"})
        self.assertEqual((st, js["error"]), (409, "e2e_required"))
        blob = seal(self.vk, hd["vk_id"], "note", nid, 1, {"title": "ssh", "body": SECRET_BODY}, pid)
        st, js, _, _ = self.w("migrate", "note", {"id": nid, "e2e": blob})
        self.assertEqual((st, js["note"]["e2e_pending"]), (200, blob))
        st, js, _, _ = self.sync11()
        n = next(x for x in js["notes"] if x["id"] == nid)
        self.assertEqual(n["body"], SECRET_BODY); self.assertEqual(n["e2e_pending"], blob)
        st, js, _, _ = self.w("migrate_confirm", "note", {"id": nid, "sha256": e2e.blob_sha(blob)})
        self.assertEqual(st, 200, js)
        nid2 = secrets.token_hex(6)
        st, js, _, _ = self.w("create", "note", {"id": nid2, "project_id": pid,
                                                 "e2e": seal(self.vk, hd["vk_id"], "note", nid2, 1, {"title": PLAIN_MARK, "body": PLAIN_MARK}, pid)})
        self.assertEqual(st, 200, js)
        st, js, _, _ = self.sync11()
        ns = {x["id"]: x for x in js["notes"]}
        for i in (nid, nid2):
            self.assertIn("e2e", ns[i]); self.assertNotIn("body", ns[i]); self.assertNotIn("title", ns[i])
        self.assertNotIn(SECRET_BODY, (nullvault.nv_dir() / "notes.json").read_text())
        self.assertNotIn(PLAIN_MARK, self.disk())
        self.assertEqual(self.w("delete", "note", {"id": nid2})[0], 200)


class RetireLegacyKeyTests(E2EBase):
    def test_refuses_until_everything_is_migrated_and_never_destroys_the_key(self):
        code, msg = e2e.retire_legacy_key(ext, confirm=True)
        self.assertEqual(code, 2)                                        # no E2E yet
        hd = self.init()
        code, msg = e2e.retire_legacy_key(ext, confirm=True)
        self.assertEqual(code, 3); self.assertIn(self.entry["id"], msg)  # a legacy item left
        self.assertNotIn(SECRET_BODY, msg)
        iid = self.entry["id"]
        blob = seal(self.vk, hd["vk_id"], "entry", iid, 1, {"title": "Bank", "tags": [], "body": SECRET_BODY})
        self.w("migrate", rec={"id": iid, "e2e": blob}); self.w("migrate_confirm", rec={"id": iid, "sha256": e2e.blob_sha(blob)})
        code, msg = e2e.retire_legacy_key(ext, confirm=False)
        self.assertEqual(code, 0); self.assertIn("--confirm", msg); self.assertFalse(e2e.retired_marker().exists())
        code, msg = e2e.retire_legacy_key(ext, confirm=True)
        self.assertEqual(code, 0); self.assertTrue(e2e.retired_marker().exists())
        self.assertTrue(server.vault_key_available())                    # the key itself is never destroyed here
        with self.assertRaises(server.VaultKeyUnavailable):
            server.save_vault_snippet({"title": "new web item", "body": "x"})
