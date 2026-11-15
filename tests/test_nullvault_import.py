"""NullVault 0.8.0 (John 2026-11-14 11:21 PM ET): bot-to-vault import queue.

Scope isolation (import token can only submit + read its own status), the phone's signed X25519 import key, sealing the
server cannot open, approve (fingerprint, K_dev) -> E2E add-only entry -> read-back -> ack -> blob deleted, reject,
replay and expiry, a no-plaintext scan of data/audit/alerts/logs, add-only on every route, and the shared crypto vector
the app checks too."""
import base64
import io
import json
import os
import secrets
import sys
import tempfile
import time
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import nullvault
import nullvault_e2e as e2e
import nullvault_import as imp
import server
from tests.test_nullvault import ORIGIN, totp_code
from tests.test_nullvault_e2e import E2EBase, header, seal as e2e_seal

b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
LEAK = "IMPORT-SECRET-MUST-NOT-LEAK-" + secrets.token_hex(6)

# Shared with the app (ImportCryptoTest.kt): same keys, ids and nonce -> same bytes.
VEC_SK = bytes(range(1, 33)); VEC_ESK = bytes(range(101, 133)); VEC_N = bytes(range(201, 213))
VEC_PUB = "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw="
VEC_IID, VEC_SUB, VEC_DEV = "0123456789abcdef0123456789abcdef", "forge", "dev_0123456789abcdef"
VEC_PT = '{"fields":{"api_key":"test-vector-not-a-secret"},"title":"Vector item","type":"secret","v":1}'
VEC_BLOB = {"v": 1, "alg": "X25519-HKDF-SHA256-A256GCM", "kid": "aaa8fff703b50b22",
            "epk": "VxR2nRFr92Q2rnS8eT0sMK0ZA8WaxSc4BcfiaYtBDDY=", "n": "ycrLzM3Oz9DR0tPU",
            "c": "r68qMaSr56y74Pn2z0ttHU17pp1Fx1qgv+Y99l0yHPRH4c/XOBCt3qrGi8BJhMOOFylnMBbnOViB2bXTWaBrCumQ6u6yJMAZ3RNqc5zHVAspahKHd+zKDQl1a0xBgs2Vvo/3xPSYcFIJLD72Zg=="}


def raw_pub(sk):
    return sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def raw_priv(sk):
    return sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())


class ImportBase(E2EBase):
    def setUp(self):
        os.environ["NULLVAULT_IMPORT_SWEEP"] = "0"
        self.addCleanup(os.environ.pop, "NULLVAULT_IMPORT_SWEEP", None)
        super().setUp()
        imp.bind(nullvault, server)
        imp.limits.clear()
        self.hd = self.init(header())
        self.kid = self.hd["vk_id"]
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.tok = self.mint("forge", "Forge (Bob)")
        self.phone_sk = X25519PrivateKey.generate()

    def mint(self, name, label):
        out = Path(self.tmp.name) / f"{name}.token"
        imp.token_add(name, label, out)
        return {"Authorization": "Bearer " + out.read_text().strip(), "_file": str(out)}

    def H(self, t):
        return {k: v for k, v in t.items() if not k.startswith("_")}

    def publish(self, dev=None, sk=None, **over):
        pub = raw_pub(sk or self.phone_sk)
        ik = {"v": 1, "alg": "X25519", "pub": b64(pub), "kid": imp.kid_of(pub), **over}
        return self.signed_call(dev or self.dev, "/api/vault/import/key", "import_key", extra={"import_key": ik}, apk=self.v11)

    def keys(self, tok=None):
        return self.req("/api/vault/import/keys", headers=self.H(tok or self.tok))

    def plaintext(self, title="Forge API key", typ="secret", secret=LEAK):
        return json.dumps({"v": 1, "type": typ, "title": title, "fields": {"api_key": secret}}, sort_keys=True,
                          separators=(",", ":")).encode()

    def submit(self, title="Forge API key", typ="secret", tok=None, iid=None, sealed=None, extra=None, sub="forge"):
        iid = iid or secrets.token_hex(16)
        did = self.dev["js"]["device_id"]
        if sealed is None:
            sealed = {did: imp.seal(raw_pub(self.phone_sk), self.plaintext(title, typ), iid, sub, did)}
        body = {"import_id": iid, "title": title, "type": typ, "sealed": sealed, **(extra or {})}
        st, _, js, _ = self.req("/api/vault/import/submit", "POST", body, headers=self.H(tok or self.tok))
        return st, js, iid

    def pending(self, dev=None):
        st, _, js, _ = self.req("/api/vault/import/pending", headers=self.bearer(dev or self.dev))
        self.assertEqual(st, 200, js)
        return js

    def decide(self, iid, decision, entry=None, dev=None, **kw):
        a = {"import_id": iid, "decision": decision}
        if entry is not None:
            a["entry"] = entry
        return self.signed_call(dev or self.dev, "/api/vault/import/decide", "import", extra={"import": a}, apk=self.v11, **kw)

    def ack(self, iid, vid, sha, dev=None):
        return self.signed_call(dev or self.dev, "/api/vault/import/ack", "import_ack",
                                extra={"import": {"import_id": iid, "entry_id": vid, "sha256": sha}}, apk=self.v11)

    def phone_open(self, item):
        did = self.dev["js"]["device_id"]
        return json.loads(imp.open_sealed(raw_priv(self.phone_sk), item["sealed"], item["import_id"], item["submitter"], did))

    def approve_flow(self, iid):
        item = next(i for i in self.pending()["imports"] if i["import_id"] == iid)
        doc = self.phone_open(item)
        vid = secrets.token_hex(6)
        blob = e2e_seal(self.vk, self.kid, "entry", vid, 1, {"title": doc["title"], "tags": ["imported"], "body": json.dumps(doc["fields"])})
        st, js, _, _ = self.decide(iid, "approve", {"id": vid, "e2e": blob})
        self.assertEqual(st, 200, js)
        self.assertEqual(js["e2e"], blob)                                   # read back from disk
        st2, js2, _, _ = self.ack(iid, vid, e2e.blob_sha(js["e2e"]))
        self.assertEqual(st2, 200, js2)
        return vid, blob

    def everything_on_disk(self) -> bytes:
        out = []
        for f in server.DATA.rglob("*"):
            if f.is_file():
                out.append(f.read_bytes())
        return b"\n".join(out)

    def audit(self):
        try:
            return [json.loads(l) for l in server.VAULT_AUDIT_FILE.read_text().splitlines()]
        except FileNotFoundError:
            return []


class PublishAndKeysTests(ImportBase):
    def test_no_key_refuses_submission_clearly(self):
        st, _, js, _ = self.keys()
        self.assertEqual((st, js["keys"], js["error"]), (200, [], "no_import_key"))
        st, js, _ = self.submit(sealed={self.dev["js"]["device_id"]: {"v": 1}})
        self.assertEqual((st, js["error"]), (409, "no_import_key"))
        self.assertIn("0.8.0", js["message"])

    def test_publish_is_device_signed_and_verifiable_by_submitters(self):
        st, js, _, _ = self.publish()
        self.assertEqual(st, 200, js)
        st, _, js, _ = self.keys()
        k = js["keys"][0]
        self.assertEqual((k["device_id"], k["pub"]), (self.dev["js"]["device_id"], b64(raw_pub(self.phone_sk))))
        self.assertTrue(imp.verify_publication(k))
        forged = dict(k, pub=b64(raw_pub(X25519PrivateKey.generate())))     # server swaps the key: signature no longer fits
        forged["kid"] = imp.kid_of(base64.b64decode(forged["pub"]))
        self.assertFalse(imp.verify_publication(forged))
        other = self.register(apk=self.v11)
        self.assertFalse(imp.verify_publication(dict(k, device_pubkey_spki=other["js"].get("pubkey_spki") or
                                                     nullvault.devices()[other["js"]["device_id"]]["pubkey_spki"])))
        self.assertIn("import_key_published", [a["event"] for a in self.audit()])

    def test_bad_publications_refused(self):
        self.assertEqual(self.publish(kid="0" * 16)[0], 400)
        self.assertEqual(self.publish(alg="P-256")[0], 400)
        pub = raw_pub(self.phone_sk)
        st, js, _, _ = self.signed_call(self.dev, "/api/vault/import/key", "sync",
                                        extra={"import_key": {"v": 1, "alg": "X25519", "pub": b64(pub), "kid": imp.kid_of(pub)}}, apk=self.v11)
        self.assertEqual(st, 400)                                          # wrong signed purpose
        self.assertEqual(imp.published(), {})

    def test_rotation_and_revoke_follow_the_device(self):
        self.publish()
        new = X25519PrivateKey.generate()
        self.publish(sk=new)
        self.assertEqual(self.keys()[2]["keys"][0]["pub"], b64(raw_pub(new)))
        st, js, _ = self.submit()                                           # sealed to the old key -> wrong kid
        self.assertEqual((st, js["error"]), (400, "bad_blob"))
        self.phone_sk = new
        self.assertEqual(self.submit()[0], 201)
        self.fresh_codes()
        self.assertEqual(self.revoke(self.dev["js"]["device_id"])[0], 200)
        self.assertEqual(self.keys()[2]["keys"], [])
        st, js, _ = self.submit()
        self.assertEqual(st, 409)


class ScopeIsolationTests(ImportBase):
    def test_import_token_cannot_read_or_modify_anything(self):
        self.publish()
        t = self.H(self.tok)
        for path, m in (("/api/vault", "GET"), ("/api/vault/" + self.entry["id"], "GET"), ("/api/vault/labels", "GET"),
                        ("/api/vault/" + self.entry["id"], "PATCH"), ("/api/vault/" + self.entry["id"], "DELETE"),
                        ("/api/vault/sync", "POST"), ("/api/vault/device/write", "POST"), ("/api/vault/sync-challenge", "POST"),
                        ("/api/vault/import/pending", "GET"), ("/api/vault/import/decide", "POST"), ("/api/vault/import/ack", "POST"),
                        ("/api/vault/import/key", "POST"), ("/api/vault/devices", "GET"), ("/api/vault/deposit", "POST"),
                        ("/api/vault/bot-read", "POST"), ("/api/files", "GET"), ("/api/vault/approvals", "GET"),
                        ("/api/vault/actions", "GET"), ("/api/vault/config", "GET"), ("/api/vault/layout", "GET")):
            st, _, js, data = self.req(path, m, {} if m != "GET" else None, headers=t)
            self.assertIn(st, (400, 401, 403, 404), (path, m, st, js))
            self.assertNotIn(b"Bank", data, path)
        self.assertTrue(server.load_vault_snippet(self.entry["id"], decrypt=False))

    def test_other_credentials_cannot_submit(self):
        self.publish()
        for h in (self.bearer(self.dev), {}, {"Authorization": "Bearer nlvi_forged"}):
            self.assertEqual(self.req("/api/vault/import/submit", "POST", {}, headers=h)[0], 401)
        self.assertEqual(self.req("/api/vault/import/submit", "POST", {}, cookie=self.owner, headers={"Origin": ORIGIN})[0], 401)
        _rec, api_tok = server.create_api_token("ai", ["read", "write"], ["*"])
        self.assertEqual(self.req("/api/vault/import/keys", headers={"Authorization": "Bearer " + api_tok})[0], 401)

    def test_status_lists_only_own_submissions_and_no_content(self):
        self.publish()
        other = self.mint("helper", "Helper bot")
        _, _, mine = self.submit()
        _, _, theirs = self.submit(title="Other", tok=other, sub="helper")
        st, _, js, data = self.req("/api/vault/import/status", headers=self.H(self.tok))
        self.assertEqual([i["import_id"] for i in js["imports"]], [mine])
        self.assertNotIn(b"sealed", data); self.assertNotIn(b'"c"', data)
        self.assertEqual(self.req("/api/vault/import/status", headers=self.H(other))[2]["imports"][0]["import_id"], theirs)

    def test_revoked_token_refused(self):
        imp.token_revoke("forge")
        self.assertEqual(self.keys()[0], 401)


class FlowTests(ImportBase):
    def setUp(self):
        super().setUp()
        self.publish()

    def test_submit_raises_import_needed_alert_and_sync_badge(self):
        n0 = len(self.alerts)
        st, js, iid = self.submit()
        self.assertEqual(st, 201, js)
        self.assertTrue(any("Import needed" in a and "Forge (Bob)" in a and "Forge API key" in a and "(secret)" in a
                            for a in self.alerts[n0:]))
        st, js, _, _ = self.sync11()
        self.assertEqual(js["imports"], {"pending": 1, "key_kid": imp.kid_of(raw_pub(self.phone_sk))})
        item = self.pending()["imports"][0]
        self.assertEqual((item["import_id"], item["title"], item["type"], item["submitter_label"]), (iid, "Forge API key", "secret", "Forge (Bob)"))
        self.assertEqual(self.phone_open(item)["fields"]["api_key"], LEAK)

    def test_approve_creates_add_only_e2e_entry_then_ack_deletes_blob(self):
        _, _, iid = self.submit()
        vid, blob = self.approve_flow(iid)
        rec = server._vault_read_raw(vid)
        self.assertEqual((rec["e2e"], rec["add_only"], rec["import_id"], rec["title"]), (blob, True, iid, ""))
        self.assertFalse(imp._blob_path(iid).exists())
        self.assertEqual(self.pending()["imports"], [])
        st, _, js, _ = self.req("/api/vault/import/status", headers=self.H(self.tok))
        self.assertEqual(js["imports"][0]["status"], "approved")
        row = next(e for e in self.sync11()[1]["entries"] if e["id"] == vid)
        self.assertEqual((row["add_only"], row["imported_from"]), (True, "Forge (Bob)"))
        ev = [a["event"] for a in self.audit()]
        for x in ("import_submit", "import_approve", "import_ack", "import_purged"):
            self.assertIn(x, ev)

    def test_approve_needs_k_dev_not_session(self):
        _, _, iid = self.submit()
        self.assertNotIn("import", nullvault.SESSION_PURPOSES)
        nonce = self.sync_challenge(self.dev, "import")[2]["nonce"]
        payload = {"purpose": "import", "nonce": nonce, "ts": int(time.time()), "device_id": self.dev["js"]["device_id"],
                   "signed_by": "session", "import": {"import_id": iid, "decision": "approve"}}
        st, _, js, _ = self.req("/api/vault/import/decide", "POST", self.envelope(self.dev["kdev"], payload), headers=self.bearer(self.dev))
        self.assertEqual((st, js.get("error")), (403, "session_not_allowed"))

    def test_retry_after_lost_response_and_ack_checks(self):
        _, _, iid = self.submit()
        vid = secrets.token_hex(6)
        blob = e2e_seal(self.vk, self.kid, "entry", vid, 1, {"title": "t", "tags": [], "body": "b"})
        self.assertEqual(self.decide(iid, "approve", {"id": vid, "e2e": blob})[0], 200)
        st, js, _, _ = self.decide(iid, "approve", {"id": vid, "e2e": blob})          # same entry again: idempotent
        self.assertEqual((st, js["e2e"]), (200, blob))
        self.assertEqual(self.decide(iid, "approve", {"id": secrets.token_hex(6), "e2e": blob})[1]["error"], "already_created")
        self.assertEqual(self.decide(iid, "reject")[1]["error"], "already_created")
        self.assertEqual(self.ack(iid, vid, "0" * 64)[1]["error"], "verify_mismatch")
        self.assertTrue(imp._blob_path(iid).exists())                                  # kept until a good ack
        self.assertEqual(self.ack(iid, vid, e2e.blob_sha(blob))[0], 200)
        self.assertEqual(self.ack(iid, vid, e2e.blob_sha(blob))[1].get("already"), True)

    def test_approve_only_creates(self):
        _, _, iid = self.submit()
        vid = self.entry["id"]                                                         # existing id: no overwrite
        blob = e2e_seal(self.vk, self.kid, "entry", vid, 1, {"title": "t", "tags": [], "body": "b"})
        self.assertEqual(self.decide(iid, "approve", {"id": vid, "e2e": blob})[1]["error"], "bad_id")
        self.assertEqual(self.decide(iid, "approve", {"id": secrets.token_hex(6), "e2e": blob, "op": "update"})[1]["error"], "bad_id")
        self.assertEqual(self.decide(iid, "approve", {"id": secrets.token_hex(6), "e2e": {"v": 1}})[0], 400)

    def test_reject_deletes_blob(self):
        _, _, iid = self.submit()
        st, js, _, _ = self.decide(iid, "reject")
        self.assertEqual((st, js["status"]), (200, "rejected"))
        self.assertFalse(imp._blob_path(iid).exists())
        self.assertEqual(self.decide(iid, "reject")[1]["error"], "already_rejected")
        self.assertIn("import_reject", [a["event"] for a in self.audit()])

    def test_replay_and_foreign_device_refused(self):
        _, _, iid = self.submit()
        st, js, _, nonce = self.decide(iid, "reject")
        self.assertEqual(st, 200)
        _, _, iid2 = self.submit()
        self.assertEqual(self.decide(iid2, "reject", nonce=nonce)[1]["error"], "nonce_invalid")   # replayed nonce
        other = self.register(apk=self.v11)
        self.assertEqual(self.decide(iid2, "reject", dev=other)[0], 404)                         # not sealed to it

    def test_expiry_purges_blobs(self):
        _, _, iid = self.submit()
        self.assertEqual(imp.purge(time.time() + imp.EXPIRY_SEC - 60), 0)
        self.assertEqual(imp.purge(time.time() + imp.EXPIRY_SEC + 1), 1)
        self.assertFalse(imp._blob_path(iid).exists())
        self.assertEqual(imp._index()[iid]["status"], "expired")
        self.assertEqual(self.decide(iid, "reject")[1]["error"], "already_expired")
        ev = [a["event"] for a in self.audit()]
        self.assertIn("import_expire", ev); self.assertIn("import_purged", ev)
        imp.purge(time.time() + imp.EXPIRY_SEC + imp.HISTORY_SEC + 10)
        self.assertNotIn(iid, imp._index())
        self.assertEqual(imp.EXPIRY_SEC, 7 * 86400)

    def test_limits(self):
        did = self.dev["js"]["device_id"]
        self.assertEqual(self.submit(title="x" * 121)[0], 400)
        self.assertEqual(self.submit(typ="exe")[0], 400)
        self.assertEqual(self.submit(extra={"target_id": "abc"})[0], 400)                 # no overwrite / target paths
        big = imp.seal(raw_pub(self.phone_sk), b"x" * (imp.MAX_CT + 10), "a" * 32, "forge", did)
        self.assertEqual(self.submit(iid="a" * 32, sealed={did: big})[1]["error"], "bad_blob")
        _, _, used = self.submit()
        self.assertEqual(self.submit(iid=used)[1]["error"], "import_id_used")
        imp.limits.clear()
        codes = [self.submit()[0] for _ in range(imp.SUBMIT_LIMIT[0] + 1)]
        self.assertEqual(codes[-1], 429)


class AddOnlyTests(ImportBase):
    def setUp(self):
        super().setUp()
        self.publish()
        _, _, iid = self.submit()
        self.vid, self.blob = self.approve_flow(iid)

    def test_device_update_and_delete_refused(self):
        b2 = e2e_seal(self.vk, self.kid, "entry", self.vid, 2, {"title": "x", "tags": [], "body": "y"})
        st, js, _, _ = self.w("update", rec={"id": self.vid, "e2e": b2})
        self.assertEqual((st, js["error"]), (409, "add_only"))
        st, js, _, _ = self.w("delete", rec={"id": self.vid})
        self.assertEqual((st, js["error"]), (409, "add_only"))
        self.assertEqual(server._vault_read_raw(self.vid)["e2e"], self.blob)

    def test_owner_web_routes_refused(self):
        self.fresh_codes()
        self.assertEqual(self.req("/api/ssh/stepup", "POST", {"code": totp_code()}, cookie=self.owner, headers={"Origin": ORIGIN})[0], 200)
        st, _, js, _ = self.req("/api/vault/" + self.vid, "DELETE", cookie=self.owner, headers={"Origin": ORIGIN})
        self.assertEqual((st, js.get("error")), (409, "add_only"))
        st, _, js, _ = self.req("/api/vault/" + self.vid, "PATCH", {"title": "x", "body": "y"}, cookie=self.owner, headers={"Origin": ORIGIN})
        self.assertEqual(st, 409)
        st, _, js, _ = self.req("/api/vault/" + self.vid, "PUT", {"title": "x", "body": "y"}, cookie=self.owner, headers={"Origin": ORIGIN})
        self.assertIn(st, (404, 405, 409))
        server.vault_rename_label("imported", "renamed")
        self.assertEqual(server._vault_read_raw(self.vid)["e2e"], self.blob)

    def test_server_functions_refuse(self):
        with self.assertRaises(server.VaultAddOnly):
            server.delete_vault_snippet(self.vid)
        with self.assertRaises((server.VaultAddOnly, server.VaultE2EItem)):
            server.save_vault_snippet({"id": self.vid, "title": "x", "body": "y"})
        self.assertTrue(server._vault_read_raw(self.vid))


class NoPlaintextTests(ImportBase):
    def test_secret_never_reaches_disk_audit_alerts_or_logs(self):
        err = io.StringIO()
        with redirect_stderr(err), redirect_stdout(err):
            self.publish()
            _, _, iid = self.submit()
            self.pending(); self.sync11()
            self.approve_flow(iid)
            _, _, iid2 = self.submit(); self.decide(iid2, "reject")
            _, _, iid3 = self.submit(); imp.purge(time.time() + imp.EXPIRY_SEC + 5)
        hay = self.everything_on_disk() + "\n".join(self.alerts).encode() + err.getvalue().encode()
        for needle in (LEAK.encode(), b64(LEAK.encode()).encode(), LEAK.encode().hex().encode()):
            self.assertNotIn(needle, hay)
        for a in self.audit():                                                         # audit: ids only, no titles
            if a["event"].startswith("import_"):
                self.assertNotIn("Forge API key", json.dumps(a))


class VectorAndCliTests(ImportBase):
    def test_python_vector_matches_app(self):
        sk = X25519PrivateKey.from_private_bytes(VEC_SK)
        self.assertEqual(b64(raw_pub(sk)), VEC_PUB)
        b = imp.seal(raw_pub(sk), VEC_PT.encode(), VEC_IID, VEC_SUB, VEC_DEV, esk=VEC_ESK, nonce=VEC_N)
        self.assertEqual(b, VEC_BLOB)
        self.assertEqual(imp.open_sealed(VEC_SK, VEC_BLOB, VEC_IID, VEC_SUB, VEC_DEV).decode(), VEC_PT)
        for wrong in ((VEC_IID[::-1], VEC_SUB, VEC_DEV), (VEC_IID, "helper", VEC_DEV), (VEC_IID, VEC_SUB, "dev_ffffffffffffffff")):
            with self.assertRaises(Exception):
                imp.open_sealed(VEC_SK, VEC_BLOB, *wrong)

    def cli_env(self):
        key = Path(self.tmp.name) / "cfg.key"
        sk = Ed25519PrivateKey.generate()
        raw = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        key.write_text(b64(raw) + "\n"); key.chmod(0o600)
        return key, b64(raw)

    def test_submit_cli_needs_published_key_and_never_prints(self):
        key, secret = self.cli_env()
        base = f"http://127.0.0.1:{self.httpd.server_port}"
        with mock.patch.dict(os.environ, {"NULLVAULT_CONFIG_KEY_FILE": str(key)}):
            r = imp.submit_ref("config-signing-key", self.tok["_file"], base, host="localhost")
            self.assertEqual((r["ok"], r["error"]), (False, "no_verified_import_key"))
            self.publish()
            with self.assertRaises(ValueError):
                imp.submit_ref("/etc/shadow", self.tok["_file"], base, host="localhost")
            out = io.StringIO()
            with mock.patch("sys.stdout", out):
                code = nullvault.main(["import-submit", "--file-ref", "config-signing-key", "--token-file", self.tok["_file"], "--base", base, "--host", "localhost"])
            self.assertEqual(code, 0, out.getvalue())
            r = json.loads(out.getvalue().strip().splitlines()[-1])   # the test server logs to the same stdout
        self.assertNotIn(secret, out.getvalue())
        item = self.pending()["imports"][0]
        self.assertEqual((item["title"], item["type"], item["import_id"]), ("NullVault settings-signing key (v12)", "key", r["import_id"]))
        doc = self.phone_open(item)
        f = doc["fields"]
        self.assertEqual((f["key_type"], f["private_key_b64"], f["owner"], f["mode"]), ("ed25519-nullvault-config", secret, "nullink:nullink", "600"))
        pub = Ed25519PrivateKey.from_private_bytes(base64.b64decode(secret)).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.assertEqual(f["public_key_b64"], b64(pub))                                # what the phone checks against its pin
        self.assertNotIn(secret.encode(), self.everything_on_disk())
        with self.assertRaises(SystemExit):
            nullvault.main(["import-submit", "--file-ref", "../secrets/other"])

    def test_token_cli_writes_file_and_prints_no_token(self):
        out_f = Path(self.tmp.name) / "new.token"
        out = io.StringIO()
        with mock.patch("sys.stdout", out):
            self.assertEqual(nullvault.main(["import-token-add", "--name", "bob2", "--label", "Bob 2", "--out", str(out_f)]), 0)
        tok = out_f.read_text().strip()
        self.assertTrue(tok.startswith("nlvi_"))
        self.assertNotIn(tok, out.getvalue())
        self.assertEqual(oct(out_f.stat().st_mode & 0o777), "0o600")
        self.assertNotIn(tok, imp.tokens_file().read_text())
        with mock.patch("sys.stdout", io.StringIO()):
            self.assertEqual(nullvault.main(["import-token-add", "--name", "bob3", "--out", str(out_f)]), 1)   # no overwrite
