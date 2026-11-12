"""NullVault device API (DESIGN v0.3, API.md v1): flag-off 404, attestation verification with fixture
chains, single-use nonces, the 2-device cap, revoke, APK pins, tamper, patch rules, registry chain."""
import base64
import json
import os
import secrets
import tempfile
import time
import uuid
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import nullvault
import server
from tests import nullvault_fixtures as fx
from tests.test_auth import AuthBase, totp_code

ORIGIN = "https://nullink.216.158.238.236.sslip.io"
CERT = "aa" * 32
APK = "bb" * 32
SECRET_BODY = "nv-test-only hunter2 body"


class NullVaultBase(AuthBase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.keydir = tempfile.TemporaryDirectory()
        kd = Path(cls.keydir.name)
        (kd / "data.key").write_text(base64.b64encode(secrets.token_bytes(32)).decode())
        (kd / "lease.key").write_text(base64.b64encode(secrets.token_bytes(32)).decode())
        cls.env = mock.patch.dict(os.environ, {
            "NULLINK_VAULT_KEY_FILE": str(kd / "data.key"),
            "NULLVAULT_LEASE_KEY_FILE": str(kd / "lease.key"),
            "NULLVAULT_STATUS_FETCH": "0", "NULLVAULT_ENABLED": "1"})
        cls.env.start()
        cls.root = fx.FakeRoot()
        nullvault.EXTRA_TRUSTED_ROOTS[:] = [cls.root.cert]
        nullvault.server = server

    @classmethod
    def tearDownClass(cls):
        nullvault.EXTRA_TRUSTED_ROOTS[:] = []
        cls.env.stop()
        cls.keydir.cleanup()
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        os.environ["NULLVAULT_ENABLED"] = "1"
        server.ensure_dirs()
        nv = server.DATA / "nullvault"
        if nv.exists():
            for f in nv.iterdir():
                f.unlink()
        for f in server.VAULT_DIR.glob("*.json"):
            f.unlink()
        server.VAULT_AUDIT_FILE.unlink(missing_ok=True)
        nullvault._nonces.clear()
        self.enable_totp()
        st, _, self.owner = self.login(totp_code())
        self.assertEqual(st, 200)
        self.entry = server.save_vault_snippet({"title": "Bank", "body": SECRET_BODY, "tags": ["money"]})
        server._atomic_write_json(nullvault.pins_file(), {"package": nullvault.PACKAGE, "releases": {
            "1": {"version_name": "0.1.0-test", "channel": "test", "signing_cert_sha256": [CERT],
                  "apk_sha256": [APK], "revoked": False}}})
        self.alerts = []
        p = mock.patch.object(nullvault, "send_alert", side_effect=self.alerts.append)
        p.start()
        self.addCleanup(p.stop)

    # ---- client simulation ----
    def fresh_codes(self):
        cfg = server.load_totp(); cfg["last_counter"] = -1; server.save_totp(cfg)

    def apk(self, **kw):
        a = {"package": nullvault.PACKAGE, "version_code": 1, "version_name": "0.1.0-test",
             "signing_cert_sha256": [CERT], "signing_lineage_sha256": [CERT], "base_apk_sha256": APK,
             "split_apk_sha256": [], "installer": {"installing": "com.google.android.packageinstaller"},
             "debuggable": False}
        a.update(kw)
        return a

    def state(self, **tamper):
        t = {"debugger": False, "tracer_pid": 0, "frida": False, "xposed": False}
        t.update(tamper)
        return {"root_indicators": [], "dev_options": True, "adb_enabled": True, "tamper": t}

    def device(self, install_id, **kw):
        d = {"manufacturer": "Google", "model": "Pixel 8", "sdk_int": 35, "security_patch": "2026-10-05",
             "install_id": install_id, "name": "Test Pixel"}
        d.update(kw)
        return d

    def challenge(self, install_id, code=None):
        return self.req("/api/vault/device/register-challenge", "POST",
                        {"code": code or totp_code(), "install_id": install_id})

    def envelope(self, key, payload):
        raw = json.dumps(payload).encode()
        return {"payload": base64.b64encode(raw).decode(), "signature": fx.sign(key, raw)}

    def register(self, kd_kw=None, apk=None, state=None, dev_kw=None, chain_kw=None, sign_key=None,
                 nonce=None, expect=201):
        self.fresh_codes()
        install_id = str(uuid.uuid4())
        if nonce is None:
            st, _, js, _ = self.challenge(install_id)
            self.assertEqual(st, 200, js)
            nonce = js["nonce"]
        kdev = ec.generate_private_key(ec.SECP256R1())
        kd = fx.key_description(nonce.encode(), **(kd_kw or {}))
        chain, _ = self.root.chain(kdev.public_key(), kd, **(chain_kw or {}))
        payload = {"purpose": "register", "nonce": nonce, "ts": int(time.time()), "install_id": install_id,
                   "attestation_chain": chain, "device": self.device(install_id, **(dev_kw or {})),
                   "apk": apk or self.apk(), "state": state or self.state(), "play_integrity": None}
        st, _, js, data = self.req("/api/vault/device/register", "POST", self.envelope(sign_key or kdev, payload))
        if expect is not None:
            self.assertEqual(st, expect, js)
        return {"st": st, "js": js, "kdev": kdev, "install_id": install_id, "nonce": nonce, "data": data}

    def bearer(self, dev):
        return {"Authorization": "Bearer " + dev["js"]["device_token"]}

    def sync_challenge(self, dev, purpose="sync"):
        return self.req("/api/vault/sync-challenge", "POST", {"purpose": purpose}, headers=self.bearer(dev))

    def signed_call(self, dev, path, purpose="sync", extra=None, kd_kw=None, dev_kw=None, apk=None,
                    state=None, nonce=None, sign_key=None):
        if nonce is None:
            st, _, js, _ = self.sync_challenge(dev, purpose)
            self.assertEqual(st, 200, js)
            nonce = js["nonce"]
        throwaway = ec.generate_private_key(ec.SECP256R1())
        chain, _ = self.root.chain(throwaway.public_key(), fx.key_description(nonce.encode(), **(kd_kw or {})))
        payload = {"purpose": purpose, "nonce": nonce, "ts": int(time.time()), "device_id": dev["js"]["device_id"],
                   "attestation_chain": chain, "apk": apk or self.apk(), "state": state or self.state(),
                   "device": self.device(dev["install_id"], **(dev_kw or {}))}
        payload.update(extra or {})
        st, _, js, data = self.req(path, "POST", self.envelope(sign_key or dev["kdev"], payload),
                                   headers=self.bearer(dev))
        return st, js, data, nonce

    def sync(self, dev, **kw):
        return self.signed_call(dev, "/api/vault/sync", "sync", **kw)

    def write(self, dev, op, entry, **kw):
        return self.signed_call(dev, "/api/vault/device/write", "write", extra={"op": op, "entry": entry}, **kw)

    def registry(self):
        return [json.loads(l) for l in nullvault.registry_file().read_text().splitlines()]

    def revoke(self, device_id, code=None):
        self.fresh_codes()
        return self.req(f"/api/vault/devices/{device_id}/revoke", "POST", {"code": code or totp_code()},
                        cookie=self.owner, headers={"Origin": ORIGIN})


class FlagOffTests(NullVaultBase):
    def test_every_route_404_when_flag_off(self):
        os.environ["NULLVAULT_ENABLED"] = "0"
        for path, m in (("/api/vault/device/register-challenge", "POST"), ("/api/vault/device/register", "POST"),
                        ("/api/vault/sync-challenge", "POST"), ("/api/vault/sync", "POST"),
                        ("/api/vault/device/write", "POST"), ("/api/vault/devices", "GET"),
                        ("/api/vault/devices/dev_0123456789abcdef/revoke", "POST")):
            st, _, js, data = self.req(path, m, {"code": totp_code()} if m == "POST" else None, cookie=self.owner)
            self.assertEqual((st, js.get("error")), (404, "not_found"), path)
            self.assertNotIn(SECRET_BODY.encode(), data)
        self.assertFalse(nullvault.registry_file().exists())
        nullvault.alert("x")
        self.assertEqual(self.alerts, [])

    def test_flag_defaults_off(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NULLVAULT_ENABLED", None)
            self.assertFalse(nullvault.enabled())


class RootsTests(NullVaultBase):
    def test_pinned_google_roots_load(self):
        nullvault.EXTRA_TRUSTED_ROOTS[:] = []
        try:
            roots = nullvault.trusted_roots()
            self.assertEqual(len(roots), 2)
            names = " ".join(r.subject.rfc4514_string() for r in roots)
            self.assertIn("f92009e853b6b045", names)
            self.assertIn("Key Attestation CA1", names)
        finally:
            nullvault.EXTRA_TRUSTED_ROOTS[:] = [self.root.cert]

    def test_fixture_chain_rejected_without_test_root(self):
        nullvault.EXTRA_TRUSTED_ROOTS[:] = []
        try:
            r = self.register(expect=403)
            self.assertEqual(r["js"]["error"], "attestation_invalid:untrusted_root")
        finally:
            nullvault.EXTRA_TRUSTED_ROOTS[:] = [self.root.cert]


class AttestationTests(NullVaultBase):
    def test_happy_path_register_sync_write(self):
        dev = self.register()
        js = dev["js"]
        self.assertTrue(js["device_token"].startswith("nvd_"))
        self.assertEqual(js["assurance"], "full")
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(js["lease_public_key"]))
        lease_raw = base64.b64decode(js["lease"]["payload"])
        pub.verify(base64.b64decode(js["lease"]["sig"]), lease_raw)
        lease = json.loads(lease_raw)
        self.assertEqual(lease["offline_until"] - lease["synced_at"], 30 * 86400)
        st, js, data, _ = self.sync(dev)
        self.assertEqual(st, 200, js)
        self.assertEqual([e["body"] for e in js["entries"]], [SECRET_BODY])
        pins = json.loads(base64.b64decode(js["pins"]["payload"]))
        self.assertEqual(pins["apk_sha256"], [APK])
        st, js, _, _ = self.write(dev, "create", {"title": "New", "body": "nv-new-secret", "tags": ["x"]})
        self.assertEqual(st, 200, js)
        new_id = js["entry"]["id"]
        self.assertEqual(server.load_vault_snippet(new_id)["body"], "nv-new-secret")
        st, js, _, _ = self.write(dev, "update", {"id": new_id, "body": "nv-changed"})
        self.assertEqual(st, 200, js)
        self.assertEqual(server.load_vault_snippet(new_id)["body"], "nv-changed")
        st, js, _, _ = self.signed_call(dev, "/api/vault/device/write", "write",
                                        extra={"op": "update", "entry": {"id": new_id, "body": "late"},
                                               "base_updated_at": "2000-01-01T00:00:00Z"})
        self.assertEqual(st, 409)
        st, js, _, _ = self.write(dev, "delete", {"id": new_id})
        self.assertEqual(st, 200, js)
        self.assertIsNone(server.load_vault_snippet(new_id))
        audit = server.VAULT_AUDIT_FILE.read_text()
        for s in (SECRET_BODY, "nv-new-secret", "nv-changed", dev["js"]["device_token"]):
            self.assertNotIn(s, audit)
            self.assertNotIn(s, nullvault.registry_file().read_text())
        self.assertIn("device_sync", audit)

    def test_rooted_unlocked_unverified_boot_accepted_as_reduced(self):
        st = self.state(); st["root_indicators"] = ["su_binary", "magisk"]
        dev = self.register(kd_kw={"boot_state": 2, "locked": False}, state=st)
        self.assertEqual(dev["js"]["assurance"], "reduced")
        self.assertIn("reduced assurance", " ".join(self.alerts))
        st_, js, _, _ = self.sync(dev, kd_kw={"boot_state": 2, "locked": False}, state=st)
        self.assertEqual(st_, 200, js)

    def test_self_signed_boot_accepted(self):
        self.assertEqual(self.register(kd_kw={"boot_state": 1})["js"]["assurance"], "reduced")

    def test_failed_boot_refused(self):
        r = self.register(kd_kw={"boot_state": 3}, expect=403)
        self.assertEqual(r["js"]["error"], "attestation_invalid:boot_failed")

    def test_software_attestation_refused(self):
        for kw in ({"sec": 0}, {"km_sec": 0}):
            r = self.register(kd_kw=kw, expect=403)
            self.assertEqual(r["js"]["error"], "attestation_invalid:software_attestation")

    def test_challenge_mismatch_refused(self):
        self.fresh_codes()
        iid = str(uuid.uuid4())
        st, _, js, _ = self.challenge(iid)
        nonce = js["nonce"]
        kdev = ec.generate_private_key(ec.SECP256R1())
        chain, _ = self.root.chain(kdev.public_key(), fx.key_description(b"some-other-challenge"))
        p = {"purpose": "register", "nonce": nonce, "ts": int(time.time()), "install_id": iid,
             "attestation_chain": chain, "device": self.device(iid), "apk": self.apk(), "state": self.state()}
        st, _, js, _ = self.req("/api/vault/device/register", "POST", self.envelope(kdev, p))
        self.assertEqual((st, js["error"]), (403, "attestation_invalid:challenge_mismatch"))

    def test_broken_chain_signature_refused(self):
        r = self.register(chain_kw={"sign_leaf_with": ec.generate_private_key(ec.SECP256R1())}, expect=403)
        self.assertEqual(r["js"]["error"], "attestation_invalid:chain_signature_0")

    def test_extension_in_intermediate_refused(self):
        r = self.register(chain_kw={"ext_in_intermediate": True}, expect=403)
        self.assertEqual(r["js"]["error"], "attestation_invalid:attestation_ext_in_ca")

    def test_expired_intermediate_refused(self):
        r = self.register(chain_kw={"expired_intermediate": True}, expect=403)
        self.assertEqual(r["js"]["error"], "attestation_invalid:cert_expired")

    def test_revoked_serial_refused(self):
        serial = format(fx.x509.load_der_x509_certificate(self.root.icert.public_bytes(
            fx.serialization.Encoding.DER)).serial_number, "x")
        server._atomic_write_json(nullvault.status_file(), {"entries": {serial: {"status": "REVOKED"}}})
        r = self.register(expect=403)
        self.assertEqual(r["js"]["error"], "attestation_invalid:cert_revoked")

    def test_imported_key_refused(self):
        r = self.register(kd_kw={"origin": 2}, expect=403)
        self.assertEqual(r["js"]["error"], "attestation_invalid:key_not_generated")

    def test_signature_by_other_key_refused(self):
        r = self.register(sign_key=ec.generate_private_key(ec.SECP256R1()), expect=403)
        self.assertEqual(r["js"]["error"], "bad_signature")

    def test_patch_floor(self):
        r = self.register(kd_kw={"patch": 202001}, expect=403)
        self.assertEqual(r["js"]["error"], "patch_below_floor")


class NonceTests(NullVaultBase):
    def test_register_nonce_single_use(self):
        dev = self.register()
        r = self.register(nonce=dev["nonce"], expect=403)
        self.assertEqual(r["js"]["error"], "nonce_invalid")

    def test_register_nonce_expires(self):
        self.fresh_codes()
        iid = str(uuid.uuid4())
        st, _, js, _ = self.challenge(iid)
        nullvault._nonces[js["nonce"]]["exp"] = time.time() - 1
        r = self.register(nonce=js["nonce"], expect=403)
        self.assertEqual(r["js"]["error"], "nonce_invalid")

    def test_nonce_bound_to_install_id(self):
        self.fresh_codes()
        st, _, js, _ = self.challenge(str(uuid.uuid4()))
        r = self.register(nonce=js["nonce"], expect=403)  # register() uses a different install id
        self.assertEqual(r["js"]["error"], "nonce_invalid")

    def test_sync_nonce_replay_and_purpose(self):
        dev = self.register()
        st, js, _, nonce = self.sync(dev)
        self.assertEqual(st, 200)
        st, js, _, _ = self.sync(dev, nonce=nonce)
        self.assertEqual((st, js["error"]), (403, "nonce_invalid"))
        st, _, js, _ = self.sync_challenge(dev, "write")
        st, js, _, _ = self.sync(dev, nonce=js["nonce"])  # write nonce used for sync
        self.assertEqual((st, js["error"]), (403, "nonce_invalid"))

    def test_bad_totp_refused_and_counts_toward_lockout(self):
        st, _, js, _ = self.challenge(str(uuid.uuid4()), code="000000" if totp_code() != "000000" else "111111")
        self.assertEqual((st, js["error"]), (401, "wrong_code"))
        self.assertIn("attempts_left", js)

    def test_totp_code_single_use(self):
        self.fresh_codes()
        code = totp_code()
        st, *_ = self.challenge(str(uuid.uuid4()), code=code)
        self.assertEqual(st, 200)
        st, _, js, _ = self.challenge(str(uuid.uuid4()), code=code)
        self.assertEqual(st, 401)


class CapRevokeTests(NullVaultBase):
    def test_cap_of_two(self):
        a = self.register(); self.register()
        self.fresh_codes()
        st, _, js, _ = self.challenge(str(uuid.uuid4()))
        self.assertEqual((st, js["error"]), (409, "device_cap"))
        st, _, js, _ = self.revoke(a["js"]["device_id"])
        self.assertEqual(st, 200, js)
        self.register()

    def test_revoke_wipes_at_next_contact(self):
        dev = self.register()
        st, _, js, _ = self.revoke(dev["js"]["device_id"])
        self.assertEqual(st, 200, js)
        st, _, js, _ = self.sync_challenge(dev)
        self.assertEqual((st, js["error"], js["wipe"]), (403, "revoked", True))
        self.assertTrue(any("revoked" in a for a in self.alerts))

    def test_revoke_needs_owner_origin_and_code(self):
        dev = self.register()
        did = dev["js"]["device_id"]
        st, *_ = self.req(f"/api/vault/devices/{did}/revoke", "POST", {"code": totp_code()},
                          headers={**self.bearer(dev), "Origin": ORIGIN})
        self.assertEqual(st, 403)
        st, *_ = self.req(f"/api/vault/devices/{did}/revoke", "POST", {"code": totp_code()}, cookie=self.owner)
        self.assertEqual(st, 403)  # no Origin
        st, *_ = self.req(f"/api/vault/devices/{did}/revoke", "POST", {"code": "12"}, cookie=self.owner,
                          headers={"Origin": ORIGIN})
        self.assertEqual(st, 401)
        st, *_ = self.req(f"/api/vault/devices/{did}/revoke", "POST", {"code": totp_code()},
                          headers={"Origin": ORIGIN})
        self.assertEqual(st, 401)
        self.assertEqual(nullvault.devices()[did]["status"], "active")

    def test_admin_list_owner_only_no_secrets(self):
        dev = self.register()
        st, _, js, data = self.req("/api/vault/devices", cookie=self.owner)
        self.assertEqual(st, 200)
        self.assertEqual(js["cap"], 2)
        self.assertTrue(js["registry_intact"])
        self.assertEqual(js["devices"][0]["status"], "active")
        self.assertNotIn(dev["js"]["device_token"].encode(), data)
        self.assertNotIn(b"token_sha256", data)
        st, *_ = self.req("/api/vault/devices", headers=self.bearer(dev))
        self.assertIn(st, (401, 403))  # a device token is never an admin credential
        st, *_ = self.req("/api/vault/devices")
        self.assertEqual(st, 401)

    def test_unknown_token(self):
        st, _, js, _ = self.req("/api/vault/sync-challenge", "POST", {}, headers={"Authorization": "Bearer nvd_nope"})
        self.assertEqual((st, js.get("wipe")), (401, True))


class ApkTamperPatchTests(NullVaultBase):
    def test_apk_mismatches_refused_at_register(self):
        cases = [(self.apk(signing_cert_sha256=["cc" * 32]), {}, "apk_mismatch:signature_mismatch"),
                 (self.apk(base_apk_sha256="dd" * 32), {}, "apk_mismatch:apk_hash_mismatch"),
                 (self.apk(version_code=7), {"version": 7}, "apk_mismatch:version_not_pinned"),
                 (self.apk(package="evil.pkg"), {}, "apk_mismatch:package_mismatch"),
                 (self.apk(), {"digests": ("cc" * 32,)}, "apk_mismatch:attested_signature_mismatch"),
                 (self.apk(), {"package": "evil.pkg"}, "apk_mismatch:attested_package_mismatch"),
                 (self.apk(debuggable=True), {}, "tamper_detected:debuggable")]
        for apk, kd, want in cases:
            r = self.register(apk=apk, kd_kw=kd, expect=403)
            self.assertEqual(r["js"]["error"], want)
            self.assertTrue(r["js"].get("wipe"))

    def test_tamper_in_process_refused_but_root_and_adb_allowed(self):
        for t, want in (({"frida": True}, "tamper_detected:frida"), ({"xposed": True}, "tamper_detected:xposed"),
                        ({"debugger": True}, "tamper_detected:debugger"), ({"tracer_pid": 4242}, "tamper_detected:tracer")):
            r = self.register(state=self.state(**t), expect=403)
            self.assertEqual(r["js"]["error"], want)
        st = self.state(); st.update(root_indicators=["su_binary"], dev_options=True, adb_enabled=True)
        self.register(state=st)

    def test_sync_apk_change_flags_device(self):
        dev = self.register()
        st, js, _, _ = self.sync(dev, apk=self.apk(base_apk_sha256="ee" * 32))
        self.assertEqual((st, js["error"], js["wipe"]), (403, "apk_mismatch:apk_hash_mismatch", True))
        st, _, js, _ = self.sync_challenge(dev)
        self.assertEqual((st, js["error"]), (403, "flagged"))

    def test_newer_patch_accepted_older_refused(self):
        dev = self.register(kd_kw={"patch": 202609})
        st, js, _, _ = self.sync(dev, kd_kw={"patch": 202610})
        self.assertEqual(st, 200, js)
        self.assertEqual(self.registry()[-1]["note"], "newer_patch")
        st, js, _, _ = self.sync(dev, kd_kw={"patch": 202609})
        self.assertEqual((st, js["error"]), (403, "patch_downgrade"))

    def test_model_or_hardware_change_needs_reregister(self):
        a = self.register(); b = self.register()
        st, js, _, _ = self.sync(a, dev_kw={"model": "Pixel 9"})
        self.assertEqual((st, js["error"]), (403, "reregister_required:model_changed"))
        st, js, _, _ = self.sync(b, kd_kw={"boot_key": b"\x99" * 32})
        self.assertEqual((st, js["error"]), (403, "reregister_required:hardware_changed"))

    def test_sync_signature_must_be_registered_key(self):
        dev = self.register()
        st, js, _, _ = self.sync(dev, sign_key=ec.generate_private_key(ec.SECP256R1()))
        self.assertEqual((st, js["error"]), (403, "bad_signature"))


class RegistryTests(NullVaultBase):
    def test_append_only_hash_chain_and_mode(self):
        dev = self.register()
        self.sync(dev)
        self.register(apk=self.apk(base_apk_sha256="dd" * 32), expect=403)
        rows = self.registry()
        self.assertEqual([r["kind"] for r in rows], ["register", "sync_report", "refused"])
        self.assertTrue(nullvault.registry_verify())
        self.assertEqual(oct(nullvault.registry_file().stat().st_mode & 0o777), "0o600")
        self.assertEqual(oct(nullvault.registry_file().parent.stat().st_mode & 0o777), "0o700")
        reg = rows[0]
        for k in ("attestation_chain", "attestation", "device", "apk", "state", "install_id", "pubkey_spki"):
            self.assertIn(k, reg)
        self.assertEqual(reg["attestation"]["security_level"], "TrustedEnvironment")
        lines = nullvault.registry_file().read_text().splitlines()
        tampered = lines[0].replace('"Pixel 8"', '"Pixel X"')
        nullvault.registry_file().write_text("\n".join([tampered] + lines[1:]) + "\n")
        self.assertFalse(nullvault.registry_verify())

    def test_lease_key_missing_returns_503_before_code_spent(self):
        with mock.patch.dict(os.environ, {"NULLVAULT_LEASE_KEY_FILE": "/nonexistent"}):
            self.fresh_codes()
            st, _, js, _ = self.challenge(str(uuid.uuid4()))
            self.assertEqual((st, js["error"]), (503, "lease_key_unavailable"))
        self.assertEqual(server.load_totp()["last_counter"], -1)


class DerTests(NullVaultBase):
    def test_parse_key_description_fields(self):
        kd = nullvault.parse_key_description(fx.key_description(b"abc", sec=2, patch=202611,
                                                                model="Pixel 8", manufacturer="Google"))
        self.assertEqual((kd["attestation_security_level"], kd["challenge"]), (2, b"abc"))
        self.assertEqual(nullvault._al_int(kd["hw"], 706), 202611)
        self.assertEqual(nullvault._al_bytes(kd["hw"], 717), b"Pixel 8")
        app = nullvault.parse_app_id(nullvault._al_bytes(kd["sw"], 709))
        self.assertEqual(app["packages"], [[nullvault.PACKAGE, 1]])

    def test_garbage_rejected(self):
        for blob in (b"", b"\x30", b"\x30\x84\xff\xff\xff\xff", b"\x02\x01\x00"):
            with self.assertRaises(nullvault.DerError):
                nullvault.parse_key_description(blob)


class PinsExampleTests(NullVaultBase):
    def test_example_pins_match_test_apk_report(self):
        ex = json.loads((Path(nullvault.__file__).parent / "deploy" / "nullvault" / "release_pins.example.json").read_text())
        rel = ex["releases"]["1"]
        server._atomic_write_json(nullvault.pins_file(), ex)
        apk = self.apk(signing_cert_sha256=rel["signing_cert_sha256"], signing_lineage_sha256=rel["signing_cert_sha256"],
                       base_apk_sha256=rel["apk_sha256"][0])
        att = {"app_id": {"packages": [[nullvault.PACKAGE, 1]], "signature_digests": rel["signing_cert_sha256"]}}
        self.assertEqual(nullvault.check_apk(apk, att)[0], None)
        self.assertEqual(rel["channel"], "test")

    def test_example_pins_v2_and_v1_both_accepted(self):
        ex = json.loads((Path(nullvault.__file__).parent / "deploy" / "nullvault" / "release_pins.example.json").read_text())
        server._atomic_write_json(nullvault.pins_file(), ex)
        for vc in (1, 2):
            rel = ex["releases"][str(vc)]
            apk = self.apk(version_code=vc, signing_cert_sha256=rel["signing_cert_sha256"],
                           signing_lineage_sha256=rel["signing_cert_sha256"], base_apk_sha256=rel["apk_sha256"][0])
            att = {"app_id": {"packages": [[nullvault.PACKAGE, vc]], "signature_digests": rel["signing_cert_sha256"]}}
            self.assertEqual(nullvault.check_apk(apk, att)[0], None, vc)
        self.assertEqual(ex["releases"]["2"]["version_name"], "0.2.0-test")
        # the v1 APK hash is not accepted for v2 and vice versa
        apk = self.apk(version_code=2, signing_cert_sha256=ex["releases"]["2"]["signing_cert_sha256"],
                       signing_lineage_sha256=ex["releases"]["2"]["signing_cert_sha256"], base_apk_sha256=ex["releases"]["1"]["apk_sha256"][0])
        att = {"app_id": {"packages": [[nullvault.PACKAGE, 2]], "signature_digests": ex["releases"]["2"]["signing_cert_sha256"]}}
        self.assertIsNotNone(nullvault.check_apk(apk, att)[0])
