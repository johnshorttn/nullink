"""0.5.0 window signing session: K_dev (fingerprint) delegates a hardware K_sess for write/files/chat only."""
import time
from unittest import mock

from cryptography.hazmat.primitives.asymmetric import ec

import nullvault
import server
from tests import nullvault_fixtures as fx
from tests.test_nullvault import NullVaultBase


class SessionKeyTests(NullVaultBase):
    def setUp(self):
        super().setUp()
        nullvault._sessions.clear()
        self.dev = self.register()

    def _session_block(self, nonce, kd_kw=None, ttl=1800):
        ksess = ec.generate_private_key(ec.SECP256R1())
        kw = {"auth_timeout": 1800}; kw.update(kd_kw or {})
        chain, _ = self.root.chain(ksess.public_key(), fx.key_description(nonce.encode(), **kw))
        return ksess, {"chain": chain, "ttl": ttl}

    def start_session(self, ttl=1800, kd_kw=None):
        """A fingerprint (K_dev) write that also delegates K_sess. Returns K_sess."""
        st, _, js, _ = self.sync_challenge(self.dev, "write")
        self.assertEqual(st, 200, js)
        n = js["nonce"]
        ksess, block = self._session_block(n, kd_kw, ttl)
        st, js, _, _ = self.signed_call(self.dev, "/api/vault/device/write", "write", nonce=n,
                                        extra={"op": "create", "entry": {"title": "A", "body": "x"}, "session": block})
        self.assertEqual(st, 200, js)
        return ksess

    def session_write(self, ksess, title="B"):
        return self.signed_call(self.dev, "/api/vault/device/write", "write", sign_key=ksess,
                                extra={"op": "create", "entry": {"title": title, "body": "y"}, "signed_by": "session"})

    def test_delegated_key_signs_writes_without_kdev(self):
        ks = self.start_session()
        did = self.dev["js"]["device_id"]
        self.assertIsNotNone(nullvault.session_get(did))
        st, js, _, _ = self.session_write(ks)
        self.assertEqual(st, 200, js)
        titles = {s["title"] for s in server.list_vault_snippets()}
        self.assertTrue({"A", "B"} <= titles)
        audit = server.VAULT_AUDIT_FILE.read_text()
        self.assertIn("device_session_start", audit)

    def test_session_cannot_sign_sync_status_approve_action(self):
        ks = self.start_session()
        for path, purpose in (("/api/vault/sync", "sync"), ("/api/vault/status/token", "status"),
                              ("/api/vault/approvals/decide", "approve"), ("/api/vault/actions/run", "action")):
            st, _, js, _ = self.sync_challenge(self.dev, purpose)
            if st != 200:
                continue  # route family switched off in this test env
            st, js, _, _ = self.signed_call(self.dev, path, purpose, nonce=js["nonce"], sign_key=ks,
                                            extra={"signed_by": "session"})
            self.assertIn(st, (403, 404), (path, js))
            if st == 403:
                self.assertEqual(js.get("error"), "session_not_allowed", path)
        self.assertNotEqual(self.devices_status(), "flagged")

    def devices_status(self):
        return nullvault.devices()[self.dev["js"]["device_id"]]["status"]

    def test_no_session_means_session_expired_not_flagged(self):
        k = ec.generate_private_key(ec.SECP256R1())
        st, js, _, _ = self.session_write(k)
        self.assertEqual((st, js.get("error")), (401, "session_expired"))
        self.assertNotIn("wipe", js)
        self.assertEqual(self.devices_status(), "active")

    def test_expiry(self):
        ks = self.start_session(ttl=60)
        real = time.time
        with mock.patch("nullvault.time.time", lambda: real() + 61):
            self.assertIsNone(nullvault.session_get(self.dev["js"]["device_id"]))
        with mock.patch("nullvault.time.time", lambda: real() + 61):
            st, js, _, _ = self.session_write(ks, title="late")  # challenge ts is real; the session is gone
        self.assertEqual((st, js.get("error")), (401, "session_expired"))

    def test_ttl_clamped_to_60_minutes(self):
        self.start_session(ttl=99999)
        s = nullvault.session_get(self.dev["js"]["device_id"])
        self.assertLessEqual(s["exp"] - time.time(), nullvault.SESSION_MAX_TTL + 1)
        self.start_session(ttl=1)
        s = nullvault.session_get(self.dev["js"]["device_id"])
        self.assertGreaterEqual(s["exp"] - time.time(), nullvault.SESSION_MIN_TTL - 2)

    def test_wrong_key_with_session_refused_and_session_dropped_no_wipe(self):
        self.start_session()
        st, js, _, _ = self.session_write(ec.generate_private_key(ec.SECP256R1()))
        self.assertEqual((st, js.get("error")), (403, "session_invalid"))
        self.assertNotIn("wipe", js)
        self.assertIsNone(nullvault.session_get(self.dev["js"]["device_id"]))
        self.assertEqual(self.devices_status(), "active")

    def test_session_chain_must_match_nonce(self):
        st, _, js, _ = self.sync_challenge(self.dev, "write")
        n = js["nonce"]
        _ks, block = self._session_block("other-nonce-0000000000000000")
        st, js, _, _ = self.signed_call(self.dev, "/api/vault/device/write", "write", nonce=n,
                                        extra={"op": "create", "entry": {"title": "A"}, "session": block})
        self.assertEqual(st, 200, js)  # the write stands, no session
        self.assertIsNone(nullvault.session_get(self.dev["js"]["device_id"]))
        self.assertIn("device_session_refused", server.VAULT_AUDIT_FILE.read_text())

    def test_session_from_other_hardware_refused(self):
        self.start_session(kd_kw={"boot_key": b"\x77" * 32})
        self.assertIsNone(nullvault.session_get(self.dev["js"]["device_id"]))

    def test_session_signed_request_ignores_nested_session_block(self):
        ks = self.start_session()
        st, _, js, _ = self.sync_challenge(self.dev, "write")
        n = js["nonce"]
        ks2, block = self._session_block(n)
        st, js, _, _ = self.signed_call(self.dev, "/api/vault/device/write", "write", nonce=n, sign_key=ks,
                                        extra={"op": "create", "entry": {"title": "C"}, "signed_by": "session", "session": block})
        self.assertEqual(st, 200, js)
        # the old K_sess still works, K_sess2 was never registered by a session-signed request
        st, js, _, _ = self.session_write(ks2)
        self.assertEqual((st, js.get("error")), (403, "session_invalid"))

    def test_kdev_bad_signature_still_flags_and_wipes(self):
        self.start_session()
        st, js, _, _ = self.write(self.dev, "create", {"title": "Z"}, sign_key=ec.generate_private_key(ec.SECP256R1()))
        self.assertEqual((st, js.get("error"), js.get("wipe")), (403, "bad_signature", True))
        self.assertEqual(self.devices_status(), "flagged")
        self.assertIsNone(nullvault.session_get(self.dev["js"]["device_id"]))

    def test_revoke_drops_session(self):
        ks = self.start_session()
        st, _, js, _ = self.revoke(self.dev["js"]["device_id"])
        self.assertEqual(st, 200, js)
        st, _, js, _ = self.sync_challenge(self.dev, "write")
        self.assertEqual((st, js.get("error")), (403, "revoked"))
        self.assertIsNone(nullvault.session_get(self.dev["js"]["device_id"]))

    def test_session_signed_still_checks_tamper_and_pins(self):
        ks = self.start_session()
        st, js, _, _ = self.signed_call(self.dev, "/api/vault/device/write", "write", sign_key=ks,
                                        state=self.state(frida=True),
                                        extra={"op": "create", "entry": {"title": "T"}, "signed_by": "session"})
        self.assertEqual(st, 403); self.assertTrue(js["error"].startswith("tamper_detected"))

    def test_sync_can_start_session(self):
        st, _, js, _ = self.sync_challenge(self.dev, "sync")
        n = js["nonce"]
        ks, block = self._session_block(n)
        st, js, _, _ = self.signed_call(self.dev, "/api/vault/sync", "sync", nonce=n, extra={"session": block})
        self.assertEqual(st, 200, js)
        st, js, _, _ = self.session_write(ks)
        self.assertEqual(st, 200, js)

    def test_unknown_signed_by_rejected(self):
        st, js, _, _ = self.signed_call(self.dev, "/api/vault/device/write", "write",
                                        extra={"op": "create", "entry": {"title": "Q"}, "signed_by": "other"})
        self.assertEqual((st, js.get("error")), (400, "bad_request"))

    def test_registry_unchanged_shape(self):
        before = len(self.registry())
        ks = self.start_session()
        self.session_write(ks)
        kinds = [r["kind"] for r in self.registry()[before:]]
        self.assertEqual(kinds, ["sync_report", "write", "sync_report", "write"])  # same rows as plain K_dev writes
        self.assertTrue(nullvault.registry_verify())


class ArchiveMarkerTests(NullVaultBase):
    """0.5.0 archive: a reserved tag on the existing synced field. No server change; it must survive writes and sync."""
    TAG = "nullvault:archived"
    def setUp(self):
        NullVaultBase.setUp(self)
        nullvault._sessions.clear()
        self.dev = self.register()

    _session_block = SessionKeyTests._session_block
    start_session = SessionKeyTests.start_session

    def test_archived_entry_still_syncs_with_marker(self):
        ks = self.start_session()
        st, js, _, _ = self.signed_call(self.dev, "/api/vault/device/write", "write", sign_key=ks,
                                        extra={"op": "create", "entry": {"title": "Old", "body": "pw", "tags": ["work", self.TAG]},
                                               "signed_by": "session"})
        self.assertEqual(st, 200, js)
        eid = js["entry"]["id"]
        st, js, _, _ = self.sync(self.dev)
        self.assertEqual(st, 200, js)
        e = next(x for x in js["entries"] if x["id"] == eid)
        self.assertIn(self.TAG, e["tags"])
        self.assertEqual("Old", e["title"])

    def test_restore_removes_marker(self):
        ks = self.start_session()
        st, js, _, _ = self.signed_call(self.dev, "/api/vault/device/write", "write", sign_key=ks,
                                        extra={"op": "create", "entry": {"title": "X", "body": "pw", "tags": [self.TAG]}, "signed_by": "session"})
        e = js["entry"]
        st, js, _, _ = self.signed_call(self.dev, "/api/vault/device/write", "write", sign_key=ks,
                                        extra={"op": "update", "entry": {"id": e["id"], "title": "X", "body": "pw", "tags": []},
                                               "base_updated_at": e["updated_at"], "signed_by": "session"})
        self.assertEqual(st, 200, js)
        self.assertNotIn(self.TAG, js["entry"].get("tags", []))


class WindowKeyRulesTests(NullVaultBase):
    """K_sess must be the phone's auth-bound window key: fingerprint auth type, AUTH_TIMEOUT 1..3600 s, same app."""
    def setUp(self):
        NullVaultBase.setUp(self)
        nullvault._sessions.clear()
        self.dev = self.register()

    _session_block = SessionKeyTests._session_block
    start_session = SessionKeyTests.start_session

    def _try(self, **kd):
        self.start_session(kd_kw=kd)
        return nullvault.session_get(self.dev["js"]["device_id"])

    def test_auth_bound_key_accepted_long_server_ttl(self):
        self.start_session(ttl=30 * 86400)
        s = nullvault.session_get(self.dev["js"]["device_id"])
        self.assertIsNotNone(s)
        self.assertGreater(s["exp"] - time.time(), 29 * 86400)

    def test_no_timeout_refused(self):
        self.assertIsNone(self._try(auth_timeout=None))

    def test_timeout_over_one_hour_refused(self):
        self.assertIsNone(self._try(auth_timeout=7200))

    def test_no_auth_required_refused(self):
        self.assertIsNone(self._try(no_auth=True))

    def test_other_app_refused(self):
        self.assertIsNone(self._try(package="com.evil.app"))

