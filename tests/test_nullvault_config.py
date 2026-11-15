"""NullVault 0.7.0 signed config bundle: dedicated Ed25519 key, strict schema, monotonic version, no security
policy and no vault data in it, device token required."""
import base64
import json
import os
import tempfile
from pathlib import Path
from unittest import mock

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import nullvault
import nullvault_config as cf
import server
from tests.test_nullvault import SECRET_BODY
from tests.test_nullvault_stage3 import S3Base


class ConfigBundleTests(S3Base):
    def setUp(self):
        super().setUp()
        cf.bind(nullvault, server)
        self.kd = tempfile.TemporaryDirectory(); self.addCleanup(self.kd.cleanup)
        self.keyfile = Path(self.kd.name) / cf.KEY_NAME
        self.pub = cf.gen_key(self.keyfile)
        p = mock.patch.dict(os.environ, {"NULLVAULT_CONFIG_KEY_FILE": str(self.keyfile)}); p.start(); self.addCleanup(p.stop)
        for n in (cf.STATE, cf.OVERRIDES):
            (nullvault.nv_dir() / n).unlink(missing_ok=True)

    def fetch(self):
        st, _, js, _ = self.req("/api/vault/config", headers=self.bearer(self.dev))
        return st, js

    def verified(self, js):
        raw = base64.b64decode(js["bundle"]["payload"])
        Ed25519PublicKey.from_public_bytes(base64.b64decode(self.pub)).verify(base64.b64decode(js["bundle"]["sig"]), raw)
        return raw, json.loads(raw)

    def overrides(self, d):
        (nullvault.nv_dir() / cf.OVERRIDES).write_text(json.dumps(d))

    def test_signed_with_dedicated_key_and_verifies(self):
        st, js = self.fetch()
        self.assertEqual(st, 200, js)
        raw, p = self.verified(js)
        self.assertEqual((p["kind"], p["v"], p["version"]), ("nullvault-config", 1, 1))
        self.assertEqual(set(p), {"kind", "v", "version", "issued_at", "config"})
        self.assertEqual(set(p["config"]), set(cf.SECTIONS))
        self.assertEqual(js["version"], 1)
        # not the lease key
        self.assertNotEqual(self.pub, nullvault.lease_public_key_b64())
        bad = bytearray(raw); bad[-2] ^= 1
        with self.assertRaises(InvalidSignature):
            Ed25519PublicKey.from_public_bytes(base64.b64decode(self.pub)).verify(base64.b64decode(js["bundle"]["sig"]), bytes(bad))

    def test_sections_content(self):
        c = self.verified(self.fetch()[1])[1]["config"]
        self.assertGreaterEqual(c["status_checks"]["interval_minutes"], 15)
        self.assertTrue(any(x["kind"] == "disk" for x in c["status_checks"]["checks"]))
        self.assertEqual(set(c["alerts"]), {"server_down", "approval_waiting", "quick_action_run", "quiet_hours"})
        self.assertEqual({t["kind"] for t in c["approvals"]["types"]}, {"github_pr", "nullaxis"})
        self.assertIn("bots", c["chat"]); self.assertIn("tag_rules", c["files"]); self.assertIn("category_rules", c["links"])
        self.assertEqual(set(c["password_health"]), {"min_length", "stale_days", "reuse_check", "weak_bits"})

    def test_no_vault_plaintext_and_no_security_policy(self):
        raw, p = self.verified(self.fetch()[1])
        text = raw.decode()
        self.assertNotIn(SECRET_BODY, text); self.assertNotIn("hunter2", text); self.assertNotIn("Bank", text)
        def keys(o):
            if isinstance(o, dict):
                for k, v in o.items():
                    yield k; yield from keys(v)
            elif isinstance(o, list):
                for v in o:
                    yield from keys(v)
        self.assertFalse(set(keys(p)) & set(cf.FORBIDDEN))
        self.assertNotIn("allowlist", text); self.assertNotIn("nullink-health", text)  # quick-action allowlist is not in here

    def test_version_monotonic_and_stable(self):
        v1 = self.fetch()[1]
        self.assertEqual(self.fetch()[1]["bundle"]["payload"], v1["bundle"]["payload"])  # same content -> same bytes, same version
        self.overrides({"password_health": {"min_length": 14}})
        v2 = self.fetch()[1]; self.assertEqual(v2["version"], 2)
        self.assertEqual(self.verified(v2)[1]["config"]["password_health"]["min_length"], 14)
        (nullvault.nv_dir() / cf.OVERRIDES).unlink()
        self.assertEqual(self.fetch()[1]["version"], 3)  # back to defaults is a new, higher version (never 1 again)

    def test_invalid_overrides_refused_not_signed(self):
        cases = [{"auth_window": {"minutes": 999}}, {"tamper": {}}, {"password_health": {"min_length": 2}},
                 {"password_health": {"min_length": 12, "wipe": True}}, {"alerts": {"server_down": "yes"}},
                 {"status_checks": {"interval_minutes": 1}}, {"chat": {"bots": [{"id": "x"}]}},
                 {"alerts": {"quiet_hours": {"start": "25:00"}}}, {"e2e": {"kdf": "none"}}, {"device_cap": 9}]
        for c in cases:
            self.overrides(c)
            st, js = self.fetch()
            self.assertEqual((st, js.get("error")), (503, "config_invalid"), c)
        aud = [json.loads(l) for l in server.VAULT_AUDIT_FILE.read_text().splitlines()]
        self.assertTrue(any(a.get("event") == "nullvault_config_invalid" for a in aud))

    def test_clean_strips_nothing_silently(self):
        with self.assertRaises(cf.ConfigInvalid):
            cf.clean({"password_health": {"min_length": 12, "device_cap": 5}})
        with self.assertRaises(cf.ConfigInvalid):
            cf.clean({"files": {"tag_rules": [{"name": "x", "contains": ["a"], "lock": True}]}})

    def test_no_key_503_and_needs_device(self):
        with mock.patch.dict(os.environ, {"NULLVAULT_CONFIG_KEY_FILE": "/nonexistent/key"}):
            self.assertEqual(self.fetch(), (503, {"error": "config_key_unavailable"}))
        self.assertEqual(self.req("/api/vault/config")[0], 401)
        self.assertEqual(self.req("/api/vault/config", cookie=self.owner)[0], 401)
        self.assertEqual(self.req("/api/vault/config", "POST", {}, headers=self.bearer(self.dev))[0], 405)

    def test_gen_key_refuses_overwrite_and_is_0600(self):
        self.assertEqual(os.stat(self.keyfile).st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            cf.gen_key(self.keyfile)
        self.assertEqual(cf.public_key_b64(), self.pub)

    def test_cli_prints_public_key_only(self):
        out = Path(self.kd.name) / "k2"
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(nullvault.main(["gen-config-key", "--out", str(out)]), 0)
        priv = out.read_text().strip()
        self.assertNotIn(priv, buf.getvalue())
        self.assertIn("Public key", buf.getvalue())
