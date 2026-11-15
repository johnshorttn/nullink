"""Quick actions go-live (John 2026-11-14 9:13 PM ET: "turn on quick actions with nullink-health and
nullink-status"). Proves, with the production allowlist: every run needs a fresh K_dev signature with purpose
"action" (window sessions refused, nonces single-use), anything off the allowlist is refused even when validly
signed, and each run writes run + result to actions.jsonl plus a device_action audit entry."""
import json
import os
from unittest import mock

from cryptography.hazmat.primitives.asymmetric import ec

import nullvault
import nullvault_actions as act
import nullvault_ext as ext
import server
from tests import nullvault_fixtures as fx
from tests.test_nullvault_stage3 import S3Base

PROD_ALLOW = "nullink-health,nullink-status"


class QuickActionsGoLiveTests(S3Base):
    flags = {"NULLVAULT_ACTIONS": "1", "NULLVAULT_ACTIONS_ALLOW": PROD_ALLOW}

    def setUp(self):
        super().setUp()
        nullvault._sessions.clear()
        server.VAULT_AUDIT_FILE.unlink(missing_ok=True)

    def run_action(self, name, **kw):
        return self.signed_call(self.dev, "/api/vault/actions/run", "action", extra={"action": {"name": name}}, **kw)

    def audit(self, event):
        f = server.VAULT_AUDIT_FILE
        rows = [json.loads(l) for l in f.read_text().splitlines()] if f.exists() else []
        return [r for r in rows if r.get("event") == event]

    def start_session(self):
        st, _, js, _ = self.sync_challenge(self.dev, "write")
        self.assertEqual(st, 200, js)
        n = js["nonce"]
        ksess = ec.generate_private_key(ec.SECP256R1())
        chain, _ = self.root.chain(ksess.public_key(), fx.key_description(n.encode(), auth_timeout=1800))
        st, js, _, _ = self.signed_call(self.dev, "/api/vault/device/write", "write", nonce=n,
                                        extra={"op": "create", "entry": {"title": "A", "body": "x"},
                                               "session": {"chain": chain, "ttl": 1800}})
        self.assertEqual(st, 200, js)
        self.assertIsNotNone(nullvault.session_get(self.dev["js"]["device_id"]))
        return ksess

    def test_prod_allowlist_exposes_exactly_two(self):
        self.assertEqual(act.allowlist(), ["nullink-health", "nullink-status"])
        st, _, js, _ = self.req("/api/vault/actions", headers=self.bearer(self.dev))
        self.assertEqual(st, 200, js)
        self.assertTrue(js["enabled"])
        self.assertEqual([a["name"] for a in js["actions"]], ["nullink-health", "nullink-status"])
        self.assertTrue(all(a["privilege"] == "none" for a in js["actions"]))

    def test_list_and_run_need_a_device(self):
        self.assertEqual(self.req("/api/vault/actions")[0], 401)
        self.assertEqual(self.req("/api/vault/actions", cookie=self.owner)[0], 401)   # owner cookie is not a device
        st, *_ = self.req("/api/vault/actions/run", "POST", {"action": {"name": "nullink-health"}})
        self.assertIn(st, (400, 401))

    def test_each_allowed_run_logs_run_result_and_audit(self):
        did = self.dev["js"]["device_id"]
        with mock.patch.object(act, "run_argv", return_value=(0, "ok")) as run:
            for name in ("nullink-health", "nullink-status"):
                st, js, _, _ = self.run_action(name)
                self.assertEqual((st, js["ok"], js["action"]), (200, True, name), js)
        self.assertEqual(run.call_count, 2)
        log = ext.chain_tail("actions.jsonl")
        self.assertEqual([(r["event"], r["action"]) for r in log],
                         [("run", "nullink-health"), ("result", "nullink-health"),
                          ("run", "nullink-status"), ("result", "nullink-status")])
        self.assertTrue(all(r["device_id"] == did for r in log))
        self.assertEqual(ext.chain_verify("actions.jsonl"), (True, 4))
        aud = self.audit("device_action")
        self.assertEqual([(a["action"], a["device"], a["result"]) for a in aud],
                         [("nullink-health", did, "ok"), ("nullink-status", did, "ok")])
        self.assertEqual(sum("quick action" in str(c) for c in self.alerts.call_args_list), 2)

    def test_failed_run_still_logged_and_audited(self):
        with mock.patch.object(act, "run_argv", return_value=(7, "boom")):
            st, js, _, _ = self.run_action("nullink-health")
        self.assertEqual((st, js["ok"], js["result"]), (200, False, "failed"))
        self.assertEqual([r["event"] for r in ext.chain_tail("actions.jsonl")], ["run", "result"])
        self.assertEqual(len(self.audit("device_action")), 1)

    def test_off_allowlist_refused_even_with_valid_signature(self):
        with mock.patch.object(act, "run_argv", side_effect=AssertionError("must not run")):
            for name in ("nulldo-restart", "nulldo-status", "nulldo-health", "nulldo-journal", "rm", "", "nullink-health,nulldo-restart"):
                st, js, _, _ = self.run_action(name)
                self.assertEqual((st, js.get("error")), (403, "action_not_allowed"), name)
        self.assertEqual(ext.chain_tail("actions.jsonl"), [])
        self.assertEqual(self.audit("device_action"), [])

    def test_window_session_cannot_sign_an_action(self):
        ks = self.start_session()
        st, _, js, _ = self.sync_challenge(self.dev, "action")
        self.assertEqual(st, 200, js)
        with mock.patch.object(act, "run_argv", side_effect=AssertionError("must not run")):
            st, js, _, _ = self.signed_call(self.dev, "/api/vault/actions/run", "action", nonce=js["nonce"], sign_key=ks,
                                            extra={"action": {"name": "nullink-health"}, "signed_by": "session"})
            self.assertEqual((st, js.get("error")), (403, "session_not_allowed"), js)
            # K_sess presented as if it were K_dev: wrong key for the device -> refused too
            st2, _, js2, _ = self.sync_challenge(self.dev, "action")
            self.assertEqual(st2, 200, js2)
            st, js, _, _ = self.run_action("nullink-health", nonce=js2["nonce"], sign_key=ks)
            self.assertGreaterEqual(st, 400, js)
        self.assertEqual(self.audit("device_action"), [])
        self.assertEqual(ext.chain_tail("actions.jsonl"), [])

    def test_needs_fresh_action_nonce(self):
        st, _, js, _ = self.sync_challenge(self.dev, "action")
        n = js["nonce"]
        with mock.patch.object(act, "run_argv", return_value=(0, "ok")) as run:
            self.assertEqual(self.run_action("nullink-health", nonce=n)[0], 200)
            st, js, _, _ = self.run_action("nullink-health", nonce=n)          # replay
            self.assertNotEqual(st, 200, js)
            st, _, js, _ = self.sync_challenge(self.dev, "write")              # other purpose's nonce
            st, js, _, _ = self.run_action("nullink-health", nonce=js["nonce"])
            self.assertNotEqual(st, 200, js)
            st, js, _, _ = self.signed_call(self.dev, "/api/vault/actions/run", "write",
                                            extra={"action": {"name": "nullink-health"}})  # signed for "write"
            self.assertNotEqual(st, 200, js)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(len(self.audit("device_action")), 1)

    def test_wrong_key_refused(self):
        other = ec.generate_private_key(ec.SECP256R1())
        with mock.patch.object(act, "run_argv", side_effect=AssertionError("must not run")):
            st, js, _, _ = self.run_action("nullink-health", sign_key=other)
        self.assertGreaterEqual(st, 400)
        self.assertEqual(self.audit("device_action"), [])

    def test_flag_off_with_allowlist_is_404(self):
        os.environ["NULLVAULT_ACTIONS"] = "0"
        self.assertEqual(self.req("/api/vault/actions", headers=self.bearer(self.dev))[0], 404)
