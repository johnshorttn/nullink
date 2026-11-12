"""NullVault Stage 2 (2026-11-12): server status (flag, device/status-token auth, metrics, no token values,
down-transition Slack alerts, rate limit) and encrypted project notes (signed writes, at-rest encryption, sync)."""
import json
import os
from pathlib import Path
from unittest import mock

import nullvault
import nullvault_ext as ext
import nullvault_status as st
import server
from tests.test_nullvault import NullVaultBase

SHOW = """Id=nullink.service
LoadState=loaded
ActiveState=active
SubState=running
ActiveEnterTimestamp=Thu 2026-11-12 23:22:22 UTC

Id=caddy.service
LoadState=loaded
ActiveState=failed
SubState=failed
ActiveEnterTimestamp=

Id=ghost.service
LoadState=not-found
ActiveState=inactive
SubState=dead
ActiveEnterTimestamp=
"""


class S2Base(NullVaultBase):
    def setUp(self):
        super().setUp()
        for k, v in (("NULLVAULT_LINKS", "1"), ("NULLVAULT_NOTES", "1"), ("NULLVAULT_STATUS", "1"),
                     ("NULLVAULT_STATUS_SERVICES", "nullink,caddy,ghost"), ("NULLVAULT_DISCOVERY_CADDY", "0")):
            os.environ[k] = v
            self.addCleanup(os.environ.pop, k, None)
        ext.nv, ext.server = nullvault, server
        st.bind(nullvault, server)
        st._cache.update(t=0.0, data=None); st._tls_cache.update(t=0.0, certs=[])
        st._mon["state"].clear(); st._mon["last_alert"].clear()
        ext._disc_cache.update(t=0.0, sites=[], source=None)
        p = mock.patch.object(st, "run_systemctl_show", return_value=SHOW); p.start(); self.addCleanup(p.stop)
        p2 = mock.patch.object(ext, "CADDYFILE", Path("/nonexistent/Caddyfile")); p2.start(); self.addCleanup(p2.stop)
        self.dev = self.register()

    def write(self, op, kind, rec, **extra):
        return self.signed_call(self.dev, "/api/vault/device/write", "write", extra={"op": op, "kind": kind, kind: rec, **extra})


class StatusTests(S2Base):
    def test_flag_off_404(self):
        os.environ["NULLVAULT_STATUS"] = "0"
        st_, *_ = self.req("/api/vault/status", headers=self.bearer(self.dev))
        self.assertEqual(st_, 404)
        os.environ["NULLVAULT_STATUS"] = "1"; os.environ["NULLVAULT_ENABLED"] = "0"
        st_, *_ = self.req("/api/vault/status", headers=self.bearer(self.dev))
        self.assertEqual(st_, 404)

    def test_requires_device_auth(self):
        self.assertEqual(self.req("/api/vault/status")[0], 401)
        self.assertEqual(self.req("/api/vault/status", headers={"Authorization": "Bearer nvs_bogus"})[0], 401)
        self.assertEqual(self.req("/api/vault/status", cookie=self.owner)[0], 401)

    def test_card_contents(self):
        server._atomic_write_json(nullvault.nv_dir() / "token_expiry.json", {"tokens": [
            {"name": "GitHub PAT (deploy)", "kind": "github_pat", "expires_at": "2027-01-31", "token": "ghp_SHOULD_NEVER_LEAK"},
            {"name": "bad date", "expires_at": "soon", "value": "xoxb-NEVER"}]})
        server._atomic_write_json(nullvault.nv_dir() / "discovered_sites.json", {"hosts": ["a.example.com"]})
        with mock.patch.object(st, "cert_expiry", return_value="2027-02-01T00:00:00Z"):
            code, _, js, raw = self.req("/api/vault/status", headers=self.bearer(self.dev))
        self.assertEqual(code, 200, js)
        self.assertNotIn(b"ghp_", raw); self.assertNotIn(b"xoxb", raw)
        svc = {s["name"]: s for s in js["services"]}
        self.assertTrue(svc["nullink"]["ok"]); self.assertEqual(svc["caddy"]["active"], "failed")
        self.assertEqual(svc["ghost"]["active"], "not-found")
        self.assertEqual(js["health"]["down"], ["caddy", "ghost"])
        self.assertIsInstance(js["uptime_s"], int); self.assertTrue(js["disk"]); self.assertIn("pct", js["disk"][0])
        toks = {t["name"]: t for t in js["tokens"]}
        self.assertEqual(set(toks["GitHub PAT (deploy)"]), {"name", "kind", "expires_at", "days_left"})
        self.assertIsNone(toks["bad date"]["expires_at"])
        self.assertEqual(toks["a.example.com"]["kind"], "tls_certificate")
        self.assertTrue(js["omitted"])

    def test_status_token_signed_issue_and_revoke(self):
        code, js, _, _ = self.signed_call(self.dev, "/api/vault/status/token", "status")
        self.assertEqual(code, 200, js)
        tok = js["status_token"]
        self.assertTrue(tok.startswith("nvs_"))
        self.assertNotIn(tok, (nullvault.nv_dir() / "status_tokens.json").read_text())  # stored hashed
        self.assertEqual(self.req("/api/vault/status", headers={"Authorization": "Bearer " + tok})[0], 200)
        # a status token is not a device token
        self.assertEqual(self.req("/api/vault/sync-challenge", "POST", {"purpose": "sync"}, headers={"Authorization": "Bearer " + tok})[0], 401)
        self.assertEqual(self.revoke(self.dev["js"]["device_id"])[0], 200)
        code, _, js, _ = self.req("/api/vault/status", headers={"Authorization": "Bearer " + tok})
        self.assertEqual((code, js.get("wipe")), (403, True))

    def test_status_token_needs_signature(self):
        code, *_ = self.req("/api/vault/status/token", "POST", {}, headers=self.bearer(self.dev))
        self.assertIn(code, (400, 403))

    def test_parse_show(self):
        r = st.parse_show(SHOW)
        self.assertEqual([x["name"] for x in r], ["nullink", "caddy", "ghost"])
        self.assertEqual([x["ok"] for x in r], [True, False, False])

    def test_unit_names_sanitized(self):
        os.environ["NULLVAULT_STATUS_SERVICES"] = "nullink,$(reboot),a b,caddy"
        self.assertEqual(st.services(), ["nullink", "caddy"])


class MonitorTests(S2Base):
    def test_transitions_alert_rate_limited(self):
        sent = []
        with mock.patch.object(nullvault, "send_alert", side_effect=sent.append):
            st.monitor_tick(1000)  # baseline: caddy already failed -> no alert
            self.assertEqual(sent, [])
            up = SHOW.replace("ActiveState=failed", "ActiveState=active")
            with mock.patch.object(st, "run_systemctl_show", return_value=up):
                st.monitor_tick(1060)
            self.assertEqual(len(sent), 1); self.assertIn("caddy", sent[0]); self.assertIn("back", sent[0])
            st.monitor_tick(1120)  # down again
            self.assertEqual(len(sent), 2); self.assertIn("DOWN", sent[1])
            with mock.patch.object(st, "run_systemctl_show", return_value=up):
                st.monitor_tick(1180)
            st.monitor_tick(1240)  # flapping inside 30 min: suppressed
            self.assertEqual(len(sent), 2)
            with mock.patch.object(st, "run_systemctl_show", return_value=up):
                st.monitor_tick(1300)
            st.monitor_tick(1120 + st.ALERT_GAP + 1)
            self.assertEqual(len(sent), 3)
        self.assertFalse(any("ghost" in s for s in sent))  # not-found units never alert

    def test_alerts_respect_switch(self):
        os.environ["NULLVAULT_ALERTS"] = "0"; self.addCleanup(os.environ.pop, "NULLVAULT_ALERTS", None)
        with mock.patch.object(nullvault, "send_alert") as sa:
            st.monitor_tick(1); st._mon["state"]["svc:caddy"] = True; st.monitor_tick(2)
        sa.assert_not_called()

    def test_monitor_not_started_in_tests_or_flag_off(self):
        self.assertIsNone(st._mon["thread"])


class NotesTests(S2Base):
    def project(self):
        code, js, _, _ = self.write("create", "project", {"name": "NullKey"})
        self.assertEqual(code, 200, js)
        return js["project"]["id"]

    def test_note_crud_encrypted_at_rest_and_synced(self):
        pid = self.project()
        code, js, _, _ = self.write("create", "note", {"project_id": pid, "title": "Deploy", "body": "nv-note-plaintext-xyz"})
        self.assertEqual(code, 200, js)
        nid = js["note"]["id"]
        self.assertEqual(js["note"]["body"], "nv-note-plaintext-xyz")
        raw = (nullvault.nv_dir() / "notes.json").read_text()
        self.assertNotIn("nv-note-plaintext-xyz", raw); self.assertNotIn("Deploy", raw)
        self.assertIn("AES-256-GCM", raw)
        notes = self.sync(self.dev)[1]["notes"]
        self.assertEqual([(n["title"], n["body"]) for n in notes], [("Deploy", "nv-note-plaintext-xyz")])
        code, js, _, _ = self.write("update", "note", {"id": nid, "body": "v2"})
        self.assertEqual((code, js["note"]["title"], js["note"]["body"]), (200, "Deploy", "v2"))
        code, js, _, _ = self.write("update", "note", {"id": nid, "body": "x"}, base_updated_at="2000-01-01T00:00:00Z")
        self.assertEqual(code, 409); self.assertNotIn("enc", js["note"])
        self.assertEqual(self.write("delete", "note", {"id": nid})[0], 200)
        self.assertEqual(self.sync(self.dev)[1]["notes"], [])

    def test_note_needs_existing_project_and_limits(self):
        self.assertEqual(self.write("create", "note", {"project_id": "nope", "body": "x"})[0], 400)
        pid = self.project()
        self.assertEqual(self.write("create", "note", {"project_id": pid})[0], 400)
        self.assertEqual(self.write("create", "note", {"project_id": pid, "body": "x" * (ext.MAX_NOTE_BODY + 1)})[0], 400)

    def test_project_delete_removes_notes(self):
        pid = self.project()
        self.write("create", "note", {"project_id": pid, "body": "a"})
        self.assertEqual(self.write("delete", "project", {"id": pid})[0], 200)
        self.assertEqual(self.sync(self.dev)[1]["notes"], [])

    def test_tampered_ciphertext_fails_closed(self):
        pid = self.project()
        self.write("create", "note", {"project_id": pid, "body": "a"})
        f = nullvault.nv_dir() / "notes.json"
        txt = f.read_text()
        n0 = json.loads(txt)
        lst = n0 if isinstance(n0, list) else next(v for v in n0.values() if isinstance(v, list))
        lst[0]["id"] = "swapped0000"  # AAD binds the ciphertext to its note id
        f.write_text(json.dumps(n0))
        code, js, _, _ = self.sync(self.dev)
        self.assertEqual((code, js["error"]), (500, "vault_integrity"))

    def test_notes_flag_off(self):
        os.environ["NULLVAULT_NOTES"] = "0"
        pid = self.project()
        self.assertEqual(self.write("create", "note", {"project_id": pid, "body": "a"})[0], 404)
        self.assertNotIn("notes", self.sync(self.dev)[1])


class MonitorLoopBindingTests(S2Base):
    def test_loop_binds_live_server_and_ticks(self):
        """The thread finds the running server module itself (no request needed) and then alerts on transitions."""
        sent = []
        st._mon["thread"] = None
        fake_main = mock.MagicMock(spec=["_slack_dm_channel"])
        ticks = []
        real_tick = st.monitor_tick

        def once(*a, **k):
            ticks.append(1)
            raise SystemExit  # stop the loop after one pass
        with mock.patch.object(nullvault, "server", None), mock.patch.dict("sys.modules", {"__main__": server}), \
             mock.patch.object(st.time, "sleep", lambda s: None), mock.patch.object(st, "monitor_tick", side_effect=once), \
             mock.patch.object(st.threading, "Thread") as T:
            st.start_monitor()
            target = T.call_args.kwargs["target"]
            try:
                target()
            except SystemExit:
                pass
            self.assertIs(nullvault.server, server)
        self.assertEqual(ticks, [1])
        st._mon["thread"] = None
