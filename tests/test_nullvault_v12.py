"""NullVault 0.7.0 (John 2026-11-14 9:37 PM ET): server-driven command list and optional layout sync.

Commands: the phone renders only what GET /api/vault/actions sends (id, label, description, group, confirm text,
params schema); only allowlisted commands are listed; parameters are validated server side against the same
schema; a changed allowlist changes the list (and its version); a removed command is refused even if a phone still
shows it. Layout: one non-secret document per owner, strict shape, last change wins, device token only."""
import json
import os
from unittest import mock

import nullvault
import nullvault_actions as act
import nullvault_ext as ext
import nullvault_layout as lay
import server
from tests.test_nullvault_stage3 import S3Base

PROD_ALLOW = "nullink-health,nullink-status"


class CommandListTests(S3Base):
    flags = {"NULLVAULT_ACTIONS": "1", "NULLVAULT_ACTIONS_ALLOW": PROD_ALLOW}

    def listing(self):
        st, _, js, _ = self.req("/api/vault/actions", headers=self.bearer(self.dev))
        self.assertEqual(st, 200, js)
        return js

    def allow(self, v):
        os.environ["NULLVAULT_ACTIONS_ALLOW"] = v

    def run_action(self, name, args=None):
        a = {"name": name}
        if args is not None:
            a["args"] = args
        return self.signed_call(self.dev, "/api/vault/actions/run", "action", extra={"action": a})

    def test_list_carries_everything_the_app_renders(self):
        js = self.listing()
        self.assertTrue(js["enabled"])
        self.assertRegex(js["version"], r"^[0-9a-f]{16}$")
        self.assertEqual([c["id"] for c in js["actions"]], ["nullink-health", "nullink-status"])
        for c in js["actions"]:
            for k in ("id", "name", "label", "description", "group", "confirm", "params", "privilege", "args"):
                self.assertIn(k, c)
            self.assertTrue(c["label"] and c["description"] and c["group"] and c["confirm"])
            self.assertEqual(c["params"], {"type": "object", "properties": {}, "required": [], "additionalProperties": False})
            self.assertNotIn("argv", c)        # the command line never leaves the server
            self.assertNotIn("timeout", c)

    def test_only_allowlisted_and_unknown_names_dropped(self):
        self.allow("nullink-status, bogus ,nulldo-restart;rm,")
        self.assertEqual([c["id"] for c in self.listing()["actions"]], ["nullink-status"])
        self.allow("")
        self.assertEqual(self.listing()["actions"], [])

    def test_list_changes_follow_allowlist_and_version(self):
        v1 = self.listing()["version"]
        self.assertEqual(self.listing()["version"], v1)                       # stable
        self.allow("nullink-health")                                           # removed
        js = self.listing(); self.assertEqual([c["id"] for c in js["actions"]], ["nullink-health"]); self.assertNotEqual(js["version"], v1)
        self.allow("nullink-health,nullink-status,nulldo-journal")             # added
        js = self.listing(); self.assertEqual(len(js["actions"]), 3); v3 = js["version"]
        with mock.patch.dict(act.CATALOG["nulldo-journal"], {"label": "Journal (renamed)"}):  # changed command
            self.assertNotEqual(self.listing()["version"], v3)

    def test_removed_command_refused_even_if_phone_still_shows_it(self):
        self.allow("nullink-health")
        with mock.patch.object(act, "run_argv", side_effect=AssertionError("must not run")):
            st, js, _, _ = self.run_action("nullink-status")
        self.assertEqual((st, js.get("error")), (403, "action_not_allowed"))
        self.assertEqual(ext.chain_tail("actions.jsonl"), [])

    def test_param_schema_published_for_params(self):
        self.allow("nulldo-journal")
        c = self.listing()["actions"][0]
        self.assertEqual(c["params"]["properties"]["lines"],
                         {"type": "integer", "minimum": 1, "maximum": 200, "default": 50, "title": "Lines"})
        self.assertEqual(c["params"]["required"], [])
        self.assertEqual(c["args"], {"lines": {"type": "int", "min": 1, "max": 200, "default": 50}})  # 0.6.0 apps

    def test_param_validation_against_schema(self):
        self.allow("nulldo-journal,nullink-health")
        bad = [{"lines": 0}, {"lines": 201}, {"lines": "50"}, {"lines": 50.0}, {"lines": True}, {"lines": None},
               {"lines": [50]}, {"lines": 50, "extra": 1}, {"cmd": "rm -rf /"}, "lines=50", [50]]
        with mock.patch.object(act, "run_argv", side_effect=AssertionError("must not run")):
            for b in bad:
                st, js, _, _ = self.run_action("nulldo-journal", b)
                self.assertEqual((st, js.get("error")), (400, "bad_args"), b)
            st, js, _, _ = self.run_action("nullink-health", {"lines": 5})     # no params declared
            self.assertEqual((st, js.get("error")), (400, "bad_args"))
        with mock.patch.object(act, "run_argv", return_value=(0, "ok")) as run:
            self.assertEqual(self.run_action("nulldo-journal", {"lines": 200})[0], 200)
            self.assertEqual(run.call_args[0][0][-1], "200")
            self.assertEqual(self.run_action("nulldo-journal")[0], 200)        # default
            self.assertEqual(run.call_args[0][0][-1], "50")

    def test_validator_units(self):
        enum = {"mode": {"type": "string", "enum": ["short", "full"], "default": "short"}}
        self.assertEqual(act.validate_args(enum, {}), {"mode": "short"})
        self.assertEqual(act.validate_args(enum, {"mode": "full"}), {"mode": "full"})
        self.assertIsNone(act.validate_args(enum, {"mode": "FULL"}))
        self.assertIsNone(act.validate_args(enum, {"mode": 1}))
        req = {"n": {"type": "integer", "minimum": 1, "maximum": 3}}
        self.assertIsNone(act.validate_args(req, {}))                      # required (no default)
        self.assertIsNone(act.validate_args({"x": {"type": "path"}}, {"x": "/etc"}))
        self.assertTrue(all(act.schema_ok(c["params"]) for c in act.CATALOG.values()))
        self.assertFalse(act.schema_ok({"x": {"type": "string"}}))
        self.assertFalse(act.schema_ok({"Bad-Name": {"type": "integer", "minimum": 1, "maximum": 2}}))

    def test_execution_unchanged_for_prod_commands(self):
        self.assertEqual(act.CATALOG["nullink-health"]["argv"][-1], "http://127.0.0.1:8766/health")
        self.assertEqual(act.CATALOG["nullink-status"]["argv"][:3], ["/usr/bin/systemctl", "show", "nullink.service"])
        for n in ("nullink-health", "nullink-status"):
            self.assertEqual(act.CATALOG[n]["privilege"], "none")

    def test_list_needs_device_and_flag(self):
        self.assertEqual(self.req("/api/vault/actions")[0], 401)
        os.environ["NULLVAULT_ACTIONS"] = "0"
        self.assertEqual(self.req("/api/vault/actions", headers=self.bearer(self.dev))[0], 404)


def good_layout(**kw):
    d = {"v": 1, "start": "Health",
         "groups": [{"id": "status", "name": "Status", "pages": ["Health", "Alerts", "Actions"]},
                    {"id": "more", "name": "More", "pages": ["Chat", "Settings"]}],
         "buttons": [{"id": "status", "row": 0, "label": "Status", "icon": "◉", "group": "status"},
                     {"id": "files", "row": 1, "label": "Files", "icon": "📁", "page": "Files"},
                     {"id": "more", "row": 0, "label": "More", "icon": "☰", "group": "more"}]}
    d.update(kw)
    return d


class LayoutSyncTests(S3Base):
    def setUp(self):
        super().setUp()
        lay.bind(nullvault, server)
        (nullvault.nv_dir() / lay.FILE).unlink(missing_ok=True)

    def put(self, layout, ts, dev=None, headers=None):
        return self.req("/api/vault/layout", "POST", {"layout": layout, "updated_at_ms": ts},
                        headers=headers if headers is not None else self.bearer(dev or self.dev))

    def get(self, dev=None):
        st, _, js, _ = self.req("/api/vault/layout", headers=self.bearer(dev or self.dev))
        self.assertEqual(st, 200, js)
        return js

    def test_empty_then_roundtrip_and_audit(self):
        self.assertEqual(self.get(), {"layout": None, "updated_at_ms": 0, "device_id": ""})
        st, _, js, _ = self.put(good_layout(), 1000)
        self.assertEqual(st, 200, js); self.assertTrue(js["applied"])
        g = self.get()
        self.assertEqual(g["layout"], good_layout()); self.assertEqual(g["updated_at_ms"], 1000)
        self.assertEqual(g["device_id"], self.dev["js"]["device_id"])
        aud = [json.loads(l) for l in server.VAULT_AUDIT_FILE.read_text().splitlines()]
        self.assertTrue(any(a.get("event") == "device_layout_set" for a in aud))
        self.assertEqual(os.stat(nullvault.nv_dir() / lay.FILE).st_mode & 0o777, 0o600)

    def test_most_recent_change_wins(self):
        self.assertTrue(self.put(good_layout(start="Files"), 2000)[2]["applied"])
        st, _, js, _ = self.put(good_layout(start="Chat"), 1500)             # older (offline phone) loses
        self.assertEqual(st, 200); self.assertFalse(js["applied"]); self.assertEqual(js["layout"]["start"], "Files")
        self.assertFalse(self.put(good_layout(start="Chat"), 2000)[2]["applied"])  # tie keeps the stored one
        self.assertTrue(self.put(good_layout(start="Chat"), 2001)[2]["applied"])
        self.assertEqual(self.get()["layout"]["start"], "Chat")

    def test_future_time_clamped(self):
        import time as _t
        far = int(_t.time() * 1000) + 10 * 86400_000
        self.assertTrue(self.put(good_layout(), far)[2]["applied"])
        self.assertLessEqual(self.get()["updated_at_ms"], int(_t.time() * 1000) + lay.SKEW_MS)

    def test_needs_device_token(self):
        self.assertEqual(self.req("/api/vault/layout")[0], 401)
        self.assertEqual(self.req("/api/vault/layout", cookie=self.owner)[0], 401)
        self.assertEqual(self.put(good_layout(), 5, headers={})[0], 401)
        self.assertEqual(self.put(good_layout(), 5, headers={"Authorization": "Bearer nope"})[0], 401)

    def test_off_with_nullvault_off(self):
        os.environ["NULLVAULT_ENABLED"] = "0"
        self.addCleanup(os.environ.__setitem__, "NULLVAULT_ENABLED", "1")
        self.assertEqual(self.req("/api/vault/layout", headers=self.bearer(self.dev))[0], 404)

    def test_strict_shape(self):
        L = good_layout
        b0 = L()["buttons"]
        bad = [
            None, [], "x", L(v=2), L(start="../etc"), L(start=""), {**L(), "secret": "x"},
            L(buttons=b0 + [{"id": f"b{i}", "row": 1, "label": "x", "icon": "x", "page": f"P{i}"} for i in range(8)]),  # 11 buttons
            L(buttons=[{"id": f"b{i}", "row": 0, "label": "x", "icon": "x", "page": f"P{i}"} for i in range(6)]),       # 6 in a row
            L(buttons=[{**b0[0], "row": 2}]), L(buttons=[{**b0[0], "row": True}]),
            L(buttons=[{**b0[0], "id": "Bad Id"}]), L(buttons=[b0[0], b0[0]]),
            L(buttons=[{**b0[0], "label": "x" * 25}]), L(buttons=[{**b0[0], "label": "a\nb"}]), L(buttons=[{**b0[0], "icon": ""}]),
            L(buttons=[{**b0[0], "page": "Files"}]),                       # both group and page
            L(buttons=[{"id": "x", "row": 0, "label": "x", "icon": "x"}]),   # neither
            L(buttons=[{**b0[0], "group": "nope"}]),                        # unknown group
            L(buttons=[{**b0[0], "token": "abc"}]),                         # unknown key
            L(buttons=[{"id": "x", "row": 0, "label": "x", "icon": "x", "page": "Health"}]),  # page already in a group
            L(groups=[{"id": "g", "name": "G", "pages": ["Health", "Health"]}], buttons=[]),
            L(groups=[{"id": "g", "name": "G", "pages": ["Bad/Page"]}], buttons=[]),
            L(groups=[{"id": "g", "name": "", "pages": []}], buttons=[]),
            L(groups=[{"id": "g", "name": "G", "pages": [], "note": "secret"}], buttons=[]),
        ]
        for b in bad:
            st, _, js, _ = self.put(b, 10)
            self.assertEqual((st, js.get("error")), (400, "bad_layout"), b)
        for ts in (0, -1, "10", 1.5, True, None):
            self.assertEqual(self.put(good_layout(), ts)[0], 400, ts)
        self.assertEqual(self.get()["layout"], None)

    def test_size_cap(self):
        st, _, js, _ = self.req("/api/vault/layout", "POST", {"layout": good_layout(), "updated_at_ms": 5, "pad": "x" * 9000},
                                headers=self.bearer(self.dev))
        self.assertEqual(st, 413)

    def test_empty_group_and_buttonless_group_ok(self):
        l = good_layout(groups=[{"id": "g", "name": "Spare", "pages": []}],
                        buttons=[{"id": "s", "row": 0, "label": "Settings", "icon": "⚙", "page": "Settings"}])
        self.assertTrue(self.put(l, 7)[2]["applied"])
