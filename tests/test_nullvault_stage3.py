"""NullVault Stage 3 (2026-11-12): chat (device chat session over the existing message store), approvals
(GitHub PR queue, signed decisions in an append-only hash-chained log, APPROVE review only, never merge,
NullAxis placeholder) and the quick-actions framework (flag off, empty allowlist, fixed argv, signed, rate-limited,
audited)."""
import base64
import json
import os
from unittest import mock

import nullvault
import nullvault_actions as act
import nullvault_approvals as ap
import nullvault_chat as chat
import nullvault_ext as ext
import server
from tests.test_nullvault import ORIGIN, NullVaultBase
from tests.test_auth import totp_code

SHA = "a" * 40
SHA2 = "b" * 40


class S3Base(NullVaultBase):
    flags = {}

    def setUp(self):
        super().setUp()
        for k, v in self.flags.items():
            os.environ[k] = v
            self.addCleanup(os.environ.pop, k, None)
        for m in (chat, ap, act):
            m.bind(nullvault, server)
            m.limits.clear()
        chat.sessions.clear()
        ap._cache.update(t=0.0, data=None); ap._login.update(t=0.0, login=None)
        for name in ("approvals.jsonl", "actions.jsonl"):
            try:
                (nullvault.nv_dir() / name).unlink()
            except FileNotFoundError:
                pass
        p = mock.patch.object(nullvault, "send_alert"); self.alerts = p.start(); self.addCleanup(p.stop)
        self.dev = self.register()


# ------------------------------------------------------------------ chat

class ChatTests(S3Base):
    flags = {"NULLVAULT_CHAT": "1"}

    def setUp(self):
        super().setUp()
        server._atomic_write_json(server.ROSTER_FILE, {"categories": [{"id": "c", "bots": [
            {"id": "morc", "title": "Chief of Staff (Morc)"}, {"id": "deepseek", "title": "DeepSeek"}]}]})
        server.MESSAGES_FILE.write_text("")
        for fn in ("write_pending", "fire_webhook"):
            p = mock.patch.object(server, fn); setattr(self, fn, p.start()); self.addCleanup(p.stop)

    def session(self):
        st, js, _, _ = self.signed_call(self.dev, "/api/vault/chat/session", "chat")
        self.assertEqual(st, 200, js)
        self.assertTrue(js["chat_session"].startswith("nvc_"))
        self.assertEqual(js["expires_in"], 600)
        return {"Authorization": "Bearer " + js["chat_session"]}

    def test_flag_off_404(self):
        os.environ["NULLVAULT_CHAT"] = "0"
        self.assertEqual(self.req("/api/vault/chat/rooms", headers=self.bearer(self.dev))[0], 404)
        self.assertEqual(self.sync_challenge(self.dev, "chat")[0], 200)  # challenge purpose itself is generic

    def test_needs_session_not_device_token_or_cookie(self):
        self.assertEqual(self.req("/api/vault/chat/rooms")[0], 401)
        self.assertEqual(self.req("/api/vault/chat/rooms", headers=self.bearer(self.dev))[0], 401)
        self.assertEqual(self.req("/api/vault/chat/rooms", cookie=self.owner)[0], 401)
        self.assertEqual(self.req("/api/vault/chat/session", "POST", {}, headers=self.bearer(self.dev))[0], 400)

    def test_session_needs_chat_purpose(self):
        st, js, _, _ = self.signed_call(self.dev, "/api/vault/chat/session", "files")
        self.assertEqual(st, 400, js)

    def test_rooms_read_send_poll(self):
        h = self.session()
        st, _, js, _ = self.req("/api/vault/chat/rooms", headers=h)
        self.assertEqual(st, 200)
        self.assertEqual([r["id"] for r in js["rooms"]], ["morc", "deepseek"])
        self.assertTrue(js["rooms"][1]["bridge"])
        server.append_message("assistant", "hello from morc", session_id="morc")
        server.append_message("assistant", "other room", session_id="deepseek")
        st, _, js, _ = self.req("/api/vault/chat/messages?session=morc", headers=h)
        self.assertEqual([m["text"] for m in js["messages"]], ["hello from morc"])
        after = js["next_after"]
        st, _, js, _ = self.req("/api/vault/chat/send", "POST", {"session_id": "morc", "text": "  hi from phone "}, headers=h)
        self.assertEqual(st, 200, js)
        self.assertEqual(js["message"]["text"], "hi from phone")
        self.write_pending.assert_called_once(); self.fire_webhook.assert_called_once()
        # same store as the web UI: the existing reader sees it as John's message in that room
        last = server.read_messages()[-1]
        self.assertEqual((last["role"], last["session_id"], last["text"]), ("user", "morc", "hi from phone"))
        st, _, js, _ = self.req(f"/api/vault/chat/messages?session=morc&after={after}", headers=h)
        self.assertEqual([m["text"] for m in js["messages"]], ["hi from phone"])
        # bridge room: no notify/webhook, same as the web UI
        self.req("/api/vault/chat/send", "POST", {"session_id": "deepseek", "text": "x"}, headers=h)
        self.assertEqual(self.write_pending.call_count, 1)

    def test_tail_and_limits(self):
        h = self.session()
        for i in range(5):
            server.append_message("assistant", f"m{i}", session_id="morc")
        st, _, js, _ = self.req("/api/vault/chat/messages?session=morc&tail=1&limit=2", headers=h)
        self.assertEqual([m["text"] for m in js["messages"]], ["m3", "m4"])
        self.assertEqual(self.req("/api/vault/chat/messages?session=nope", headers=h)[0], 404)
        self.assertEqual(self.req("/api/vault/chat/send", "POST", {"session_id": "nope", "text": "x"}, headers=h)[0], 404)
        self.assertEqual(self.req("/api/vault/chat/send", "POST", {"session_id": "morc", "text": "  "}, headers=h)[0], 400)
        self.assertEqual(self.req("/api/vault/chat/send", "POST", {"session_id": "morc", "text": "x" * 8001}, headers=h)[0], 400)

    def test_send_rate_limit(self):
        h = self.session()
        with mock.patch.object(chat, "SEND_LIMIT", (2, 600)):
            codes = [self.req("/api/vault/chat/send", "POST", {"session_id": "morc", "text": "x"}, headers=h)[0] for _ in range(3)]
        self.assertEqual(codes, [200, 200, 429])

    def test_revoke_ends_session(self):
        h = self.session()
        self.fresh_codes()
        st, _, js, _ = self.req(f"/api/vault/devices/{self.dev['js']['device_id']}/revoke", "POST",
                                {"code": totp_code()}, cookie=self.owner, headers={"Origin": ORIGIN})
        self.assertEqual(st, 200, js)
        st, _, js, _ = self.req("/api/vault/chat/rooms", headers=h)
        self.assertEqual(st, 403); self.assertTrue(js["wipe"])

    def test_expired_session(self):
        h = self.session()
        for v in chat.sessions._s.values():
            v["exp"] = 0
        self.assertEqual(self.req("/api/vault/chat/rooms", headers=h)[2]["error"], "chat_session_expired")


# ------------------------------------------------------------------ approvals

def fake_gh(prs, user="johnshorttn", review_status=200, calls=None):
    def gh(method, path, body=None):
        if calls is not None:
            calls.append((method, path, body))
        if path == "/user":
            return 200, {"login": user}
        if path.startswith("/search/issues"):
            return 200, {"items": [{"repository_url": f"https://api.github.com/repos/{p['repo']}", "number": p["number"]} for p in prs]}
        for p in prs:
            if path == f"/repos/{p['repo']}/pulls/{p['number']}" and method == "GET":
                return 200, {"number": p["number"], "title": p.get("title", "t"), "state": p.get("state", "open"),
                             "user": {"login": p.get("author", "someone")}, "html_url": "https://github.com/x",
                             "head": {"sha": p.get("sha", SHA)}, "base": {"repo": {"full_name": p["repo"]}}}
            if path == f"/repos/{p['repo']}/pulls/{p['number']}/reviews" and method == "POST":
                return review_status, {}
        return 404, {}
    return gh


class ApprovalsTests(S3Base):
    flags = {"NULLVAULT_APPROVALS": "1"}

    def setUp(self):
        super().setUp()
        self.tokfile = nullvault.nv_dir().parent / "gh_token_test.txt"
        self.tokfile.write_text("github_pat_TEST_NEVER_LEAKS\n")
        os.environ["NULLVAULT_GITHUB_TOKEN_FILE"] = str(self.tokfile)
        self.addCleanup(os.environ.pop, "NULLVAULT_GITHUB_TOKEN_FILE", None)
        self.calls = []

    def decide(self, **a):
        appr = {"source": "github", "repo": "johnshorttn/nullink", "number": 34, "head_sha": SHA, "decision": "approve"}
        appr.update(a)
        return self.signed_call(self.dev, "/api/vault/approvals/decide", "approve", extra={"approval": appr})

    def test_flag_off_404(self):
        os.environ["NULLVAULT_APPROVALS"] = "0"
        self.assertEqual(self.req("/api/vault/approvals", headers=self.bearer(self.dev))[0], 404)

    def test_requires_device(self):
        self.assertEqual(self.req("/api/vault/approvals")[0], 401)
        self.assertEqual(self.req("/api/vault/approvals", cookie=self.owner)[0], 401)

    def test_no_token_shows_unavailable(self):
        self.tokfile.unlink()
        with mock.patch.object(ap, "gh", side_effect=AssertionError("no GitHub call without a token")):
            st, _, js, _ = self.req("/api/vault/approvals", headers=self.bearer(self.dev))
            self.assertEqual(st, 200)
            self.assertEqual(js["github"], {"available": False, "reason": "no_token", "items": []})
            self.assertEqual(js["nullaxis"]["items"], []); self.assertFalse(js["nullaxis"]["available"])
            st, js, _, _ = self.decide()
            self.assertEqual((st, js["error"]), (409, "github_unavailable"))
        self.assertEqual(ext.chain_tail("approvals.jsonl"), [])

    def test_unreadable_token_is_unavailable(self):
        os.environ["NULLVAULT_GITHUB_TOKEN_FILE"] = "/nonexistent/github_token.txt"
        st, _, js, _ = self.req("/api/vault/approvals", headers=self.bearer(self.dev))
        self.assertFalse(js["github"]["available"])

    def test_queue_lists_prs_without_token(self):
        prs = [{"repo": "johnshorttn/nullink", "number": 34, "author": "johnshorttn"},
               {"repo": "johnshorttn/nullvault", "number": 3, "author": "dependabot[bot]", "sha": SHA2}]
        with mock.patch.object(ap, "gh", fake_gh(prs)):
            st, _, js, raw = self.req("/api/vault/approvals", headers=self.bearer(self.dev))
        self.assertEqual(st, 200)
        self.assertNotIn(b"github_pat_", raw)
        g = js["github"]
        self.assertTrue(g["available"])
        self.assertEqual([(i["repo"], i["number"], i["own_pr"]) for i in g["items"]],
                         [("johnshorttn/nullink", 34, True), ("johnshorttn/nullvault", 3, False)])
        self.assertEqual(g["items"][1]["head_sha"], SHA2)

    def test_approve_records_signed_decision_and_reviews(self):
        prs = [{"repo": "johnshorttn/nullink", "number": 34, "author": "dependabot[bot]"}]
        with mock.patch.object(ap, "gh", fake_gh(prs, calls=self.calls)):
            st, js, _, _ = self.decide(note="looks good")
        self.assertEqual(st, 200, js)
        self.assertEqual(js["review"], "submitted")
        posts = [c for c in self.calls if c[0] == "POST"]
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0][1], "/repos/johnshorttn/nullink/pulls/34/reviews")
        self.assertEqual((posts[0][2]["event"], posts[0][2]["commit_id"]), ("APPROVE", SHA))
        self.assertFalse(any("merge" in c[1] for c in self.calls))
        log = ext.chain_tail("approvals.jsonl")
        self.assertEqual([r["event"] for r in log], ["decision", "github_review"])
        rec = log[0]
        self.assertEqual((rec["decision"], rec["head_sha"], rec["note"]), ("approve", SHA, "looks good"))
        # the stored payload + signature verify against the device key: the decision is provable later
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        pub = serialization.load_der_public_key(base64.b64decode(nullvault.devices()[self.dev["js"]["device_id"]]["pubkey_spki"]))
        pub.verify(base64.b64decode(rec["signature"]), base64.b64decode(rec["payload_b64"]), ec.ECDSA(hashes.SHA256()))
        self.assertEqual(json.loads(base64.b64decode(rec["payload_b64"]))["approval"]["decision"], "approve")
        self.assertEqual(ext.chain_verify("approvals.jsonl"), (True, 2))
        self.alerts.assert_called()

    def test_own_pr_not_reviewed(self):
        prs = [{"repo": "johnshorttn/nullink", "number": 34, "author": "johnshorttn"}]
        with mock.patch.object(ap, "gh", fake_gh(prs, calls=self.calls)):
            st, js, _, _ = self.decide()
        self.assertEqual((st, js["review"]), (200, "own_pr"))
        self.assertFalse([c for c in self.calls if c[0] == "POST"])

    def test_token_without_scope(self):
        prs = [{"repo": "johnshorttn/nullink", "number": 34}]
        with mock.patch.object(ap, "gh", fake_gh(prs, review_status=403)):
            self.assertEqual(self.decide()[1]["review"], "not_permitted")

    def test_review_can_be_disabled(self):
        os.environ["NULLVAULT_APPROVALS_GITHUB_REVIEW"] = "0"
        self.addCleanup(os.environ.pop, "NULLVAULT_APPROVALS_GITHUB_REVIEW", None)
        prs = [{"repo": "johnshorttn/nullink", "number": 34}]
        with mock.patch.object(ap, "gh", fake_gh(prs, calls=self.calls)):
            self.assertEqual(self.decide()[1]["review"], "disabled")
        self.assertFalse([c for c in self.calls if c[0] == "POST"])

    def test_reject_records_only(self):
        prs = [{"repo": "johnshorttn/nullink", "number": 34}]
        with mock.patch.object(ap, "gh", fake_gh(prs, calls=self.calls)):
            st, js, _, _ = self.decide(decision="reject")
        self.assertEqual((st, js["review"]), (200, "not_requested"))
        self.assertFalse([c for c in self.calls if c[0] == "POST"])
        self.assertEqual([r["event"] for r in ext.chain_tail("approvals.jsonl")], ["decision"])

    def test_stale_head_and_closed_and_bad_input(self):
        prs = [{"repo": "johnshorttn/nullink", "number": 34, "sha": SHA2}, {"repo": "johnshorttn/x", "number": 1, "state": "closed"}]
        with mock.patch.object(ap, "gh", fake_gh(prs)):
            st, js, _, _ = self.decide()
            self.assertEqual((st, js["error"], js["head_sha"]), (409, "stale_head", SHA2))
            self.assertEqual(self.decide(repo="johnshorttn/x", number=1)[1]["error"], "pr_not_open")
            for bad in ({"decision": "merge"}, {"repo": "../../etc"}, {"head_sha": "zz"}, {"number": -1}, {"source": "nullaxis"}):
                self.assertEqual(self.decide(**bad)[0], 400, bad)
        self.assertEqual(ext.chain_tail("approvals.jsonl"), [])

    def test_decide_needs_approve_purpose_and_valid_signature(self):
        st, *_ = self.signed_call(self.dev, "/api/vault/approvals/decide", "write",
                                  extra={"approval": {"source": "github"}})
        self.assertEqual(st, 400)

    def test_log_tamper_detected(self):
        prs = [{"repo": "johnshorttn/nullink", "number": 34}]
        with mock.patch.object(ap, "gh", fake_gh(prs)):
            self.decide(decision="reject"); self.decide(decision="reject")
        p = nullvault.nv_dir() / "approvals.jsonl"
        lines = p.read_text().splitlines()
        lines[0] = lines[0].replace('"reject"', '"approve"')
        p.write_text("\n".join(lines) + "\n")
        self.assertFalse(ext.chain_verify("approvals.jsonl")[0])


# ------------------------------------------------------------------ quick actions

class ActionsTests(S3Base):
    flags = {"NULLVAULT_ACTIONS": "1"}

    def run_action(self, name, args=None):
        a = {"name": name}
        if args is not None:
            a["args"] = args
        return self.signed_call(self.dev, "/api/vault/actions/run", "action", extra={"action": a})

    def test_default_is_off_and_empty(self):
        os.environ.pop("NULLVAULT_ACTIONS", None)
        self.assertEqual(self.req("/api/vault/actions", headers=self.bearer(self.dev))[0], 404)
        os.environ["NULLVAULT_ACTIONS"] = "1"
        st, _, js, _ = self.req("/api/vault/actions", headers=self.bearer(self.dev))
        self.assertEqual((st, js["actions"]), (200, []))
        with mock.patch.object(act, "run_argv", side_effect=AssertionError("must not run")):
            st, js, _, _ = self.run_action("nullink-health")
        self.assertEqual((st, js["error"]), (403, "action_not_allowed"))

    def test_shipped_drop_in_has_no_allowlist(self):
        self.assertEqual(act.allowlist(), [])

    def test_catalog_is_fixed_argv_no_shell(self):
        for name, spec in act.CATALOG.items():
            self.assertTrue(spec["argv"][0].startswith("/"), name)
            for part in spec["argv"]:
                self.assertNotIn(part, ("sh", "bash", "-c", "/bin/sh", "/bin/bash"))
                if part.startswith("{"):
                    self.assertIn(part.strip("{}"), spec["args"])

    def test_allowlisted_run_and_audit(self):
        os.environ["NULLVAULT_ACTIONS_ALLOW"] = "nullink-health,nulldo-journal,bogus"
        self.addCleanup(os.environ.pop, "NULLVAULT_ACTIONS_ALLOW", None)
        st, _, js, _ = self.req("/api/vault/actions", headers=self.bearer(self.dev))
        self.assertEqual([a["name"] for a in js["actions"]], ["nullink-health", "nulldo-journal"])
        with mock.patch.object(act, "run_argv", return_value=(0, "200 ok")) as run:
            st, js, _, _ = self.run_action("nulldo-journal", {"lines": 20})
        self.assertEqual(st, 200, js)
        argv, timeout = run.call_args[0]
        self.assertEqual(argv, ["/usr/bin/sudo", "-n", "/usr/local/sbin/nulldo", "journal", "20"])
        log = ext.chain_tail("actions.jsonl")
        self.assertEqual([r["event"] for r in log], ["run", "result"])
        self.assertNotIn("output", log[1]); self.assertIn("output_sha256", log[1])
        self.assertEqual(ext.chain_verify("actions.jsonl"), (True, 2))

    def test_args_validated(self):
        os.environ["NULLVAULT_ACTIONS_ALLOW"] = "nulldo-journal,nullink-health"
        self.addCleanup(os.environ.pop, "NULLVAULT_ACTIONS_ALLOW", None)
        with mock.patch.object(act, "run_argv", side_effect=AssertionError("must not run")):
            for bad in ({"lines": 0}, {"lines": 201}, {"lines": "20"}, {"lines": "20; rm -rf /"}, {"lines": True},
                        {"lines": 5, "extra": 1}):
                self.assertEqual(self.run_action("nulldo-journal", bad)[0], 400, bad)
            self.assertEqual(self.run_action("nullink-health", {"x": 1})[0], 400)

    def test_rate_limit_and_privilege_reporting(self):
        os.environ["NULLVAULT_ACTIONS_ALLOW"] = "nulldo-restart"
        self.addCleanup(os.environ.pop, "NULLVAULT_ACTIONS_ALLOW", None)
        nnp = (1, 'sudo: The "no new privileges" flag is set, which prevents sudo from running as root.')
        with mock.patch.object(act, "run_argv", return_value=nnp):
            st, js, _, _ = self.run_action("nulldo-restart")
            self.assertEqual((st, js["result"], js["ok"]), (200, "needs_privilege", False))
            st, js, _, _ = self.run_action("nulldo-restart")
            self.assertEqual(st, 429)
        self.assertEqual([r["event"] for r in ext.chain_tail("actions.jsonl")], ["run", "result", "refused"])

    def test_needs_action_purpose(self):
        os.environ["NULLVAULT_ACTIONS_ALLOW"] = "nullink-health"
        self.addCleanup(os.environ.pop, "NULLVAULT_ACTIONS_ALLOW", None)
        st, *_ = self.signed_call(self.dev, "/api/vault/actions/run", "write", extra={"action": {"name": "nullink-health"}})
        self.assertEqual(st, 400)

    def test_run_argv_never_uses_shell(self):
        with mock.patch.object(act.subprocess, "run") as r:
            r.return_value = mock.Mock(returncode=0, stdout="x", stderr="")
            act.run_argv(["/usr/bin/true"], 5)
        self.assertIs(r.call_args.kwargs["shell"], False)
        self.assertEqual(r.call_args.kwargs["env"]["PATH"], "/usr/sbin:/usr/bin:/sbin:/bin")


class ChainTests(S3Base):
    def test_append_only_open_flags(self):
        real = os.open
        seen = []
        with mock.patch.object(ext.os, "open", side_effect=lambda p, f, *a: (seen.append(f), real(p, f, *a))[1]):
            ext.chained_append("t.jsonl", {"event": "x"})
        self.assertTrue(seen[-1] & os.O_APPEND)
        self.assertFalse(seen[-1] & os.O_TRUNC)
