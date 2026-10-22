"""Bots profile page (bots1): senders list, aliases/merge, Slack starter seeds, owner-only."""
import json
import os

import avatars
import server
from tests.test_avatars import AvBase, B64, PNG


class BotsTests(AvBase):
    def setUp(self):
        super().setUp()
        avatars._senders_cache.update(key=None, val=None)
        self._msgs = server.MESSAGES_FILE.read_text() if server.MESSAGES_FILE.exists() else ""

    def tearDown(self):
        server.MESSAGES_FILE.write_text(self._msgs)
        super().tearDown()

    def write_msgs(self, msgs):
        server.MESSAGES_FILE.write_text("".join(json.dumps(m) + "\n" for m in msgs))

    def test_sender_of_matches_js_rules(self):
        self.assertEqual(avatars.sender_of({"role": "agent", "text": "[Jinx] hi"}, "Council"), "Jinx")
        self.assertEqual(avatars.sender_of({"role": "user", "text": "yo"}, "Council"), "John")
        self.assertEqual(avatars.sender_of({"role": "assistant", "text": "ok"}, "Chief of Staff (Morc)"), "Morc")
        self.assertEqual(avatars.sender_of({"role": "assistant", "text": "x", "from": "Claude"}, "R"), "Claude")

    def test_senders_lists_chat_history(self):
        self.write_msgs([{"role": "user", "text": "hi", "session_id": "council"},
                         {"role": "agent", "text": "[Claude] a", "session_id": "council", "ts": "2026-10-22T10:00:00"},
                         {"role": "agent", "text": "[Claude-Code] b", "session_id": "council"},
                         {"role": "agent", "text": "[Replit] c", "session_id": "council"},
                         {"role": "assistant", "text": "d", "session_id": "morc"}])
        st, _, js, _ = self.j("/api/avatars/senders")
        self.assertEqual(st, 200)
        keys = {p["key"]: p for p in js["profiles"]}
        for k in ("john", "claude", "claude-code", "replit", "morc"):
            self.assertIn(k, keys)
        self.assertEqual(keys["claude"]["count"], 1)
        self.assertEqual(js["profiles"][-1]["key"], "john")

    def test_merge_aliases_and_unmerge(self):
        self.write_msgs([{"role": "agent", "text": "[Claude] a", "session_id": "council"},
                         {"role": "agent", "text": "[Claude-Code] b", "session_id": "council"}])
        self.set(name="Claude Code", key="claude-code", image_b64=B64, color="#112233")
        st, _, js, _ = self.j("/api/avatars/merge", {"into": "claude", "from": "claude-code", "name": "Claude"})
        self.assertEqual(st, 200, js)
        av = json.loads(avatars._file().read_text())["avatars"]
        self.assertEqual(list(av), ["claude"])
        self.assertEqual(av["claude"]["aliases"], ["claude-code"])
        self.assertEqual(av["claude"]["image"], "claude.png")  # picture moved over
        m = self.j("/api/avatars")[2]["avatars"]
        self.assertEqual(m["claude-code"]["alias_of"], "claude")
        self.assertEqual(m["claude-code"]["url"], m["claude"]["url"])
        self.assertEqual(self.j("/api/avatars/img/claude-code")[3], PNG)
        prof = {p["key"]: p for p in self.j("/api/avatars/senders")[2]["profiles"]}
        self.assertNotIn("claude-code", prof)
        self.assertEqual(prof["claude"]["count"], 2)
        # setting via the alias edits the canonical profile
        self.set(key="claude-code", name="Claude!")
        self.assertEqual(json.loads(avatars._file().read_text())["avatars"]["claude"]["name"], "Claude!")
        self.assertEqual(self.j("/api/avatars/merge", {"into": "claude", "from": "claude-code"})[2]["error"], "same_profile")
        self.assertEqual(self.j("/api/avatars/unmerge", {"alias": "claude-code"})[0], 200)
        self.assertNotIn("claude-code", self.j("/api/avatars")[2]["avatars"])
        self.assertEqual(self.j("/api/avatars/unmerge", {"alias": "claude-code"})[0], 404)

    def test_writes_need_stepup(self):
        self.age_stepup()
        self.assertEqual(self.j("/api/avatars/merge", {"into": "a", "from": "b"})[2]["error"], "step_up_required")
        self.assertEqual(self.j("/api/avatars/unmerge", {"alias": "b"})[2]["error"], "step_up_required")
        self.assertEqual(self.j("/api/avatars/senders")[0], 200)

    def test_token_and_anon_refused(self):
        _, plain = server.create_api_token("agent", ["messages:read"], ["morc"])
        bearer = {"Authorization": f"Bearer {plain}"}
        for path, m, body in (("/api/avatars/senders", "GET", None), ("/api/avatars/merge", "POST", {"into": "a", "from": "b"})):
            self.assertEqual(self.req(path, m, body)[0], 401)
            self.assertEqual(self.req(path, m, body, cookie=self.owner, headers=bearer)[0], 403)

    def test_seed_defaults_once_and_never_overwrite(self):
        self.set(name="Jinx (mine)", key="jinx")
        done = avatars.seed_defaults()
        self.assertEqual(done, ["morc"])
        av = json.loads(avatars._file().read_text())
        self.assertEqual(av["avatars"]["jinx"]["name"], "Jinx (mine)")
        self.assertEqual(av["avatars"]["morc"]["image"], "morc.png")
        self.assertEqual(av["seeded"], ["morc"])
        self.assertEqual(self.j("/api/avatars/img/morc")[0], 200)
        self.j("/api/avatars/remove", {"key": "morc"})
        self.assertEqual(avatars.seed_defaults(), [])  # removed seed stays removed
        self.assertNotIn("morc", self.j("/api/avatars")[2]["avatars"])

    def test_seed_files_shipped_and_small(self):
        for key, (_, fn) in avatars.SEEDS.items():
            p = server.STATIC / "seed-avatars" / fn
            raw = p.read_bytes()
            self.assertLessEqual(len(raw), avatars.MAX_BYTES)
            self.assertIn(avatars._sniff(raw), ("png", "jpg"))

    def test_static_and_nav_wired(self):
        st, _, _, data = self.req("/bots.js")
        self.assertEqual(st, 200)
        self.assertIn(b"NullinkBots", data)
        idx = (server.STATIC / "index.html").read_text()
        self.assertEqual(idx.count('data-tool="bots"'), 2)
        self.assertEqual(idx.count("data-bots-open"), 2)
        self.assertIn('tool === "bots"', (server.STATIC / "app.js").read_text())
