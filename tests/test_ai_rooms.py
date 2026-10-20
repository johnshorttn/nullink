import json, tempfile, unittest
from pathlib import Path
import sys; sys.path.insert(0, str(Path(__file__).resolve().parents[1])); import ai_rooms as R

class T(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        R.CONFIG = Path(self.d.name) / "c.json"; R.AUDIT = Path(self.d.name) / "a.jsonl"
        self.auth = {"token_id": "t1", "name": "bot", "sessions": ["chatgpt", "deepseek", "replit"]}
    def tearDown(self): self.d.cleanup()
    def audit(self): return [json.loads(l) for l in R.AUDIT.read_text().splitlines()]

    def test_parse(self):
        self.assertEqual(R.parse("/room forge"), ("/room", "forge"))
        self.assertIsNone(R.parse("/roomy x")); self.assertIsNone(R.parse("hello"))
        self.assertIsNone(R.parse("/room a\nmore"))
    def test_default_rooms_exclude_deepseek_and_channels(self):
        c, r = R.handle("/rooms", "", self.auth)
        self.assertEqual([x["id"] for x in r["rooms"]], ["chatgpt"])
    def test_switch_and_where_audited(self):
        R.save({"channels": ["replit"], "connections": {"t1": {"allow_rooms": ["chatgpt", "forge"]}}})
        c, r = R.handle("/room", "Forge", self.auth, {"forge": "Forge (Bob)"})
        self.assertEqual((c, r["current"]), (200, "forge"))
        self.assertEqual(R.handle("/where", "", self.auth)[1]["current"], "forge")
        self.assertEqual(self.audit()[-1]["event"], "switch")
        self.assertTrue(R.allowed("t1", ["chatgpt"], "forge"))
    def test_room_refused_outside_allowlist(self):
        c, r = R.handle("/room", "deepseek", self.auth)
        self.assertEqual(c, 403); self.assertFalse(R.allowed("t1", ["deepseek"], "deepseek"))
    def test_channel_non_admin_refused_logged(self):
        c, r = R.handle("/channel", "replit", self.auth)
        self.assertEqual((c, r["error"]), (403, "not_admin"))
        self.assertEqual(self.audit()[-1]["reason"], "not_admin")
        self.assertEqual(R.handle("/channels", "", self.auth)[0], 403)
    def test_channel_admin(self):
        R.save({"channels": ["replit", "deepseek"], "connections": {"t1": {"admin": True}}})
        self.assertEqual([x["id"] for x in R.handle("/channels", "", self.auth)[1]["channels"]], ["replit"])
        c, r = R.handle("/channel", "replit", self.auth)
        self.assertEqual((c, r["kind"]), (200, "channel"))
        self.assertEqual(R.handle("/where", "", self.auth)[1]["kind"], "channel")
        self.assertEqual(R.handle("/room", "replit", self.auth)[0], 403)

if __name__ == "__main__": unittest.main()
