"""Chat avatars (av1): owner-only map + images, step-up writes, initials/colour fallback
shared between avatars.py and static/avatars.js."""
import base64
import json
import os
import shutil
import subprocess
import unittest

import avatars
import server
from tests.test_server_drive import SDBase
from tests import test_guest as _tg

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
B64 = base64.b64encode(PNG).decode()
JS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "avatars.js")


class AvBase(SDBase):
    def setUp(self):
        super().setUp()
        for p in (avatars._file(),):
            try:
                p.unlink()
            except FileNotFoundError:
                pass
        shutil.rmtree(avatars._dir(), ignore_errors=True)

    def set(self, **body):
        return self.j("/api/avatars/set", body)


class AvatarHelpersTests(unittest.TestCase):
    def test_key_for(self):
        self.assertEqual(avatars.key_for("Chief of Staff (Morc)"), "morc")
        self.assertEqual(avatars.key_for("[Jinx]"), "jinx")
        self.assertEqual(avatars.key_for(" Claude Code "), "claude-code")
        self.assertEqual(avatars.key_for("../etc/passwd"), "etc-passwd")
        self.assertEqual(avatars.key_for(""), "")

    def test_initials(self):
        self.assertEqual(avatars.initials("John"), "Jo")
        self.assertEqual(avatars.initials("Forge (Bob)"), "Bo")
        self.assertEqual(avatars.initials("Claude Code"), "CC")
        self.assertEqual(avatars.initials("X"), "X")
        self.assertEqual(avatars.initials("  "), "?")

    def test_hue_deterministic(self):
        self.assertEqual(avatars.hue_for("Morc"), avatars.hue_for("Chief of Staff (Morc)"))
        self.assertTrue(0 <= avatars.hue_for("Jinx") < 360)
        hues = {avatars.hue_for(n) for n in ("John", "Morc", "Jinx", "Claude", "Replit")}
        self.assertGreater(len(hues), 3)

    @unittest.skipUnless(shutil.which("node"), "node not installed")
    def test_js_matches_python(self):
        names = ["John", "Morc", "Chief of Staff (Morc)", "[Jinx]", "Claude", "Replit", "Claude Code", "deepseek", "X", ""]
        script = (f"const a=require({json.dumps(JS)});const n={json.dumps(names)};"
                  "console.log(JSON.stringify(n.map(x=>[a.keyFor(x),a.initials(x),a.hueFor(x)])))")
        out = json.loads(subprocess.check_output(["node", "-e", script], timeout=20))
        self.assertEqual(out, [[avatars.key_for(x), avatars.initials(x), avatars.hue_for(x)] for x in names])

    @unittest.skipUnless(shutil.which("node"), "node not installed")
    def test_js_sender_for(self):
        cases = [({"role": "agent", "text": "[Jinx] hi"}, "Council", "Jinx"),
                 ({"role": "user", "text": "yo"}, "Council", "John"),
                 ({"role": "assistant", "text": "ok"}, "Chief of Staff (Morc)", "Morc"),
                 ({"role": "assistant", "text": "ok", "from": "Claude"}, "AI room", "Claude"),
                 ({"role": "assistant", "text": "[not a tag] x"}, "Replit", "Replit")]
        script = (f"const a=require({json.dumps(JS)});const c={json.dumps(cases)};"
                  "console.log(JSON.stringify(c.map(([m,t])=>a.senderFor(m,t))))")
        out = json.loads(subprocess.check_output(["node", "-e", script], timeout=20))
        self.assertEqual(out, [c[2] for c in cases])


class AvatarApiTests(AvBase):
    def test_empty_map(self):
        st, _, js, _ = self.j("/api/avatars")
        self.assertEqual((st, js), (200, {"avatars": {}}))

    def test_set_upload_serve_and_persist(self):
        st, _, js, _ = self.set(name="Jinx", image_b64="data:image/png;base64," + B64, color="#336699")
        self.assertEqual(st, 200, js)
        av = js["avatar"]
        self.assertEqual((av["key"], av["initials"], av["color"]), ("jinx", "Ji", "#336699"))
        self.assertTrue(av["url"].startswith("/api/avatars/img/jinx?v="))
        st, hdrs, _, data = self.j(av["url"].split("?")[0])
        self.assertEqual((st, data), (200, PNG))
        h = {k.lower(): v for k, v in hdrs}
        self.assertEqual(h["content-type"], "image/png")
        self.assertEqual(h["x-content-type-options"], "nosniff")
        self.assertEqual(oct(os.stat(avatars._file()).st_mode & 0o777), "0o600")
        self.assertEqual(json.loads(avatars._file().read_text())["avatars"]["jinx"]["image"], "jinx.png")
        self.assertIn("jinx", self.j("/api/avatars")[2]["avatars"])

    def test_name_only_and_remove_image(self):
        self.assertEqual(self.set(name="Chief of Staff (Morc)", key="Morc")[0], 200)
        m = self.j("/api/avatars")[2]["avatars"]["morc"]
        self.assertEqual((m["url"], m["color"]), (None, None))
        self.set(key="morc", name="Morc", image_b64=B64)
        self.assertIsNotNone(self.j("/api/avatars")[2]["avatars"]["morc"]["url"])
        self.set(key="morc", name="Morc", remove_image=True)
        self.assertIsNone(self.j("/api/avatars")[2]["avatars"]["morc"]["url"])
        self.assertEqual(list(avatars._dir().glob("morc.*")), [])

    def test_replace_image_changes_ext(self):
        self.set(name="Claude", image_b64=B64)
        gif = base64.b64encode(b"GIF89a" + b"\x00" * 16).decode()
        self.set(name="Claude", image_b64=gif)
        self.assertEqual(sorted(p.name for p in avatars._dir().iterdir()), ["claude.gif"])

    def test_rejects_bad_input(self):
        self.assertEqual(self.set(name="")[2]["error"], "name_required")
        self.assertEqual(self.set(name="A", color="red")[2]["error"], "bad_color")
        self.assertEqual(self.set(name="A", image_b64="!!notb64")[2]["error"], "bad_image")
        svg = base64.b64encode(b"<svg onload=alert(1)>").decode()
        self.assertEqual(self.set(name="A", image_b64=svg)[0], 415)
        big = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"0" * (avatars.MAX_BYTES + 1)).decode()
        self.assertEqual(self.set(name="A", image_b64=big)[0], 413)

    def test_remove_entry(self):
        self.set(name="Replit", image_b64=B64)
        self.assertEqual(self.j("/api/avatars/remove", {"key": "replit"})[0], 200)
        self.assertEqual(self.j("/api/avatars")[2]["avatars"], {})
        self.assertFalse((avatars._dir() / "replit.png").exists())
        self.assertEqual(self.j("/api/avatars/remove", {"key": "replit"})[0], 404)

    def test_img_404_and_traversal(self):
        self.assertEqual(self.j("/api/avatars/img/nobody")[0], 404)
        self.assertEqual(self.j("/api/avatars/img/..%2Fsecrets")[0], 404)
        self.assertEqual(self.j("/api/avatars/nope")[0], 404)

    def test_symlinked_image_not_served(self):
        avatars._dir().mkdir(parents=True, exist_ok=True)
        os.symlink(server.SECRETS / "otp.json", avatars._dir() / "evil.png")
        avatars.save({"evil": {"name": "Evil", "image": "evil.png"}})
        self.assertEqual(self.j("/api/avatars/img/evil")[0], 404)
        self.assertIsNone(self.j("/api/avatars")[2]["avatars"]["evil"]["url"])

    def test_image_field_must_match_key(self):
        avatars._dir().mkdir(parents=True, exist_ok=True)
        (avatars._dir() / "john.png").write_bytes(PNG)
        avatars.save({"jinx": {"name": "Jinx", "image": "john.png"}, "x": {"name": "X", "image": "../x.png"}})
        self.assertEqual(self.j("/api/avatars/img/jinx")[0], 404)
        self.assertEqual(self.j("/api/avatars/img/x")[0], 404)

    def test_writes_need_stepup(self):
        self.age_stepup()
        self.assertEqual(self.set(name="A")[2]["error"], "step_up_required")
        self.assertEqual(self.j("/api/avatars/remove", {"key": "a"})[2]["error"], "step_up_required")
        self.assertEqual(self.j("/api/avatars")[0], 200)

    def test_token_and_anon_refused(self):
        _, plain = server.create_api_token("agent", ["messages:read"], ["morc"])
        bearer = {"Authorization": f"Bearer {plain}"}
        for path, body in (("/api/avatars", None), ("/api/avatars/img/jinx", None),
                           ("/api/avatars/set", {"name": "A"})):
            m = "POST" if body is not None else "GET"
            self.assertEqual(self.req(path, m, body)[0], 401)
            self.assertEqual(self.req(path, m, body, headers=bearer)[0], 403)
            self.assertEqual(self.req(path, m, body, cookie=self.owner, headers=bearer)[0], 403)

    def test_static_wired(self):
        st, _, _, data = self.req("/avatars.js")
        self.assertEqual(st, 200)
        self.assertIn(b"NullinkAvatars", data)
        idx = (server.STATIC / "index.html").read_text()
        self.assertLess(idx.index("/avatars.js"), idx.index("/app.js"))
        app = (server.STATIC / "app.js").read_text()
        self.assertIn("NullinkAvatars.load()", app)
        self.assertIn("AV.senderFor(msg", app)


class AvatarGuestTests(AvBase):
    request, approve, redeem, guest = _tg.GuestTests.request, _tg.GuestTests.approve, _tg.GuestTests.redeem, _tg.GuestTests.guest

    def test_guest_refused(self):
        ck, _ = self.guest("full")
        self.assertEqual(self.req("/api/avatars", "GET", cookie=ck)[0], 403)
        self.assertEqual(self.req("/api/avatars/set", "POST", {"name": "A"}, cookie=ck)[0], 403)
