"""Server drive (2026-10-21): owner-only, TOTP unlock (15 min, server-side), step-up writes,
typed-confirm permanent delete, audit of every action, secrets/env/token masking, no symlinks."""
import http.client
import json
import os
import time
from pathlib import Path

import server
import server_drive
from tests.test_auth import AuthBase, totp_code
from tests import test_guest as _tg


class SDBase(AuthBase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from unittest.mock import patch
        cls.drive = cls.root / "hostroot"
        cls.drive.mkdir(exist_ok=True)
        cls._bp = patch.object(server, "BASE", cls.drive / "opt" / "nullink")
        cls._bp.start()
        cls._sp = patch.object(server, "SECRETS", cls.drive / "opt" / "nullink" / "secrets")
        cls._sp.start()
        os.environ["NULLINK_SD_ROOT"] = str(cls.drive)

    @classmethod
    def tearDownClass(cls):
        os.environ.pop("NULLINK_SD_ROOT", None)
        cls._sp.stop()
        cls._bp.stop()
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        import shutil
        for p in self.drive.iterdir():
            shutil.rmtree(p) if p.is_dir() and not p.is_symlink() else p.unlink()
        d = self.drive
        (d / "etc").mkdir()
        (d / "etc" / "hosts").write_text("127.0.0.1 localhost\n")
        (d / "etc" / "pic.png").write_bytes(b"\x89PNG\r\n\x1a\nfake")
        (d / "etc" / "page.html").write_text("<script>alert(1)</script>")
        (d / "etc" / "blob.bin").write_bytes(b"\x00\x01\x02")
        (d / "opt" / "nullink" / "secrets").mkdir(parents=True)
        (d / "opt" / "nullink" / "secrets" / "otp.json").write_text("{}")
        (d / "opt" / "nullink" / ".env").write_text("X=1")
        (d / "opt" / "nullink" / "github_token.txt").write_text("ghp_x")
        (d / "opt" / "nullink" / "README").write_text("hi")
        (d / "outside").mkdir()
        (d / "outside" / "x.txt").write_text("outside")
        os.symlink(d / "opt" / "nullink" / "secrets", d / "tmp-link")
        os.symlink("/etc/passwd", d / "etc" / "passwd-link")
        try:
            server_drive.audit_file().unlink()
        except FileNotFoundError:
            pass
        self.enable_totp()
        st, _, self.owner = self.login(totp_code())
        self.assertEqual(st, 200)

    def j(self, path, body=None, method=None, cookie=None, **kw):
        method = method or ("POST" if body is not None else "GET")
        return self.req(path, method, body, cookie=cookie or self.owner, **kw)

    def unlock(self, offset=1):
        st, _, js, _ = self.j("/api/sd/unlock", {"code": totp_code(offset)})
        self.assertEqual(st, 200, js)

    def audit_events(self):
        try:
            return [json.loads(l) for l in server_drive.audit_file().read_text().splitlines()]
        except FileNotFoundError:
            return []

    def raw(self, method, path, data=b"", headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.httpd.server_port, timeout=10)
        h = {"Host": "nullink.216.158.238.236.sslip.io", "X-Forwarded-Proto": "https",
             "X-Forwarded-For": "198.51.100.10", "Cookie": self.owner}
        h.update(headers or {})
        conn.request(method, path, body=data, headers=h)
        r = conn.getresponse()
        body = r.read()
        hd = dict((k.lower(), v) for k, v in r.getheaders())
        conn.close()
        return r.status, hd, body


class AccessTests(SDBase):
    def test_unauthenticated_401(self):
        st, *_ = self.req("/api/sd/status")
        self.assertEqual(st, 401)

    def test_bearer_and_any_authorization_403(self):
        _, plain = server.create_api_token("agent", ["messages:read"], ["morc"])
        for hdr in ({"Authorization": f"Bearer {plain}"}, {"Authorization": "Basic eDp5"}):
            st, *_ = self.req("/api/sd/status", headers=hdr)
            self.assertEqual(st, 403)
            st, *_ = self.req("/api/sd/list?path=/", cookie=self.owner, headers=hdr)
            self.assertEqual(st, 403)
        self.assertTrue(any(e["reason"] == "authorization_header" for e in self.audit_events()))

    def test_locked_until_totp_unlock(self):
        st, _, js, _ = self.j("/api/sd/status")
        self.assertEqual((st, js["unlocked"]), (200, False))
        st, _, js, _ = self.j("/api/sd/list?path=/")
        self.assertEqual((st, js["error"]), (403, "drive_locked"))
        st, _, js, _ = self.j("/api/sd/unlock", {"code": "000000"})
        self.assertEqual(st, 401)
        self.unlock()
        st, _, js, _ = self.j("/api/sd/list?path=/")
        self.assertEqual(st, 200)

    def test_recovery_code_or_pin_cannot_unlock(self):
        st, *_ = self.j("/api/sd/unlock", {"code": "ABCDE-23456"})
        self.assertEqual(st, 401)

    def test_unlock_expires_after_15_minutes(self):
        self.unlock()
        sessions = server.load_sessions()
        for rec in sessions.values():
            rec["sd_unlock_at"] = time.time() - server_drive.UNLOCK_WINDOW_SEC - 1
        server.save_sessions(sessions)
        st, _, js, _ = self.j("/api/sd/list?path=/")
        self.assertEqual((st, js["error"]), (403, "drive_locked"))

    def test_lock_endpoint(self):
        self.unlock()
        self.j("/api/sd/lock", {})
        st, *_ = self.j("/api/sd/list?path=/")
        self.assertEqual(st, 403)


class ReadTests(SDBase):
    def setUp(self):
        super().setUp()
        self.unlock()

    def test_list_masks_secrets_env_tokens_and_audits(self):
        st, _, js, _ = self.j("/api/sd/list?path=/opt/nullink")
        self.assertEqual(st, 200)
        by = {i["name"]: i for i in js["items"]}
        for n in ("secrets", ".env", "github_token.txt"):
            self.assertTrue(by[n]["masked"], n)
            self.assertNotIn("size", by[n])
        self.assertFalse(by["README"]["masked"])
        ev = self.audit_events()
        self.assertTrue(any(e["event"] == "list" and e["path"] == "/opt/nullink" for e in ev))

    def test_blocked_paths_refused_everywhere(self):
        for p in ("/opt/nullink/secrets", "/opt/nullink/secrets/otp.json", "/opt/nullink/.env",
                  "/opt/nullink/github_token.txt"):
            for ep in ("list", "preview", "download", "stat"):
                st, _, js, _ = self.j(f"/api/sd/{ep}?path={p}")
                self.assertEqual(st, 403, (ep, p))

    def test_symlink_to_secrets_refused(self):
        st, _, js, _ = self.j("/api/sd/list?path=/tmp-link")
        self.assertEqual(st, 403)
        st, *_ = self.j("/api/sd/preview?path=/tmp-link/otp.json")
        self.assertEqual(st, 403)
        st, *_ = self.j("/api/sd/download?path=/etc/passwd-link")
        self.assertEqual(st, 403)
        st, _, js, _ = self.j("/api/sd/list?path=/etc")
        kinds = {i["name"]: i["kind"] for i in js["items"]}
        self.assertEqual(kinds["passwd-link"], "symlink")

    def test_traversal_refused(self):
        for p in ("/../..", "/etc/../../x", "/etc/%00x"):
            st, *_ = self.j(f"/api/sd/list?path={p}")
            self.assertIn(st, (400, 403), p)

    def test_preview_text_image_and_refusals(self):
        st, _, js, _ = self.j("/api/sd/preview?path=/etc/hosts")
        self.assertEqual((st, js["text"]), (200, "127.0.0.1 localhost\n"))
        st, hd, body = self.raw("GET", "/api/sd/preview?path=/etc/pic.png")
        self.assertEqual((st, hd["content-type"]), (200, "image/png"))
        self.assertEqual(hd["x-content-type-options"], "nosniff")
        st, hd, body = self.raw("GET", "/api/sd/preview?path=/etc/page.html")
        self.assertEqual(hd["content-type"], "application/json")  # text as JSON, never text/html
        st, *_ = self.j("/api/sd/preview?path=/etc/blob.bin")
        self.assertEqual(st, 415)

    def test_download_forced_attachment_and_audited(self):
        st, hd, body = self.raw("GET", "/api/sd/download?path=/etc/page.html")
        self.assertEqual(st, 200)
        self.assertEqual(hd["content-type"], "application/octet-stream")
        self.assertTrue(hd["content-disposition"].startswith("attachment"))
        self.assertEqual(hd["x-content-type-options"], "nosniff")
        self.assertEqual(body, b"<script>alert(1)</script>")
        self.assertTrue(any(e["event"] == "download" for e in self.audit_events()))
        self.assertNotIn("alert", server_drive.audit_file().read_text())

    def test_audit_file_mode_600(self):
        self.j("/api/sd/list?path=/")
        self.assertEqual(os.stat(server_drive.audit_file()).st_mode & 0o777, 0o600)


class WriteTests(SDBase):
    def setUp(self):
        super().setUp()
        self.unlock()

    def test_writes_need_stepup(self):
        self.age_stepup()
        for path, body in (("/api/sd/mkdir", {"path": "/etc", "name": "n"}),
                           ("/api/sd/rename", {"path": "/etc/hosts", "name": "h2"}),
                           ("/api/sd/delete", {"path": "/etc/hosts", "confirm": "hosts"})):
            st, _, js, _ = self.j(path, body)
            self.assertEqual((st, js["error"]), (403, "step_up_required"), path)
        st, _, _ = self.raw("POST", "/api/sd/upload?path=/etc&name=u.txt", b"x")
        self.assertEqual(st, 403)
        self.assertTrue((self.drive / "etc" / "hosts").exists())

    def test_mkdir_rename_upload_delete(self):
        st, *_ = self.j("/api/sd/mkdir", {"path": "/etc", "name": "newdir"})
        self.assertEqual(st, 200)
        self.assertTrue((self.drive / "etc" / "newdir").is_dir())
        st, _, js, _ = self.j("/api/sd/rename", {"path": "/etc/hosts", "name": "hosts2"})
        self.assertEqual((st, js["path"]), (200, "/etc/hosts2"))
        st, _, js, _ = self.j("/api/sd/rename", {"path": "/etc/hosts2", "dest_dir": "/outside"})
        self.assertEqual(js["path"], "/outside/hosts2")
        st, _, body = self.raw("POST", "/api/sd/upload?path=/etc/newdir&name=u.txt", b"data")
        self.assertEqual(st, 200)
        self.assertEqual((self.drive / "etc/newdir/u.txt").read_bytes(), b"data")
        st, _, body = self.raw("POST", "/api/sd/upload?path=/etc/newdir&name=u.txt", b"again")
        self.assertEqual(st, 409)  # no overwrite
        st, _, js, _ = self.j("/api/sd/delete", {"path": "/etc/newdir/u.txt", "confirm": "wrong"})
        self.assertEqual((st, js["error"]), (400, "confirm_mismatch"))
        st, *_ = self.j("/api/sd/delete", {"path": "/etc/newdir/u.txt", "confirm": "u.txt"})
        self.assertEqual(st, 200)
        self.assertFalse((self.drive / "etc/newdir/u.txt").exists())
        events = [e["event"] for e in self.audit_events()]
        for e in ("mkdir", "rename", "upload", "delete"):
            self.assertIn(e, events)

    def test_delete_nonempty_dir_refused_and_root_refused(self):
        st, _, js, _ = self.j("/api/sd/delete", {"path": "/etc", "confirm": "etc"})
        self.assertEqual(st, 409)
        st, *_ = self.j("/api/sd/delete", {"path": "/", "confirm": ""})
        self.assertEqual(st, 400)

    def test_cannot_write_into_or_create_blocked(self):
        for path, body in (("/api/sd/mkdir", {"path": "/opt/nullink/secrets", "name": "x"}),
                           ("/api/sd/mkdir", {"path": "/etc", "name": ".env"}),
                           ("/api/sd/rename", {"path": "/etc/hosts", "name": "api_token"}),
                           ("/api/sd/rename", {"path": "/etc/hosts", "dest_dir": "/opt/nullink/secrets"}),
                           ("/api/sd/rename", {"path": "/opt/nullink/.env", "name": "plain"}),
                           ("/api/sd/delete", {"path": "/opt/nullink/secrets/otp.json", "confirm": "otp.json"})):
            st, *_ = self.j(path, body)
            self.assertEqual(st, 403, (path, body))
        st, _, _ = self.raw("POST", "/api/sd/upload?path=/opt/nullink/secrets&name=a", b"x")
        self.assertEqual(st, 403)
        st, _, _ = self.raw("POST", "/api/sd/upload?path=/etc&name=x.pem", b"x")
        self.assertEqual(st, 403)
        self.assertTrue((self.drive / "opt/nullink/secrets/otp.json").exists())

    def test_delete_symlink_removes_link_not_target(self):
        st, *_ = self.j("/api/sd/delete", {"path": "/etc/passwd-link", "confirm": "passwd-link"})
        self.assertEqual(st, 200)
        self.assertFalse(os.path.lexists(self.drive / "etc/passwd-link"))


class GuestSDTests(AuthBase):
    request, approve, redeem, guest = (_tg.GuestTests.request, _tg.GuestTests.approve,
                                       _tg.GuestTests.redeem, _tg.GuestTests.guest)

    def setUp(self):
        super().setUp()
        for f in (server.GUEST_FILE, server.GUEST_AUDIT_FILE):
            try:
                f.unlink()
            except FileNotFoundError:
                pass
        self.enable_totp()
        st, _, self.owner = self.login(totp_code())

    def test_guest_refused(self):
        ck, _ = self.guest("full")
        for path, method in (("/api/sd/status", "GET"), ("/api/sd/list?path=/", "GET"),
                             ("/api/sd/unlock", "POST")):
            st, *_ = self.req(path, method, {"code": totp_code(1)} if method == "POST" else None, cookie=ck)
            self.assertEqual(st, 403, path)
