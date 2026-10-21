"""Files manager Slice 1 (2026-10-20): files.json migration, traversal/symlink guards,
owner-only auth, step-up on delete/empty-trash, legacy /api/files/* aliases."""
import json
import os
import uuid

import files_manager
import server
from tests.test_auth import AuthBase, totp_code
from tests import test_guest as _tg


def _seed(entries):
    server.FILES_FILE.parent.mkdir(parents=True, exist_ok=True)
    server.FILES_FILE.write_text(json.dumps({"files": entries}), encoding="utf-8")
    for b in server.FILES_FILE.parent.glob("files.json.bak-fm*"):
        b.unlink()
    try:
        (server.DATA / "fm_folders.json").unlink()
    except FileNotFoundError:
        pass


def _put(rel, data=b"hello\n"):
    p = server.BASE / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


class FMBase(AuthBase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # BASE is not redirected by AuthBase; point it at the temp root for real-file tests.
        from unittest.mock import patch
        cls._bp = patch.object(server, "BASE", cls.root)
        cls._bp.start()

    @classmethod
    def tearDownClass(cls):
        cls._bp.stop()
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        self.enable_totp()
        st, _, self.owner = self.login(totp_code())
        self.assertEqual(st, 200)
        _put("data/files/a.txt", b"alpha\n")
        _put("data/files/pic.png", b"\x89PNG\r\n\x1a\nfake")
        _put("data/files/page.html", b"<script>alert(1)</script>")
        _seed([
            {"id": "aaa111", "name": "a.txt", "path": "data/files/a.txt", "labels": ["inbox"], "size": 6},
            {"id": "pic222", "name": "pic.png", "path": "data/files/pic.png", "labels": ["inbox"], "size": 12},
            {"id": "htm333", "name": "page.html", "path": "data/files/page.html", "labels": ["inbox"], "size": 25},
        ])

    def j(self, path, body=None, method="POST", cookie=None, **kw):
        return self.req(path, method, body, cookie=cookie or self.owner, **kw)


class MigrationTests(FMBase):
    def test_idempotent_backup_once_ids_kept(self):
        before = json.loads(server.FILES_FILE.read_text())["files"]
        r1 = files_manager.migrate()
        self.assertEqual(r1["changed"], 3)
        self.assertTrue(r1["backup"])
        backup = server.FILES_FILE.parent / r1["backup"]
        self.assertEqual(json.loads(backup.read_text())["files"], before)
        after1 = server.FILES_FILE.read_text()
        r2 = files_manager.migrate()
        self.assertEqual(r2, {"changed": 0, "backup": None})
        self.assertEqual(server.FILES_FILE.read_text(), after1)
        self.assertEqual(len(list(server.FILES_FILE.parent.glob("files.json.bak-fm*"))), 1)
        files = json.loads(after1)["files"]
        self.assertEqual([f["id"] for f in files], [f["id"] for f in before])
        self.assertEqual([f["path"] for f in files], [f["path"] for f in before])
        for f in files:
            self.assertEqual(f["folder"], "")
            self.assertIsNone(f["trashed_at"])
        self.assertTrue((server.BASE / "data/files/a.txt").exists())

    def test_bad_folder_values_normalized(self):
        _seed([{"id": "x1", "name": "a.txt", "path": "data/files/a.txt", "folder": "../../etc"},
               {"id": "x2", "name": "a.txt", "path": "data/files/a.txt", "folder": "/docs//"}])
        files_manager.migrate()
        files = {f["id"]: f for f in server.load_files()}
        self.assertEqual(files["x1"]["folder"], "")
        self.assertEqual(files["x2"]["folder"], "docs")
        self.assertEqual(files_manager.norm_folder("/docs/sub/"), "docs/sub")

    def test_moves_keep_ids_and_disk(self):
        self.assertEqual(self.j("/api/fm/folders", {"parent": "", "name": "Docs"})[0], 201)
        self.assertEqual(self.j("/api/fm/folders", {"parent": "Docs", "name": "Sub"})[0], 201)
        st, _, js, _ = self.j("/api/fm/move", {"ids": ["aaa111"], "dest": "Docs/Sub"})
        self.assertEqual(st, 200, js)
        st, _, js, _ = self.j("/api/fm/rename", {"folder": "Docs", "name": "Papers"})
        self.assertEqual(st, 200, js)
        st, _, tree, _ = self.req("/api/fm/tree", cookie=self.owner)
        self.assertIn("Papers/Sub", tree["folders"])
        a = next(f for f in tree["files"] if f["id"] == "aaa111")
        self.assertEqual(a["folder"], "Papers/Sub")
        self.assertEqual(a["path"], "data/files/a.txt")
        st, _, js, _ = self.j("/api/fm/move", {"folders": ["Papers"], "dest": "Papers/Sub"})
        self.assertEqual(st, 400)
        self.assertEqual(js["error"], "move_into_self")


class TraversalSymlinkTests(FMBase):
    def test_folder_traversal_rejected(self):
        for bad in ("..", "../x", "a/../b", "a\\b", "x\x00y"):
            st, _, js, _ = self.j("/api/fm/folders", {"parent": "", "name": bad})
            self.assertEqual(st, 400, (bad, js))
        st, _, _, _ = self.j("/api/fm/move", {"ids": ["aaa111"], "dest": "../../etc"})
        self.assertEqual(st, 400)
        st, _, _, _ = self.req("/api/fm/upload?folder=..%2F..", "POST", cookie=self.owner)
        self.assertEqual(st, 400)

    def test_entry_path_traversal_rejected(self):
        outside = self.root.parent / f"outside-{uuid.uuid4().hex}.txt"
        outside.write_text("secret")
        try:
            _seed([{"id": "evil01", "name": "x.txt", "path": f"../{outside.name}"},
                   {"id": "evil02", "name": "x.txt", "path": str(outside)}])
            for fid in ("evil01", "evil02"):
                st, _, _, data = self.req(f"/api/fm/files/{fid}/download", cookie=self.owner)
                self.assertEqual(st, 404)
                self.assertNotIn(b"secret", data)
                st, _, _, data = self.req(f"/api/files/{fid}/content", cookie=self.owner)
                self.assertEqual(st, 404)
        finally:
            outside.unlink()

    def test_symlink_not_followed(self):
        target = _put("data/secret.txt", b"topsecret")
        link = server.BASE / "data/files/link.txt"
        os.symlink(target, link)
        dlink = server.BASE / "data/linkdir"
        os.symlink(server.BASE / "data", dlink)
        try:
            _seed([{"id": "lnk001", "name": "link.txt", "path": "data/files/link.txt"},
                   {"id": "lnk002", "name": "s.txt", "path": "data/linkdir/secret.txt"}])
            for fid in ("lnk001", "lnk002"):
                for url in (f"/api/fm/files/{fid}/download", f"/api/files/{fid}/download",
                            f"/api/files/{fid}/content", f"/api/fm/files/{fid}/preview"):
                    st, _, _, data = self.req(url, cookie=self.owner)
                    self.assertEqual(st, 404, url)
                    self.assertNotIn(b"topsecret", data)
        finally:
            link.unlink()
            dlink.unlink()

    def test_html_svg_forced_download_png_inline(self):
        st, hdrs, _, data = self.req("/api/fm/files/htm333/download", cookie=self.owner)
        h = {k.lower(): v for k, v in hdrs}
        self.assertEqual(st, 200)
        self.assertEqual(h["content-type"], "application/octet-stream")
        self.assertTrue(h["content-disposition"].startswith("attachment"))
        self.assertEqual(h["x-content-type-options"], "nosniff")
        st, _, js, _ = self.req("/api/fm/files/htm333/preview", cookie=self.owner)
        self.assertEqual(st, 415)
        st, hdrs, _, data = self.req("/api/fm/files/pic222/preview", cookie=self.owner)
        h = {k.lower(): v for k, v in hdrs}
        self.assertEqual(st, 200)
        self.assertEqual(h["content-type"], "image/png")
        self.assertIn("sandbox", h["content-security-policy"])
        self.assertEqual(files_manager.preview_kind({"name": "x.svg"}), "none")


class AuthStepupTests(FMBase):
    def test_unauthenticated_and_agent_token_refused(self):
        rec, token = server.create_api_token("agent", list(server.AGENT_SCOPES), ["chatgpt"])
        bearer = {"Authorization": f"Bearer {token}"}
        for path, method in (("/api/fm/tree", "GET"), ("/api/fm/folders", "POST"),
                             ("/api/fm/files/aaa111/download", "GET"), ("/api/fm/trash", "POST"),
                             ("/api/files", "GET"), ("/api/files/aaa111/download", "GET"),
                             ("/api/files/aaa111", "DELETE")):
            st, _, _, _ = self.req(path, method, {} if method == "POST" else None)
            self.assertEqual(st, 401, path)
            st, _, _, _ = self.req(path, method, {} if method == "POST" else None, headers=bearer)
            self.assertEqual(st, 403, path)

    def test_trash_and_empty_trash_need_stepup(self):
        self.age_stepup()
        for path, body in (("/api/fm/trash", {"ids": ["aaa111"]}), ("/api/fm/empty-trash", {}),
                           ("/api/fm/purge", {"ids": ["aaa111"]})):
            st, _, js, _ = self.j(path, body)
            self.assertEqual(st, 403, path)
            self.assertEqual(js["error"], "step_up_required")
        st, _, js, _ = self.req("/api/files/aaa111", "DELETE", cookie=self.owner)
        self.assertEqual((st, js.get("error")), (403, "step_up_required"))
        self.assertIsNone(next(f for f in server.load_files() if f["id"] == "aaa111").get("trashed_at"))
        st, _, _, _ = self.req("/api/auth/stepup", "POST", {"code": totp_code(1)}, cookie=self.owner)
        self.assertEqual(st, 200)
        st, _, js, _ = self.j("/api/fm/trash", {"ids": ["aaa111"]})
        self.assertEqual((st, js.get("trashed")), (200, 1))
        st, _, lst, _ = self.req("/api/files", cookie=self.owner)
        self.assertNotIn("aaa111", [f["id"] for f in lst["files"]])
        st, _, tr, _ = self.req("/api/fm/trash", cookie=self.owner)
        self.assertEqual([f["id"] for f in tr["files"]], ["aaa111"])
        st, _, js, _ = self.j("/api/fm/restore", {"ids": ["aaa111"]})
        self.assertEqual(js["restored"], 1)
        self.j("/api/fm/trash", {"ids": ["aaa111"]})
        st, _, js, _ = self.j("/api/fm/empty-trash", {})
        self.assertEqual((st, js["purged"], js["files_removed"]), (200, 1, 1))
        self.assertFalse((server.BASE / "data/files/a.txt").exists())
        self.assertTrue((server.BASE / "data/files/pic.png").exists())


class AliasTests(FMBase):
    def test_legacy_routes_still_work(self):
        st, _, lst, _ = self.req("/api/files", cookie=self.owner)
        self.assertEqual(st, 200)
        self.assertEqual({f["id"] for f in lst["files"]}, {"aaa111", "pic222", "htm333"})
        st, _, js, _ = self.req("/api/files/aaa111", cookie=self.owner)
        self.assertEqual(js["file"]["id"], "aaa111")
        st, _, js, _ = self.req("/api/files/aaa111/content", cookie=self.owner)
        self.assertEqual(js["content"], "alpha\n")
        st, _, _, data = self.req("/api/files/aaa111/download", cookie=self.owner)
        self.assertEqual((st, data), (200, b"alpha\n"))
        st, _, js, _ = self.req("/api/fm/files/aaa111/content", cookie=self.owner)
        self.assertEqual(js["content"], "alpha\n")
        st, _, js, _ = self.req("/api/fm/files/aaa111", cookie=self.owner)
        self.assertEqual(js["file"]["id"], "aaa111")
        # legacy DELETE = move to Trash (fresh login counts as step-up), file kept on disk
        st, _, js, _ = self.req("/api/files/aaa111", "DELETE", cookie=self.owner)
        self.assertEqual((st, js.get("trashed")), (200, True))
        self.assertTrue((server.BASE / "data/files/a.txt").exists())
        st, _, js, _ = self.req("/api/files/aaa111", cookie=self.owner)
        self.assertEqual(js["file"]["trashed_at"] is not None, True)

    def test_upload_into_folder(self):
        self.j("/api/fm/folders", {"parent": "", "name": "Inbox2"})
        b = "----fmtest"
        body = (f"--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"n.txt\"\r\n"
                f"Content-Type: text/plain\r\n\r\nnew\r\n--{b}--\r\n").encode()
        st, _, js, _ = self._raw("/api/fm/upload?folder=Inbox2", body, b)
        self.assertEqual(st, 200, js)
        self.assertEqual(js["file"]["folder"], "Inbox2")

    def _raw(self, path, body, boundary):
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", self.httpd.server_port, timeout=10)
        conn.request("POST", path, body=body, headers={
            "Host": "nullink.216.158.238.236.sslip.io", "X-Forwarded-Proto": "https",
            "X-Forwarded-For": "198.51.100.10", "Cookie": self.owner,
            "Content-Type": f"multipart/form-data; boundary={boundary}"})
        r = conn.getresponse()
        data = r.read()
        conn.close()
        return r.status, None, json.loads(data or b"{}"), data


class GuestFMTests(AuthBase):
    def setUp(self):
        super().setUp()
        for f in (server.GUEST_FILE, server.GUEST_AUDIT_FILE):
            try:
                f.unlink()
            except FileNotFoundError:
                pass
        self.enable_totp()
        st, _, self.owner = self.login(totp_code())
        self.assertEqual(st, 200)

    request, approve, redeem, guest = _tg.GuestTests.request, _tg.GuestTests.approve, _tg.GuestTests.redeem, _tg.GuestTests.guest

    def test_guest_refused_fm(self):
        ck, _ = self.guest("full")
        for path, method in (("/api/fm/tree", "GET"), ("/api/fm/trash", "POST"), ("/api/files", "GET")):
            st, _, js, _ = self.req(path, method, {} if method == "POST" else None, cookie=ck)
            self.assertEqual(st, 403, path)
