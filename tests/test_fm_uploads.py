"""Chunked/resumable uploads + streamed zip download (2026-10-21)."""
import http.client
import io
import json
import os
import time
import zipfile

import fm_uploads
import server
from tests.test_auth import HTTPS_HOST
from tests.test_files_manager import FMBase, _seed, _put
from tests import test_guest as _tg


class UploadBase(FMBase):
    def raw(self, path, data, cookie=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.httpd.server_port, timeout=10)
        h = {"Host": HTTPS_HOST, "X-Forwarded-For": "198.51.100.10", "X-Forwarded-Proto": "https",
             "Content-Type": "application/octet-stream"}
        if cookie is not False:
            h["Cookie"] = cookie or self.owner
        h.update(headers or {})
        conn.request("POST", path, body=data, headers=h)
        r = conn.getresponse()
        body = r.read()
        conn.close()
        try:
            js = json.loads(body)
        except ValueError:
            js = {}
        return r.status, js, body

    def start(self, name="big.bin", size=10, folder=""):
        st, _, js, _ = self.j("/api/fm/uploads", {"name": name, "size": size, "folder": folder})
        self.assertEqual(st, 200, js)
        return js["upload_id"]


class ChunkedUploadTests(UploadBase):
    def test_full_flow_resume_and_register(self):
        data = os.urandom(3000)
        uid = self.start(size=len(data), folder="docs/sub")
        st, js, _ = self.raw(f"/api/fm/uploads/{uid}/chunk?offset=0", data[:1000])
        self.assertEqual((st, js["received"]), (200, 1000))
        # wrong offset -> 409 with the server's received count (resume point)
        st, js, _ = self.raw(f"/api/fm/uploads/{uid}/chunk?offset=0", data[:1000])
        self.assertEqual((st, js["received"]), (409, 1000))
        st, _, js, _ = self.j(f"/api/fm/uploads/{uid}", method="GET")
        self.assertEqual(js["received"], 1000)
        st, _, js, _ = self.j(f"/api/fm/uploads/{uid}/complete", {})
        self.assertEqual(st, 409)
        st, js, _ = self.raw(f"/api/fm/uploads/{uid}/chunk?offset=1000", data[1000:])
        self.assertEqual(js["received"], 3000)
        st, _, js, _ = self.j(f"/api/fm/uploads/{uid}/complete", {})
        self.assertEqual(st, 200, js)
        f = js["file"]
        self.assertEqual((f["folder"], f["size"], f["name"]), ("docs/sub", 3000, "big.bin"))
        self.assertEqual((server.BASE / f["path"]).read_bytes(), data)
        self.assertIn(f["id"], [e["id"] for e in server.load_files()])
        self.assertIn("docs/sub", json.loads((server.DATA / "fm_folders.json").read_text())["folders"]
                      if isinstance(json.loads((server.DATA / "fm_folders.json").read_text()), dict)
                      else json.loads((server.DATA / "fm_folders.json").read_text()))
        self.assertFalse(any(fm_uploads.parts_dir().iterdir()))

    def test_overflow_and_size_cap_and_bad_name(self):
        uid = self.start(size=5)
        st, js, _ = self.raw(f"/api/fm/uploads/{uid}/chunk?offset=0", b"123456")
        self.assertEqual(st, 400)
        self.assertEqual(js["error"], "exceeds_size")
        st, _, js, _ = self.j("/api/fm/uploads", {"name": "x.bin", "size": 6 * 1024 ** 3})
        self.assertEqual(st, 413)
        st, _, js, _ = self.j("/api/fm/uploads", {"name": "../x", "size": 1, "folder": "../etc"})
        self.assertEqual(st, 400)
        st, js, _ = self.raw(f"/api/fm/uploads/{uid}/chunk?offset=0", b"x",
                             headers={"Content-Length": str(fm_uploads.MAX_CHUNK + 1)})
        self.assertEqual(st, 413)

    def test_abort_and_stale_cleanup(self):
        uid = self.start(size=4)
        self.raw(f"/api/fm/uploads/{uid}/chunk?offset=0", b"ab")
        st, _, js, _ = self.j(f"/api/fm/uploads/{uid}/abort", {})
        self.assertEqual(st, 200)
        st, _, _, _ = self.j(f"/api/fm/uploads/{uid}", method="GET")
        self.assertEqual(st, 404)
        uid2 = self.start(size=4)
        old = time.time() - fm_uploads.STALE_SECS - 10
        for p in fm_uploads.parts_dir().glob(f"{uid2}.*"):
            os.utime(p, (old, old))
        self.assertEqual(fm_uploads.cleanup_stale(), 1)
        self.assertFalse(list(fm_uploads.parts_dir().glob(f"{uid2}.*")))

    def test_unauth_bearer_refused(self):
        uid = self.start(size=1)
        st, _, _ = self.raw(f"/api/fm/uploads/{uid}/chunk?offset=0", b"a", cookie=False)
        self.assertIn(st, (401, 403))
        st, _, _ = self.raw(f"/api/fm/uploads/{uid}/chunk?offset=0", b"a",
                            headers={"Authorization": "Bearer nlk_fake"})
        self.assertEqual(st, 403)
        st, _, _, _ = self.req("/api/fm/zip?ids=aaa111", headers={"Authorization": "Bearer nlk_x"})
        self.assertEqual(st, 403)
        st, _, _, _ = self.req("/api/fm/zip?ids=aaa111")
        self.assertIn(st, (401, 403))


class ZipTests(UploadBase):
    def setUp(self):
        super().setUp()
        _put("data/files/b.txt", b"bravo\n")
        _put("data/files/c.txt", b"charlie\n")
        _put("data/files/t.txt", b"trashed\n")
        _seed([
            {"id": "aaa111", "name": "a.txt", "path": "data/files/a.txt", "folder": ""},
            {"id": "bbb222", "name": "b.txt", "path": "data/files/b.txt", "folder": "proj"},
            {"id": "ccc333", "name": "c.txt", "path": "data/files/c.txt", "folder": "proj/deep"},
            {"id": "ttt444", "name": "t.txt", "path": "data/files/t.txt", "folder": "proj",
             "trashed_at": "2026-10-21T00:00:00Z"},
            {"id": "dup555", "name": "a.txt", "path": "data/files/b.txt", "folder": ""},
        ])

    def test_folder_subtree_and_multiselect(self):
        st, hdrs, _, data = self.req("/api/fm/zip?folders=proj&ids=aaa111,dup555", cookie=self.owner)
        self.assertEqual(st, 200)
        self.assertIn("application/zip", dict(hdrs)["Content-Type"])
        z = zipfile.ZipFile(io.BytesIO(data))
        names = set(z.namelist())
        self.assertTrue({"a.txt", "a (1).txt", "proj/b.txt", "proj/deep/c.txt"} <= names, names)
        self.assertNotIn("proj/t.txt", names)
        self.assertEqual(z.read("proj/deep/c.txt"), b"charlie\n")
        self.assertIsNone(z.testzip())

    def test_bad_and_empty(self):
        st, _, _, _ = self.req("/api/fm/zip", cookie=self.owner)
        self.assertEqual(st, 400)
        st, _, _, _ = self.req("/api/fm/zip?folders=../etc", cookie=self.owner)
        self.assertEqual(st, 400)

    def test_symlinked_entry_skipped(self):
        target = server.BASE / "data/files/b.txt"
        link = server.BASE / "data/files/link.txt"
        try:
            link.unlink()
        except FileNotFoundError:
            pass
        link.symlink_to(target)
        _seed([{"id": "lnk1", "name": "link.txt", "path": "data/files/link.txt", "folder": "s"},
               {"id": "aaa111", "name": "a.txt", "path": "data/files/a.txt", "folder": "s"}])
        st, _, _, data = self.req("/api/fm/zip?folders=s", cookie=self.owner)
        self.assertEqual(zipfile.ZipFile(io.BytesIO(data)).namelist(), ["s/", "s/a.txt"])


class GuestUploadTests(FMBase):
    request, approve, redeem, guest = (_tg.GuestTests.request, _tg.GuestTests.approve,
                                       _tg.GuestTests.redeem, _tg.GuestTests.guest)

    def test_guest_refused(self):
        ck, _ = self.guest("full")
        st, _, _, _ = self.req("/api/fm/uploads", "POST", {"name": "a", "size": 1}, cookie=ck)
        self.assertEqual(st, 403)
        st, _, _, _ = self.req("/api/fm/zip?ids=aaa111", cookie=ck)
        self.assertEqual(st, 403)
