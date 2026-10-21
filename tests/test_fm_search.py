"""Files search (name + contents, size caps) and file share links (2026-10-21)."""
import json
import time
from unittest.mock import patch

import fm_search
import server
import share_links
from tests.test_files_manager import FMBase, _seed, _put
from tests import test_guest as _tg


class SearchBase(FMBase):
    def setUp(self):
        super().setUp()
        _put("data/files/notes.md", b"intro\nthe Quarterly budget lives here\n")
        _put("data/files/big.txt", b"x" * 100 + b" needle ")
        _put("data/files/trash.txt", b"needle in trash")
        _put("secrets/key.txt", b"needle secret")
        _seed([
            {"id": "n1", "name": "notes.md", "path": "data/files/notes.md", "folder": "docs"},
            {"id": "b1", "name": "big.txt", "path": "data/files/big.txt", "folder": ""},
            {"id": "t1", "name": "trash.txt", "path": "data/files/trash.txt", "folder": "", "trashed_at": "2026-10-21T00:00:00Z"},
            {"id": "p1", "name": "pic.png", "path": "data/files/pic.png", "folder": ""},
            {"id": "s1", "name": "key.txt", "path": "secrets/key.txt", "folder": ""},
        ])
        try:
            (server.DATA / "share_links.json").unlink()
        except FileNotFoundError:
            pass

    def search(self, q, **extra):
        qs = "&".join([f"q={q}"] + [f"{k}={v}" for k, v in extra.items()])
        return self.req(f"/api/fm/search?{qs}", cookie=self.owner)


class SearchTests(SearchBase):
    def test_name_and_content(self):
        st, _, js, _ = self.search("quarterly")
        self.assertEqual(st, 200)
        r = [x for x in js["results"] if x.get("id") == "n1"][0]
        self.assertEqual((r["match"], r["line"]), ("content", 2))
        self.assertIn("Quarterly budget", r["snippet"])
        st, _, js, _ = self.search("notes")
        self.assertEqual(js["results"][0]["match"], "name")
        st, _, js, _ = self.search("docs")
        self.assertEqual(js["results"][0], {"type": "folder", "folder": "docs", "match": "name"})

    def test_trash_skipped_and_contents_off(self):
        st, _, js, _ = self.search("needle")
        ids = {x.get("id") for x in js["results"]}
        self.assertIn("b1", ids)
        self.assertNotIn("t1", ids)
        st, _, js, _ = self.search("needle", contents="0")
        self.assertEqual(js["results"], [])

    def test_size_caps(self):
        with patch.object(fm_search, "MAX_FILE_BYTES", 50):
            st, _, js, _ = self.search("needle")
            self.assertNotIn("b1", {x.get("id") for x in js["results"]})
        with patch.object(fm_search, "MAX_SCAN_BYTES", 10):
            st, _, js, _ = self.search("needle")
            self.assertTrue(js["truncated"])
            self.assertEqual(js["scanned_bytes"], 0)

    def test_bad_query_and_auth(self):
        self.assertEqual(self.search("")[0], 400)
        self.assertEqual(self.search("a" * 201)[0], 400)
        self.assertIn(self.req("/api/fm/search?q=x")[0], (401, 403))
        self.assertEqual(self.req("/api/fm/search?q=x", headers={"Authorization": "Bearer nlk_x"})[0], 403)


class ShareTests(SearchBase):
    def create(self, fid="n1", ttl="24h"):
        return self.req("/api/fm/shares", "POST", {"file_id": fid, "ttl": ttl}, cookie=self.owner)

    def test_create_open_revoke(self):
        st, _, js, _ = self.create()
        self.assertEqual(st, 201, js)
        token = js["url"].rsplit("/f/", 1)[1]
        st, hdrs, _, data = self.req(f"/f/{token}")
        self.assertEqual(st, 200)
        h = dict(hdrs)
        self.assertEqual(h["Content-Type"], "application/octet-stream")
        self.assertIn("attachment", h["Content-Disposition"])
        self.assertIn(b"Quarterly", data)
        st, _, lst, _ = self.req("/api/fm/shares?file_id=n1", cookie=self.owner)
        self.assertEqual((lst["links"][0]["opens"], lst["links"][0]["status"]), (1, "active"))
        st, _, _, _ = self.req(f"/api/fm/shares/{js['id']}/revoke", "POST", {}, cookie=self.owner)
        self.assertEqual(st, 200)
        self.assertEqual(self.req(f"/f/{token}")[0], 410)

    def test_expiry(self):
        st, _, js, _ = self.create(ttl="1h")
        token = js["url"].rsplit("/f/", 1)[1]
        with patch.object(share_links, "_now", lambda: time.time() + 3601):
            self.assertEqual(self.req(f"/f/{token}")[0], 410)

    def test_refusals(self):
        self.assertEqual(self.create(ttl="99d")[0], 400)
        self.assertEqual(self.create(fid="t1")[0], 404)       # trashed
        self.assertEqual(self.create(fid="s1")[0], 403)       # secrets/
        self.assertEqual(self.create(fid="nope")[0], 404)
        self.assertEqual(self.req("/f/" + "A" * 43)[0], 404)
        self.assertIn(self.req("/api/fm/shares", "POST", {"file_id": "n1"})[0], (401, 403))
        self.assertEqual(self.req("/api/fm/shares", "POST", {"file_id": "n1"},
                                  headers={"Authorization": "Bearer nlk_x"})[0], 403)
        # Server drive has no share route
        self.assertEqual(self.req("/api/sd/share", "POST", {"path": "/etc/hosts"}, cookie=self.owner)[0] in (403, 404, 405), True)

    def test_trashed_after_share_unavailable(self):
        st, _, js, _ = self.create()
        token = js["url"].rsplit("/f/", 1)[1]
        files = server.load_files()
        for f in files:
            if f["id"] == "n1":
                f["trashed_at"] = "2026-10-21T00:00:00Z"
        server.save_files(files)
        self.assertEqual(self.req(f"/f/{token}")[0], 410)


class GuestSearchTests(SearchBase):
    request, approve, redeem, guest = (_tg.GuestTests.request, _tg.GuestTests.approve,
                                       _tg.GuestTests.redeem, _tg.GuestTests.guest)

    def test_guest_refused(self):
        ck, _ = self.guest("full")
        self.assertEqual(self.req("/api/fm/search?q=x", cookie=ck)[0], 403)
        self.assertEqual(self.req("/api/fm/shares", "POST", {"file_id": "n1"}, cookie=ck)[0], 403)
