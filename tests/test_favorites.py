"""Favorites (fav1): pinned folders on the Files and Server drives, owner-only,
stored in data/fm_favorites.json; Server favorites need the drive unlock."""
import json
import os

import favorites
import server
from tests.test_server_drive import SDBase
from tests.test_auth import totp_code  # noqa: F401
from tests import test_guest as _tg


class FavBase(SDBase):
    def setUp(self):
        super().setUp()
        try:
            favorites._file().unlink()
        except FileNotFoundError:
            pass
        import files_manager
        files_manager.save_folders(["Projects", "Projects/web"])

    def add(self, drive, path, label=None):
        body = {"drive": drive, "path": path}
        if label:
            body["label"] = label
        return self.j("/api/fm/favorites/add", body)


class FavoritesTests(FavBase):
    def test_add_list_dedupe_and_persist(self):
        st, _, js, _ = self.add("files", "Projects/web")
        self.assertEqual(st, 200, js)
        self.assertEqual((js["item"]["label"], js["item"]["path"]), ("web", "Projects/web"))
        st, _, js2, _ = self.add("files", "Projects/web")
        self.assertEqual(js2["item"]["id"], js["item"]["id"])
        st, _, lst, _ = self.j("/api/fm/favorites")
        self.assertEqual(len(lst["items"]), 1)
        data = json.loads(favorites._file().read_text())
        self.assertEqual(data["owners"]["owner"][0]["path"], "Projects/web")
        self.assertEqual(oct(os.stat(favorites._file()).st_mode & 0o777), "0o600")

    def test_root_and_bad_paths(self):
        st, _, js, _ = self.add("files", "")
        self.assertEqual((st, js["item"]["label"]), (200, "Files"))
        self.assertEqual(self.add("files", "../etc")[0], 400)
        self.assertEqual(self.add("files", "Nope")[0], 404)
        self.assertEqual(self.add("github", "x")[0], 400)

    def test_rename_reorder_remove(self):
        a = self.add("files", "Projects")[2]["item"]["id"]
        b = self.add("files", "Projects/web", "Site")[2]["item"]["id"]
        st, _, js, _ = self.j("/api/fm/favorites/rename", {"id": a, "label": "  Main   work "})
        self.assertEqual((st, js["item"]["label"]), (200, "Main work"))
        self.assertEqual(self.j("/api/fm/favorites/rename", {"id": a, "label": " "})[0], 400)
        st, _, js, _ = self.j("/api/fm/favorites/reorder", {"ids": [b, a]})
        self.assertEqual([i["id"] for i in js["items"]], [b, a])
        self.assertEqual(self.j("/api/fm/favorites/reorder", {"ids": [b]})[0], 400)
        self.assertEqual(self.j("/api/fm/favorites/reorder", {"ids": [b, b]})[0], 400)
        st, _, js, _ = self.j("/api/fm/favorites/remove", {"id": a})
        self.assertEqual([i["id"] for i in js["items"]], [b])
        self.assertEqual(self.j("/api/fm/favorites/remove", {"id": a})[0], 404)

    def test_server_favorite_needs_unlock_and_open_still_locked(self):
        st, _, js, _ = self.add("server", "/etc")
        self.assertEqual((st, js["error"]), (403, "drive_locked"))
        self.unlock()
        st, _, js, _ = self.add("server", "/etc")
        self.assertEqual((st, js["item"]["path"]), (200, "/etc"))
        self.assertEqual(self.add("server", "/opt/nullink/secrets")[0], 403)
        self.assertEqual(self.add("server", "/../x")[0], 400)
        # Re-lock: the favorite is still listed, but opening it is refused by the drive.
        self.j("/api/sd/lock", {})
        st, _, lst, _ = self.j("/api/fm/favorites")
        self.assertEqual(lst["items"][0]["drive"], "server")
        st, _, js, _ = self.j("/api/sd/list?path=/etc")
        self.assertEqual((st, js["error"]), (403, "drive_locked"))

    def test_token_and_anon_refused(self):
        _, plain = server.create_api_token("agent", ["messages:read"], ["morc"])
        bearer = {"Authorization": f"Bearer {plain}"}
        for path, body in (("/api/fm/favorites", None), ("/api/fm/favorites/add", {"drive": "files", "path": ""})):
            m = "POST" if body is not None else "GET"
            self.assertEqual(self.req(path, m, body)[0], 401)
            self.assertEqual(self.req(path, m, body, headers=bearer)[0], 403)
            self.assertEqual(self.req(path, m, body, cookie=self.owner, headers=bearer)[0], 403)


class FavoritesGuestTests(FavBase):
    request, approve, redeem, guest = _tg.GuestTests.request, _tg.GuestTests.approve, _tg.GuestTests.redeem, _tg.GuestTests.guest

    def test_guest_refused(self):
        ck, _ = self.guest("full")
        self.assertEqual(self.req("/api/fm/favorites", "GET", cookie=ck)[0], 403)
        self.assertEqual(self.req("/api/fm/favorites/add", "POST", {"drive": "files", "path": ""}, cookie=ck)[0], 403)
