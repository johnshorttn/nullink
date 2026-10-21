"""GitHub drive (gh1): mocked GitHub API. Token server-side only, owner-only, read-only default,
step-up for edit/commit, sha conflict 409, branch/PR commit modes, audit, favorites."""
import base64
import json
from unittest.mock import patch

import favorites
import github_drive as GH
import server
from tests.test_auth import AuthBase, totp_code
from tests import test_guest as _tg

REAL_GH = GH.gh
TOKEN = "ghp_SECRETTOKENVALUE1234567890"
SHA1, SHA2 = "a" * 40, "b" * 40


class FakeGH:
    def __init__(self):
        self.calls = []
        self.file_sha = SHA1

    def __call__(self, method, path, body=None, query=None):
        self.calls.append((method, path, body, query))
        if path == "/user":
            return 200, {"login": "johnshorttn"}
        if path == "/user/repos":
            return 200, [{"full_name": "johnshorttn/nullink", "private": True, "default_branch": "main",
                          "permissions": {"push": True}}]
        if path.endswith("/branches"):
            return 200, [{"name": "main", "commit": {"sha": SHA1}, "protected": True}]
        if path.endswith("/contents/") or path.endswith("/contents/docs"):
            return 200, [{"name": "README.md", "path": "README.md", "type": "file", "size": 5, "sha": SHA1},
                         {"name": "docs", "path": "docs", "type": "dir", "size": 0, "sha": SHA2}]
        if "/contents/" in path and method == "GET":
            return 200, {"type": "file", "name": "README.md", "path": "README.md", "size": 6, "sha": self.file_sha,
                         "content": base64.b64encode(b"hello\n").decode()}
        if "/contents/" in path and method == "PUT":
            return 200, {"commit": {"sha": "c" * 40}, "content": {"sha": SHA2}}
        if "/git/ref/heads/" in path:
            return 200, {"object": {"sha": SHA1}}
        if path.endswith("/git/refs"):
            return 201, {"ref": body["ref"]}
        if path.endswith("/pulls"):
            return 201, {"html_url": "https://github.com/johnshorttn/nullink/pull/99", "number": 99}
        return 404, {}


class GHBase(AuthBase):
    def setUp(self):
        super().setUp()
        self.enable_totp()
        st, _, self.owner = self.login(totp_code())
        self._bp = patch.object(server, "BASE", self.root)
        self._bp.start()
        self.addCleanup(self._bp.stop)
        self.tf = self.root / "secrets" / "github_token.txt"
        self.tf.parent.mkdir(parents=True, exist_ok=True)
        self.tf.write_text(TOKEN + "\n")
        self.fake = FakeGH()
        p = patch.object(GH, "gh", self.fake)
        p.start(); self.addCleanup(p.stop)
        for f in ("github_drive_audit.jsonl", "fm_favorites.json"):
            try:
                (server.DATA / f).unlink()
            except FileNotFoundError:
                pass

    def g(self, path, body=None, method=None, **kw):
        return self.req(path, method or ("POST" if body is not None else "GET"), body, cookie=kw.pop("cookie", self.owner), **kw)

    def audit_text(self):
        try:
            return (server.DATA / "github_drive_audit.jsonl").read_text()
        except FileNotFoundError:
            return ""


class BrowseTests(GHBase):
    def test_browse_and_token_never_leaks(self):
        bodies = []
        for path in ("/api/gh/status", "/api/gh/repos", "/api/gh/branches?repo=johnshorttn/nullink",
                     "/api/gh/tree?repo=johnshorttn/nullink&ref=main&path=",
                     "/api/gh/file?repo=johnshorttn/nullink&ref=main&path=README.md"):
            st, _, js, raw = self.g(path)
            self.assertEqual(st, 200, (path, js))
            bodies.append(raw)
        self.assertEqual(json.loads(bodies[1])["repos"][0]["private"], True)
        self.assertEqual(json.loads(bodies[3])["items"][0]["type"], "dir")
        f = json.loads(bodies[4])
        self.assertEqual((f["content"], f["sha"]), ("hello\n", SHA1))
        for raw in bodies:
            self.assertNotIn(TOKEN.encode(), raw)
        self.assertNotIn(TOKEN, self.audit_text())

    def test_unconfigured(self):
        self.tf.unlink()
        st, _, js, _ = self.g("/api/gh/status")
        self.assertEqual((st, js["configured"]), (200, False))

    def test_real_gh_without_token_503(self):
        self.tf.unlink()
        with self.assertRaises(GH.GhErr) as cm:
            REAL_GH("GET", "/user")
        self.assertEqual(cm.exception.err, "token_not_configured")

    def test_bad_inputs(self):
        for p in ("/api/gh/branches?repo=../x", "/api/gh/tree?repo=a/b&ref=..&path=",
                  "/api/gh/tree?repo=a/b&ref=main&path=../etc", "/api/gh/file?repo=a/b&ref=main&path="):
            self.assertEqual(self.g(p)[0], 400, p)

    def test_refusals(self):
        self.assertEqual(self.req("/api/gh/repos")[0], 401)
        self.assertEqual(self.req("/api/gh/repos", headers={"Authorization": "Bearer nlk_x"})[0], 403)
        self.assertEqual(self.req("/api/gh/repos", cookie=self.owner, headers={"Authorization": "Bearer nlk_x"})[0], 403)


class EditTests(GHBase):
    def commit(self, **over):
        body = {"repo": "johnshorttn/nullink", "branch": "main", "path": "README.md", "sha": SHA1,
                "content": "hello world\n", "message": "Update README", "mode": "branch"}
        body.update(over)
        return self.g("/api/gh/commit", body)

    def test_stepup_required(self):
        self.age_stepup()
        st, _, js, _ = self.g("/api/gh/edit", {"repo": "johnshorttn/nullink", "path": "README.md"})
        self.assertEqual((st, js["error"]), (403, "step_up_required"))
        st, _, js, _ = self.commit()
        self.assertEqual((st, js["error"]), (403, "step_up_required"))
        self.assertFalse(any(c[0] == "PUT" for c in self.fake.calls))
        st, _, _, _ = self.req("/api/auth/stepup", "POST", {"code": totp_code(1)}, cookie=self.owner)
        self.assertEqual(st, 200)
        self.assertEqual(self.g("/api/gh/edit", {})[0], 200)

    def test_commit_to_branch_and_audit(self):
        st, _, js, _ = self.commit()
        self.assertEqual(st, 200, js)
        self.assertEqual((js["branch"], js["commit"]), ("main", "c" * 40))
        put = [c for c in self.fake.calls if c[0] == "PUT"][0]
        self.assertEqual((put[2]["sha"], put[2]["branch"], put[2]["message"]), (SHA1, "main", "Update README"))
        self.assertEqual(base64.b64decode(put[2]["content"]), b"hello world\n")
        a = self.audit_text()
        self.assertIn('"event": "commit"', a)
        self.assertNotIn("hello world", a)

    def test_message_required(self):
        self.assertEqual(self.commit(message="  ")[1:3][1]["error"], "message_required")

    def test_sha_conflict_409(self):
        self.fake.file_sha = SHA2
        st, _, js, _ = self.commit()
        self.assertEqual((st, js["error"]), (409, "changed_since_open"))
        self.assertFalse(any(c[0] == "PUT" for c in self.fake.calls))
        self.assertIn("commit_conflict", self.audit_text())

    def test_new_branch_and_pr(self):
        st, _, js, _ = self.commit(mode="pr", new_branch="nullink/edit-1")
        self.assertEqual(st, 200, js)
        self.assertEqual((js["branch"], js["pr_number"]), ("nullink/edit-1", 99))
        ref = [c for c in self.fake.calls if c[1].endswith("/git/refs")][0]
        self.assertEqual(ref[2], {"ref": "refs/heads/nullink/edit-1", "sha": SHA1})
        put = [c for c in self.fake.calls if c[0] == "PUT"][0]
        self.assertEqual(put[2]["branch"], "nullink/edit-1")
        pr = [c for c in self.fake.calls if c[1].endswith("/pulls")][0]
        self.assertEqual((pr[2]["head"], pr[2]["base"]), ("nullink/edit-1", "main"))

    def test_bearer_cannot_commit(self):
        st, _, _, _ = self.req("/api/gh/commit", "POST", {"repo": "a/b"}, headers={"Authorization": "Bearer nlk_x"})
        self.assertEqual(st, 403)


class FavTests(GHBase):
    def test_github_favorite(self):
        st, _, js, _ = self.g("/api/fm/favorites/add", {"drive": "github", "path": "johnshorttn/nullink@main:docs"})
        self.assertEqual(st, 200, js)
        self.assertEqual((js["item"]["path"], js["item"]["label"]), ("johnshorttn/nullink@main:docs", "docs"))
        st, _, js, _ = self.g("/api/fm/favorites/add", {"drive": "github", "path": "bad/../x@main:"})
        self.assertEqual(st, 400)


class GuestGHTests(GHBase):
    request, approve, redeem, guest = (_tg.GuestTests.request, _tg.GuestTests.approve,
                                       _tg.GuestTests.redeem, _tg.GuestTests.guest)

    def test_guest_refused(self):
        ck, _ = self.guest("full")
        self.assertEqual(self.req("/api/gh/repos", cookie=ck)[0], 403)
        self.assertEqual(self.req("/api/gh/commit", "POST", {}, cookie=ck)[0], 403)


# ---------- gh2: downloads ----------
import io
import zipfile

BIN = bytes(range(256)) * 10 + b"\x00\xff"


class DLFake(FakeGH):
    def __init__(self):
        super().__init__()
        self.streams = []
        self.remaining = 5000
        self.tree = [
            {"path": "README.md", "type": "blob", "sha": "1" * 40, "size": 6, "mode": "100644"},
            {"path": "docs", "type": "tree", "sha": "2" * 40},
            {"path": "docs/a.md", "type": "blob", "sha": "3" * 40, "size": 2, "mode": "100644"},
            {"path": "docs/sub", "type": "tree", "sha": "4" * 40},
            {"path": "docs/sub/run.sh", "type": "blob", "sha": "5" * 40, "size": 3, "mode": "100755"},
            {"path": "docs/mod", "type": "commit", "sha": "6" * 40},
            {"path": "img/logo.png", "type": "blob", "sha": "7" * 40, "size": len(BIN), "mode": "100644"},
            {"path": "docsx/no.md", "type": "blob", "sha": "8" * 40, "size": 1, "mode": "100644"},
        ]
        self.truncated = False
        self.blobs = {"1" * 40: b"hello\n", "3" * 40: b"A\n", "5" * 40: b"#!\n", "7" * 40: BIN, "8" * 40: b"x"}

    def __call__(self, method, path, body=None, query=None):
        if path == "/rate_limit":
            self.calls.append((method, path, body, query))
            return 200, {"resources": {"core": {"remaining": self.remaining, "reset": 1}}}
        if "/git/trees/" in path:
            self.calls.append((method, path, body, query))
            return 200, {"tree": self.tree, "truncated": self.truncated}
        if path.endswith("/contents/img/logo.png"):
            return 200, {"type": "file", "name": "logo.png", "path": "img/logo.png", "size": len(BIN), "sha": "7" * 40}
        if path.endswith("/contents/big.bin"):
            return 200, {"type": "file", "name": "big.bin", "path": "big.bin", "size": GH.MAX_DL_FILE + 1, "sha": "9" * 40}
        return super().__call__(method, path, body, query)

    def stream(self, path):
        self.streams.append(path)
        return io.BytesIO(self.blobs[path.rsplit("/", 1)[1]])


class DownloadTests(GHBase):
    def setUp(self):
        super().setUp()
        self.fake = DLFake()
        for name, val in (("gh", self.fake), ("gh_stream", self.fake.stream)):
            p = patch.object(GH, name, val)
            p.start(); self.addCleanup(p.stop)

    def test_single_binary_file(self):
        st, hd, _, raw = self.g("/api/gh/download?repo=johnshorttn/nullink&ref=main&path=img/logo.png")
        self.assertEqual(st, 200)
        hd = {k.lower(): v for k, v in hd}
        self.assertEqual(raw, BIN)
        self.assertEqual(hd["content-type"], "image/png")
        self.assertEqual(hd["content-length"], str(len(BIN)))
        self.assertIn('filename="logo.png"', hd["content-disposition"])
        self.assertEqual(self.fake.streams, ["/repos/johnshorttn/nullink/git/blobs/" + "7" * 40])
        self.assertNotIn(TOKEN.encode(), raw)
        self.assertIn('"event": "download"', self.audit_text())
        self.assertNotIn(TOKEN, self.audit_text())

    def test_single_errors(self):
        self.assertEqual(self.g("/api/gh/download?repo=johnshorttn/nullink&ref=main&path=big.bin")[2]["error"], "file_too_large")
        self.assertEqual(self.g("/api/gh/download?repo=johnshorttn/nullink&ref=main&path=docs")[0], 400)
        self.assertEqual(self.g("/api/gh/download?repo=johnshorttn/nullink&ref=main&path=../x")[0], 400)

    def test_no_stepup_but_owner_only(self):
        self.age_stepup()
        self.assertEqual(self.g("/api/gh/download?repo=johnshorttn/nullink&ref=main&path=img/logo.png")[0], 200)
        self.assertEqual(self.req("/api/gh/download?repo=a/b&ref=main&path=x")[0], 401)
        self.assertEqual(self.req("/api/gh/zip?repo=a/b&ref=main&paths=x", headers={"Authorization": "Bearer nlk_x"})[0], 403)

    def test_zip_folder_and_files(self):
        st, hd, _, raw = self.g("/api/gh/zip?repo=johnshorttn/nullink&ref=main&paths=docs,README.md,img/logo.png")
        self.assertEqual(st, 200)
        hd = {k.lower(): v for k, v in hd}
        self.assertEqual(hd["content-type"], "application/zip")
        self.assertIn('filename="nullink.zip"', hd["content-disposition"])
        z = zipfile.ZipFile(io.BytesIO(raw))
        self.assertIsNone(z.testzip())
        names = set(z.namelist())
        self.assertEqual(names, {"docs/", "docs/sub/", "docs/a.md", "docs/sub/run.sh", "README.md", "img/logo.png"})
        self.assertEqual(z.read("img/logo.png"), BIN)
        self.assertEqual(z.read("docs/sub/run.sh"), b"#!\n")
        self.assertEqual(z.getinfo("docs/sub/run.sh").external_attr >> 16, 0o100755)
        tr = [c for c in self.fake.calls if "/git/trees/" in c[1]][0]
        self.assertEqual((tr[1], tr[3]), ("/repos/johnshorttn/nullink/git/trees/main", {"recursive": "1"}))
        self.assertIn('"event": "zip"', self.audit_text())

    def test_zip_single_folder_name(self):
        st, hd, _, raw = self.g("/api/gh/zip?repo=johnshorttn/nullink&ref=main&paths=docs/sub")
        self.assertEqual(st, 200)
        self.assertIn('filename="sub.zip"', dict((k.lower(), v) for k, v in hd)["content-disposition"])
        self.assertEqual(set(zipfile.ZipFile(io.BytesIO(raw)).namelist()), {"docs/sub/", "docs/sub/run.sh"})

    def test_zip_limits_and_errors(self):
        base = "/api/gh/zip?repo=johnshorttn/nullink&ref=main&paths="
        self.assertEqual(self.g(base)[2]["error"], "nothing_selected")
        self.assertEqual(self.g(base + "nope")[0], 404)
        self.assertEqual(self.g(base + "../etc")[0], 400)
        self.assertEqual(self.g(base + ",".join(f"f{i}" for i in range(GH.ZIP_MAX_PATHS + 1)))[2]["error"], "too_many_selected")
        with patch.object(GH, "ZIP_MAX_FILES", 2):
            st, _, js, _ = self.g(base + "docs,README.md")
            self.assertEqual((st, js["error"]), (413, "too_many_files"))
        with patch.object(GH, "ZIP_MAX_BYTES", 100):
            self.assertEqual(self.g(base + "img/logo.png")[2]["error"], "zip_too_large")
        self.fake.remaining = 10
        st, _, js, _ = self.g(base + "README.md")
        self.assertEqual((st, js["error"]), (429, "rate_limited"))
        self.fake.remaining = 5000
        self.fake.truncated = True
        self.assertEqual(self.g(base + "README.md")[2]["error"], "repo_too_large")
        self.assertEqual(self.fake.streams, [])
