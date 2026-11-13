"""NullVault Links / Projects / Files (2026-11-12): sub-flags, signed writes, sync extras, discovery,
device Files sessions with Range downloads, signed uploads (size cap, label, sha256), revoke, and the
browser Files API left unchanged."""
import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from unittest import mock

import fm_uploads
import nullvault
import nullvault_ext as ext
import server
from tests.test_nullvault import NullVaultBase, ORIGIN

NODE = shutil.which("node")


class ExtBase(NullVaultBase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._bp = mock.patch.object(server, "BASE", Path(cls.tmp.name))
        cls._bp.start()

    @classmethod
    def tearDownClass(cls):
        cls._bp.stop()
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        os.environ["NULLVAULT_LINKS"] = "1"
        os.environ["NULLVAULT_FILES"] = "1"
        os.environ["NULLVAULT_DISCOVERY_CADDY"] = "0"
        self.addCleanup(lambda: [os.environ.pop(k, None) for k in ("NULLVAULT_LINKS", "NULLVAULT_FILES", "NULLVAULT_DISCOVERY_CADDY")])
        ext.nv, ext.server = nullvault, server
        ext._sessions.clear()
        ext._disc_cache.update(t=0.0, sites=[], source=None)
        self._cf = mock.patch.object(ext, "CADDYFILE", Path(tempfile.gettempdir()) / "nv-no-caddyfile")
        self._cf.start(); self.addCleanup(self._cf.stop)
        self.dev = self.register()

    def write(self, dev, op, kind, rec, **kw):
        extra = {"op": op, "kind": kind, kind: rec}
        extra.update(kw.pop("extra", {}))
        return self.signed_call(dev, "/api/vault/device/write", "write", extra=extra, **kw)

    def files_session(self, dev=None):
        st, js, _, _ = self.signed_call(dev or self.dev, "/api/vault/files/session", "files")
        self.assertEqual(st, 200, js)
        return {"Authorization": "Bearer " + js["files_session"]}

    def put_file(self, fid, name, data, added, labels=("inbox",)):
        p = server.BASE / "data" / "files" / f"{fid}-{name}"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        files = server.load_files()
        files.append({"id": fid, "name": name, "path": f"data/files/{fid}-{name}", "labels": list(labels),
                      "size": len(data), "updated_at": added, "added_at": added, "created_at": added, "folder": ""})
        server.save_files(files)


class FlagTests(ExtBase):
    def test_subflags_off_hide_everything_new(self):
        os.environ["NULLVAULT_LINKS"] = "0"; os.environ["NULLVAULT_FILES"] = "0"
        st, js, _, _ = self.sync(self.dev)
        self.assertEqual(st, 200)
        self.assertNotIn("links", js); self.assertNotIn("projects", js)
        st, js, _, _ = self.write(self.dev, "create", "link", {"url": "https://a.example"})
        self.assertEqual(st, 404)
        for path, m in (("/api/vault/files", "GET"), ("/api/vault/files/session", "POST"), ("/api/vault/links", "GET")):
            st, *_ = self.req(path, m, {} if m == "POST" else None, cookie=self.owner)
            self.assertEqual(st, 404, path)

    def test_master_flag_off_404(self):
        os.environ["NULLVAULT_ENABLED"] = "0"
        for path, m in (("/api/vault/files", "GET"), ("/api/vault/files/abc/download", "GET"), ("/api/vault/links", "GET")):
            st, *_ = self.req(path, m, cookie=self.owner)
            self.assertEqual(st, 404, path)


class LinksProjectsTests(ExtBase):
    def test_link_crud_and_sync(self):
        st, js, _, _ = self.write(self.dev, "create", "link", {"name": "Mail", "url": "https://mail.example.com/x", "host_label": "vps1"})
        self.assertEqual(st, 200, js)
        lid = js["link"]["id"]
        st, js, _, _ = self.write(self.dev, "update", "link", {"id": lid, "name": "Nullmail"})
        self.assertEqual((st, js["link"]["name"], js["link"]["url"]), (200, "Nullmail", "https://mail.example.com/x"))
        st, js, _, _ = self.sync(self.dev)
        self.assertEqual([l["name"] for l in js["links"]], ["Nullmail"])
        st, js, _, _ = self.write(self.dev, "delete", "link", {"id": lid})
        self.assertEqual(st, 200)
        self.assertEqual(self.sync(self.dev)[1]["links"], [])
        self.assertEqual(self.registry()[-2]["kind"], "write")

    def test_only_http_https(self):
        for u in ("javascript:alert(1)", "file:///etc/passwd", "intent://x", "ftp://a.b", "https://", "https://a b.com"):
            st, js, _, _ = self.write(self.dev, "create", "link", {"url": u})
            self.assertEqual(st, 400, u)

    def test_conflict(self):
        lid = self.write(self.dev, "create", "link", {"url": "https://a.example"})[1]["link"]["id"]
        st, js, _, _ = self.write(self.dev, "update", "link", {"id": lid, "name": "x"},
                                  extra={"base_updated_at": "2000-01-01T00:00:00Z"})
        self.assertEqual(st, 409)

    def test_project_references_only(self):
        lid = self.write(self.dev, "create", "link", {"url": "https://ling.example"})[1]["link"]["id"]
        st, js, _, _ = self.write(self.dev, "create", "project", {
            "name": "LinguaSheet", "repo_url": "https://github.com/johnshorttn/linguasheet", "server": "vps1",
            "link_ids": [lid], "entry_ids": [self.entry["id"], "../bad"], "body": "should-be-dropped"})
        self.assertEqual(st, 200, js)
        p = js["project"]
        self.assertEqual((p["link_ids"], p["entry_ids"]), ([lid], [self.entry["id"]]))
        self.assertNotIn("body", p)
        raw = (nullvault.nv_dir() / "projects.json").read_text()
        self.assertNotIn("nv-test-only", raw)  # no vault secret ever lands in a project record
        self.write(self.dev, "delete", "link", {"id": lid})
        self.assertEqual(self.sync(self.dev)[1]["projects"][0]["link_ids"], [])
        st, *_ = self.write(self.dev, "create", "project", {"name": "x", "repo_url": "javascript:x"})
        self.assertEqual(st, 400)
        st, *_ = self.write(self.dev, "create", "project", {"name": ""})
        self.assertEqual(st, 400)

    def test_admin_links_owner_only(self):
        st, _, js, _ = self.req("/api/vault/links", cookie=self.owner)
        self.assertEqual(st, 200)
        self.assertIn("suggestions", js)
        st, *_ = self.req("/api/vault/links")
        self.assertEqual(st, 401)
        st, *_ = self.req("/api/vault/links", headers=self.bearer(self.dev))
        self.assertIn(st, (401, 403))


class DiscoveryTests(ExtBase):
    def test_caddy_json_hosts(self):
        cfg = {"apps": {"http": {"servers": {"srv0": {"routes": [
            {"match": [{"host": ["a.example.com", "b.example.com"]}], "handle": [{"handler": "subroute", "routes": [
                {"match": [{"host": ["c.example.com"]}]}]}]},
            {"match": [{"host": ["*.wild.example"]}]}]}}}}}
        self.assertEqual(ext._caddy_hosts(cfg), ["a.example.com", "b.example.com", "c.example.com"])

    def test_caddyfile_parse(self):
        text = "{\n  admin localhost:2019\n}\n(snip) {\n  header X 1\n}\nmail.example.com, https://ling.example.com {\n  reverse_proxy 127.0.0.1:1\n  @x host inner.example.com {\n }\n}\n# old.example.com {\n"
        self.assertEqual(ext.caddyfile_hosts(text), ["ling.example.com", "mail.example.com"])

    def test_order_caddyfile_then_seed_and_sync_suggestions(self):
        cf = Path(tempfile.mkdtemp()) / "Caddyfile"
        cf.write_text("site.example.com {\n respond 200\n}\n")
        with mock.patch.object(ext, "CADDYFILE", cf):
            self.assertEqual(ext.discover(force=True)["source"], "caddyfile")
        server._atomic_write_json(nullvault.nv_dir() / "discovered_sites.json", {"hosts": ["seed.example.com"]})
        d = ext.discover(force=True)
        self.assertEqual((d["source"], d["sites"][0]["url"]), ("seed", "https://seed.example.com"))
        server._atomic_write_json(nullvault.nv_dir() / "repo_catalog.json", {"repos": [
            {"full_name": "johnshorttn/nullink", "url": "https://github.com/johnshorttn/nullink", "private": False},
            {"full_name": "x/evil", "url": "javascript:alert(1)"}]})
        s = self.sync(self.dev)[1]["suggestions"]
        self.assertEqual([r["name"] for r in s["repos"]], ["nullink"])
        self.assertEqual(s["sites"][0]["host"], "seed.example.com")

    def test_caddy_admin_get_only(self):
        os.environ["NULLVAULT_DISCOVERY_CADDY"] = "1"
        seen = {}

        class R:
            def __enter__(s): return s
            def __exit__(s, *a): return False
            def read(s, n): return json.dumps({"x": {"match": [{"host": ["z.example.com"]}]}}).encode()

        def fake(url, timeout):
            seen["url"] = url if isinstance(url, str) else url.full_url
            seen["method"] = "GET" if isinstance(url, str) else url.get_method()
            return R()
        with mock.patch.object(ext.urllib.request, "urlopen", fake):
            d = ext.discover(force=True)
        self.assertEqual((d["source"], seen["url"], seen["method"]), ("caddy_admin", "http://localhost:2019/config/", "GET"))


class FilesTests(ExtBase):
    def setUp(self):
        super().setUp()
        server.save_files([])
        self.blob = bytes(range(256)) * 40  # 10240 bytes
        self.put_file("old111", "nullkey-v1.apk", b"old", "2026-11-01T00:00:00Z", labels=["apk"])
        self.put_file("new222", "nullkey-v2.apk", self.blob, "2026-11-10T00:00:00Z", labels=["apk"])
        self.put_file("doc333", "notes.txt", b"hello", "2026-11-05T00:00:00Z")

    def test_list_newest_first_labels_latest(self):
        h = self.files_session()
        st, _, js, _ = self.req("/api/vault/files", headers=h)
        self.assertEqual(st, 200, js)
        self.assertEqual([f["id"] for f in js["files"]], ["new222", "doc333", "old111"])
        lat = {f["id"]: f["latest"] for f in js["files"]}
        self.assertEqual(lat, {"new222": True, "old111": False, "doc333": False})
        self.assertEqual(js["labels"], ["apk", "inbox"])
        self.assertNotIn("path", js["files"][0])

    def test_range_download(self):
        h = self.files_session()
        st, hdrs, _, data = self.req("/api/vault/files/new222/download", headers=h)
        self.assertEqual((st, data), (200, self.blob))
        st, hdrs, _, data = self.req("/api/vault/files/new222/download", headers={**h, "Range": "bytes=100-199"})
        self.assertEqual((st, data), (206, self.blob[100:200]))
        self.assertIn(("Content-Range", "bytes 100-199/10240"), hdrs)
        st, _, _, data = self.req("/api/vault/files/new222/download", headers={**h, "Range": "bytes=10000-"})
        self.assertEqual((st, data), (206, self.blob[10000:]))
        st, *_ = self.req("/api/vault/files/new222/download", headers={**h, "Range": "bytes=99999-"})
        self.assertEqual(st, 416)
        self.assertIn("device_file_download", server.VAULT_AUDIT_FILE.read_text())

    def test_session_required_and_revoke_ends_it(self):
        st, *_ = self.req("/api/vault/files")
        self.assertEqual(st, 401)
        st, *_ = self.req("/api/vault/files", headers=self.bearer(self.dev))  # device token is not a files session
        self.assertEqual(st, 401)
        h = self.files_session()
        self.assertEqual(self.revoke(self.dev["js"]["device_id"])[0], 200)
        st, _, js, _ = self.req("/api/vault/files", headers=h)
        self.assertEqual((st, js.get("wipe")), (403, True))
        st, *_ = self.req("/api/vault/files/new222/download", headers=h)
        self.assertEqual(st, 403)

    def test_session_expires(self):
        h = self.files_session()
        for v in ext._sessions.values():
            v["exp"] = time.time() - 1
        st, *_ = self.req("/api/vault/files", headers=h)
        self.assertEqual(st, 401)

    def upload(self, data, label="phone", sha=None, size=None):
        st, js, _, _ = self.write(self.dev, "upload_begin", "file", {
            "name": "photo.jpg", "size": len(data) if size is None else size, "label": label,
            "sha256": sha or hashlib.sha256(data).hexdigest()})
        return st, js

    def test_signed_upload_with_label_then_listed_and_notified(self):
        data = os.urandom(300_000)
        st, js = self.upload(data)
        self.assertEqual(st, 200, js)
        uid = js["upload_id"]
        h = self.files_session()
        import http.client
        for off in range(0, len(data), 100_000):
            conn = http.client.HTTPConnection("127.0.0.1", self.httpd.server_port, timeout=10)
            conn.request("POST", f"/api/vault/files/uploads/{uid}/chunk?offset={off}", body=data[off:off + 100_000],
                         headers={**h, "Host": "nullink.216.158.238.236.sslip.io", "X-Forwarded-Proto": "https"})
            r = conn.getresponse(); body = json.loads(r.read()); conn.close()
            self.assertEqual(r.status, 200, body)
        st, _, js, _ = self.req(f"/api/vault/files/uploads/{uid}", headers=h)
        self.assertEqual(js["received"], len(data))
        with mock.patch.object(server, "write_pending") as wp, mock.patch.object(server, "fire_webhook") as fw:
            st, _, js, _ = self.req(f"/api/vault/files/uploads/{uid}/complete", "POST", {}, headers=h)
        self.assertEqual(st, 200, js)
        self.assertEqual((js["file"]["labels"], js["file"]["source"]), (["phone"], "nullvault"))
        self.assertTrue(wp.called and fw.called)
        fid = js["file"]["id"]
        st, _, _, got = self.req(f"/api/vault/files/{fid}/download", headers=h)
        self.assertEqual(got, data)
        st, js, _, _ = self.write(self.dev, "delete", "file", {"id": fid})
        self.assertEqual(st, 200, js)
        self.assertTrue(next(f for f in server.load_files() if f["id"] == fid)["trashed_at"])
        self.assertIn("device_upload", server.VAULT_AUDIT_FILE.read_text())

    def test_upload_size_cap(self):
        with mock.patch.object(fm_uploads, "MAX_FILE", 1000):
            st, js = self.upload(b"x", size=1001)
        self.assertEqual((st, js["error"]), (413, "too_large"))
        st, js = self.upload(b"x", label="../etc")
        self.assertEqual(st, 400)

    def test_upload_sha_mismatch_refused(self):
        data = b"real bytes"
        st, js = self.upload(data, sha="00" * 32)
        uid = js["upload_id"]
        h = self.files_session()
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", self.httpd.server_port, timeout=10)
        conn.request("POST", f"/api/vault/files/uploads/{uid}/chunk?offset=0", body=data,
                     headers={**h, "Host": "nullink.216.158.238.236.sslip.io", "X-Forwarded-Proto": "https"})
        r = conn.getresponse(); body = r.read(); conn.close()
        self.assertEqual(r.status, 200, body)
        st, _, js, _ = self.req(f"/api/vault/files/uploads/{uid}/complete", "POST", {}, headers=h)
        self.assertEqual((st, js["error"]), (422, "sha256_mismatch"))
        self.assertFalse(any(f.get("name") == "photo.jpg" for f in server.load_files()))

    def test_upload_cancel_removes_partial(self):
        data = os.urandom(150_000)
        st, js = self.upload(data)
        uid = js["upload_id"]
        h = self.files_session()
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", self.httpd.server_port, timeout=10)
        conn.request("POST", f"/api/vault/files/uploads/{uid}/chunk?offset=0", body=data[:100_000],
                     headers={**h, "Host": "nullink.216.158.238.236.sslip.io", "X-Forwarded-Proto": "https"})
        r = conn.getresponse(); r.read(); conn.close()
        self.assertEqual(r.status, 200)
        self.assertTrue(fm_uploads._part_path(uid).exists())
        # another device cannot cancel it
        other = self.register()
        st, _, js, _ = self.req(f"/api/vault/files/uploads/{uid}/cancel", "POST", {}, headers=self.files_session(other))
        self.assertEqual(st, 404)
        self.assertTrue(fm_uploads._part_path(uid).exists())
        st, _, js, _ = self.req(f"/api/vault/files/uploads/{uid}/cancel", "POST", {}, headers=h)
        self.assertEqual((st, js.get("cancelled")), (200, True), js)
        self.assertFalse(fm_uploads._part_path(uid).exists())
        self.assertFalse(fm_uploads._meta_path(uid).exists())
        st, *_ = self.req(f"/api/vault/files/uploads/{uid}", headers=h)
        self.assertEqual(st, 404)
        st, *_ = self.req(f"/api/vault/files/uploads/{uid}/complete", "POST", {}, headers=h)
        self.assertEqual(st, 404)
        self.assertIn("device_upload_cancel", server.VAULT_AUDIT_FILE.read_text())
        # no session -> 401
        st, *_ = self.req(f"/api/vault/files/uploads/{uid}/cancel", "POST", {})
        self.assertEqual(st, 401)

    def test_upload_belongs_to_device(self):
        st, js = self.upload(b"abc")
        uid = js["upload_id"]
        other = self.register()
        h2 = self.files_session(other)
        st, *_ = self.req(f"/api/vault/files/uploads/{uid}", headers=h2)
        self.assertEqual(st, 404)

    def test_browser_files_unchanged(self):
        st, _, js, _ = self.req("/api/fm/tree", cookie=self.owner)
        self.assertEqual(st, 200)
        self.assertEqual({f["id"] for f in js["files"]}, {"old111", "new222", "doc333"})
        self.assertNotIn("latest", js["files"][0])
        h = self.files_session()
        for path in ("/api/fm/tree", "/api/fm/files/new222/download", "/api/files/new222/download"):
            st, *_ = self.req(path, headers=h)
            self.assertIn(st, (401, 403), path)
        st, _, _, data = self.req("/api/fm/files/new222/download", cookie=self.owner)
        self.assertEqual((st, data), (200, self.blob))

    def test_version_not_pinned_refused_without_flag(self):
        st, js, _, _ = self.sync(self.dev, apk=self.apk(version_code=2), kd_kw={"version": 2})
        self.assertEqual((st, js["error"], js.get("wipe")), (403, "apk_mismatch:version_not_pinned", None))
        self.assertEqual(nullvault.devices()[self.dev["js"]["device_id"]]["status"], "active")
        self.assertEqual(self.sync(self.dev)[0], 200)


class LatestParityTests(ExtBase):
    NAMES = [("a", "nullkey-v1.2.apk", "2026-10-01T00:00:00Z"), ("b", "nullkey-v1.3.apk", "2026-10-05T00:00:00Z"),
             ("c", "NullKey-test-96e43b4.apk", "2026-10-03T00:00:00Z"), ("d", "report.pdf", "2026-10-01T00:00:00Z"),
             ("e", "report (1).pdf", "2026-10-02T00:00:00Z"), ("f", "report.docx", "2026-10-09T00:00:00Z"),
             ("g", "photo_2026-10-01.jpg", "2026-10-01T00:00:00Z"), ("h", "photo_2026-10-02.jpg", "2026-10-04T00:00:00Z"),
             ("i", "solo.txt", "2026-10-01T00:00:00Z")]

    def test_python_matches_js_similar_groups(self):
        files = [{"id": i, "name": n, "added_at": t} for i, n, t in self.NAMES]
        py = sorted(ext.latest_ids(files))
        if not NODE:
            self.skipTest("node not installed")
        js_src = (Path(server.__file__).parent / "static" / "fm-sort.js").as_posix()
        code = (f"const S=require({json.dumps(js_src)});const g=S.similarGroups({json.dumps(files)});"
                "const o=[];g.forEach((v,k)=>{if(v.latest)o.push(k)});console.log(JSON.stringify(o.sort()))")
        r = subprocess.run([NODE, "--jitless", "-e", code], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(py, json.loads(r.stdout))
        self.assertIn("b", py)
