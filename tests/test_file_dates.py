"""Date added / Date created capture (2026-10-26): file_dates stamping + EXIF, writers, backfill, /api/fm/tree."""
import http.client
import json
import os
import struct
import time
import uuid

import file_dates
import files_manager
import server
from tests.test_auth import HTTPS_HOST
from tests.test_files_manager import FMBase, _seed, _put


def _jpeg_with_exif(dt=b"2021:07:04 09:30:00", offset=None):
    """Minimal little-endian JPEG: SOI, APP1 Exif (IFD0 -> ExifIFD with DateTimeOriginal [+ OffsetTimeOriginal]), EOI."""
    e = "<"
    entries = [(0x9003, 2, len(dt) + 1, dt + b"\0")]
    if offset:
        entries.append((0x9011, 2, len(offset) + 1, offset + b"\0"))
    ifd0_off = 8
    ifd0 = struct.pack(e + "H", 1) + struct.pack(e + "HHII", 0x8769, 4, 1, 0) + struct.pack(e + "I", 0)
    exif_off = ifd0_off + len(ifd0)
    data_off = exif_off + 2 + 12 * len(entries) + 4
    exif, blob = struct.pack(e + "H", len(entries)), b""
    for tag, typ, cnt, val in entries:
        exif += struct.pack(e + "HHII", tag, typ, cnt, data_off + len(blob))
        blob += val
    exif += struct.pack(e + "I", 0)
    ifd0 = struct.pack(e + "H", 1) + struct.pack(e + "HHII", 0x8769, 4, 1, exif_off) + struct.pack(e + "I", 0)
    tiff = b"II*\0" + struct.pack(e + "I", ifd0_off) + ifd0 + exif + blob
    app1 = b"Exif\0\0" + tiff
    return b"\xff\xd8" + b"\xff\xe1" + struct.pack(">H", len(app1) + 2) + app1 + b"\xff\xd9"


class FileDatesUnitTests(FMBase):
    def test_exif_with_and_without_offset(self):
        p = _put("data/files/p1.jpg", _jpeg_with_exif(offset=b"+02:00"))
        self.assertEqual(file_dates.iso_utc(file_dates.exif_ts(p)), "2021-07-04T07:30:00Z")
        p2 = _put("data/files/p2.jpeg", _jpeg_with_exif())  # naive -> America/New_York (EDT, -4)
        self.assertEqual(file_dates.iso_utc(file_dates.exif_ts(p2)), "2021-07-04T13:30:00Z")
        self.assertIsNone(file_dates.exif_ts(_put("data/files/x.jpg", b"\xff\xd8garbage")))
        self.assertIsNone(file_dates.exif_ts(_put("data/files/y.png", _jpeg_with_exif())), "only jpeg/tiff names")
        self.assertIsNone(file_dates.exif_ts(_put("data/files/z.jpg", _jpeg_with_exif(dt=b"1970:01:01 00:00:00"))))

    def test_stamp_priority_and_sanity(self):
        now = "2026-10-26T21:00:00Z"
        e = file_dates.stamp({}, client_ms=1700000000000, now_iso=now)
        self.assertEqual((e["added_at"], e["created_at"], e["created_src"]), (now, "2023-11-14T22:13:20Z", "client"))
        for bad in (0, -5, "abc", 10 ** 15, (time.time() + 10 * 86400) * 1000, True and None):
            e = file_dates.stamp({}, client_ms=bad, now_iso=now)
            self.assertEqual((e["created_at"], e["created_src"]), (now, "added"), bad)
        src = _put("data/files/src.bin", b"x")
        os.utime(src, (1600000000, 1600000000))
        e = file_dates.stamp({}, src_path=src, now_iso=now)
        self.assertEqual((e["created_at"], e["created_src"]), ("2020-09-13T12:26:40Z", "source_mtime"))
        jp = _put("data/files/cam.jpg", _jpeg_with_exif(offset=b"+00:00"))
        e = file_dates.stamp({}, exif_path=jp, client_ms=1700000000000, src_path=src, now_iso=now)
        self.assertEqual(e["created_src"], "exif")
        e = file_dates.stamp({"created_at": "2025-01-01T00:00:00Z", "added_at": "2025-02-01T00:00:00Z"}, client_ms=1700000000000)
        self.assertEqual((e["created_at"], e["added_at"], e["created_src"]), ("2025-01-01T00:00:00Z", "2025-02-01T00:00:00Z", "existing"))

    def test_view_falls_back_for_legacy_entries(self):
        v = files_manager._view({"id": "x", "name": "a", "path": "data/files/a.txt", "updated_at": "2026-01-01T00:00:00+00:00"})
        self.assertEqual((v["added_at"], v["created_at"], v["created_src"]), ("2026-01-01T00:00:00+00:00",) * 2 + ("added",))


class BackfillTests(FMBase):
    def test_backfill_idempotent_and_backup_once(self):
        a = _put("data/files/a.txt")
        os.utime(a, (1600000000, 1600000000))
        reg_src = _put("chat-bridge/out/b.apk", b"apk")
        os.utime(reg_src, (1650000000, 1650000000))
        b = _put("data/files/b.apk", b"apk")
        _put("data/files/new.txt")  # mtime now > added -> capped at added
        jp = _put("data/files/c.jpg", _jpeg_with_exif(offset=b"+00:00"))
        _seed([
            {"id": "a1", "name": "a.txt", "path": "data/files/a.txt", "updated_at": "2026-10-01T00:00:00+00:00"},
            {"id": "b1", "name": "b.apk", "path": "data/files/b.apk", "updated_at": "2026-10-02T00:00:00+00:00",
             "registered_from": str(reg_src)},
            {"id": "c1", "name": "c.jpg", "path": "data/files/c.jpg", "updated_at": "2026-10-03T00:00:00+00:00"},
            {"id": "d1", "name": "new.txt", "path": "data/files/new.txt", "updated_at": "2026-09-01T00:00:00+00:00"},
            {"id": "e1", "name": "gone.txt", "path": "data/files/gone.txt", "updated_at": "2026-09-05T00:00:00+00:00"},
            {"id": "f1", "name": "p.md", "path": "data/files/missing.md", "updated_at": "2026-09-23T02:22:36Z",
             "created_at": "2026-09-23T02:22:36Z"},
        ])
        for x in server.FILES_FILE.parent.glob("files.json.bak-dates-*"):
            x.unlink()
        r = files_manager.backfill_dates()
        self.assertEqual(r["changed"], 6)
        self.assertTrue(r["backup"])
        self.assertEqual(oct((server.FILES_FILE.parent / r["backup"]).stat().st_mode & 0o777), "0o600")
        by = {e["id"]: e for e in server.load_files()}
        self.assertEqual((by["a1"]["added_at"], by["a1"]["created_at"], by["a1"]["created_src"]),
                         ("2026-10-01T00:00:00Z", "2020-09-13T12:26:40Z", "file_mtime"))
        self.assertEqual((by["b1"]["created_at"], by["b1"]["created_src"]), ("2022-04-15T05:20:00Z", "source_mtime"))
        self.assertEqual((by["c1"]["created_at"], by["c1"]["created_src"]), ("2021-07-04T09:30:00Z", "exif"))
        self.assertEqual((by["d1"]["created_at"], by["d1"]["created_src"]), ("2026-09-01T00:00:00Z", "added"))
        self.assertEqual((by["e1"]["created_at"], by["e1"]["created_src"]), ("2026-09-05T00:00:00Z", "added"))
        self.assertEqual((by["f1"]["added_at"], by["f1"]["created_at"], by["f1"]["created_src"]),
                         ("2026-09-23T02:22:36Z", "2026-09-23T02:22:36Z", "existing"))
        before = server.FILES_FILE.read_text()
        self.assertEqual(files_manager.backfill_dates(), {"changed": 0, "backup": None})
        self.assertEqual(server.FILES_FILE.read_text(), before)
        self.assertEqual(len(list(server.FILES_FILE.parent.glob("files.json.bak-dates-*"))), 1)


class WriterTests(FMBase):
    def _raw(self, path, body, ctype):
        conn = http.client.HTTPConnection("127.0.0.1", self.httpd.server_port, timeout=10)
        conn.request("POST", path, body=body, headers={"Host": HTTPS_HOST, "X-Forwarded-For": "198.51.100.10",
                                                       "X-Forwarded-Proto": "https", "Content-Type": ctype, "Cookie": self.owner})
        r = conn.getresponse(); data = r.read(); conn.close()
        return r.status, json.loads(data or b"{}")

    def test_chunked_upload_keeps_browser_last_modified(self):
        st, _, js, _ = self.j("/api/fm/uploads", {"name": "n.txt", "size": 3, "folder": "", "last_modified": 1700000000000})
        self.assertEqual(st, 200, js)
        uid = js["upload_id"]
        st, js = self._raw(f"/api/fm/uploads/{uid}/chunk?offset=0", b"abc", "application/octet-stream")
        self.assertEqual(st, 200, js)
        st, _, js, _ = self.j(f"/api/fm/uploads/{uid}/complete", {})
        self.assertEqual(st, 200, js)
        f = js["file"]
        self.assertEqual((f["created_at"], f["created_src"]), ("2023-11-14T22:13:20Z", "client"))
        self.assertTrue(f["added_at"])
        st, _, tree, _ = self.j("/api/fm/tree", method="GET")
        row = [x for x in tree["files"] if x["id"] == f["id"]][0]
        self.assertEqual((row["created_at"], row["created_src"]), ("2023-11-14T22:13:20Z", "client"))
        # no / bogus last_modified -> date added
        st, _, js, _ = self.j("/api/fm/uploads", {"name": "m.txt", "size": 1, "folder": "", "last_modified": "x"})
        uid = js["upload_id"]
        self._raw(f"/api/fm/uploads/{uid}/chunk?offset=0", b"a", "application/octet-stream")
        f = self.j(f"/api/fm/uploads/{uid}/complete", {})[2]["file"]
        self.assertEqual((f["created_src"], f["created_at"]), ("added", f["added_at"]))

    def test_multipart_upload_per_file_last_modified(self):
        bnd = "----nlbnd" + uuid.uuid4().hex
        parts = []
        for name, data in (("one.txt", b"1"), ("two.txt", b"2")):
            parts.append(f'--{bnd}\r\nContent-Disposition: form-data; name="file"; filename="{name}"\r\n'
                         f"Content-Type: text/plain\r\n\r\n".encode() + data + b"\r\n")
        for k, v in (("labels", "inbox"), ("last_modified", "1600000000000,")):
            parts.append(f'--{bnd}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
        body = b"".join(parts) + f"--{bnd}--\r\n".encode()
        st, js = self._raw("/api/files/upload", body, f"multipart/form-data; boundary={bnd}")
        self.assertEqual(st, 200, js)
        by = {e["name"]: e for e in server.load_files()}
        self.assertEqual((by["one.txt"]["created_at"], by["one.txt"]["created_src"]), ("2020-09-13T12:26:40Z", "client"))
        self.assertEqual(by["two.txt"]["created_src"], "added")

    def test_register_uses_source_mtime(self):
        src = _put("chat-bridge/out/nullkey-x-1234567.apk", b"apk")
        os.utime(src, (1650000000, 1650000000))
        st, _, js, _ = self.j("/api/files/register", {"path": str(src)})
        self.assertEqual(st, 200, js)
        e = [x for x in server.load_files() if x.get("registered_from") == str(src.resolve())][0]
        self.assertEqual((e["created_at"], e["created_src"]), ("2022-04-15T05:20:00Z", "source_mtime"))
        self.assertTrue(e["added_at"])
