"""Files manager — chunked/resumable uploads + streamed zip download (2026-10-21).

Uploads (owner cookie session only; routed through files_manager.handle):
  POST /api/fm/uploads                 {"name","size","folder"} -> {"upload_id","chunk_size","received"}
  GET  /api/fm/uploads/<id>            -> {"received","size",...}   (resume: continue at "received")
  POST /api/fm/uploads/<id>/chunk?offset=N   raw body (<= MAX_CHUNK); offset must equal received
  POST /api/fm/uploads/<id>/complete   -> registers the file in data/files.json
  POST /api/fm/uploads/<id>/abort
Parts are streamed to uploads/.parts/<id>.part (never held in memory); files up to MAX_FILE;
stale parts (untouched > STALE_SECS) are removed on create and at startup.

Zip: GET /api/fm/zip?ids=a,b&folders=x/y -> streamed application/zip (no Content-Length,
connection closed at end). Folders include their whole subtree; trashed files are skipped.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import threading
import time
import uuid
import zipfile
from pathlib import Path

import files_manager as fm

MAX_FILE = 5 * 1024 ** 3 + 64 * 1024 ** 2   # ~5 GB (+ slack)
CHUNK_SIZE = 8 * 1024 ** 2
MAX_CHUNK = 16 * 1024 ** 2
STALE_SECS = 24 * 3600
MIN_FREE = 512 * 1024 ** 2
MAX_ACTIVE = 20
_ID = re.compile(r"^[a-f0-9]{24}$")
_locks: dict[str, threading.Lock] = {}
_glock = threading.Lock()


def _S():
    return fm.S


def parts_dir() -> Path:
    d = _S().UPLOADS / ".parts"
    d.mkdir(parents=True, exist_ok=True)
    if d.is_symlink():
        raise fm._Err(500, "parts_symlink")
    try:
        d.chmod(0o700)
    except OSError:
        pass
    return d


def _meta_path(uid: str) -> Path:
    return parts_dir() / f"{uid}.json"


def _part_path(uid: str) -> Path:
    return parts_dir() / f"{uid}.part"


def _lock(uid: str) -> threading.Lock:
    with _glock:
        return _locks.setdefault(uid, threading.Lock())


def _load(uid: str) -> dict:
    if not _ID.match(uid or ""):
        raise fm._Err(404, "upload_not_found")
    try:
        meta = json.loads(_meta_path(uid).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise fm._Err(404, "upload_not_found")
    p = _part_path(uid)
    meta["received"] = p.stat().st_size if p.exists() and not p.is_symlink() else 0
    return meta


def _save(meta: dict) -> None:
    m = {k: v for k, v in meta.items() if k != "received"}
    tmp = _meta_path(meta["upload_id"]).with_suffix(".json.tmp")
    tmp.write_text(json.dumps(m), encoding="utf-8")
    os.replace(tmp, _meta_path(meta["upload_id"]))


def _remove(uid: str) -> None:
    for p in (_meta_path(uid), _part_path(uid)):
        try:
            p.unlink()
        except FileNotFoundError:
            pass
    with _glock:
        _locks.pop(uid, None)


def cleanup_stale(now: float | None = None) -> int:
    """Delete parts/metadata not touched for STALE_SECS. Returns number of uploads removed."""
    now = now or time.time()
    removed = 0
    try:
        d = parts_dir()
    except Exception:
        return 0
    seen = set()
    for p in d.iterdir():
        uid = p.name.split(".", 1)[0]
        if uid in seen:
            continue
        seen.add(uid)
        newest = 0.0
        for q in (d / f"{uid}.json", d / f"{uid}.part"):
            try:
                newest = max(newest, q.lstat().st_mtime)
            except OSError:
                pass
        if now - newest > STALE_SECS:
            _remove(uid)
            removed += 1
    for p in d.glob("*.tmp"):
        try:
            if now - p.lstat().st_mtime > STALE_SECS:
                p.unlink()
        except OSError:
            pass
    return removed


def route(h, method: str, path: str, qs) -> bool:
    """Called by files_manager._route before JSON body parsing. Returns True if handled."""
    if method == "GET" and path == "/api/fm/zip":
        _zip(h, qs)
        return True
    if not (path == "/api/fm/uploads" or path.startswith("/api/fm/uploads/")):
        return False
    if path == "/api/fm/uploads":
        if method != "POST":
            raise fm._Err(405, "method_not_allowed")
        return _create(h)
    m = re.match(r"^/api/fm/uploads/([a-f0-9]{24})(/chunk|/complete|/abort)?$", path)
    if not m:
        raise fm._Err(404, "not_found")
    uid, sub = m.group(1), m.group(2) or ""
    if method == "GET" and not sub:
        h._json(200, _public(_load(uid)))
        return True
    if method != "POST":
        raise fm._Err(405, "method_not_allowed")
    if sub == "/chunk":
        return _chunk(h, uid, qs)
    if sub == "/complete":
        return _complete(h, uid)
    if sub == "/abort":
        _load(uid)
        _remove(uid)
        h._json(200, {"ok": True})
        return True
    raise fm._Err(404, "not_found")


def _public(meta: dict) -> dict:
    return {k: meta.get(k) for k in ("upload_id", "name", "size", "folder", "received", "created_at")} | {
        "chunk_size": CHUNK_SIZE}


def _create(h) -> bool:
    b = fm._body(h)
    S = _S()
    name = Path(str(b.get("name") or "")).name.strip()
    if not name or not S.allowed_upload_name(name) or len(name) > 255:
        raise fm._Err(400, "bad_name")
    try:
        size = int(b.get("size"))
    except (TypeError, ValueError):
        raise fm._Err(400, "bad_size")
    if size < 0:
        raise fm._Err(400, "bad_size")
    if size > MAX_FILE:
        raise fm._Err(413, "too_large", message="Max 5 GB per file.")
    folder = fm.norm_folder(b.get("folder") or "")
    if folder is None:
        raise fm._Err(400, "bad_folder")
    cleanup_stale()
    d = parts_dir()
    if len(list(d.glob("*.json"))) >= MAX_ACTIVE:
        raise fm._Err(429, "too_many_uploads", message="Too many unfinished uploads; finish or cancel some.")
    if shutil.disk_usage(d).free < size + MIN_FREE:
        raise fm._Err(507, "insufficient_storage")
    uid = uuid.uuid4().hex[:24]
    meta = {"upload_id": uid, "name": name, "size": size, "folder": folder,
            "created_at": S.iso_now()}
    _save(meta)
    _part_path(uid).touch(mode=0o600)
    meta["received"] = 0
    h._json(200, _public(meta))
    return True


def _chunk(h, uid: str, qs) -> bool:
    try:
        offset = int((qs.get("offset") or ["-1"])[0])
        length = int(h.headers.get("Content-Length") or -1)
    except ValueError:
        raise fm._Err(400, "bad_request")
    if length < 0 or length > MAX_CHUNK:
        raise fm._Err(413, "chunk_too_large", max=MAX_CHUNK)
    lk = _lock(uid)
    if not lk.acquire(blocking=False):
        raise fm._Err(409, "busy")
    try:
        meta = _load(uid)
        if offset != meta["received"]:
            h.close_connection = True
            raise fm._Err(409, "offset_mismatch", received=meta["received"])
        if meta["received"] + length > meta["size"]:
            h.close_connection = True
            raise fm._Err(400, "exceeds_size", received=meta["received"])
        p = _part_path(uid)
        fd = os.open(p, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
        got = 0
        try:
            with os.fdopen(fd, "ab", closefd=True) as out:
                while got < length:
                    buf = h.rfile.read(min(1024 * 1024, length - got))
                    if not buf:
                        break
                    out.write(buf)
                    got += len(buf)
        finally:
            if got < length:  # client dropped mid-chunk: truncate back to the last whole chunk
                with open(p, "r+b") as f:
                    f.truncate(offset)
        if got < length:
            h.close_connection = True
            raise fm._Err(400, "incomplete_chunk", received=offset)
        h._json(200, {"ok": True, "received": offset + got, "size": meta["size"]})
        return True
    finally:
        lk.release()


def _complete(h, uid: str) -> bool:
    S = _S()
    lk = _lock(uid)
    if not lk.acquire(blocking=False):
        raise fm._Err(409, "busy")
    try:
        meta = _load(uid)
        if meta["received"] != meta["size"]:
            raise fm._Err(409, "incomplete", received=meta["received"], size=meta["size"])
        labels = ["inbox"]
        dest_dir = S.upload_dest_for_labels(labels)
        fid = uuid.uuid4().hex[:12]
        safe = S.slugify(meta["name"])
        dest = dest_dir / safe
        if dest.exists() or dest.is_symlink():
            stem, suf = Path(safe).stem, Path(safe).suffix
            dest = dest_dir / f"{stem}-{fid[:6]}{suf}"
        os.replace(_part_path(uid), dest)
        try:
            dest.chmod(0o644)
        except OSError:
            pass
        entry = {
            "id": fid, "name": meta["name"], "path": str(dest.relative_to(S.BASE)),
            "labels": labels, "size": meta["size"], "updated_at": S.iso_now(), "source": "upload",
            "folder": meta.get("folder") or "", "trashed_at": None, "fm": fm.FM_VERSION,
        }
        with fm._lock:
            files = S.load_files()
            files.append(entry)
            S.save_files(files)
            if entry["folder"]:
                fm.save_folders(set(fm.load_folders()) | fm._with_parents({entry["folder"]}))
        _remove(uid)
    finally:
        lk.release()
    try:
        S.write_pending("upload", {"file_id": fid, "file_ids": [fid], "name": entry["name"],
                                   "names": [entry["name"]], "path": entry["path"], "labels": labels,
                                   "count": 1, "preview": f"Uploaded 1 file(s): {entry['name']}"})
        S.fire_webhook("upload", f"Uploaded 1 file(s): {entry['name']}")
    except Exception:
        pass
    h._json(200, {"ok": True, "file": entry})
    return True


# ---------- zip ----------
def _csv(qs, key) -> list[str]:
    out = []
    for v in qs.get(key) or []:
        out.extend(x for x in str(v).split(",") if x)
    return out[:2000]


def _zip(h, qs) -> None:
    S = _S()
    ids = set(_csv(qs, "ids"))
    folders = []
    for f in _csv(qs, "folders"):
        nf = fm.norm_folder(f)
        if nf is None:
            raise fm._Err(400, "bad_folder")
        folders.append(nf)
    if not ids and not folders:
        raise fm._Err(400, "nothing_selected")
    files = [e for e in S.load_files() if isinstance(e, dict) and not e.get("trashed_at")]
    items: list[tuple[str, Path]] = []
    used: set[str] = set()

    def add(arc: str, entry: dict):
        p = fm.safe_entry_path(entry)
        if p is None:
            return
        base, n = arc, 1
        while arc in used:
            stem, suf = os.path.splitext(base)
            arc = f"{stem} ({n}){suf}"
            n += 1
        used.add(arc)
        items.append((arc, p))

    for e in files:
        if str(e.get("id")) in ids:
            add(fm.valid_name(e.get("name")) or Path(str(e.get("path"))).name, e)
    dirs: list[str] = []
    for f in folders:
        top = f.split("/")[-1]
        dirs.append(top + "/")
        for sub in fm.load_folders():
            if fm._under(sub, f) and sub != f:
                dirs.append(top + "/" + sub[len(f) + 1:] + "/")
        for e in files:
            ef = str(e.get("folder") or "")
            if fm._under(ef, f):
                rel = ef[len(f):].lstrip("/")
                nm = fm.valid_name(e.get("name")) or Path(str(e.get("path"))).name
                add("/".join(x for x in (top, rel, nm) if x), e)
    if not items and not dirs:
        raise fm._Err(404, "nothing_to_zip")
    zname = (folders[0].split("/")[-1] if len(folders) == 1 and not ids else "nullink-files") + ".zip"
    h.send_response(200)
    h.send_header("Content-Type", "application/zip")
    h.send_header("Content-Disposition", f'attachment; filename="{S.slugify(zname)}"')
    h.send_header("Cache-Control", "no-store")
    h.send_header("X-Content-Type-Options", "nosniff")
    h.send_header("Connection", "close")
    h.end_headers()
    h.close_connection = True
    try:
        with zipfile.ZipFile(_Sink(h.wfile), "w", zipfile.ZIP_STORED, allowZip64=True) as z:
            for d in dict.fromkeys(dirs):
                z.writestr(zipfile.ZipInfo(d), b"")
            for arc, p in items:
                zi = zipfile.ZipInfo.from_file(p, arc)
                zi.compress_type = zipfile.ZIP_STORED
                with open(p, "rb") as src, z.open(zi, "w", force_zip64=True) as dst:
                    shutil.copyfileobj(src, dst, 1024 * 1024)
    except (BrokenPipeError, ConnectionResetError):
        pass


class _Sink:
    """Non-seekable write-only wrapper so zipfile streams with data descriptors."""

    def __init__(self, w):
        self.w, self.n = w, 0

    def write(self, b):
        self.w.write(b)
        self.n += len(b)
        return len(b)

    def tell(self):
        return self.n

    def flush(self):
        try:
            self.w.flush()
        except Exception:
            pass

    def seekable(self):
        return False
