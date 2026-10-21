"""Files manager (Slice 1, 2026-10-20): virtual folder tree + Trash over data/files.json.

Folders are metadata only: each files.json entry gains ``folder`` ("" = root, "a/b" nested)
and ``trashed_at`` (null or ISO time). Nothing on disk is moved; file IDs and ``path`` are
untouched, so existing links (#files/<id>), Ask Morc and the old /api/files/* routes keep
working. Empty folders live in data/fm_folders.json. Owner cookie session only; trash /
empty-trash need step-up. Bound to the server module like share_links.py.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import threading
import time
import urllib.parse
from pathlib import Path

S = None  # server module
_lock = threading.RLock()
FM_VERSION = 1
MAX_SEG = 120
MAX_DEPTH = 16
# Inline preview is only allowed for these raster types; everything else (HTML, SVG, PDF,
# scripts...) is forced to download as application/octet-stream.
SAFE_INLINE = {
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".gif": "image/gif", ".webp": "image/webp", ".bmp": "image/bmp", ".avif": "image/avif",
}
MAX_TEXT_PREVIEW = 2 * 1024 * 1024
_SEG_BAD = re.compile(r"[\x00-\x1f\x7f/\\]")


def bind(mod):
    global S
    S = mod


def _folders_file() -> Path:
    return S.DATA / "fm_folders.json"


# ---------- validation ----------
def norm_folder(raw) -> str | None:
    """Normalize a virtual folder path ("" = root). None if invalid / traversal."""
    if raw is None:
        return ""
    s = str(raw).strip().strip("/")
    if not s:
        return ""
    parts = s.split("/")
    if len(parts) > MAX_DEPTH:
        return None
    out = []
    for p in parts:
        p = p.strip()
        if not p or p in (".", "..") or len(p) > MAX_SEG or _SEG_BAD.search(p):
            return None
        out.append(p)
    return "/".join(out)


def valid_name(raw) -> str | None:
    s = str(raw or "").strip()
    if not s or s in (".", "..") or len(s) > 200 or _SEG_BAD.search(s):
        return None
    return s


def safe_entry_path(entry: dict) -> Path | None:
    """Real file for an entry: relative, under BASE (safe_rel_under), no symlink anywhere."""
    rel = str(entry.get("path") or "")
    if not rel or rel.startswith("/") or "\x00" in rel:
        return None
    if any(part == ".." for part in Path(rel).parts):
        return None
    if S.safe_rel_under(S.BASE, rel) is None:
        return None
    cur = S.BASE
    for part in Path(rel).parts:
        cur = cur / part
        try:
            st = os.lstat(cur)
        except OSError:
            return None
        if stat.S_ISLNK(st.st_mode):
            return None
    try:
        if not stat.S_ISREG(os.lstat(cur).st_mode):
            return None
    except OSError:
        return None
    return cur


# ---------- storage ----------
def load_folders() -> list[str]:
    try:
        data = json.loads(_folders_file().read_text(encoding="utf-8"))
        return sorted({f for f in (norm_folder(x) for x in data.get("folders") or []) if f})
    except (OSError, ValueError, AttributeError):
        return []


def save_folders(folders) -> None:
    clean = sorted({f for f in folders if f})
    _folders_file().parent.mkdir(parents=True, exist_ok=True)
    tmp = _folders_file().with_suffix(".json.tmp")
    tmp.write_text(json.dumps({"version": FM_VERSION, "folders": clean}, indent=2), encoding="utf-8")
    os.replace(tmp, _folders_file())


def _with_parents(folders) -> set[str]:
    out = set()
    for f in folders:
        parts = f.split("/") if f else []
        for i in range(1, len(parts) + 1):
            out.add("/".join(parts[:i]))
    return out


def migrate() -> dict:
    """Idempotent in-place migration of data/files.json. Backs up once before the first write.
    Never moves files on disk and never changes ids or paths."""
    with _lock:
        ff = S.FILES_FILE
        if not ff.exists():
            return {"changed": 0, "backup": None}
        files = S.load_files()
        changed = 0
        for e in files:
            if not isinstance(e, dict):
                continue
            before = (e.get("folder"), e.get("trashed_at", "<missing>"), e.get("fm"))
            f = norm_folder(e.get("folder"))
            e["folder"] = f if f is not None else ""
            if "trashed_at" not in e:
                e["trashed_at"] = None
            e["fm"] = FM_VERSION
            if before != (e.get("folder"), e.get("trashed_at", "<missing>"), e.get("fm")):
                changed += 1
        backup = None
        prior = sorted(ff.parent.glob(f"files.json.bak-fm{FM_VERSION}-*"))
        if changed and not prior:
            backup = ff.with_name(f"files.json.bak-fm{FM_VERSION}-{time.strftime('%Y%m%d-%H%M%S')}")
            n = 1
            while backup.exists():
                backup = ff.with_name(f"files.json.bak-fm{FM_VERSION}-{time.strftime('%Y%m%d-%H%M%S')}-{n}")
                n += 1
            shutil.copy2(ff, backup)
            try:
                os.chmod(backup, 0o600)
            except OSError:
                pass
        if changed:
            S.save_files(files)
        folders = set(load_folders()) | _with_parents({e.get("folder") or "" for e in files if isinstance(e, dict)})
        if set(load_folders()) != folders:
            save_folders(folders)
        return {"changed": changed, "backup": str(backup.name) if backup else None}


def _view(e: dict) -> dict:
    return {k: e.get(k) for k in ("id", "name", "path", "labels", "size", "updated_at", "source",
                                  "folder", "trashed_at")} | {"preview": preview_kind(e)}


def preview_kind(e: dict) -> str:
    name = str(e.get("name") or e.get("path") or "")
    ext = os.path.splitext(name.lower())[1]
    if ext in SAFE_INLINE:
        return "image"
    if ext in (".html", ".htm", ".svg", ".xhtml"):
        return "none"  # never rendered; plain-text view is still offered via /content
    if S.is_text_file(name):
        return "text"
    return "none"


# ---------- HTTP ----------
def _owner(h) -> bool:
    if h.headers.get("Authorization") is not None:
        h._json(403, {"error": "forbidden", "message": "owner cookie session required"})
        return False
    return h._require_owner() is not None


def handle(h, method: str, path: str, qs) -> bool:
    if not path.startswith("/api/fm"):
        return False
    if path != "/api/fm" and not path.startswith("/api/fm/"):
        return False
    if h.headers.get("Authorization") is not None:
        h._json(403, {"error": "forbidden", "message": "owner cookie session required"})
        return True
    rec = h._require_owner()
    if rec is None:
        return True
    if path == "/api/fm/favorites" or path.startswith("/api/fm/favorites/"):
        import favorites
        favorites.handle(h, method, path, rec)
        return True
    if method == "POST" and path in ("/api/fm/trash", "/api/fm/empty-trash", "/api/fm/purge"):
        if not h._require_stepup():
            return True
    migrate()
    try:
        return _route(h, method, path, qs)
    except _Err as e:
        h._json(e.code, {"error": e.err, **e.extra})
        return True


class _Err(Exception):
    def __init__(self, code, err, **extra):
        self.code, self.err, self.extra = code, err, extra


def _body(h) -> dict:
    b = h._read_json()
    return b if isinstance(b, dict) else {}


def _route(h, method, path, qs) -> bool:
    import fm_uploads
    if fm_uploads.route(h, method, path, qs):
        return True
    import fm_search
    if fm_search.route(h, method, path, qs):
        return True
    m = re.match(r"^/api/fm/files/([A-Za-z0-9_-]{1,64})(/download|/content|/preview)?$", path)
    if m and method == "GET":
        fid, sub = m.group(1), m.group(2) or ""
        if sub == "/download":
            h._file_download(fid)
        elif sub == "/content":
            h._file_content(fid)
        elif sub == "/preview":
            _preview(h, fid)
        else:
            h._file_get(fid)
        return True
    if method == "GET" and path == "/api/fm/tree":
        files = S.load_files()
        live = [_view(e) for e in files if isinstance(e, dict) and not e.get("trashed_at")]
        trash = sum(1 for e in files if isinstance(e, dict) and e.get("trashed_at"))
        h._json(200, {"folders": load_folders(), "files": live, "trash_count": trash})
        return True
    if method == "GET" and path == "/api/fm/trash":
        files = [_view(e) for e in S.load_files() if isinstance(e, dict) and e.get("trashed_at")]
        h._json(200, {"files": files})
        return True
    if method == "POST" and path == "/api/fm/upload":
        folder = norm_folder((qs.get("folder") or [""])[0])
        if folder is None:
            raise _Err(400, "bad_folder")
        h._fm_upload_folder = folder
        try:
            h._file_upload()
        finally:
            h._fm_upload_folder = None
        if folder:
            with _lock:
                save_folders(set(load_folders()) | _with_parents({folder}))
        return True
    if method != "POST":
        raise _Err(404, "not_found")
    b = _body(h)
    if path == "/api/fm/folders":
        return _mkdir(h, b)
    if path == "/api/fm/rename":
        return _rename(h, b)
    if path == "/api/fm/move":
        return _move(h, b)
    if path == "/api/fm/trash":
        return _trash(h, b)
    if path == "/api/fm/restore":
        return _restore(h, b)
    if path in ("/api/fm/empty-trash", "/api/fm/purge"):
        return _empty_trash(h, b, only=None if path == "/api/fm/empty-trash" else b.get("ids"))
    raise _Err(404, "not_found")


def _ids(b) -> list[str]:
    ids = b.get("ids")
    if ids is None and b.get("id"):
        ids = [b.get("id")]
    if not isinstance(ids, list):
        return []
    return [str(x) for x in ids if isinstance(x, (str, int))][:500]


def _folder_list(b) -> list[str]:
    raw = b.get("folders")
    if not isinstance(raw, list):
        return []
    out = []
    for x in raw[:200]:
        f = norm_folder(x)
        if not f:
            raise _Err(400, "bad_folder")
        out.append(f)
    return out


def _under(f: str, root: str) -> bool:
    return f == root or f.startswith(root + "/")


def _mkdir(h, b) -> bool:
    parent = norm_folder(b.get("parent"))
    name = valid_name(b.get("name"))
    if parent is None or name is None:
        raise _Err(400, "bad_folder")
    full = norm_folder(f"{parent}/{name}" if parent else name)
    if not full:
        raise _Err(400, "bad_folder")
    with _lock:
        folders = set(load_folders())
        if full in folders:
            raise _Err(409, "exists")
        save_folders(folders | _with_parents({full}))
    h._json(201, {"ok": True, "folder": full})
    return True


def _rename(h, b) -> bool:
    name = valid_name(b.get("name"))
    if name is None:
        raise _Err(400, "bad_name")
    with _lock:
        if b.get("folder") is not None:
            old = norm_folder(b.get("folder"))
            if not old:
                raise _Err(400, "bad_folder")
            parent = old.rsplit("/", 1)[0] if "/" in old else ""
            new = norm_folder(f"{parent}/{name}" if parent else name)
            if not new:
                raise _Err(400, "bad_folder")
            folders = set(load_folders())
            if old not in folders:
                raise _Err(404, "not_found")
            if new != old and new in folders:
                raise _Err(409, "exists")
            _relocate(folders, old, new)
            h._json(200, {"ok": True, "folder": new})
            return True
        fid = str(b.get("id") or "")
        files = S.load_files()
        e = next((x for x in files if isinstance(x, dict) and x.get("id") == fid), None)
        if not e:
            raise _Err(404, "not_found")
        e["name"] = name  # display name only; disk path untouched
        e["updated_at"] = S.iso_now()
        S.save_files(files)
        h._json(200, {"ok": True, "file": _view(e)})
        return True


def _relocate(folders: set, old: str, new: str) -> None:
    def mv(f):
        return new + f[len(old):] if _under(f, old) else f
    S.save_files([({**e, "folder": mv(e.get("folder") or "")} if isinstance(e, dict) else e)
                  for e in S.load_files()])
    save_folders(_with_parents({mv(f) for f in folders}))


def _move(h, b) -> bool:
    dest = norm_folder(b.get("dest"))
    if dest is None:
        raise _Err(400, "bad_folder")
    ids, flds = _ids(b), _folder_list(b)
    with _lock:
        folders = set(load_folders())
        if dest and dest not in folders:
            raise _Err(404, "dest_not_found")
        for f in flds:
            if f not in folders:
                raise _Err(404, "not_found", folder=f)
            if _under(dest, f):
                raise _Err(400, "move_into_self")
        moved = 0
        if ids:
            files = S.load_files()
            for e in files:
                if isinstance(e, dict) and e.get("id") in ids and not e.get("trashed_at"):
                    e["folder"] = dest
                    moved += 1
            S.save_files(files)
        for f in flds:
            leaf = f.rsplit("/", 1)[-1]
            new = f"{dest}/{leaf}" if dest else leaf
            folders = set(load_folders())
            if new != f and new in folders:
                raise _Err(409, "exists", folder=new)
            _relocate(folders, f, new)
            moved += 1
    h._json(200, {"ok": True, "moved": moved})
    return True


def _trash(h, b) -> bool:
    ids, flds = set(_ids(b)), _folder_list(b)
    now = S.iso_now()
    with _lock:
        files = S.load_files()
        n = 0
        for e in files:
            if not isinstance(e, dict) or e.get("trashed_at"):
                continue
            if e.get("id") in ids or any(_under(e.get("folder") or "", f) for f in flds):
                e["trashed_at"] = now
                n += 1
        S.save_files(files)
        if flds:
            save_folders({f for f in load_folders() if not any(_under(f, r) for r in flds)})
    h._json(200, {"ok": True, "trashed": n})
    return True


def _restore(h, b) -> bool:
    ids = set(_ids(b))
    with _lock:
        files = S.load_files()
        back = set()
        n = 0
        for e in files:
            if isinstance(e, dict) and e.get("trashed_at") and e.get("id") in ids:
                e["trashed_at"] = None
                back.add(e.get("folder") or "")
                n += 1
        S.save_files(files)
        save_folders(set(load_folders()) | _with_parents(back))
    h._json(200, {"ok": True, "restored": n})
    return True


DELETABLE_PREFIXES = ("uploads/", "data/files/", "scratch/", "playground/")


def _empty_trash(h, b, only) -> bool:
    only = set(str(x) for x in only) if isinstance(only, list) else None
    with _lock:
        files = S.load_files()
        keep, gone = [], []
        for e in files:
            if isinstance(e, dict) and e.get("trashed_at") and (only is None or e.get("id") in only):
                gone.append(e)
            else:
                keep.append(e)
        S.save_files(keep)
    still_used = {str(e.get("path")) for e in keep if isinstance(e, dict)}
    removed = 0
    for e in gone:
        rel = str(e.get("path") or "")
        fp = safe_entry_path(e)
        if fp and rel not in still_used and rel.startswith(DELETABLE_PREFIXES):
            try:
                fp.unlink()
                removed += 1
            except OSError:
                pass
    h._json(200, {"ok": True, "purged": len(gone), "files_removed": removed})
    return True


def _preview(h, fid: str) -> None:
    e = next((x for x in S.load_files() if isinstance(x, dict) and x.get("id") == fid), None)
    if not e:
        return h._json(404, {"error": "not_found"})
    fp = safe_entry_path(e)
    if not fp:
        return h._json(404, {"error": "missing_file"})
    kind = preview_kind(e)
    if kind != "image":
        return h._json(415, {"error": "no_inline_preview", "kind": kind})
    ext = os.path.splitext(str(e.get("name") or e.get("path") or "").lower())[1]
    data = fp.read_bytes()
    h._send(200, data, SAFE_INLINE[ext], [
        ("Content-Disposition", "inline"),
        ("X-Content-Type-Options", "nosniff"),
        ("Content-Security-Policy", "default-src 'none'; sandbox"),
    ])
