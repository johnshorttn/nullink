"""Files manager — search (name + text contents) and file share links (2026-10-21).

GET  /api/fm/search?q=...&contents=1&folder=x   owner only; Nullink Files drive only.
     Name match on every live entry; contents match only for text files <= MAX_FILE_BYTES,
     total scanned bytes capped at MAX_SCAN_BYTES, results capped at MAX_RESULTS.
GET  /api/fm/shares?file_id=...                  list file links
POST /api/fm/shares {"file_id","ttl"}            create (1h/24h/7d/30d) -> {"id","url"}
POST /api/fm/shares/<SF-id>/revoke
The Server drive (/api/sd) has no share or search route; links resolve only files.json entries.
"""
from __future__ import annotations

import os
import re

import files_manager as fm

MAX_Q = 200
MAX_RESULTS = 200
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_SCAN_BYTES = 64 * 1024 * 1024
SNIPPET = 60


def route(h, method, path, qs) -> bool:
    if path == "/api/fm/search" and method == "GET":
        _search(h, qs)
        return True
    if path == "/api/fm/shares":
        import share_links
        if method == "GET":
            fid = (qs.get("file_id") or [""])[0] or None
            h._json(200, {"links": share_links.file_links(fid)})
            return True
        if method == "POST":
            return _create(h)
        raise fm._Err(405, "method_not_allowed")
    m = re.match(r"^/api/fm/shares/(SF-[A-Z0-9]{6})/revoke$", path)
    if m and method == "POST":
        import share_links
        rec = h._require_owner() or {}
        ok = share_links.revoke_file_link(m.group(1), "owner:" + str(rec.get("id")))
        h._json(200 if ok else 404, {"ok": ok})
        return True
    return False


def _create(h) -> bool:
    import share_links
    S = fm.S
    b = fm._body(h)
    fid = str(b.get("file_id") or "")
    ttl = str(b.get("ttl") or "7d")
    if ttl not in share_links.FILE_TTLS:
        raise fm._Err(400, "bad_ttl")
    entry = next((e for e in S.load_files() if isinstance(e, dict) and e.get("id") == fid), None)
    if not entry or entry.get("trashed_at"):
        raise fm._Err(404, "not_found")
    p = fm.safe_entry_path(entry)
    if p is None:
        raise fm._Err(400, "unshareable")
    try:
        p.resolve().relative_to((S.BASE / "secrets").resolve())
        raise fm._Err(403, "unshareable")
    except ValueError:
        pass
    rec = h._require_owner() or {}
    lid, url = share_links.create_file_link(fid, entry.get("name"), "owner:" + str(rec.get("id")), ttl,
                                            host=getattr(h, "req_host", None))
    h._json(201, {"id": lid, "url": url, "ttl": ttl})
    return True


def _snippet(text: str, i: int, n: int) -> str:
    a, b = max(0, i - SNIPPET), min(len(text), i + n + SNIPPET)
    s = text[a:b].replace("\r", " ").replace("\n", " ")
    return ("…" if a else "") + s + ("…" if b < len(text) else "")


def _search(h, qs) -> None:
    S = fm.S
    q = ((qs.get("q") or [""])[0]).strip()
    if not q or len(q) > MAX_Q:
        raise fm._Err(400, "bad_query")
    contents = (qs.get("contents") or ["1"])[0] not in ("0", "false", "")
    folder = fm.norm_folder((qs.get("folder") or [""])[0])
    if folder is None:
        raise fm._Err(400, "bad_folder")
    ql = q.lower()
    results, scanned, truncated = [], 0, False
    for f in fm.load_folders():
        if ql in f.split("/")[-1].lower() and (not folder or fm._under(f, folder)):
            results.append({"type": "folder", "folder": f, "match": "name"})
    for e in S.load_files():
        if len(results) >= MAX_RESULTS:
            truncated = True
            break
        if not isinstance(e, dict) or e.get("trashed_at"):
            continue
        ef = str(e.get("folder") or "")
        if folder and not fm._under(ef, folder):
            continue
        name = str(e.get("name") or "")
        if ql in name.lower():
            results.append({"type": "file", "match": "name", **fm._view(e)})
            continue
        if not contents or fm.preview_kind(e) == "image" or not S.is_text_file(name):
            continue
        p = fm.safe_entry_path(e)
        if p is None:
            continue
        try:
            size = os.lstat(p).st_size
        except OSError:
            continue
        if size > MAX_FILE_BYTES:
            continue
        if scanned + size > MAX_SCAN_BYTES:
            truncated = True
            continue
        scanned += size
        try:
            text = p.read_bytes().decode("utf-8", "replace")
        except OSError:
            continue
        i = text.lower().find(ql)
        if i >= 0:
            line = text.count("\n", 0, i) + 1
            results.append({"type": "file", "match": "content", "line": line,
                            "snippet": _snippet(text, i, len(q)), **fm._view(e)})
    h._json(200, {"q": q, "results": results, "truncated": truncated, "scanned_bytes": scanned})
