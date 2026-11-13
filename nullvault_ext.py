"""NullVault extensions (2026-11-12, John: Links, Projects and Files tabs). All under NULLVAULT_ENABLED.

Sub-flags (default OFF):
  NULLVAULT_LINKS=1   links + projects stores, included in /api/vault/sync, signed writes
                      (device/write with "kind": "link" | "project"), discovered-site and repo suggestions.
  NULLVAULT_FILES=1   device access to Nullink Files: a fingerprint-signed files session (10 min), list with
                      labels newest first and the "Latest" flag, Range downloads, signed uploads/deletes.

Links and projects are not secret, but only an owner cookie session or a signed device request can read
or change them. Projects hold references only (link ids, vault entry ids), never secret values.
Discovery is read-only: Caddy admin API GET http://localhost:2019/config/, then a readable Caddyfile,
then the admin seed file data/nullvault/discovered_sites.json. Repo suggestions come from
data/nullvault/repo_catalog.json (admin seed; same shape as account-repo-catalog.json).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import socket
import sys
import threading
import time
import urllib.parse
import urllib.request
import uuid
from datetime import datetime
from pathlib import Path

nv = None      # nullvault module
server = None  # live server module

FILES_SESSION_TTL = 600
CADDY_ADMIN = "http://localhost:2019/config/"
CADDYFILE = Path("/etc/caddy/Caddyfile")
DISCOVERY_TTL = 300
MAX_LINKS = 500
MAX_PROJECTS = 200
_lock = threading.RLock()
_sessions: dict[str, dict] = {}
_disc_cache: dict = {"t": 0.0, "sites": [], "source": None}


def bind(nv_mod, srv):
    global nv, server
    nv, server = nv_mod, srv


def links_enabled() -> bool:
    return os.environ.get("NULLVAULT_LINKS", "0") == "1"


def notes_enabled() -> bool:
    return links_enabled() and os.environ.get("NULLVAULT_NOTES", "0") == "1"


def files_enabled() -> bool:
    return os.environ.get("NULLVAULT_FILES", "0") == "1"


def server_label() -> str:
    return os.environ.get("NULLVAULT_SERVER_LABEL") or socket.gethostname()[:60]


def _now_iso() -> str:
    return server.iso_now()


def _store(name: str) -> Path:
    return nv.nv_dir() / name


def _load_list(name: str) -> list:
    try:
        d = json.loads(_store(name).read_text(encoding="utf-8"))
        return d.get("items", []) if isinstance(d, dict) else []
    except (OSError, ValueError):
        return []


def _save_list(name: str, items: list) -> None:
    server._atomic_write_json(_store(name), {"items": items})


# ---------------------------------------------------------------- validation

def clean_url(u) -> str | None:
    u = str(u or "").strip()
    if len(u) > 2000:
        return None
    p = urllib.parse.urlsplit(u)
    if p.scheme not in ("http", "https") or not p.hostname or any(c in u for c in "\r\n\t <>\"'`"):
        return None
    return urllib.parse.urlunsplit(p)


def _text(v, n=200) -> str:
    return "".join(ch for ch in str(v or "") if ch.isprintable()).strip()[:n]


def _ids(v, n=200) -> list[str]:
    if not isinstance(v, list):
        return []
    out = []
    for x in v[:n]:
        x = str(x)
        if re.fullmatch(r"[A-Za-z0-9_-]{1,64}", x) and x not in out:
            out.append(x)
    return out


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


def link_from(e: dict, cur: dict | None = None) -> dict | None:
    cur = cur or {}
    url = clean_url(e.get("url", cur.get("url")))
    if not url:
        return None
    host = urllib.parse.urlsplit(url).hostname or ""
    return {"id": cur.get("id") or _new_id(),
            "name": _text(e.get("name", cur.get("name"))) or host,
            "url": url,
            "host_label": _text(e.get("host_label", cur.get("host_label")), 80) or server_label(),
            "created_at": cur.get("created_at") or _now_iso(), "updated_at": _now_iso()}


def project_from(e: dict, cur: dict | None = None) -> dict | None:
    cur = cur or {}
    name = _text(e.get("name", cur.get("name")), 120)
    if not name:
        return None
    repo = e.get("repo_url", cur.get("repo_url"))
    repo = clean_url(repo) if repo else None
    if e.get("repo_url") and not repo:
        return None
    return {"id": cur.get("id") or _new_id(), "name": name, "repo_url": repo,
            "server": _text(e.get("server", cur.get("server")), 80) or None,
            "link_ids": _ids(e.get("link_ids", cur.get("link_ids"))),
            "entry_ids": _ids(e.get("entry_ids", cur.get("entry_ids"))),  # references only, never secrets
            "notes": _text(e.get("notes", cur.get("notes")), 1000) or None,
            "created_at": cur.get("created_at") or _now_iso(), "updated_at": _now_iso()}


MAX_NOTES = 1000
MAX_NOTE_BODY = 64 * 1024


def _note_aad(nid: str) -> str:
    return "nvnote_" + nid


def note_from(e: dict, cur: dict | None = None) -> dict | None:
    """Stored form: title and body encrypted at rest with the vault key (same AES-GCM as entry bodies)."""
    cur = cur or {}
    pid = str(e.get("project_id", cur.get("project_id")) or "")
    if not any(p.get("id") == pid for p in _load_list("projects.json")):
        return None
    old = note_plain(cur) if cur else {}
    title = _text(e.get("title", old.get("title")), 200)
    body = e.get("body", old.get("body"))
    body = body if isinstance(body, str) else ""
    if len(body.encode("utf-8")) > MAX_NOTE_BODY or not (title or body):
        return None
    nid = cur.get("id") or _new_id()
    enc = server.vault_encrypt(_note_aad(nid), json.dumps({"title": title, "body": body}))
    return {"id": nid, "project_id": pid, "enc": enc,
            "created_at": cur.get("created_at") or _now_iso(), "updated_at": _now_iso()}


def note_plain(n: dict) -> dict:
    d = json.loads(server.vault_decrypt(_note_aad(n["id"]), n["enc"]))
    return {"id": n["id"], "project_id": n["project_id"], "title": d.get("title") or "", "body": d.get("body") or "",
            "created_at": n.get("created_at"), "updated_at": n.get("updated_at")}


KINDS = {"link": ("links.json", link_from, MAX_LINKS), "project": ("projects.json", project_from, MAX_PROJECTS),
         "note": ("notes.json", note_from, MAX_NOTES)}


def write_record(kind: str, op: str, e: dict, base: str | None):
    """-> (status, body). Same op semantics as entries: create ignores client ids."""
    fname, build, cap = KINDS[kind]
    with _lock:
        items = _load_list(fname)
        if op == "create":
            if len(items) >= cap:
                return 409, {"error": "too_many"}
            rec = build(e)
            if not rec:
                return 400, {"error": "bad_record"}
            items.append(rec)
        elif op in ("update", "delete"):
            cur = next((x for x in items if x.get("id") == str(e.get("id") or "")), None)
            if not cur:
                return 404, {"error": "not_found"}
            if base and base != cur.get("updated_at"):
                return 409, {"error": "conflict", kind: note_plain(cur) if kind == "note" else cur}
            if op == "delete":
                items = [x for x in items if x is not cur]
                rec = cur
                if kind == "project":  # a project's notes go with it
                    _save_list("notes.json", [n for n in _load_list("notes.json") if n.get("project_id") != rec["id"]])
                if kind == "link":  # drop dangling references from projects
                    projs = _load_list("projects.json")
                    for pr in projs:
                        if rec["id"] in pr.get("link_ids", []):
                            pr["link_ids"] = [i for i in pr["link_ids"] if i != rec["id"]]
                    _save_list("projects.json", projs)
            else:
                rec = build(e, cur)
                if not rec:
                    return 400, {"error": "bad_record"}
                items = [rec if x is cur else x for x in items]
        else:
            return 400, {"error": "bad_request"}
        _save_list(fname, items)
    if kind == "note":
        rec = note_plain(rec) if op != "delete" else {"id": rec["id"], "project_id": rec.get("project_id")}
    return 200, {kind: rec}


# ---------------------------------------------------------------- discovery (read-only)

def _caddy_hosts(cfg) -> list[str]:
    hosts: set[str] = set()

    def walk(x):
        if isinstance(x, dict):
            for m in x.get("match") or [] if isinstance(x.get("match"), list) else []:
                if isinstance(m, dict):
                    for hst in m.get("host") or []:
                        hosts.add(str(hst))
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk(cfg)
    return sorted(h for h in hosts if re.fullmatch(r"[A-Za-z0-9.-]{1,253}", h) and "*" not in h)


def caddyfile_hosts(text: str) -> list[str]:
    """Top-level site addresses: lines like `a.example, b.example {` at brace depth 0."""
    hosts, depth = set(), 0
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if depth == 0 and line.endswith("{") and not line.startswith(("(", "{")):
            for a in line[:-1].replace(",", " ").split():
                a = re.sub(r"^https?://", "", a).split("/")[0].split(":")[0]
                if re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", a):
                    hosts.add(a)
        depth += line.count("{") - line.count("}")
        depth = max(depth, 0)
    return sorted(hosts)


def discover(force: bool = False) -> dict:
    now = time.time()
    if not force and now - _disc_cache["t"] < DISCOVERY_TTL and _disc_cache["source"]:
        return {"sites": _disc_cache["sites"], "source": _disc_cache["source"]}
    hosts, source = [], None
    if os.environ.get("NULLVAULT_DISCOVERY_CADDY", "1") == "1":
        try:
            with urllib.request.urlopen(CADDY_ADMIN, timeout=2) as r:  # GET only
                hosts = _caddy_hosts(json.loads(r.read(8 * 1024 * 1024).decode("utf-8")))
                source = "caddy_admin"
        except Exception:  # noqa: BLE001 - try the next source
            hosts = []
    if not hosts:
        try:
            hosts = caddyfile_hosts(CADDYFILE.read_text(encoding="utf-8"))
            source = "caddyfile" if hosts else None
        except OSError:
            hosts = []
    if not hosts:
        try:
            d = json.loads(_store("discovered_sites.json").read_text(encoding="utf-8"))
            hosts = [str(x) for x in d.get("hosts", []) if isinstance(x, str)]
            source = "seed" if hosts else None
        except (OSError, ValueError):
            hosts = []
    label = server_label()
    sites = [{"name": h.split(".")[0], "url": f"https://{h}", "host": h, "host_label": label} for h in hosts]
    _disc_cache.update(t=now, sites=sites, source=source or "none")
    return {"sites": sites, "source": source or "none"}


def repo_suggestions() -> list[dict]:
    try:
        d = json.loads(_store("repo_catalog.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    out = []
    for r in (d.get("repos") or [])[:500]:
        url = clean_url(r.get("url"))
        if url and str(url).startswith("https://github.com/"):
            out.append({"name": _text(r.get("full_name") or url, 120).split("/")[-1], "repo_url": url,
                        "private": bool(r.get("private"))})
    return out


def sync_extras() -> dict:
    if not links_enabled():
        return {}
    out = {"links": _load_list("links.json"), "projects": _load_list("projects.json"),
           "suggestions": {"sites": discover()["sites"], "repos": repo_suggestions()}}
    if notes_enabled():
        out["notes"] = [note_plain(n) for n in _load_list("notes.json")]
    return out


# ---------------------------------------------------------------- Files: "Latest of similar files"
# Python port of static/fm-sort.js similarGroups(); parity is tested against node when available.
_SEP = re.compile(r"[-_. ]+")


def _ext(name):
    base = str(name or "").lower().split("/")[-1]
    i = base.rfind(".")
    return base[i + 1:] if i > 0 else ""


def _stem(name):
    base = str(name or "").lower().split("/")[-1]
    i = base.rfind(".")
    return base[:i] if i > 0 else base


def _ts(s):
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp() * 1000
    except (TypeError, ValueError):
        return 0


def _added(f):
    return _ts(f.get("added_at") or f.get("updated_at"))


def _created(f):
    return _ts(f.get("created_at") or f.get("added_at") or f.get("updated_at"))


def norm_base(name):
    s = _stem(name)
    s = re.sub(r"\s*\(\d+\)\s*$", "", s)
    s = re.sub(r"[-_ ]*(copy|kopie)(\s*\d+)?$", "", s, flags=re.I)
    s = re.sub(r"\d{4}[-_.]?\d{2}[-_.]?\d{2}(?:[t_ -]?\d{2}[:.-]?\d{2}(?:[:.-]?\d{2})?z?)?", " ", s)
    s = re.sub(r"\bv?\d+(?:\.\d+)+\b", " ", s)
    toks = [t for t in _SEP.split(s) if t and not (
        re.fullmatch(r"v?\d+", t) or (re.fullmatch(r"[0-9a-f]{7,12}", t) and re.search(r"\d", t))
        or re.fullmatch(r"\d{9,13}", t))]
    return "-".join(toks)


def shared_prefix(a, b):
    i = 0
    while i < len(a) and i < len(b) and a[i] == b[i]:
        i += 1
    if i == len(a) and i == len(b):
        return i
    cut = a[:i]
    j = max(cut.rfind("-"), cut.rfind("_"), cut.rfind("."), cut.rfind(" "))
    if i < len(a) and i < len(b) and j < 0:
        return 0
    at_b = (i == len(a) and bool(_SEP.match(b[i:i + 1] or "x") and b[i:i + 1])) or \
           (i == len(b) and bool(_SEP.match(a[i:i + 1] or "x") and a[i:i + 1]))
    return i if at_b else j


def same_group(a, b):
    if _ext(a.get("name")) != _ext(b.get("name")):
        return False
    na, nb = norm_base(a.get("name")), norm_base(b.get("name"))
    if na and na == nb:
        return True
    return shared_prefix(_stem(a.get("name")), _stem(b.get("name"))) >= 6


def latest_ids(files: list[dict]) -> set[str]:
    lst = []
    seen = set()
    for f in files:
        if f and f.get("id") is not None and f["id"] not in seen:
            seen.add(f["id"]); lst.append(f)
    parent = list(range(len(lst)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    for i in range(len(lst)):
        for j in range(i + 1, len(lst)):
            if find(i) != find(j) and same_group(lst[i], lst[j]):
                parent[find(j)] = find(i)
    groups: dict[int, list] = {}
    for i, f in enumerate(lst):
        groups.setdefault(find(i), []).append(f)
    out = set()
    for g in groups.values():
        if len(g) < 2:
            continue
        import functools

        def cmp(a, b):
            d = _added(b) - _added(a) or _created(b) - _created(a)
            if d:
                return -1 if d < 0 else 1
            na, nb = str(a.get("name") or "").lower(), str(b.get("name") or "").lower()
            return (nb > na) - (nb < na)
        out.add(sorted(g, key=functools.cmp_to_key(cmp))[0]["id"])
    return out


# ---------------------------------------------------------------- Files: sessions

def files_session_issue(device_id: str) -> tuple[str, int]:
    tok = "nvf_" + nv.b64url(secrets.token_bytes(32))
    now = time.time()
    with _lock:
        for k in [k for k, v in _sessions.items() if v["exp"] < now]:
            _sessions.pop(k, None)
        _sessions[hashlib.sha256(tok.encode()).hexdigest()] = {"device_id": device_id, "exp": now + FILES_SESSION_TTL}
    return tok, FILES_SESSION_TTL


def files_session(h):
    """Bearer nvf_ session -> active device, or None (response sent). Revoke/flag ends it at once."""
    tok = h._bearer_token() or ""
    rec = None
    if tok.startswith("nvf_"):
        with _lock:
            rec = _sessions.get(hashlib.sha256(tok.encode()).hexdigest())
    if not rec or rec["exp"] < time.time():
        h._json(401, {"error": "files_session_expired"})
        return None
    d = nv.devices().get(rec["device_id"])
    if not d or d["status"] != "active":
        h._json(403, {"error": (d or {}).get("status") or "unauthorized", "wipe": True})
        return None
    return d


def _fm():
    import files_manager
    return files_manager


def files_list():
    S = server
    files = [_fm()._view(e) for e in S.load_files() if isinstance(e, dict) and not e.get("trashed_at")]
    latest = latest_ids(files)
    for f in files:
        f["latest"] = f["id"] in latest
        f.pop("path", None)
    files.sort(key=lambda f: (_added(f), _created(f)), reverse=True)
    labels = sorted({lb for f in files for lb in (f.get("labels") or [])}, key=str.lower)
    return {"files": files, "labels": labels}


def send_file_range(h, fid: str, device_id: str):
    S = server
    entry = next((f for f in S.load_files() if f.get("id") == fid and not f.get("trashed_at")), None)
    fp = S.resolve_file_path(entry) if entry else None
    if not fp:
        return h._json(404, {"error": "not_found"})
    size = fp.stat().st_size
    start, end, status = 0, size - 1, 200
    rng = h.headers.get("Range")
    if rng:
        m = re.fullmatch(r"bytes=(\d*)-(\d*)", rng.strip())
        if not m or (not m.group(1) and not m.group(2)):
            return h._send(416, b"", "application/octet-stream", [("Content-Range", f"bytes */{size}")])
        if m.group(1):
            start = int(m.group(1)); end = int(m.group(2)) if m.group(2) else size - 1
        else:
            start = max(0, size - int(m.group(2)))
        end = min(end, size - 1)
        if start > end or start >= size:
            return h._send(416, b"", "application/octet-stream", [("Content-Range", f"bytes */{size}")])
        status = 206
    n = end - start + 1 if size else 0
    name = entry.get("name") or fp.name
    h.send_response(status)
    h.send_header("Content-Type", "application/octet-stream")
    h.send_header("Content-Length", str(n))
    h.send_header("Accept-Ranges", "bytes")
    if status == 206:
        h.send_header("Content-Range", f"bytes {start}-{end}/{size}")
    h.send_header("Content-Disposition", f'attachment; filename="{S.slugify(name)}"')
    h.send_header("Cache-Control", "no-store")
    h.send_header("X-Content-Type-Options", "nosniff")
    h.end_headers()
    if start == 0 or status == 206:
        server.vault_audit("device_file_download", device=device_id, id=fid, start=start, bytes=n, ip=server.client_ip(h))
    with open(fp, "rb") as f:
        f.seek(start)
        left = n
        while left > 0:
            buf = f.read(min(1024 * 1024, left))
            if not buf:
                break
            h.wfile.write(buf)
            left -= len(buf)


def upload_begin(h, d, f: dict):
    """Signed intent -> upload id. Size limits and free-space checks reuse fm_uploads."""
    import fm_uploads as up
    fm = _fm()
    name = Path(str(f.get("name") or "")).name.strip()
    if not name or not server.allowed_upload_name(name) or len(name) > 255:
        return h._json(400, {"error": "bad_name"})
    try:
        size = int(f.get("size"))
    except (TypeError, ValueError):
        return h._json(400, {"error": "bad_size"})
    if size < 0:
        return h._json(400, {"error": "bad_size"})
    if size > up.MAX_FILE:
        return h._json(413, {"error": "too_large", "max": up.MAX_FILE})
    sha = str(f.get("sha256") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", sha):
        return h._json(400, {"error": "sha256_required"})
    label = _text(f.get("label"), 40) or "inbox"
    if not re.fullmatch(r"[A-Za-z0-9 _.-]{1,40}", label):
        return h._json(400, {"error": "bad_label"})
    try:
        up.cleanup_stale()
        dd = up.parts_dir()
        if len(list(dd.glob("*.json"))) >= up.MAX_ACTIVE:
            return h._json(429, {"error": "too_many_uploads"})
        import shutil
        if shutil.disk_usage(dd).free < size + up.MIN_FREE:
            return h._json(507, {"error": "insufficient_storage"})
    except fm._Err as e:
        return h._json(e.code, {"error": e.err})
    uid = uuid.uuid4().hex[:24]
    up._save({"upload_id": uid, "name": name, "size": size, "folder": "", "created_at": server.iso_now(),
              "nullvault": {"device_id": d["device_id"], "sha256": sha, "label": label}})
    up._part_path(uid).touch(mode=0o600)
    server.vault_audit("device_upload_begin", device=d["device_id"], upload=uid, size=size, label=label)
    return h._json(200, {"upload_id": uid, "chunk_size": up.CHUNK_SIZE, "received": 0, "max_chunk": up.MAX_CHUNK})


def _own_upload(d, uid):
    import fm_uploads as up
    meta = up._load(uid)
    if (meta.get("nullvault") or {}).get("device_id") != d["device_id"]:
        raise _fm()._Err(404, "upload_not_found")
    return meta


def upload_chunk(h, d, uid, qs):
    import fm_uploads as up
    try:
        _own_upload(d, uid)
        up._chunk(h, uid, qs)
    except _fm()._Err as e:
        h._json(e.code, {"error": e.err, **e.extra})


def upload_status(h, d, uid):
    import fm_uploads as up
    try:
        h._json(200, up._public(_own_upload(d, uid)))
    except _fm()._Err as e:
        h._json(e.code, {"error": e.err})


def upload_complete(h, d, uid):
    """Checks the bytes against the SHA-256 in the signed intent, then registers like a browser upload
    (same file_dates stamping, files.json entry, pending + webhook notify), but with the chosen label."""
    import fm_uploads as up
    import file_dates
    fm = _fm()
    S = server
    lk = up._lock(uid)
    # The last chunk's handler may still hold the lock for a moment after its response went out.
    if not lk.acquire(timeout=5):
        return h._json(409, {"error": "busy"})
    try:
        try:
            meta = _own_upload(d, uid)
        except fm._Err as e:
            return h._json(e.code, {"error": e.err})
        if meta["received"] != meta["size"]:
            return h._json(409, {"error": "incomplete", "received": meta["received"], "size": meta["size"]})
        md = hashlib.sha256()
        with open(up._part_path(uid), "rb") as fh:
            for buf in iter(lambda: fh.read(1024 * 1024), b""):
                md.update(buf)
        if md.hexdigest() != meta["nullvault"]["sha256"]:
            up._remove(uid)
            S.vault_audit("device_upload_refused", device=d["device_id"], upload=uid, reason="sha256_mismatch")
            return h._json(422, {"error": "sha256_mismatch"})
        labels = [meta["nullvault"]["label"]]
        dest_dir = S.upload_dest_for_labels(labels)
        fid = uuid.uuid4().hex[:12]
        safe = S.slugify(meta["name"])
        dest = dest_dir / safe
        if dest.exists() or dest.is_symlink():
            dest = dest_dir / f"{Path(safe).stem}-{fid[:6]}{Path(safe).suffix}"
        os.replace(up._part_path(uid), dest)
        try:
            dest.chmod(0o644)
        except OSError:
            pass
        entry = {"id": fid, "name": meta["name"], "path": str(dest.relative_to(S.BASE)), "labels": labels,
                 "size": meta["size"], "updated_at": S.iso_now(), "source": "nullvault", "folder": "",
                 "trashed_at": None, "fm": fm.FM_VERSION}
        file_dates.stamp(entry, exif_path=dest, client_ms=None, now_iso=entry["updated_at"])
        with fm._lock:
            files = S.load_files(); files.append(entry); S.save_files(files)
        up._remove(uid)
    finally:
        lk.release()
    S.vault_audit("device_upload", device=d["device_id"], id=fid, size=entry["size"], label=labels[0])
    try:
        S.write_pending("upload", {"file_id": fid, "file_ids": [fid], "name": entry["name"], "names": [entry["name"]],
                                   "path": entry["path"], "labels": labels, "count": 1,
                                   "preview": f"Uploaded 1 file(s) from NullVault: {entry['name']}"})
        S.fire_webhook("upload", f"Uploaded 1 file(s) from NullVault: {entry['name']}")
    except Exception:  # noqa: BLE001 - same best-effort notify as browser uploads
        pass
    v = fm._view(entry); v.pop("path", None)
    return h._json(200, {"ok": True, "file": v})


def file_trash(fid: str) -> bool:
    fm = _fm()
    with fm._lock:
        files = server.load_files()
        hit = False
        for e in files:
            if isinstance(e, dict) and e.get("id") == fid and not e.get("trashed_at"):
                e["trashed_at"] = server.iso_now(); hit = True
        if hit:
            server.save_files(files)
    return hit


# ---------------------------------------------------------------- Stage 3: shared helpers

_chain_lock = threading.Lock()


def chained_append(name: str, rec: dict) -> dict:
    """Append-only, hash-chained JSONL log in data/nullvault/<name>. Opened only with O_APPEND, so it is
    compatible with `chattr +a`. Each record carries prev = SHA-256 of the previous line."""
    path = nv.nv_dir() / name
    with _chain_lock:
        prev = "0" * 64
        try:
            with open(path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - 65536))
                tail = f.read().splitlines()
                if tail:
                    prev = hashlib.sha256(tail[-1]).hexdigest()
        except FileNotFoundError:
            pass
        out = {"ts": _now_iso(), **rec, "prev": prev}
        line = (json.dumps(out, sort_keys=True, ensure_ascii=True) + "\n").encode()
        fd = os.open(str(path), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, line)
        finally:
            os.close(fd)
    return out


def chain_verify(name: str) -> tuple[bool, int]:
    """(ok, records): every record's prev matches the hash of the line before it."""
    path = nv.nv_dir() / name
    try:
        lines = path.read_bytes().splitlines()
    except FileNotFoundError:
        return True, 0
    prev = "0" * 64
    for ln in lines:
        try:
            if json.loads(ln).get("prev") != prev:
                return False, len(lines)
        except ValueError:
            return False, len(lines)
        prev = hashlib.sha256(ln).hexdigest()
    return True, len(lines)


def chain_tail(name: str, n: int = 50) -> list[dict]:
    try:
        lines = (nv.nv_dir() / name).read_bytes().splitlines()[-n:]
    except FileNotFoundError:
        return []
    out = []
    for ln in lines:
        try:
            out.append(json.loads(ln))
        except ValueError:
            continue
    return out


class SessionStore:
    """Short-lived bearer sessions in server memory only (like the Files session)."""

    def __init__(self, prefix: str, ttl: int):
        self.prefix, self.ttl, self._s, self._l = prefix, ttl, {}, threading.Lock()

    def issue(self, device_id: str) -> tuple[str, int]:
        tok = self.prefix + nv.b64url(secrets.token_bytes(32))
        now = time.time()
        with self._l:
            for k in [k for k, v in self._s.items() if v["exp"] < now]:
                self._s.pop(k, None)
            self._s[hashlib.sha256(tok.encode()).hexdigest()] = {"device_id": device_id, "exp": now + self.ttl}
        return tok, self.ttl

    def device(self, h, expired_error: str):
        """Bearer session -> active device, or None (response sent). Revoke/flag ends it at once."""
        tok = h._bearer_token() or ""
        rec = None
        if tok.startswith(self.prefix):
            with self._l:
                rec = self._s.get(hashlib.sha256(tok.encode()).hexdigest())
        if not rec or rec["exp"] < time.time():
            h._json(401, {"error": expired_error})
            return None
        d = nv.devices().get(rec["device_id"])
        if not d or d["status"] != "active":
            h._json(403, {"error": (d or {}).get("status") or "unauthorized", "wipe": True})
            return None
        return d

    def clear(self):
        with self._l:
            self._s.clear()


class RateLimit:
    """Sliding-window limiter: at most n events per window seconds per key."""

    def __init__(self):
        self._ev: dict[str, list[float]] = {}
        self._l = threading.Lock()

    def hit(self, key: str, n: int, window: float, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        with self._l:
            ev = [t for t in self._ev.get(key, []) if now - t < window]
            if len(ev) >= n:
                self._ev[key] = ev
                return False
            ev.append(now)
            self._ev[key] = ev
            return True

    def clear(self):
        with self._l:
            self._ev.clear()


def capture_body(h) -> dict:
    """Reads the JSON body once and makes later h._read_json() calls return the same dict."""
    body = h._read_json() or {}
    h._read_json = lambda: body
    return body
