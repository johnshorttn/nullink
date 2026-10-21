"""Server drive (file manager slice, 2026-10-21): browse the host filesystem ("/") as a
separate drive, distinct from the Nullink Files drive.

Runs at the nullink.service user's own privileges only. It never calls sudo, never spawns
a process and never uses a privileged helper, so it can reach exactly what that user can.

Rules (all enforced server-side):
- Owner cookie session only. Guests, and any request carrying an Authorization header
  (Bearer / agent / AI tokens), get 403.
- The drive is locked until POST /api/sd/unlock with a fresh authenticator (TOTP) code.
  The unlock is stored on the session record (sd_unlock_at) and lasts UNLOCK_WINDOW_SEC.
- Read-only by default. mkdir / rename / upload / delete also need the normal 5-minute
  step-up (/api/auth/stepup). No Trash: delete is permanent and needs "confirm" equal to
  the item's name.
- Every action (list, stat, preview, download and all writes, including refusals) is
  appended to data/server_drive_audit.jsonl (mode 600). File contents are never logged.
- Nullink's own secrets/ directory, env files and token/key files are masked in listings
  and refused for every operation, checked on the fully resolved path.
- Symlinks are never followed: every path component is lstat'ed, files are opened with
  O_NOFOLLOW and re-checked (fstat) after opening. Symlinks are listed but not openable.
- Download is always attachment + application/octet-stream + nosniff. Preview only for
  UTF-8 text (as JSON) and a small set of raster image types.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import stat
import time
import urllib.parse
from pathlib import Path

S = None  # server module (bound in server.py)

UNLOCK_WINDOW_SEC = 15 * 60
MAX_UPLOAD = 50 * 1024 * 1024
MAX_TEXT_PREVIEW = 256 * 1024
MAX_IMAGE_PREVIEW = 10 * 1024 * 1024
MAX_LIST = 5000
SAFE_IMAGE = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
              ".gif": "image/gif", ".webp": "image/webp", ".bmp": "image/bmp"}
_SEG_BAD = re.compile(r"[\x00-\x1f\x7f/\\]")
# Name patterns that are always masked/refused, anywhere on the drive (case-insensitive).
BLOCKED_NAME_GLOBS = (
    ".env", ".env.*", "*.env", "env", "*token*", "*secret*", "*.pem", "*.key", "id_rsa*",
    "id_ed25519*", "id_ecdsa*", ".netrc", ".git-credentials", "credentials", "credentials.json",
    "auth_sessions.json", "otp.json", "totp.json", "session_secret*",
)


def bind(mod):
    global S
    S = mod


def drive_root() -> Path:
    return Path(os.environ.get("NULLINK_SD_ROOT") or "/")


def audit_file() -> Path:
    return S.DATA / "server_drive_audit.jsonl"


def blocked_dirs() -> list[str]:
    """Absolute real paths that are fully blocked (Nullink's own secrets/)."""
    out = []
    for p in {Path(S.BASE) / "secrets", Path(S.SECRETS)}:
        try:
            out.append(os.path.realpath(p))
        except OSError:
            pass
    return out


def audit(event: str, **fields) -> None:
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "t": round(time.time(), 3),
           "event": event}
    for k, v in fields.items():
        rec[k] = v if isinstance(v, (int, float, bool)) or v is None else \
            "".join(ch for ch in str(v) if ch.isprintable())[:300]
    try:
        audit_file().parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(audit_file(), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, separators=(",", ":")) + "\n")
    except OSError:
        pass


class _Err(Exception):
    def __init__(self, code, err, **extra):
        self.code, self.err, self.extra = code, err, extra


# ---------- path safety ----------
def name_blocked(name: str) -> bool:
    n = name.lower()
    return any(fnmatch.fnmatchcase(n, g) for g in BLOCKED_NAME_GLOBS)


def is_blocked(abs_path: str) -> bool:
    """abs_path is an absolute, normalized host path (no symlinks resolved or resolved)."""
    for cand in {abs_path, os.path.realpath(abs_path)}:
        for b in blocked_dirs():
            if cand == b or cand.startswith(b + os.sep):
                return True
        if any(name_blocked(seg) for seg in cand.split(os.sep) if seg):
            return True
    return False


def norm_rel(raw) -> str:
    """Drive path ("/", "/etc/hosts") -> relative "etc/hosts". Raises on traversal / junk."""
    s = str(raw if raw is not None else "/")
    if "\x00" in s or len(s) > 4096:
        raise _Err(400, "bad_path")
    parts = [p for p in s.split("/") if p not in ("", ".")]
    if any(p == ".." or _SEG_BAD.search(p) for p in parts):
        raise _Err(400, "bad_path")
    return "/".join(parts)


def host_path(rel: str) -> str:
    root = os.path.realpath(drive_root())
    return os.path.join(root, rel) if rel else root


def check_path(rel: str, must_exist=True, allow_final_symlink=False) -> str:
    """Return the host path for rel after refusing symlinks in any component and blocked paths."""
    root = os.path.realpath(drive_root())
    cur = root
    parts = rel.split("/") if rel else []
    for i, seg in enumerate(parts):
        cur = os.path.join(cur, seg)
        try:
            st = os.lstat(cur)
        except FileNotFoundError:
            if must_exist or i != len(parts) - 1:
                raise _Err(404, "not_found")
            break
        except PermissionError:
            raise _Err(403, "permission_denied")
        if stat.S_ISLNK(st.st_mode) and not (allow_final_symlink and i == len(parts) - 1):
            raise _Err(403, "symlink_refused")
    if is_blocked(cur):
        raise _Err(403, "blocked_path")
    # Re-check: the resolved path must still be inside the drive root.
    real = os.path.realpath(cur)
    if not allow_final_symlink and real != root and not real.startswith(root.rstrip(os.sep) + os.sep):
        raise _Err(403, "escape_refused")
    return cur


def drive_path(host: str) -> str:
    root = os.path.realpath(drive_root())
    rel = os.path.relpath(host, root)
    return "/" if rel == "." else "/" + rel.replace(os.sep, "/")


def valid_name(raw) -> str:
    s = str(raw or "").strip()
    if not s or s in (".", "..") or len(s) > 255 or _SEG_BAD.search(s):
        raise _Err(400, "bad_name")
    return s


def _open_nofollow(host: str):
    fd = os.open(host, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise _Err(400, "not_a_file")
    lst = os.lstat(host)
    if (lst.st_dev, lst.st_ino) != (st.st_dev, st.st_ino):  # swapped after check
        os.close(fd)
        raise _Err(409, "changed_during_open")
    return fd, st


def _kind(mode: int) -> str:
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISREG(mode):
        return "file"
    return "special"


# ---------- auth ----------
def _session(h) -> dict | None:
    if h.headers.get("Authorization") is not None:
        h._json(403, {"error": "forbidden", "message": "Owner browser session only."})
        return None
    rec = h._require_owner()
    if rec is None:
        return None
    if rec.get("guest"):
        h._json(403, {"error": "guest_forbidden"})
        return None
    return rec


def unlocked_for(rec: dict) -> int:
    left = UNLOCK_WINDOW_SEC - (time.time() - float(rec.get("sd_unlock_at") or 0))
    return int(left) if left > 0 else 0


def _mark_unlock(key: str, value: float) -> bool:
    with S._auth_lock:
        sessions = S.load_sessions()
        rec = sessions.get(key)
        if not isinstance(rec, dict) or rec.get("method") == "guest" or rec.get("guest"):
            return False
        rec["sd_unlock_at"] = value
        sessions[key] = rec
        S.save_sessions(sessions)
        return True


def _unlock(h, rec, ip, ua) -> None:
    if not S.totp_enabled():
        audit("unlock_refused", reason="totp_not_enabled", ip=ip, session=rec.get("id"))
        raise _Err(409, "totp_not_enabled", message="Turn on the authenticator app in Nullink settings first.")
    code = str((h._read_json() or {}).get("code", "")).replace(" ", "").strip()
    now = time.time()
    with S._auth_lock:
        rate = S.load_rate()
        S._prune_rate(rate, now)
        locked, retry, _scope = S.rate_locked(rate, ip, now)
        if locked:
            audit("unlock_refused", reason="locked", ip=ip, session=rec.get("id"))
            raise _Err(429, "locked", retry_after_sec=retry)
        ok = bool(code.isdigit() and len(code) == S.TOTP_DIGITS
                  and S.verify_totp(code, S.load_totp() or {}, now, consume=True))
        if not ok:
            info = S.rate_record_failure(rate, ip, now)
            S.save_rate(rate)
            audit("unlock_failed", ip=ip, ua=ua, session=rec.get("id"))
            if info["locked"]:
                raise _Err(429, "locked", retry_after_sec=info["retry_after"])
            raise _Err(401, "wrong_code", attempts_left=info["attempts_left"])
        S.rate_record_success(rate, ip)
        S.save_rate(rate)
    _mark_unlock(rec.get("_key", ""), now)
    audit("unlock_ok", ip=ip, ua=ua, session=rec.get("id"))
    h._json(200, {"ok": True, "unlocked_for_sec": UNLOCK_WINDOW_SEC})


# ---------- HTTP ----------
WRITE_PATHS = ("/api/sd/mkdir", "/api/sd/rename", "/api/sd/upload", "/api/sd/delete")


def handle(h, method: str, path: str, qs) -> bool:
    if path != "/api/sd" and not path.startswith("/api/sd/"):
        return False
    ip = S.client_ip(h)
    ua = str(h.headers.get("User-Agent") or "")[:160]
    if h.headers.get("Authorization") is not None:
        audit("refused", reason="authorization_header", path=path, ip=ip)
    rec = _session(h)
    if rec is None:
        if h.headers.get("Authorization") is None:
            audit("refused", reason="not_owner", path=path, ip=ip)
        return True
    sid = rec.get("id")
    try:
        if method == "GET" and path == "/api/sd/status":
            left = unlocked_for(rec)
            audit("status", ip=ip, session=sid, unlocked=bool(left))
            h._json(200, {"unlocked": bool(left), "unlocked_for_sec": left,
                          "window_sec": UNLOCK_WINDOW_SEC, "root": "/", "read_only_default": True,
                          "trash": False, "runs_as": _runs_as()})
            return True
        if method == "POST" and path == "/api/sd/unlock":
            _unlock(h, rec, ip, ua)
            return True
        if method == "POST" and path == "/api/sd/lock":
            _mark_unlock(rec.get("_key", ""), 0)
            audit("lock", ip=ip, session=sid)
            h._json(200, {"ok": True})
            return True
        if not unlocked_for(rec):
            audit("refused", reason="locked", path=path, ip=ip, session=sid)
            raise _Err(403, "drive_locked", unlock_endpoint="/api/sd/unlock",
                       message="Enter an authenticator code to open the Server drive for 15 minutes.")
        if method == "POST" and path in WRITE_PATHS:
            stepped = time.time() - float(rec.get("stepup_at") or 0) <= S.STEPUP_WINDOW_SEC
            if not stepped:
                audit("refused", reason="step_up_required", path=path, ip=ip, session=sid)
                raise _Err(403, "step_up_required", stepup_endpoint="/api/auth/stepup",
                           message="Confirm it's you: enter an authenticator code to make changes.")
        return _route(h, method, path, qs, ip, sid)
    except _Err as e:
        if e.code in (400, 403, 404, 409) and e.err not in ("drive_locked", "step_up_required"):
            audit("error", path=path, err=e.err, ip=ip, session=sid,
                  target=(qs.get("path") or [""])[0])
        h._json(e.code, {"error": e.err, **e.extra})
        return True


def _runs_as() -> str:
    try:
        import pwd
        return pwd.getpwuid(os.geteuid()).pw_name
    except Exception:
        return str(os.geteuid())


def _q(qs, k, default=None):
    v = qs.get(k)
    return v[0] if v else default


def _route(h, method, path, qs, ip, sid) -> bool:
    if method == "GET" and path == "/api/sd/list":
        return _list(h, norm_rel(_q(qs, "path", "/")), ip, sid)
    if method == "GET" and path == "/api/sd/stat":
        rel = norm_rel(_q(qs, "path"))
        host = check_path(rel, allow_final_symlink=True)
        st = os.lstat(host)
        audit("stat", path=drive_path(host), ip=ip, session=sid)
        h._json(200, _entry(os.path.basename(host) or "/", st, drive_path(host)))
        return True
    if method == "GET" and path == "/api/sd/preview":
        return _preview(h, norm_rel(_q(qs, "path")), ip, sid)
    if method == "GET" and path == "/api/sd/download":
        return _download(h, norm_rel(_q(qs, "path")), ip, sid)
    if method == "POST" and path == "/api/sd/upload":
        return _upload(h, qs, ip, sid)
    if method != "POST":
        raise _Err(404, "not_found")
    b = h._read_json()
    b = b if isinstance(b, dict) else {}
    if path == "/api/sd/mkdir":
        parent = check_path(norm_rel(b.get("path")))
        if not os.path.isdir(parent):
            raise _Err(400, "not_a_dir")
        name = valid_name(b.get("name"))
        target = os.path.join(parent, name)
        if is_blocked(target):
            raise _Err(403, "blocked_path")
        try:
            os.mkdir(target, 0o755)
        except FileExistsError:
            raise _Err(409, "exists")
        except PermissionError:
            raise _Err(403, "permission_denied")
        audit("mkdir", path=drive_path(target), ip=ip, session=sid)
        h._json(200, {"ok": True, "path": drive_path(target)})
        return True
    if path == "/api/sd/rename":
        src = check_path(norm_rel(b.get("path")), allow_final_symlink=True)
        if drive_path(src) == "/":
            raise _Err(400, "bad_path")
        dest_dir = os.path.dirname(src)
        if b.get("dest_dir") is not None:
            dest_dir = check_path(norm_rel(b.get("dest_dir")))
            if not os.path.isdir(dest_dir):
                raise _Err(400, "not_a_dir")
        name = valid_name(b.get("name") or os.path.basename(src))
        dst = os.path.join(dest_dir, name)
        if is_blocked(dst):
            raise _Err(403, "blocked_path")
        if os.path.lexists(dst):
            raise _Err(409, "exists")
        try:
            os.rename(src, dst)
        except PermissionError:
            raise _Err(403, "permission_denied")
        except OSError as e:
            raise _Err(400, "rename_failed", message=e.strerror or "rename failed")
        audit("rename", path=drive_path(src), to=drive_path(dst), ip=ip, session=sid)
        h._json(200, {"ok": True, "path": drive_path(dst)})
        return True
    if path == "/api/sd/delete":
        host = check_path(norm_rel(b.get("path")), allow_final_symlink=True)
        name = os.path.basename(host)
        if drive_path(host) == "/" or not name:
            raise _Err(400, "bad_path")
        if str(b.get("confirm") or "") != name:
            audit("refused", reason="confirm_mismatch", path=drive_path(host), ip=ip, session=sid)
            raise _Err(400, "confirm_mismatch", message="Type the exact name to delete it permanently.")
        st = os.lstat(host)
        try:
            if stat.S_ISDIR(st.st_mode):
                os.rmdir(host)  # empty directories only; no recursive delete
            else:
                os.unlink(host)  # removes a symlink itself, never its target
        except OSError as e:
            if isinstance(e, PermissionError):
                raise _Err(403, "permission_denied")
            raise _Err(409, "not_empty" if os.path.isdir(host) else "delete_failed")
        audit("delete", path=drive_path(host), kind=_kind(st.st_mode), ip=ip, session=sid)
        h._json(200, {"ok": True, "deleted": drive_path(host), "permanent": True})
        return True
    raise _Err(404, "not_found")


def _entry(name, st, dpath, masked=False) -> dict:
    d = {"name": name, "path": dpath, "kind": _kind(st.st_mode), "masked": masked}
    if not masked:
        d.update(size=st.st_size, mtime=int(st.st_mtime), mode=stat.filemode(st.st_mode),
                 uid=st.st_uid, gid=st.st_gid)
    return d


def _list(h, rel, ip, sid) -> bool:
    host = check_path(rel)
    if not os.path.isdir(host):
        raise _Err(400, "not_a_dir")
    items, truncated = [], False
    try:
        with os.scandir(host) as it:
            for de in it:
                if len(items) >= MAX_LIST:
                    truncated = True
                    break
                full = os.path.join(host, de.name)
                dp = drive_path(full)
                try:
                    st = de.stat(follow_symlinks=False)
                except OSError:
                    continue
                if is_blocked(full):
                    items.append({"name": de.name, "path": dp, "kind": "masked", "masked": True})
                    continue
                items.append(_entry(de.name, st, dp))
    except PermissionError:
        raise _Err(403, "permission_denied")
    items.sort(key=lambda e: (e["kind"] != "dir", e["name"].lower()))
    audit("list", path=drive_path(host), count=len(items), ip=ip, session=sid)
    h._json(200, {"path": drive_path(host), "items": items, "truncated": truncated})
    return True


def _read_fd(fd, limit):
    chunks, total = [], 0
    with os.fdopen(fd, "rb") as f:
        while total < limit:
            b = f.read(min(65536, limit - total))
            if not b:
                break
            chunks.append(b)
            total += len(b)
    return b"".join(chunks)


def _preview(h, rel, ip, sid) -> bool:
    host = check_path(rel)
    try:
        fd, st = _open_nofollow(host)
    except PermissionError:
        raise _Err(403, "permission_denied")
    except OSError:
        raise _Err(403, "symlink_refused")
    ext = os.path.splitext(host)[1].lower()
    if ext in SAFE_IMAGE:
        if st.st_size > MAX_IMAGE_PREVIEW:
            os.close(fd)
            raise _Err(413, "too_large")
        data = _read_fd(fd, MAX_IMAGE_PREVIEW)
        audit("preview", path=drive_path(host), type="image", ip=ip, session=sid)
        h._send(200, data, SAFE_IMAGE[ext], [("X-Content-Type-Options", "nosniff"),
                                             ("Content-Security-Policy", "default-src 'none'; sandbox"),
                                             ("Content-Disposition", "inline")])
        return True
    data = _read_fd(fd, MAX_TEXT_PREVIEW + 1)
    if b"\x00" in data[:8192]:
        audit("preview_refused", path=drive_path(host), reason="binary", ip=ip, session=sid)
        raise _Err(415, "not_previewable", message="Binary file. Download it instead.")
    truncated = len(data) > MAX_TEXT_PREVIEW
    try:
        text = data[:MAX_TEXT_PREVIEW].decode("utf-8")
    except UnicodeDecodeError as e:
        if truncated and e.start >= MAX_TEXT_PREVIEW - 4:
            text = data[:e.start].decode("utf-8")
        else:
            audit("preview_refused", path=drive_path(host), reason="not_utf8", ip=ip, session=sid)
            raise _Err(415, "not_previewable", message="Not a text file. Download it instead.")
    audit("preview", path=drive_path(host), type="text", ip=ip, session=sid)
    h._json(200, {"path": drive_path(host), "text": text, "truncated": truncated, "size": st.st_size})
    return True


def _download(h, rel, ip, sid) -> bool:
    host = check_path(rel)
    try:
        fd, st = _open_nofollow(host)
    except PermissionError:
        raise _Err(403, "permission_denied")
    except OSError:
        raise _Err(403, "symlink_refused")
    name = os.path.basename(host)
    ascii_name = re.sub(r'[^A-Za-z0-9._-]', "_", name) or "download"
    audit("download", path=drive_path(host), size=st.st_size, ip=ip, session=sid)
    h.send_response(200)
    h.send_header("Content-Type", "application/octet-stream")
    h.send_header("Content-Length", str(st.st_size))
    h.send_header("Content-Disposition",
                  f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{urllib.parse.quote(name)}")
    h.send_header("X-Content-Type-Options", "nosniff")
    h.send_header("Cache-Control", "no-store")
    h.end_headers()
    with os.fdopen(fd, "rb") as f:
        remaining = st.st_size
        while remaining > 0:
            b = f.read(min(1 << 20, remaining))
            if not b:
                break
            h.wfile.write(b)
            remaining -= len(b)
    return True


def _upload(h, qs, ip, sid) -> bool:
    """Raw body upload: POST /api/sd/upload?path=/dir&name=file (no overwrite)."""
    parent = check_path(norm_rel(_q(qs, "path", "/")))
    if not os.path.isdir(parent):
        raise _Err(400, "not_a_dir")
    name = valid_name(_q(qs, "name"))
    target = os.path.join(parent, name)
    if is_blocked(target):
        raise _Err(403, "blocked_path")
    length = int(h.headers.get("Content-Length") or 0)
    if length <= 0 and length != 0:
        raise _Err(400, "bad_length")
    if length > MAX_UPLOAD:
        raise _Err(413, "too_large")
    try:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    except FileExistsError:
        raise _Err(409, "exists")
    except PermissionError:
        raise _Err(403, "permission_denied")
    written = 0
    try:
        with os.fdopen(fd, "wb") as f:
            while written < length:
                b = h.rfile.read(min(1 << 20, length - written))
                if not b:
                    break
                f.write(b)
                written += len(b)
    except OSError:
        try:
            os.unlink(target)
        except OSError:
            pass
        raise _Err(500, "write_failed")
    if written != length:
        os.unlink(target)
        raise _Err(400, "incomplete_upload")
    audit("upload", path=drive_path(target), size=written, ip=ip, session=sid)
    h._json(200, {"ok": True, "path": drive_path(target), "size": written})
    return True
