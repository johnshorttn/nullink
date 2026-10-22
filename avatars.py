"""Chat avatars (av1): an owner-configurable picture per message sender.

Map lives in data/avatars.json  {"avatars": {"<key>": {"name", "image"?, "color"?}}}
Images live in data/avatars/<key>.<png|jpg|webp|gif> and are served only to the owner
cookie session (no guests, no Bearer/agent tokens), like the Files manager.
Senders without a picture get initials on a deterministic colour (same hash in
static/avatars.js). Uploads/removals need step-up. Nothing under secrets/ is touched.
"""
import base64
import json
import os
import re
import threading

import server as S

MAX_BYTES = 512 * 1024
MAX_ENTRIES = 200
IMG_TYPES = {"png": "image/png", "jpg": "image/jpeg", "webp": "image/webp", "gif": "image/gif"}
MAGIC = {"png": (b"\x89PNG\r\n\x1a\n",), "jpg": (b"\xff\xd8\xff",), "gif": (b"GIF87a", b"GIF89a")}
_lock = threading.Lock()


class AvErr(Exception):
    def __init__(self, code, err):
        self.code, self.err = code, err


def _file():
    return S.DATA / "avatars.json"


def _dir():
    return S.DATA / "avatars"


def key_for(name: str) -> str:
    """Normalise a sender name: '[Jinx]', 'Chief of Staff (Morc)', ' morc ' -> 'morc'."""
    s = str(name or "").strip()
    m = re.search(r"\(([^()]+)\)\s*$", s)
    if m:
        s = m.group(1)
    s = s.strip("[] ").lower()
    return re.sub(r"[^a-z0-9_.-]+", "-", s).strip("-.")[:48]


def initials(name: str) -> str:
    s = str(name or "").strip()
    m = re.search(r"\(([^()]+)\)\s*$", s)
    if m:
        s = m.group(1)
    words = [w for w in re.split(r"[^A-Za-z0-9]+", s) if w]
    if not words:
        return "?"
    if len(words) == 1:
        return words[0][:2].capitalize() if len(words[0]) > 1 else words[0].upper()
    return (words[0][0] + words[1][0]).upper()


def hue_for(name: str) -> int:
    """32-bit FNV-1a over the key, mod 360. Mirrored in static/avatars.js."""
    h = 0x811C9DC5
    for ch in key_for(name).encode("utf-8"):
        h ^= ch
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h % 360


def _valid_color(c):
    return isinstance(c, str) and re.fullmatch(r"#[0-9a-fA-F]{6}", c) is not None


def load() -> dict:
    try:
        data = json.loads(_file().read_text(encoding="utf-8"))
        av = data.get("avatars") or {}
        return {k: v for k, v in av.items() if isinstance(v, dict) and key_for(k) == k and k}
    except (OSError, ValueError, AttributeError):
        return {}


def save(av: dict) -> None:
    f = _file()
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps({"avatars": av}, indent=2, ensure_ascii=False), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, f)


def _image_path(key: str, entry: dict):
    img = str(entry.get("image") or "")
    m = re.fullmatch(r"([a-z0-9_.-]{1,48})\.(png|jpg|webp|gif)", img)
    if not m or m.group(1) != key:
        return None, None
    p = _dir() / img
    if p.is_symlink() or not p.is_file():
        return None, None
    return p, IMG_TYPES[m.group(2)]


def public_map() -> dict:
    out = {}
    for k, v in load().items():
        p, _ = _image_path(k, v)
        e = {"name": str(v.get("name") or k)[:64], "initials": initials(v.get("name") or k)}
        e["color"] = v["color"] if _valid_color(v.get("color")) else None
        e["url"] = f"/api/avatars/img/{k}?v={int(p.stat().st_mtime)}" if p else None
        out[k] = e
    return out


def _sniff(raw: bytes):
    for ext, sigs in MAGIC.items():
        if any(raw.startswith(s) for s in sigs):
            return ext
    if raw[:4] == b"RIFF" and raw[8:12] == b"WEBP":
        return "webp"
    return None


def set_avatar(body: dict) -> dict:
    name = str(body.get("name") or "").strip()[:64]
    key = key_for(body.get("key") or name)
    if not key or not name:
        raise AvErr(400, "name_required")
    color = body.get("color")
    if color not in (None, "") and not _valid_color(color):
        raise AvErr(400, "bad_color")
    raw = None
    if body.get("image_b64"):
        try:
            raw = base64.b64decode(str(body["image_b64"]).split(",", 1)[-1], validate=True)
        except (ValueError, TypeError):
            raise AvErr(400, "bad_image")
        if len(raw) > MAX_BYTES:
            raise AvErr(413, "image_too_large")
        ext = _sniff(raw)
        if not ext:
            raise AvErr(415, "unsupported_image")  # no SVG: script risk
    with _lock:
        av = load()
        if key not in av and len(av) >= MAX_ENTRIES:
            raise AvErr(400, "too_many")
        entry = dict(av.get(key) or {})
        entry["name"] = name
        if color:
            entry["color"] = color
        elif color == "":
            entry.pop("color", None)
        if raw is not None:
            d = _dir()
            d.mkdir(parents=True, exist_ok=True)
            for old in d.glob(f"{key}.*"):
                if not old.is_symlink():
                    old.unlink()
            fp = d / f"{key}.{ext}"
            tmp = d / f".{key}.upload"
            tmp.write_bytes(raw)
            os.chmod(tmp, 0o600)
            os.replace(tmp, fp)
            entry["image"] = fp.name
        if body.get("remove_image"):
            p, _ = _image_path(key, entry)
            if p:
                p.unlink()
            entry.pop("image", None)
        av[key] = entry
        save(av)
    return {"key": key, **public_map()[key]}


def remove(key: str) -> None:
    key = key_for(key)
    with _lock:
        av = load()
        entry = av.pop(key, None)
        if entry is None:
            raise AvErr(404, "not_found")
        p, _ = _image_path(key, entry)
        if p:
            p.unlink()
        save(av)


def handle(h, method: str, path: str) -> bool:
    if path != "/api/avatars" and not path.startswith("/api/avatars/"):
        return False
    if h.headers.get("Authorization") is not None:
        h._json(403, {"error": "forbidden", "message": "owner cookie session required"})
        return True
    if h._require_owner() is None:
        return True
    try:
        if method == "GET" and path == "/api/avatars":
            h._json(200, {"avatars": public_map()})
            return True
        m = re.fullmatch(r"/api/avatars/img/([a-z0-9_.-]{1,48})", path)
        if method == "GET" and m:
            entry = load().get(m.group(1))
            p, ctype = _image_path(m.group(1), entry or {})
            if not p:
                raise AvErr(404, "not_found")
            data = p.read_bytes()
            h.send_response(200)
            h.send_header("Content-Type", ctype)
            h.send_header("Content-Length", str(len(data)))
            h.send_header("Cache-Control", "private, max-age=86400")
            h.send_header("X-Content-Type-Options", "nosniff")
            h.send_header("Content-Security-Policy", "default-src 'none'; sandbox")
            h.end_headers()
            h.wfile.write(data)
            return True
        if method == "POST" and path in ("/api/avatars/set", "/api/avatars/remove"):
            if not h._require_stepup():
                return True
            body = h._read_json()
            if path.endswith("/set"):
                h._json(200, {"ok": True, "avatar": set_avatar(body)})
            else:
                remove(str(body.get("key") or ""))
                h._json(200, {"ok": True})
            return True
        raise AvErr(404, "not_found")
    except AvErr as e:
        h._json(e.code, {"error": e.err})
        return True
