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


def save(av: dict, seeded=None) -> None:
    f = _file()
    f.parent.mkdir(parents=True, exist_ok=True)
    if seeded is None:
        try:
            seeded = json.loads(f.read_text(encoding="utf-8")).get("seeded") or []
        except (OSError, ValueError, AttributeError):
            seeded = []
    tmp = f.with_suffix(".tmp")
    doc = {"avatars": av}
    if seeded:
        doc["seeded"] = list(seeded)
    tmp.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
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


def _aliases(v: dict) -> list:
    return [a for a in (v.get("aliases") or []) if isinstance(a, str) and a and key_for(a) == a]


def resolve(key: str, av: dict | None = None) -> str:
    """Canonical profile key for a sender key (follows merged aliases)."""
    av = load() if av is None else av
    if key in av:
        return key
    for k, v in av.items():
        if key in _aliases(v):
            return k
    return key


def public_map() -> dict:
    out = {}
    av = load()
    for k, v in av.items():
        p, _ = _image_path(k, v)
        e = {"name": str(v.get("name") or k)[:64], "initials": initials(v.get("name") or k)}
        e["color"] = v["color"] if _valid_color(v.get("color")) else None
        e["url"] = f"/api/avatars/img/{k}?v={int(p.stat().st_mtime)}" if p else None
        e["aliases"] = [a for a in _aliases(v) if a not in av]
        out[k] = e
    for k in list(out):
        for a in out[k]["aliases"]:
            out.setdefault(a, {**out[k], "alias_of": k, "aliases": []})
    return out


# Starter pictures shipped in static/seed-avatars (Morc + Jinx from their Slack profiles).
SEEDS = {"morc": ("Morc", "morc.png"), "jinx": ("Jinx", "jinx.png")}


def seed_defaults(seed_dir=None) -> list:
    """Add starter avatars once. Never overwrites an existing profile; remembers what it
    seeded (avatars.json 'seeded') so a removed seed is not re-added."""
    seed_dir = seed_dir or (S.STATIC / "seed-avatars")
    done = []
    with _lock:
        try:
            meta = json.loads(_file().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            meta = {}
        seeded = set(meta.get("seeded") or [])
        av = load()
        for key, (name, fn) in SEEDS.items():
            src = seed_dir / fn
            if key in seeded or resolve(key, av) in av or not src.is_file():
                continue
            raw = src.read_bytes()
            ext = _sniff(raw)
            if not ext or len(raw) > MAX_BYTES:
                continue
            d = _dir()
            d.mkdir(parents=True, exist_ok=True)
            fp = d / f"{key}.{ext}"
            fp.write_bytes(raw)
            os.chmod(fp, 0o600)
            av[key] = {"name": name, "image": fp.name}
            seeded.add(key)
            done.append(key)
        if done:
            save(av, seeded=sorted(seeded))
    return done


def merge(body: dict) -> dict:
    """Fold sender `from` into profile `into` (e.g. claude-code -> claude)."""
    into = key_for(body.get("into") or "")
    frm = key_for(body.get("from") or "")
    if not into or not frm:
        raise AvErr(400, "key_required")
    with _lock:
        av = load()
        into = resolve(into, av)
        frm_c = resolve(frm, av)
        if frm_c == into:
            raise AvErr(400, "same_profile")
        if into not in av:
            av[into] = {"name": str(body.get("name") or into)[:64]}
        tgt = av[into]
        al = set(_aliases(tgt))
        if frm_c in av:
            src = av.pop(frm_c)
            al |= set(_aliases(src))
            p, _ = _image_path(frm_c, src)
            if p:
                if not _image_path(into, tgt)[0]:
                    ext = p.suffix
                    np_ = _dir() / f"{into}{ext}"
                    os.replace(p, np_)
                    tgt["image"] = np_.name
                else:
                    p.unlink()
            if not _valid_color(tgt.get("color")) and _valid_color(src.get("color")):
                tgt["color"] = src["color"]
        al.add(frm_c)
        al.add(frm)
        al.discard(into)
        tgt["aliases"] = sorted(al)[:50]
        av[into] = tgt
        save(av)
    return {"key": into, **public_map()[into]}


def unmerge(body: dict) -> None:
    alias = key_for(body.get("alias") or "")
    with _lock:
        av = load()
        for v in av.values():
            al = _aliases(v)
            if alias in al:
                v["aliases"] = [a for a in al if a != alias]
                save(av)
                return
    raise AvErr(404, "not_found")


ROLE_USER = "user"
_PREFIX = re.compile(r"^\[([A-Za-z0-9_.-]{1,64})\]\s")


def sender_of(msg: dict, room_title: str) -> str:
    """Python twin of senderFor() in static/avatars.js."""
    if msg.get("from"):
        return str(msg["from"])
    m = _PREFIX.match(str(msg.get("text") or ""))
    if m:
        return m.group(1)
    if msg.get("role") == ROLE_USER:
        return "John"
    t = str(room_title or "Assistant")
    p = re.search(r"\(([^()]+)\)\s*$", t)
    return p.group(1) if p else t


_senders_cache = {"key": None, "val": None}


def senders() -> list:
    """Every sender seen in chat history (plus roster bots), grouped by profile."""
    titles = {b["id"]: b["title"] for b in S.flat_sessions_from_roster(S.load_roster())}
    try:
        st = S.MESSAGES_FILE.stat()
        ck = (st.st_size, st.st_mtime_ns, tuple(sorted(titles.items())))
    except OSError:
        ck = None
    if ck is None or _senders_cache["key"] != ck:
        seen = {}
        for sid, t in titles.items():
            n = sender_of({"role": "assistant", "text": ""}, t)
            seen.setdefault(key_for(n), {"name": n, "count": 0, "last": None})
        for msg in (S.read_messages() if ck else []):
            n = sender_of(msg, titles.get(msg.get("session_id"), msg.get("session_id") or ""))
            k = key_for(n)
            if not k:
                continue
            e = seen.setdefault(k, {"name": n, "count": 0, "last": None})
            e["count"] += 1
            e["last"] = msg.get("ts") or e["last"]
        _senders_cache.update(key=ck, val=seen)
    seen = _senders_cache["val"] or {}
    av = load()
    pm = public_map()
    hidden = load_hidden()
    prof = {}
    for k, e in seen.items():
        c = resolve(k, av)
        p = prof.setdefault(c, {"key": c, "names": [], "count": 0, "last": None})
        p["names"].append(e["name"])
        p["count"] += e["count"]
        if e["last"] and (not p["last"] or e["last"] > p["last"]):
            p["last"] = e["last"]
    for k in av:
        prof.setdefault(k, {"key": k, "names": [], "count": 0, "last": None})
    out = []
    for c, p in prof.items():
        m = pm.get(c) or {}
        p.update(name=m.get("name") or (p["names"][0] if p["names"] else c),
                 url=m.get("url"), color=m.get("color"), initials=m.get("initials") or initials(p["names"][0] if p["names"] else c),
                 hue=hue_for(c), aliases=m.get("aliases") or [], configured=c in av,
                 hidden=c in hidden)
        out.append(p)
    out.sort(key=lambda p: (p["key"] == "john", -p["count"], p["name"].lower()))
    return out


def _hidden_file():
    return S.DATA / "bots_hidden.json"


def load_hidden() -> set:
    """Profile keys hidden from the Bots page (display only; chat + history untouched)."""
    try:
        h = json.loads(_hidden_file().read_text(encoding="utf-8")).get("hidden") or []
        return {k for k in h if isinstance(k, str) and k and key_for(k) == k}
    except (OSError, ValueError, AttributeError):
        return set()


def set_hidden(body: dict) -> dict:
    keys = body.get("keys")
    if keys is None:
        keys = [body.get("key")]
    if not isinstance(keys, list) or not keys or len(keys) > MAX_ENTRIES:
        raise AvErr(400, "key_required")
    hide = bool(body.get("hidden", True))
    with _lock:
        av = load()
        ks = []
        for k in keys:
            k = key_for(k or "")
            if not k:
                raise AvErr(400, "key_required")
            ks.append(resolve(k, av))
        if hide and "john" in ks:
            raise AvErr(400, "cannot_hide_owner")
        cur = load_hidden()
        cur = (cur | set(ks)) if hide else (cur - set(ks))
        f = _hidden_file()
        f.parent.mkdir(parents=True, exist_ok=True)
        tmp = f.with_suffix(".tmp")
        tmp.write_text(json.dumps({"hidden": sorted(cur)}, indent=2), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, f)
    return {"keys": ks, "hidden": hide}


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
        key = resolve(key, av)
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
            av = load()
            k = resolve(m.group(1), av)
            p, ctype = _image_path(k, av.get(k) or {})
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
        if method == "GET" and path == "/api/avatars/senders":
            h._json(200, {"profiles": senders()})
            return True
        if method == "POST" and path in ("/api/avatars/set", "/api/avatars/remove",
                                         "/api/avatars/merge", "/api/avatars/unmerge",
                                         "/api/avatars/hide"):
            if not h._require_stepup():
                return True
            body = h._read_json()
            if path.endswith("/set"):
                h._json(200, {"ok": True, "avatar": set_avatar(body)})
            elif path.endswith("/merge"):
                h._json(200, {"ok": True, "avatar": merge(body)})
            elif path.endswith("/hide"):
                h._json(200, {"ok": True, **set_hidden(body)})
            elif path.endswith("/unmerge"):
                unmerge(body)
                h._json(200, {"ok": True})
            else:
                remove(str(body.get("key") or ""))
                h._json(200, {"ok": True})
            return True
        raise AvErr(404, "not_found")
    except AvErr as e:
        h._json(e.code, {"error": e.err})
        return True
