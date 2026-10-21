"""Files manager Favorites (fav1): pinned folders on either drive, stored server-side
per owner in data/fm_favorites.json. Routed from files_manager.handle, so the owner-only
gate (no guests, no Bearer/agent tokens) already applies. Opening a Server-drive favorite
still goes through /api/sd/list, which enforces the 15-minute unlock."""
import json
import os
import re
import secrets
import threading
import time

import server as S

DRIVES = ("files", "server", "github")
MAX_FAVORITES = 100
MAX_LABEL = 80
OWNER_KEY = "owner"  # Nullink has a single owner account
_lock = threading.Lock()


class FavErr(Exception):
    def __init__(self, code, err, **extra):
        self.code, self.err, self.extra = code, err, extra


def _file():
    return S.DATA / "fm_favorites.json"


def load() -> list[dict]:
    try:
        data = json.loads(_file().read_text(encoding="utf-8"))
        items = (data.get("owners") or {}).get(OWNER_KEY) or []
        return [i for i in items if isinstance(i, dict) and i.get("id") and i.get("drive") in DRIVES]
    except (OSError, ValueError, AttributeError):
        return []


def save(items: list[dict]) -> None:
    f = _file()
    f.parent.mkdir(parents=True, exist_ok=True)
    tmp = f.with_suffix(".json.tmp")
    tmp.write_text(json.dumps({"version": 1, "owners": {OWNER_KEY: items}}, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, f)


def _label(raw, path) -> str:
    s = " ".join(str(raw if raw is not None else "").split())[:MAX_LABEL]
    if s:
        return s
    leaf = path.rstrip("/").rsplit("/", 1)[-1]
    if ":" in path and "@" in path:
        repo, rest = path.split("@", 1)
        sub = rest.split(":", 1)[1]
        return (sub.rsplit("/", 1)[-1] if sub else repo.split("/")[-1])[:MAX_LABEL]
    return leaf or ("Server /" if path == "/" else "Files")


def _norm(drive: str, raw) -> str:
    import files_manager as FM
    import server_drive as SD
    if drive == "files":
        folder = FM.norm_folder(raw if raw is not None else "")
        if folder is None:
            raise FavErr(400, "bad_path")
        if folder and folder not in FM.load_folders():
            raise FavErr(404, "not_found")
        return folder
    if drive == "github":
        import github_drive as GH
        m = re.match(r"^([^@:]+)@([^:]+):(.*)$", str(raw or ""))
        if not m:
            raise FavErr(400, "bad_path")
        try:
            return f"{GH._repo(m.group(1))}@{GH._ref(m.group(2))}:{GH._path(m.group(3))}"
        except GH.GhErr:
            raise FavErr(400, "bad_path")
    try:
        rel = SD.norm_rel(raw)
    except Exception:
        raise FavErr(400, "bad_path")
    path = "/" + rel
    if SD.is_blocked(os.path.join(os.path.realpath(SD.drive_root()), rel)):
        raise FavErr(403, "blocked_path")
    return path


def handle(h, method: str, path: str, rec: dict | None) -> None:
    try:
        if method == "GET" and path == "/api/fm/favorites":
            return h._json(200, {"items": load()})
        if method != "POST":
            raise FavErr(405, "method_not_allowed")
        body = h._read_json()
        body = body if isinstance(body, dict) else {}
        with _lock:
            items = load()
            if path == "/api/fm/favorites/add":
                drive = str(body.get("drive") or "files")
                if drive not in DRIVES:
                    raise FavErr(400, "bad_drive")
                if drive == "server":
                    import server_drive as SD
                    if not rec or not SD.unlocked_for(rec):
                        raise FavErr(403, "drive_locked")
                p = _norm(drive, body.get("path"))
                dup = next((i for i in items if i["drive"] == drive and i["path"] == p), None)
                if dup:
                    return h._json(200, {"item": dup, "items": items})
                if len(items) >= MAX_FAVORITES:
                    raise FavErr(400, "too_many")
                item = {"id": secrets.token_hex(6), "drive": drive, "path": p,
                        "label": _label(body.get("label"), p), "created_at": time.time()}
                items.append(item)
                save(items)
                return h._json(200, {"item": item, "items": items})
            fid = str(body.get("id") or "")
            if path == "/api/fm/favorites/rename":
                it = next((i for i in items if i["id"] == fid), None)
                if not it:
                    raise FavErr(404, "not_found")
                lab = " ".join(str(body.get("label") or "").split())[:MAX_LABEL]
                if not lab:
                    raise FavErr(400, "bad_label")
                it["label"] = lab
                save(items)
                return h._json(200, {"item": it, "items": items})
            if path == "/api/fm/favorites/remove":
                left = [i for i in items if i["id"] != fid]
                if len(left) == len(items):
                    raise FavErr(404, "not_found")
                save(left)
                return h._json(200, {"items": left})
            if path == "/api/fm/favorites/reorder":
                ids = body.get("ids")
                if not isinstance(ids, list) or sorted(map(str, ids)) != sorted(i["id"] for i in items):
                    raise FavErr(400, "bad_order", message="ids must list every favorite exactly once")
                by = {i["id"]: i for i in items}
                items = [by[str(x)] for x in ids]
                save(items)
                return h._json(200, {"items": items})
        raise FavErr(404, "not_found")
    except FavErr as e:
        h._json(e.code, {"error": e.err, **e.extra})
