"""NullVault 0.7.0: optional layout sync (John 2026-11-14 9:37 PM ET, Morc's call: opt-in, default off on the phone).

One non-secret document per owner (Nullink has a single owner): the bottom-navigation layout and the start page.
Nothing else is accepted: the shape is checked field by field (ids, short labels, icons, page names), unknown keys
are refused, and the body is capped at 8 KB. The most recent change wins by the phone's change time (clamped to
the server clock), so a phone that was offline keeps its own layout until it syncs and is newer.

Routes (device bearer token; a layout is not a security setting, so no fingerprint signature):
  GET  /api/vault/layout   -> {"layout": {...} | null, "updated_at_ms": int, "device_id": str}
  POST /api/vault/layout   {"layout": {...}, "updated_at_ms": int} -> {"applied": bool, ...stored doc}
"""
from __future__ import annotations

import json
import re
import threading
import time

nv = None
server = None

FILE = "layout.json"
MAX_BODY = 8 * 1024
MAX_BUTTONS, PER_ROW, ROWS, MAX_GROUPS, MAX_PAGES = 10, 5, 2, 12, 40
ID = re.compile(r"^[a-z0-9_-]{1,24}$")
PAGE = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,31}$")
SKEW_MS = 5 * 60 * 1000
_lock = threading.Lock()


def bind(nv_mod, srv):
    global nv, server
    nv, server = nv_mod, srv


def _text(v, n) -> str | None:
    if not isinstance(v, str) or not 0 < len(v) <= n or any(ord(c) < 32 or 0x7f <= ord(c) < 0xa0 for c in v):
        return None
    return v


def clean(layout) -> dict | None:
    """The validated layout, or None. Exact key sets: nothing but layout data can be stored."""
    if not isinstance(layout, dict) or set(layout) - {"v", "buttons", "groups", "start"}:
        return None
    buttons, groups, start = layout.get("buttons"), layout.get("groups", []), layout.get("start")
    if layout.get("v", 1) != 1 or not isinstance(buttons, list) or not isinstance(groups, list):
        return None
    if not isinstance(start, str) or not PAGE.match(start) or len(buttons) > MAX_BUTTONS or len(groups) > MAX_GROUPS:
        return None
    out_g, gids, seen_pages = [], set(), set()
    for g in groups:
        if not isinstance(g, dict) or set(g) - {"id", "name", "pages"} or not isinstance(g.get("id"), str) or not ID.match(g["id"]):
            return None
        name, pages = _text(g.get("name"), 24), g.get("pages", [])
        if name is None or g["id"] in gids or not isinstance(pages, list) or len(pages) > MAX_PAGES:
            return None
        for p in pages:
            if not isinstance(p, str) or not PAGE.match(p) or p in seen_pages:
                return None
            seen_pages.add(p)
        gids.add(g["id"]); out_g.append({"id": g["id"], "name": name, "pages": list(pages)})
    out_b, bids, rows = [], set(), [0] * ROWS
    for b in buttons:
        if not isinstance(b, dict) or set(b) - {"id", "row", "label", "icon", "group", "page"}:
            return None
        bid, row = b.get("id"), b.get("row", 0)
        if not isinstance(bid, str) or not ID.match(bid) or bid in bids or isinstance(row, bool) or row not in range(ROWS):
            return None
        label, icon = _text(b.get("label"), 24), _text(b.get("icon"), 8)
        group, page = b.get("group"), b.get("page")
        if label is None or icon is None or (group is None) == (page is None):
            return None
        if group is not None and (not isinstance(group, str) or group not in gids):
            return None
        if page is not None and (not isinstance(page, str) or not PAGE.match(page) or page in seen_pages):
            return None
        rows[row] += 1
        if rows[row] > PER_ROW:
            return None
        if page is not None:
            seen_pages.add(page)
        bids.add(bid)
        nb = {"id": bid, "row": row, "label": label, "icon": icon}
        nb.update({"group": group} if group is not None else {"page": page})
        out_b.append(nb)
    return {"v": 1, "buttons": out_b, "groups": out_g, "start": start}


def _path():
    return nv.nv_dir() / FILE


def load() -> dict:
    try:
        d = json.loads(_path().read_text(encoding="utf-8"))
        if isinstance(d, dict) and clean(d.get("layout")) is not None:
            return d
    except (OSError, ValueError):
        pass
    return {"layout": None, "updated_at_ms": 0, "device_id": ""}


def route(h, method: str, path: str):
    d = nv._device_from_bearer(h)
    if not d:
        return
    if method == "GET":
        return h._json(200, load())
    if int(h.headers.get("Content-Length") or 0) > MAX_BODY:
        return h._json(413, {"error": "too_large"})
    body = h._read_json() or {}
    lay, ts = clean(body.get("layout")), body.get("updated_at_ms")
    if lay is None or isinstance(ts, bool) or not isinstance(ts, int) or ts <= 0:
        return h._json(400, {"error": "bad_layout"})
    now = int(time.time() * 1000)
    ts = min(ts, now + SKEW_MS)
    with _lock:
        cur = load()
        if ts <= int(cur.get("updated_at_ms") or 0):
            return h._json(200, {"applied": False, **cur})
        doc = {"layout": lay, "updated_at_ms": ts, "device_id": d["device_id"]}
        server._atomic_write_json(_path(), doc)
    server.vault_audit("device_layout_set", device=d["device_id"], buttons=len(lay["buttons"]), groups=len(lay["groups"]))
    return h._json(200, {"applied": True, **doc})
