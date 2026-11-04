"""Files "Date added" / "Date created" stamps (2026-10-26).

added_at   = when the entry was registered in Nullink Files (set once, never changed).
created_at = the file's original timestamp when we can know it, in this order:
             1. EXIF DateTimeOriginal (JPEG/TIFF only, bounded pure-Python read)
             2. browser File.lastModified sent with the upload
             3. source file mtime for server-side / bot registrations (register, uploads/ copies)
             4. otherwise the date added.
created_src records which of these was used: exif | client | source_mtime | file_mtime | existing | added.
Never raises; bad or implausible values are ignored."""
from __future__ import annotations

import os
import struct
import time
from datetime import datetime, timezone
from pathlib import Path

MIN_TS = 315532800  # 1980-01-01
EXIF_TZ = "America/New_York"  # EXIF without OffsetTimeOriginal is local camera time; assume John's zone
EXIF_EXT = (".jpg", ".jpeg", ".jpe", ".tif", ".tiff")
EXIF_READ_MAX = 256 * 1024


def iso_utc(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def parse_iso(s) -> float | None:
    if not s or not isinstance(s, str):
        return None
    try:
        d = datetime.fromisoformat(s.strip().replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d.timestamp()
    except ValueError:
        return None


def sane(ts) -> bool:
    try:
        ts = float(ts)
    except (TypeError, ValueError):
        return False
    return MIN_TS <= ts <= time.time() + 86400


def client_ms_to_ts(v) -> float | None:
    try:
        ts = float(v) / 1000.0
    except (TypeError, ValueError):
        return None
    return ts if sane(ts) else None


def _exif_from_tiff(t: bytes) -> tuple[str | None, str | None]:
    if len(t) < 8 or t[:2] not in (b"II", b"MM"):
        return None, None
    e = "<" if t[:2] == b"II" else ">"

    def ifd(off):
        out = {}
        if off <= 0 or off + 2 > len(t):
            return out
        (n,) = struct.unpack_from(e + "H", t, off)
        for i in range(min(n, 512)):
            p = off + 2 + i * 12
            if p + 12 > len(t):
                break
            tag, typ, cnt = struct.unpack_from(e + "HHI", t, p)
            if typ == 2:  # ASCII
                vo = p + 8 if cnt <= 4 else struct.unpack_from(e + "I", t, p + 8)[0]
                if 0 <= vo and vo + cnt <= len(t) and cnt <= 64:
                    out[tag] = t[vo:vo + cnt].split(b"\0")[0].decode("ascii", "ignore")
            elif typ == 4 and cnt == 1:
                out[tag] = struct.unpack_from(e + "I", t, p + 8)[0]
        return out

    (ifd0,) = struct.unpack_from(e + "I", t, 4)
    d0 = ifd(ifd0)
    sub = ifd(d0[0x8769]) if isinstance(d0.get(0x8769), int) else {}
    dt = sub.get(0x9003) or sub.get(0x9004) or None
    return (dt if isinstance(dt, str) else None), (sub.get(0x9011) if isinstance(sub.get(0x9011), str) else None)


def exif_ts(path) -> float | None:
    """DateTimeOriginal as epoch seconds, or None. Reads at most EXIF_READ_MAX bytes."""
    try:
        p = Path(path)
        if p.suffix.lower() not in EXIF_EXT or not p.is_file() or p.is_symlink():
            return None
        with open(p, "rb") as f:
            b = f.read(EXIF_READ_MAX)
        tiff = None
        if b[:2] == b"\xff\xd8":
            i = 2
            while i + 4 <= len(b) and b[i] == 0xFF:
                mk = b[i + 1]
                if mk in (0xD9, 0xDA):
                    break
                (ln,) = struct.unpack_from(">H", b, i + 2)
                seg = b[i + 4:i + 2 + ln]
                if mk == 0xE1 and seg[:6] == b"Exif\0\0":
                    tiff = seg[6:]
                    break
                i += 2 + ln
        elif b[:2] in (b"II", b"MM"):
            tiff = b
        if not tiff:
            return None
        dt, off = _exif_from_tiff(tiff)
        if not dt:
            return None
        d = datetime.strptime(dt.strip()[:19], "%Y:%m:%d %H:%M:%S")
        if off and len(off) >= 6 and off[0] in "+-":
            d = datetime.fromisoformat(d.strftime("%Y-%m-%dT%H:%M:%S") + off[:6])
        else:
            try:
                from zoneinfo import ZoneInfo
                d = d.replace(tzinfo=ZoneInfo(EXIF_TZ))
            except Exception:  # noqa: BLE001
                d = d.replace(tzinfo=timezone.utc)
        ts = d.timestamp()
        return ts if sane(ts) else None
    except Exception:  # noqa: BLE001
        return None


def _mtime(path) -> float | None:
    try:
        p = Path(path)
        if p.is_symlink() or not p.is_file():
            return None
        ts = p.stat().st_mtime
        return ts if sane(ts) else None
    except (OSError, TypeError, ValueError):
        return None


def stamp(entry: dict, *, exif_path=None, client_ms=None, src_path=None, now_iso: str | None = None) -> dict:
    """Set added_at (if missing) and created_at/created_src (if missing) on a new registry entry."""
    if not entry.get("added_at"):
        entry["added_at"] = now_iso or entry.get("updated_at") or iso_utc(time.time())
    if entry.get("created_at"):
        entry.setdefault("created_src", "existing")
        return entry
    for src, ts in (("exif", exif_ts(exif_path) if exif_path else None),
                    ("client", client_ms_to_ts(client_ms) if client_ms is not None else None),
                    ("source_mtime", _mtime(src_path) if src_path else None)):
        if ts:
            entry["created_at"], entry["created_src"] = iso_utc(ts), src
            return entry
    entry["created_at"], entry["created_src"] = entry["added_at"], "added"
    return entry


def backfill(files: list, resolve) -> int:
    """Fill added_at/created_at on existing entries in place. `resolve(entry)` -> stored Path or None.
    added_at := earliest of existing created_at / updated_at (best record of registration we have).
    created_at := EXIF, else min(source mtime, stored file mtime) capped at added_at, else added_at.
    Returns the number of entries changed. Idempotent."""
    changed = 0
    for e in files:
        if not isinstance(e, dict):
            continue
        before = (e.get("added_at"), e.get("created_at"), e.get("created_src"))
        if not e.get("added_at"):
            cands = [t for t in (parse_iso(e.get("created_at")), parse_iso(e.get("updated_at"))) if t]
            e["added_at"] = iso_utc(min(cands)) if cands else iso_utc(time.time())
            e.setdefault("added_src", "backfill")
        if e.get("created_at"):
            e.setdefault("created_src", "existing")
        else:
            added = parse_iso(e["added_at"]) or time.time()
            try:
                stored = resolve(e)
            except Exception:  # noqa: BLE001
                stored = None
            ts, src = (exif_ts(stored) if stored else None), "exif"
            if not ts:
                rf = e.get("registered_from")
                opts = [(t, s) for t, s in ((_mtime(rf) if rf else None, "source_mtime"),
                                            (_mtime(stored) if stored else None, "file_mtime")) if t]
                if opts:
                    ts, src = min(opts)
                    if ts > added:
                        ts, src = added, "added"
            if ts:
                e["created_at"], e["created_src"] = iso_utc(ts), src
            else:
                e["created_at"], e["created_src"] = e["added_at"], "added"
        if before != (e.get("added_at"), e.get("created_at"), e.get("created_src")):
            changed += 1
    return changed
