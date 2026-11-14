"""NullVault 0.6.0 (John 2026-11-13 11:59 PM ET: "End to end"): end-to-end encrypted vault items.

The server stores ciphertext and metadata only. It never receives the passphrase, the recovery key or the vault key
(VK); it validates shapes and sizes, binds versions, and keeps the per-account header of *wrapped* VK blobs.

Records (data/vault/<id>.json for entries, notes.json for notes):
  E2E item:      {"id", "title": "", "tags": [], "created_at", "updated_at", "ver": N, "e2e": BLOB}
  legacy item:   {"id", "title", "tags", ..., "enc": server-key AES-GCM}            (pre-0.6.0)
  migrating:     legacy + "e2e_pending": BLOB  (device uploaded, not yet read back and confirmed)
BLOB = {"v": 1, "alg": "A256GCM", "kid": <vk_id>, "ver": N, "n": b64(12), "c": b64(ct||tag)}
The device's AAD binds kind, id, version and kid (and the project for notes), so the server cannot swap items.

Migration: `migrate` stores e2e_pending next to the legacy copy and returns it as read back from disk; the device
decrypts and compares, then `migrate_confirm` (SHA-256 of the pending blob) promotes it and deletes the legacy,
server-decryptable copy of that item. The legacy server key itself is never touched here (retire-legacy-key).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import threading
import time
from pathlib import Path

nv = None
server = None
_lock = threading.RLock()

E2E_MIN_VC = 11                      # 0.6.0-test
ID_RE = re.compile(r"[0-9a-f]{12,32}")
VK_ID_RE = re.compile(r"[0-9a-f]{16,32}")
MAX_CT = 150_000                     # 100 KB body + title/tags + JSON + tag
HEADER_KEYS = {"v", "vk_id", "passphrase", "recovery"}
ARGON2_MIN_M, ARGON2_MAX_M = 65536, 1048576   # KiB: 64 MiB .. 1 GiB
ARGON2_MIN_T, ARGON2_MAX_T = 3, 10
OLD_CLIENT_MSG = ("This vault is end-to-end encrypted. Install NullVault 0.6.0 or newer to open it. "
                  "Nothing was wiped.")


def bind(nv_mod, srv):
    global nv, server
    nv, server = nv_mod, srv


# ---------------------------------------------------------------- shapes

def _b64(s, lo: int, hi: int) -> bytes | None:
    if not isinstance(s, str) or len(s) > hi * 2 + 8:
        return None
    try:
        b = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None
    return b if lo <= len(b) <= hi else None


def _int(v, lo, hi):
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v <= hi


def valid_wrap(w, kind: str) -> bool:
    if not isinstance(w, dict):
        return False
    common = _b64(w.get("salt"), 16, 64) and _b64(w.get("n"), 12, 12) and _b64(w.get("c"), 48, 48)
    if not common:
        return False
    if kind == "passphrase":
        return set(w) == {"kdf", "m", "t", "p", "salt", "n", "c"} and w.get("kdf") == "argon2id" and \
            _int(w.get("m"), ARGON2_MIN_M, ARGON2_MAX_M) and _int(w.get("t"), ARGON2_MIN_T, ARGON2_MAX_T) and \
            _int(w.get("p"), 1, 8)
    return set(w) == {"kdf", "salt", "n", "c"} and w.get("kdf") == "hkdf-sha256"


def valid_header(hd) -> bool:
    return isinstance(hd, dict) and set(hd) == HEADER_KEYS and hd.get("v") == 1 and \
        isinstance(hd.get("vk_id"), str) and bool(VK_ID_RE.fullmatch(hd["vk_id"])) and \
        valid_wrap(hd.get("passphrase"), "passphrase") and valid_wrap(hd.get("recovery"), "recovery")


def valid_blob(b, kid: str | None, ver: int | None = None) -> bool:
    if not isinstance(b, dict) or set(b) != {"v", "alg", "kid", "ver", "n", "c"}:
        return False
    if b.get("v") != 1 or b.get("alg") != "A256GCM" or not _int(b.get("ver"), 1, 2**31 - 1):
        return False
    if kid is None or b.get("kid") != kid or (ver is not None and b["ver"] != ver):
        return False
    return bool(_b64(b.get("n"), 12, 12) and _b64(b.get("c"), 17, MAX_CT))


def blob_sha(b: dict) -> str:
    return hashlib.sha256(json.dumps(b, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# ---------------------------------------------------------------- header (wrapped VK blobs only)

def header_file() -> Path:
    return nv.nv_dir() / "e2e.json"


def header() -> dict | None:
    try:
        d = json.loads(header_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return d if isinstance(d, dict) and d.get("vk_id") else None


def public_header() -> dict | None:
    hd = header()
    return {k: hd[k] for k in ("v", "vk_id", "passphrase", "recovery", "gen", "created_at", "updated_at") if k in hd} if hd else None


def kid() -> str | None:
    hd = header()
    return hd["vk_id"] if hd else None


def old_client(p: dict) -> bool:
    if header() is None:
        return False
    try:
        return int((p.get("apk") or {}).get("version_code") or 0) < E2E_MIN_VC
    except (TypeError, ValueError):
        return True


def refuse_old(h, did: str | None = None):
    server.vault_audit("device_refused", device=did, reason="e2e_client_required")
    return h._json(426, {"error": "e2e_client_required", "min_version_code": E2E_MIN_VC, "message": OLD_CLIENT_MSG})


def header_write(p: dict):
    """-> (status, body). init: first setup. rewrap: same VK, new passphrase and/or recovery wrap (gen must match).
    Changing vk_id (full VK rotation) is not supported in 0.6.0."""
    if p.get("signed_by", "device") != "device":
        return 403, {"error": "fingerprint_required", "message": "Encryption settings need this phone's fingerprint key."}
    op, hd = p.get("op"), p.get("e2e_header")
    if not valid_header(hd):
        return 400, {"error": "bad_header"}
    with _lock:
        cur = header()
        now = server.iso_now()
        if op == "init":
            if cur is not None:
                return 409, {"error": "e2e_exists", "e2e": public_header()}
            rec = {**hd, "gen": 1, "created_at": now, "updated_at": now}
        elif op == "rewrap":
            if cur is None:
                return 409, {"error": "e2e_not_set_up"}
            if hd["vk_id"] != cur["vk_id"]:
                return 409, {"error": "rotation_not_supported"}
            if p.get("base_gen") != cur.get("gen"):
                return 409, {"error": "conflict", "e2e": public_header()}
            rec = {**hd, "gen": int(cur.get("gen") or 1) + 1, "created_at": cur.get("created_at"), "updated_at": now}
        else:
            return 400, {"error": "bad_request"}
        server._atomic_write_json(header_file(), rec)
    return 200, {"e2e": public_header()}


# ---------------------------------------------------------------- vault entries

def _raw(vid):
    return server._vault_read_raw(vid)


def _put(vid: str, rec: dict) -> None:
    server._atomic_write_json(server.VAULT_DIR / f"{vid}.json", rec)


def _meta(rec: dict) -> dict:
    return {"id": rec["id"], "ver": rec.get("ver"), "created_at": rec.get("created_at"), "updated_at": rec.get("updated_at")}


def is_e2e(rec: dict | None) -> bool:
    return isinstance(rec, dict) and isinstance(rec.get("e2e"), dict)


def entry_write(p: dict, op: str):
    """-> (status, body, id). Called only when the account has an E2E header and op != delete."""
    k = kid()
    e = p.get("entry") if isinstance(p.get("entry"), dict) else {}
    if "body" in e or "title" in e or "tags" in e:
        if op in ("create", "update"):
            return 409, {"error": "e2e_required", "message": "This vault is end-to-end encrypted: plaintext writes are refused."}, None
    vid = str(e.get("id") or "")
    now = server.iso_now()
    with _lock:
        if op == "create":
            if not ID_RE.fullmatch(vid) or _raw(vid) is not None:
                return 409, {"error": "bad_id"}, None
            b = e.get("e2e")
            if not valid_blob(b, k, 1):
                return 400, {"error": "bad_blob"}, None
            rec = {"id": vid, "title": "", "tags": [], "created_at": now, "updated_at": now, "ver": 1, "e2e": b}
            _put(vid, rec)
            return 200, {"entry": _meta(rec)}, vid
        cur = _raw(vid) if server._vault_safe_id(vid) else None
        if not cur:
            return 404, {"error": "not_found"}, None
        base = p.get("base_updated_at")
        if op == "update":
            if base and base != cur.get("updated_at"):
                return 409, {"error": "conflict", "entry": _meta({**cur, "id": vid})}, None
            want = int(cur.get("ver") or 0) + 1 if is_e2e(cur) else 1
            b = e.get("e2e")
            if not valid_blob(b, k, want):
                return 409, {"error": "bad_version", "expected_ver": want}, None
            rec = {"id": vid, "title": "", "tags": [], "created_at": cur.get("created_at") or now, "updated_at": now,
                   "ver": want, "e2e": b}
            _put(vid, rec)
            return 200, {"entry": _meta(rec)}, vid
        if op == "migrate":
            if is_e2e(cur) or not isinstance(cur.get("enc"), dict):
                return 409, {"error": "not_legacy"}, None
            b = e.get("e2e")
            if not valid_blob(b, k, 1):
                return 400, {"error": "bad_blob"}, None
            _put(vid, {**cur, "e2e_pending": b})
            back = (_raw(vid) or {}).get("e2e_pending")      # read back from disk for the device to verify
            return 200, {"entry": {"id": vid, "e2e_pending": back, "updated_at": cur.get("updated_at")}}, vid
        if op == "migrate_confirm":
            pend = cur.get("e2e_pending")
            if is_e2e(cur):
                return 200, {"entry": _meta({**cur, "id": vid}), "already": True}, vid
            if not isinstance(pend, dict) or str(e.get("sha256") or "") != blob_sha(pend) or not valid_blob(pend, k, 1):
                return 409, {"error": "verify_mismatch"}, None
            rec = {"id": vid, "title": "", "tags": [], "created_at": cur.get("created_at") or now, "updated_at": now,
                   "ver": 1, "e2e": pend}
            _put(vid, rec)                                    # the server-decryptable copy of this item is gone
            return 200, {"entry": _meta(rec)}, vid
    return 400, {"error": "bad_request"}, None


def sync_entries(audit) -> list[dict]:
    out = []
    for fp in sorted(server.VAULT_DIR.glob("*.json")):
        rec = _raw(fp.stem)
        if not rec:
            continue
        vid = str(rec.get("id") or fp.stem)
        if is_e2e(rec):
            out.append({"id": vid, "e2e": rec["e2e"], "ver": rec.get("ver"), "created_at": rec.get("created_at"),
                        "updated_at": rec.get("updated_at")})
            continue
        try:
            item = server.load_vault_snippet(vid, decrypt=True)
        except server.VaultIntegrityError:
            audit(vid)
            continue
        if item:
            row = {k: item.get(k) for k in ("id", "title", "tags", "body", "created_at", "updated_at")}
            if isinstance(rec.get("e2e_pending"), dict):
                row["e2e_pending"] = rec["e2e_pending"]
            out.append(row)
    return out


# ---------------------------------------------------------------- notes (notes.json)

def note_view(n: dict) -> dict:
    v = {"id": n["id"], "project_id": n.get("project_id"), "created_at": n.get("created_at"), "updated_at": n.get("updated_at")}
    if is_e2e(n):
        v.update(e2e=n["e2e"], ver=n.get("ver"))
    return v


def note_write(p: dict, op: str, ext):
    """-> (status, body, id) or None to fall through (delete). Account has an E2E header."""
    if op == "delete":
        return None
    k = kid()
    e = p.get("note") if isinstance(p.get("note"), dict) else {}
    if ("body" in e or "title" in e) and op in ("create", "update"):
        return 409, {"error": "e2e_required", "message": "This vault is end-to-end encrypted: plaintext writes are refused."}, None
    nid = str(e.get("id") or "")
    now = server.iso_now()
    with ext._lock:
        items = ext._load_list("notes.json")
        cur = next((x for x in items if x.get("id") == nid), None)
        if op == "create":
            pid = str(e.get("project_id") or "")
            if not ID_RE.fullmatch(nid) or cur is not None:
                return 409, {"error": "bad_id"}, None
            if not any(pr.get("id") == pid for pr in ext._load_list("projects.json")):
                return 400, {"error": "bad_record"}, None
            if len(items) >= ext.MAX_NOTES:
                return 409, {"error": "too_many"}, None
            if not valid_blob(e.get("e2e"), k, 1):
                return 400, {"error": "bad_blob"}, None
            rec = {"id": nid, "project_id": pid, "created_at": now, "updated_at": now, "ver": 1, "e2e": e["e2e"]}
            items.append(rec)
            ext._save_list("notes.json", items)
            return 200, {"note": note_view(rec)}, nid
        if not cur:
            return 404, {"error": "not_found"}, None
        base = p.get("base_updated_at")
        if op == "update":
            if base and base != cur.get("updated_at"):
                return 409, {"error": "conflict", "note": note_view(cur)}, None
            want = int(cur.get("ver") or 0) + 1 if is_e2e(cur) else 1
            if not valid_blob(e.get("e2e"), k, want):
                return 409, {"error": "bad_version", "expected_ver": want}, None
            rec = {"id": nid, "project_id": cur["project_id"], "created_at": cur.get("created_at") or now,
                   "updated_at": now, "ver": want, "e2e": e["e2e"]}
        elif op == "migrate":
            if is_e2e(cur) or not isinstance(cur.get("enc"), dict):
                return 409, {"error": "not_legacy"}, None
            if not valid_blob(e.get("e2e"), k, 1):
                return 400, {"error": "bad_blob"}, None
            rec = {**cur, "e2e_pending": e["e2e"]}
        elif op == "migrate_confirm":
            if is_e2e(cur):
                return 200, {"note": note_view(cur), "already": True}, nid
            pend = cur.get("e2e_pending")
            if not isinstance(pend, dict) or str(e.get("sha256") or "") != blob_sha(pend) or not valid_blob(pend, k, 1):
                return 409, {"error": "verify_mismatch"}, None
            rec = {"id": nid, "project_id": cur["project_id"], "created_at": cur.get("created_at") or now,
                   "updated_at": now, "ver": 1, "e2e": pend}
        else:
            return 400, {"error": "bad_request"}, None
        ext._save_list("notes.json", [rec if x is cur else x for x in items])
    if op == "migrate":
        back = next((x for x in ext._load_list("notes.json") if x.get("id") == nid), {}).get("e2e_pending")
        return 200, {"note": {"id": nid, "project_id": cur.get("project_id"), "e2e_pending": back}}, nid
    return 200, {"note": note_view(rec)}, nid


# ---------------------------------------------------------------- legacy key inventory (retire-legacy-key)

def legacy_inventory(ext) -> dict:
    """Items that still depend on the legacy server data key (or are plaintext on disk)."""
    entries, pending, notes = [], [], []
    for fp in sorted(server.VAULT_DIR.glob("*.json")):
        rec = _raw(fp.stem) or {}
        if is_e2e(rec):
            continue
        entries.append(str(rec.get("id") or fp.stem))
        if isinstance(rec.get("e2e_pending"), dict):
            pending.append(str(rec.get("id") or fp.stem))
    for n in ext._load_list("notes.json"):
        if not is_e2e(n):
            notes.append(str(n.get("id")))
    return {"legacy_entries": entries, "pending_confirm": pending, "legacy_notes": notes}


def retired_marker() -> Path:
    return nv.nv_dir() / "legacy_key_retired.json"


def retire_legacy_key(ext, confirm: bool) -> tuple[int, str]:
    """Never destroys anything by itself. Refuses unless E2E is set up and every entry and note is E2E.
    With --confirm it writes a marker so the server stops using the legacy key for new writes, then prints the
    root-only steps that destroy the key (John's explicit OK first; irreversible)."""
    if header() is None:
        return 2, "refused: end-to-end encryption is not set up for this account"
    inv = legacy_inventory(ext)
    left = len(inv["legacy_entries"]) + len(inv["legacy_notes"])
    if left:
        return 3, (f"refused: {len(inv['legacy_entries'])} vault entries and {len(inv['legacy_notes'])} notes still use the "
                   f"legacy server key ({len(inv['pending_confirm'])} awaiting device confirmation). Sync the phone first.\n"
                   f"entries: {', '.join(inv['legacy_entries'][:50])}\nnotes: {', '.join(inv['legacy_notes'][:50])}")
    if not confirm:
        return 0, "ready: every vault entry and note is end-to-end encrypted. Re-run with --confirm after John's OK."
    server._atomic_write_json(retired_marker(), {"retired_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                                 "by": "nullvault.py retire-legacy-key"})
    return 0, ("marker written: the server no longer encrypts anything with the legacy data key.\n"
               "To destroy the key (irreversible; root, John's OK):\n"
               "  1. remove the LoadCredential=vault_data_key line from the nullink unit/drop-in, systemctl daemon-reload\n"
               "  2. sudo shred -u /etc/nullink/vault/data.key\n"
               "  3. restart nullink via nulldo\n"
               "  4. delete backups that hold legacy ciphertext together with that key (e.g. nullvault-v11-*/data.tgz)\n")
