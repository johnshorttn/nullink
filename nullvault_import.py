"""NullVault 0.8.0 (John 2026-11-14 11:21 PM ET): bot-to-vault import queue.

"Build an import tool that bots can access to add an entry. Have it submitted like an approval import. It would show
up as an alert saying import needed. Then I sync and process it."

Trust model
* Each phone keeps a long-lived X25519 import key. The private half never leaves the phone (it is stored inside the
  SQLCipher database, wrapped by the vault key). The phone publishes the public half in a K_dev-signed request
  (fingerprint, signed purpose "import_key"); the server keeps the signed envelope so submitters can check it against
  the device's registered P-256 key themselves. Only active devices' keys are handed out, so revoke follows the device.
* A submitter (bot) holds an import-only token (prefix nlvi_, SHA-256 stored in data/nullvault/import_tokens.json).
  It can fetch the published keys, submit sealed imports and list ITS OWN submissions' status. Nothing else: the
  token is unknown to every other route (owner, device, API and bot-deposit tokens all use other prefixes).
* The submitter seals {v, type, title, fields} client side: X25519(ephemeral, phone key) -> HKDF-SHA256(salt =
  epk || phone pub, info "nullvault-import-v1") -> AES-256-GCM, AAD = nullvault-import-v1|import_id|submitter|device|kid.
  The server stores only the sealed blob and non-secret metadata (submitter, title, type, created, expires). The title
  and type ARE visible to the server and appear in the Slack alert: keep secrets out of titles.
* The phone pulls pending imports on Sync, decrypts one in memory, and only on Approve (K_dev = fingerprint) creates a
  normal E2E entry (server-chosen nothing: new id, ver 1, add-only), reads it back, then acks with a device/session
  signature carrying the read-back SHA-256. Only then is the sealed blob deleted. Reject deletes the blob too.
  Imports can only create: there is no edit, delete or overwrite path, and add-only entries are refused for update or
  delete on every route (phone writes, owner web, label rename).
* Pending imports expire after 7 days (EXPIRY_SEC): a week covers a phone left at home over a weekend, and an
  unopened secret should not sit on the server longer. Expired blobs are purged (on every import call and hourly).
* Audit (vault_audit.jsonl): import_submit / import_approve / import_ack / import_reject / import_expire /
  import_purged, ids and sizes only, never titles, fields or blobs.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
import urllib.parse
from pathlib import Path

import nullvault_ext as ext

nv = None
server = None

TOKEN_PREFIX = "nlvi_"
ALG = "X25519-HKDF-SHA256-A256GCM"
INFO = b"nullvault-import-v1"
TYPES = ("login", "note", "secret", "key")
EXPIRY_SEC = 7 * 86400
HISTORY_SEC = 30 * 86400
MAX_TITLE = 120
MAX_CT = 48 * 1024
MAX_BODY = 256 * 1024
MAX_PENDING_PER_SUBMITTER = 20
SUBMIT_LIMIT = (20, 3600)
READ_LIMIT = (240, 3600)
DECIDE_LIMIT = (60, 3600)
SWEEP_SEC = 3600
ID_RE = re.compile(r"^[0-9a-f]{32}$")
KID_RE = re.compile(r"^[0-9a-f]{16}$")
ENTRY_ID_RE = re.compile(r"^[0-9a-f]{12,32}$")
NAME_RE = re.compile(r"^[a-z0-9-]{1,32}$")
PATHS = {"/api/vault/import/keys", "/api/vault/import/submit", "/api/vault/import/status",
         "/api/vault/import/key", "/api/vault/import/pending", "/api/vault/import/decide", "/api/vault/import/ack"}
_lock = threading.RLock()
_sweeper = {"started": False}
limits = ext.RateLimit()


def bind(nv_mod, srv):
    global nv, server
    nv, server = nv_mod, srv
    ext.bind(nv_mod, srv)
    _start_sweeper()


def _start_sweeper():
    if _sweeper["started"] or os.environ.get("NULLVAULT_IMPORT_SWEEP", "1") == "0":
        return
    _sweeper["started"] = True

    def run():
        while True:
            time.sleep(SWEEP_SEC)
            try:
                if nv.enabled():
                    purge()
            except Exception:  # noqa: BLE001
                pass
    threading.Thread(target=run, name="nullvault-import-sweep", daemon=True).start()


# ---------------------------------------------------------------- files

def _dir() -> Path:
    return nv.nv_dir()


def tokens_file() -> Path:
    return _dir() / "import_tokens.json"


def keys_file() -> Path:
    return _dir() / "import_keys.json"


def index_file() -> Path:
    return _dir() / "imports.json"


def blob_dir() -> Path:
    d = _dir() / "imports"
    d.mkdir(mode=0o700, exist_ok=True)
    return d


def _blob_path(iid: str) -> Path:
    return blob_dir() / f"{iid}.json"


def _load(p: Path, default):
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default
    return d if isinstance(d, type(default)) else default


def _index() -> dict:
    return _load(index_file(), {})


def _save_index(ix: dict) -> None:
    server._atomic_write_json(index_file(), ix)


def _audit(event: str, **kw) -> None:
    server.vault_audit(event, **{k: v for k, v in kw.items() if v is not None})


# ---------------------------------------------------------------- crypto helpers (shared with the submit CLI/tests)

def kid_of(pub: bytes) -> str:
    return hashlib.sha256(pub).hexdigest()[:16]


def aad(import_id: str, submitter: str, device_id: str, kid: str) -> bytes:
    return f"nullvault-import-v1|{import_id}|{submitter}|{device_id}|{kid}".encode()


def _hkdf(shared: bytes, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=INFO).derive(shared)


def seal(pub: bytes, plaintext: bytes, import_id: str, submitter: str, device_id: str,
         esk: bytes | None = None, nonce: bytes | None = None) -> dict:
    """Seal to a phone's X25519 import key. Runs in the submitter's process; plaintext stays in memory."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    sk = X25519PrivateKey.from_private_bytes(esk) if esk else X25519PrivateKey.generate()
    epk = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key = _hkdf(sk.exchange(X25519PublicKey.from_public_bytes(pub)), epk + pub)
    n = nonce or secrets.token_bytes(12)
    kid = kid_of(pub)
    c = AESGCM(key).encrypt(n, plaintext, aad(import_id, submitter, device_id, kid))
    b = lambda x: base64.b64encode(x).decode()  # noqa: E731
    return {"v": 1, "alg": ALG, "kid": kid, "epk": b(epk), "n": b(n), "c": b(c)}


def open_sealed(sk_raw: bytes, blob: dict, import_id: str, submitter: str, device_id: str) -> bytes:
    """Test/vector helper (the phone does this in Kotlin). The server never holds a phone's private key."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    sk = X25519PrivateKey.from_private_bytes(sk_raw)
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    epk = base64.b64decode(blob["epk"])
    key = _hkdf(sk.exchange(X25519PublicKey.from_public_bytes(epk)), epk + pub)
    return AESGCM(key).decrypt(base64.b64decode(blob["n"]), base64.b64decode(blob["c"]),
                               aad(import_id, submitter, device_id, blob["kid"]))


def _b64(s, lo: int, hi: int) -> bytes | None:
    if not isinstance(s, str) or len(s) > hi * 4 // 3 + 8:
        return None
    try:
        b = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None
    return b if lo <= len(b) <= hi else None


def valid_blob(b, kid: str) -> bool:
    return (isinstance(b, dict) and set(b) == {"v", "alg", "kid", "epk", "n", "c"} and b["v"] == 1 and b["alg"] == ALG
            and b["kid"] == kid and _b64(b["epk"], 32, 32) is not None and _b64(b["n"], 12, 12) is not None
            and _b64(b["c"], 17, MAX_CT) is not None)


def verify_publication(k: dict) -> bool:
    """What a submitter checks: the phone's K_dev signature over the publish envelope, and that it names this key."""
    from cryptography.hazmat.primitives import serialization
    try:
        raw = base64.b64decode(k["payload"], validate=True)
        pub = serialization.load_der_public_key(base64.b64decode(k["device_pubkey_spki"]))
        if not nv.verify_sig(pub, raw, base64.b64decode(k["signature"])):
            return False
        p = json.loads(raw)
        ik = p.get("import_key") or {}
        return (p.get("purpose") == "import_key" and p.get("device_id") == k["device_id"] and ik.get("pub") == k["pub"]
                and ik.get("kid") == k["kid"] == kid_of(base64.b64decode(k["pub"])))
    except (KeyError, TypeError, ValueError, binascii.Error):
        return False


# ---------------------------------------------------------------- submitter tokens

def token_add(name: str, label: str, out: Path) -> dict:
    """Writes a new import token to `out` (0600, refuses to overwrite) and stores only its SHA-256."""
    if not NAME_RE.match(name):
        raise ValueError("name must be [a-z0-9-]{1,32}")
    with _lock:
        toks = _load(tokens_file(), {"tokens": []})
        if any(t.get("name") == name and not t.get("revoked_at") for t in toks["tokens"]):
            raise ValueError("an active token with that name exists; revoke it first")
        plain = TOKEN_PREFIX + secrets.token_urlsafe(32)
        fd = os.open(str(out), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(plain + "\n")
        rec = {"id": secrets.token_hex(8), "name": name, "label": str(label or name)[:60],
               "sha256": hashlib.sha256(plain.encode()).hexdigest(), "scope": "vault:import",
               "created_at": int(time.time()), "revoked_at": None}
        del plain
        toks["tokens"].append(rec)
        server._atomic_write_json(tokens_file(), toks)
    _audit("import_token_added", submitter=name, token_id=rec["id"])
    return {k: rec[k] for k in ("id", "name", "label", "scope", "created_at")}


def token_revoke(name: str) -> int:
    n = 0
    with _lock:
        toks = _load(tokens_file(), {"tokens": []})
        for t in toks["tokens"]:
            if t.get("name") == name and not t.get("revoked_at"):
                t["revoked_at"] = int(time.time()); n += 1
        server._atomic_write_json(tokens_file(), toks)
    if n:
        _audit("import_token_revoked", submitter=name)
    return n


def token_list() -> list[dict]:
    return [{k: t.get(k) for k in ("id", "name", "label", "scope", "created_at", "revoked_at")}
            for t in _load(tokens_file(), {"tokens": []})["tokens"]]


def submitter_for(token: str | None) -> dict | None:
    if not token or not token.startswith(TOKEN_PREFIX):
        return None
    h = hashlib.sha256(token.encode()).hexdigest()
    for t in _load(tokens_file(), {"tokens": []})["tokens"]:
        if t.get("sha256") and hmac.compare_digest(t["sha256"], h) and not t.get("revoked_at"):
            return t
    return None


def _submitter(h):
    s = submitter_for(h._bearer_token())
    if not s:
        _audit("import_auth_failed", ip=nv._ctx(h)[0])
        h._json(401, {"error": "unauthorized"})
        return None
    return s


# ---------------------------------------------------------------- published phone keys

def published() -> dict:
    return _load(keys_file(), {})


def key_for(device_id: str) -> dict | None:
    k = published().get(device_id)
    d = nv.devices().get(device_id)
    if not k or not d or d["status"] != "active":
        return None
    return k


def keys_for_submitters() -> list[dict]:
    out = []
    devs = nv.devices()
    for did, k in sorted(published().items()):
        d = devs.get(did)
        if not d or d["status"] != "active":
            continue
        out.append({"device_id": did, "device_name": d.get("name"), "device_pubkey_spki": d.get("pubkey_spki"),
                    "kid": k["kid"], "pub": k["pub"], "alg": "X25519", "published_at": k.get("published_at"),
                    "payload": k["payload"], "signature": k["signature"]})
    return out


def _publish(h):
    body = ext.capture_body(h)
    r = nv._verify_device_request(h, "import_key")
    if not r:
        return
    d, p, _att, _pin = r
    ik = p.get("import_key") if isinstance(p.get("import_key"), dict) else {}
    pub = _b64(ik.get("pub"), 32, 32)
    if ik.get("v") != 1 or ik.get("alg") != "X25519" or pub is None or ik.get("kid") != kid_of(pub):
        return h._json(400, {"error": "bad_import_key"})
    did = d["device_id"]
    with _lock:
        keys = published()
        prev = keys.get(did)
        keys[did] = {"kid": ik["kid"], "pub": ik["pub"], "payload": str(body.get("payload") or ""),
                     "signature": str(body.get("signature") or ""), "published_at": int(time.time())}
        server._atomic_write_json(keys_file(), keys)
    ip, ua = nv._ctx(h)
    _audit("import_key_published", device=did, kid=ik["kid"], rotated=bool(prev and prev["kid"] != ik["kid"]), ip=ip, ua=ua)
    if not prev or prev["kid"] != ik["kid"]:
        nv.alert(f"NullVault: phone {did[:12]} published a {'new ' if prev else ''}import key ({ik['kid']}). "
                 "Bots can now send it sealed imports.")
    return h._json(200, {"ok": True, "kid": ik["kid"]})


# ---------------------------------------------------------------- queue

def purge(now: float | None = None) -> int:
    """Expires pending imports past their date, drops old history and orphan blobs. Returns blobs deleted."""
    now = time.time() if now is None else now
    n = 0
    with _lock:
        ix = _index()
        changed = False
        for iid, it in list(ix.items()):
            if it.get("status") in ("pending", "created") and now >= float(it.get("expires_at") or 0):
                _blob_path(iid).unlink(missing_ok=True)
                it.update(status="expired", decided_at=int(now))
                changed = True; n += 1
                _audit("import_expire", import_id=iid, submitter=it.get("submitter"))
                _audit("import_purged", import_id=iid, reason="expired")
            elif it.get("status") not in ("pending", "created") and now - float(it.get("decided_at") or now) > HISTORY_SEC:
                del ix[iid]; changed = True
        for f in blob_dir().glob("*.json"):
            st = ix.get(f.stem, {}).get("status")
            if st not in ("pending", "created"):
                f.unlink(missing_ok=True); n += 1
                _audit("import_purged", import_id=f.stem, reason="orphan")
        if changed:
            _save_index(ix)
    return n


def _pending_for(did: str) -> list[dict]:
    return [dict(it, import_id=iid) for iid, it in _index().items()
            if it.get("status") in ("pending", "created") and did in (it.get("devices") or [])]


def pending_count(did: str) -> int:
    try:
        return len(_pending_for(did))
    except Exception:  # noqa: BLE001
        return 0


def _clean_title(t) -> str | None:
    if not isinstance(t, str):
        return None
    t = re.sub(r"[\x00-\x1f\x7f]", " ", t).strip()
    return t if 1 <= len(t) <= MAX_TITLE else None


def _slack_safe(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("`", "'").replace("*", "")


def _submit(h, s: dict):
    if int(h.headers.get("Content-Length") or 0) > MAX_BODY:
        return h._json(413, {"error": "too_large"})
    if not limits.hit("submit:" + s["id"], *SUBMIT_LIMIT):
        return h._json(429, {"error": "rate_limited"})
    b = h._read_json() or {}
    if set(b) - {"import_id", "title", "type", "sealed"}:
        return h._json(400, {"error": "bad_request", "message": "unknown fields"})
    iid, title, typ, sealed = str(b.get("import_id") or ""), _clean_title(b.get("title")), b.get("type"), b.get("sealed")
    if not ID_RE.match(iid) or title is None or typ not in TYPES or not isinstance(sealed, dict) \
            or not 1 <= len(sealed) <= nv.device_cap():
        return h._json(400, {"error": "bad_request"})
    if not keys_for_submitters():
        return h._json(409, {"error": "no_import_key",
                             "message": "No phone has published an import key yet. Install NullVault 0.8.0, unlock and Sync."})
    size = 0
    for did, blob in sealed.items():
        k = key_for(str(did))
        if not k:
            return h._json(409, {"error": "device_key_unavailable", "device_id": str(did)[:24]})
        if not valid_blob(blob, k["kid"]):
            return h._json(400, {"error": "bad_blob", "device_id": did})
        size += len(blob["c"])
    with _lock:
        purge()
        ix = _index()
        if iid in ix:
            return h._json(409, {"error": "import_id_used"})
        if sum(1 for it in ix.values() if it.get("submitter_id") == s["id"] and it.get("status") in ("pending", "created")) \
                >= MAX_PENDING_PER_SUBMITTER:
            return h._json(429, {"error": "too_many_pending"})
        now = int(time.time())
        server._atomic_write_json(_blob_path(iid), {"import_id": iid, "sealed": sealed})
        ix[iid] = {"submitter_id": s["id"], "submitter": s["name"], "submitter_label": s.get("label") or s["name"],
                   "title": title, "type": typ, "created_at": now, "expires_at": now + EXPIRY_SEC,
                   "status": "pending", "devices": sorted(sealed), "size": size}
        _save_index(ix)
    _audit("import_submit", import_id=iid, submitter=s["name"], type=typ, size=size, devices=sorted(sealed), ip=nv._ctx(h)[0])
    nv.alert(f"NullVault: Import needed. {_slack_safe(s.get('label') or s['name'])} sent \"{_slack_safe(title)}\" ({typ}). "
             "Open NullVault and Sync to review it.")
    return h._json(201, {"ok": True, "import_id": iid, "status": "pending", "expires_at": now + EXPIRY_SEC})


def _status(h, s: dict):
    purge()
    out = [{"import_id": iid, "title": it["title"], "type": it["type"], "status": "approved" if it["status"] == "approved" else
            ("pending" if it["status"] in ("pending", "created") else it["status"]),
            "created_at": it["created_at"], "expires_at": it["expires_at"], "decided_at": it.get("decided_at")}
           for iid, it in sorted(_index().items(), key=lambda x: -x[1].get("created_at", 0)) if it.get("submitter_id") == s["id"]]
    return h._json(200, {"imports": out})


def _pending(h, d: dict):
    purge()
    did = d["device_id"]
    items = []
    for it in sorted(_pending_for(did), key=lambda x: x["created_at"]):
        blob = (_load(_blob_path(it["import_id"]), {}).get("sealed") or {}).get(did)
        if not blob:
            continue
        items.append({"import_id": it["import_id"], "submitter": it["submitter"], "submitter_label": it["submitter_label"],
                      "title": it["title"], "type": it["type"], "created_at": it["created_at"], "expires_at": it["expires_at"],
                      "status": it["status"], "entry_id": it.get("entry_id"), "sealed": blob})
    k = published().get(did)
    return h._json(200, {"imports": items, "key_kid": k["kid"] if k else None})


def _decide(h):
    r = nv._verify_device_request(h, "import")
    if not r:
        return
    d, p, _att, _pin = r
    did = d["device_id"]
    ip, ua = nv._ctx(h)
    a = p.get("import") if isinstance(p.get("import"), dict) else {}
    iid, dec = str(a.get("import_id") or ""), a.get("decision")
    if not ID_RE.match(iid) or dec not in ("approve", "reject"):
        return h._json(400, {"error": "bad_request"})
    if not limits.hit("decide:" + did, *DECIDE_LIMIT):
        return h._json(429, {"error": "rate_limited"})
    import nullvault_e2e as e2e
    with _lock:
        purge()
        ix = _index()
        it = ix.get(iid)
        if not it or did not in (it.get("devices") or []):
            return h._json(404, {"error": "not_found"})
        if it["status"] not in ("pending", "created"):
            return h._json(409, {"error": "already_" + it["status"]})
        if dec == "reject":
            if it["status"] == "created":
                return h._json(409, {"error": "already_created", "entry_id": it.get("entry_id")})
            _blob_path(iid).unlink(missing_ok=True)
            it.update(status="rejected", decided_at=int(time.time()), decided_by=did)
            _save_index(ix)
            _audit("import_reject", import_id=iid, submitter=it["submitter"], device=did, ip=ip, ua=ua)
            _audit("import_purged", import_id=iid, reason="rejected")
            return h._json(200, {"ok": True, "status": "rejected"})
        kid = e2e.kid()
        e = a.get("entry") if isinstance(a.get("entry"), dict) else {}
        vid, blob = str(e.get("id") or ""), e.get("e2e")
        if kid is None:
            return h._json(409, {"error": "e2e_required", "message": "Turn on end-to-end encryption before approving imports."})
        if it["status"] == "created":                          # retry after a lost response: same entry only
            cur = e2e._raw(it["entry_id"]) or {}
            if vid != it["entry_id"] or cur.get("import_id") != iid:
                return h._json(409, {"error": "already_created", "entry_id": it["entry_id"]})
            return h._json(200, {"ok": True, "status": "created", "entry": e2e._meta(cur), "e2e": cur.get("e2e")})
        if set(e) != {"id", "e2e"} or not ENTRY_ID_RE.match(vid) or e2e._raw(vid) is not None:
            return h._json(409, {"error": "bad_id"})
        if not e2e.valid_blob(blob, kid, 1):
            return h._json(400, {"error": "bad_blob"})
        now = server.iso_now()
        e2e._put(vid, {"id": vid, "title": "", "tags": [], "created_at": now, "updated_at": now, "ver": 1, "e2e": blob,
                       "add_only": True, "import_id": iid, "imported_from": it["submitter_label"]})
        back = (e2e._raw(vid) or {}).get("e2e")               # read back from disk for the phone to verify
        it.update(status="created", entry_id=vid)
        _save_index(ix)
    nv.registry_append("write", device_id=did, op="import_create", entry_id=vid, e2e=True, ip=ip, ua=ua)
    _audit("import_approve", import_id=iid, submitter=it["submitter"], device=did, id=vid, ip=ip, ua=ua)
    return h._json(200, {"ok": True, "status": "created", "entry": e2e._meta({"id": vid, "ver": 1, "created_at": now,
                                                                              "updated_at": now}), "e2e": back})


def _ack(h):
    r = nv._verify_device_request(h, "import_ack")
    if not r:
        return
    d, p, _att, _pin = r
    did = d["device_id"]
    ip, ua = nv._ctx(h)
    a = p.get("import") if isinstance(p.get("import"), dict) else {}
    iid, vid, sha = str(a.get("import_id") or ""), str(a.get("entry_id") or ""), str(a.get("sha256") or "")
    if not ID_RE.match(iid) or not ENTRY_ID_RE.match(vid):
        return h._json(400, {"error": "bad_request"})
    import nullvault_e2e as e2e
    with _lock:
        ix = _index()
        it = ix.get(iid)
        if not it or did not in (it.get("devices") or []):
            return h._json(404, {"error": "not_found"})
        if it["status"] == "approved" and it.get("entry_id") == vid:
            return h._json(200, {"ok": True, "status": "approved", "already": True})
        if it["status"] != "created" or it.get("entry_id") != vid:
            return h._json(409, {"error": "not_created"})
        cur = e2e._raw(vid) or {}
        if not cur.get("add_only") or cur.get("import_id") != iid or not e2e.is_e2e(cur) \
                or not hmac.compare_digest(sha, e2e.blob_sha(cur["e2e"])):
            return h._json(409, {"error": "verify_mismatch"})
        _blob_path(iid).unlink(missing_ok=True)
        it.update(status="approved", decided_at=int(time.time()), decided_by=did)
        _save_index(ix)
    _audit("import_ack", import_id=iid, submitter=it["submitter"], device=did, id=vid, ip=ip, ua=ua)
    _audit("import_purged", import_id=iid, reason="approved")
    nv.alert(f"NullVault: import approved on phone {did[:12]}: \"{_slack_safe(it['title'])}\" from "
             f"{_slack_safe(it['submitter_label'])} (saved end-to-end encrypted, add-only).")
    return h._json(200, {"ok": True, "status": "approved"})


def route(h, method: str, path: str):
    if path in ("/api/vault/import/keys", "/api/vault/import/submit", "/api/vault/import/status"):
        s = _submitter(h)
        if not s:
            return
        if not limits.hit("read:" + s["id"], *READ_LIMIT):
            return h._json(429, {"error": "rate_limited"})
        if path == "/api/vault/import/keys" and method == "GET":
            keys = keys_for_submitters()
            return h._json(200, {"keys": keys, "submitter": s["name"], "alg": ALG,
                                 **({} if keys else {"error": "no_import_key"})})
        if path == "/api/vault/import/submit" and method == "POST":
            return _submit(h, s)
        if path == "/api/vault/import/status" and method == "GET":
            return _status(h, s)
        return h._json(405, {"error": "method_not_allowed"})
    if path == "/api/vault/import/pending" and method == "GET":
        d = nv._device_from_bearer(h)
        if not d:
            return
        return _pending(h, d)
    if method != "POST":
        return h._json(405, {"error": "method_not_allowed"})
    if path == "/api/vault/import/key":
        return _publish(h)
    if path == "/api/vault/import/decide":
        return _decide(h)
    if path == "/api/vault/import/ack":
        return _ack(h)
    return h._json(404, {"error": "not_found"})


# ---------------------------------------------------------------- submit CLI (first import: the config-signing key)

FILE_REFS = {"config-signing-key"}       # named references only; no arbitrary paths


def _ref_plaintext(ref: str) -> tuple[str, str, dict]:
    """-> (title, type, fields). Reads the file in memory only."""
    if ref != "config-signing-key":
        raise ValueError("unknown file reference")
    import nullvault_config as cf
    cf.bind(nv, server)
    p = cf.key_path()
    st = p.stat()
    text = p.read_text(encoding="ascii").strip()
    pub = cf.public_key_b64()
    fields = {"key_type": "ed25519-nullvault-config", "private_key_b64": text, "public_key_b64": pub,
              "server_path": str(p), "owner": "nullink:nullink", "mode": "600", "bytes": str(st.st_size),
              "restore": ("ssh morc@vps, then: sudo -u nullink bash -c 'umask 077; read -rs K; printf \"%s\\n\" \"$K\" > "
                          f"{p}; unset K' (paste private_key_b64, Enter); chmod 600; nulldo restart; "
                          "nullvault.py config-show must print public_key_b64")}
    return "NullVault settings-signing key (v12)", "key", fields


def submit_ref(ref: str, token_file: str, base: str = "http://127.0.0.1:8766", device_id: str | None = None,
               urlopen=None, host: str | None = None) -> dict:
    """Seals a named server file to the published phone key(s) and submits it with the import token.
    Returns only non-secret results. Refuses unless a published key verifies against its device's K_dev."""
    import urllib.error
    import urllib.request
    if ref not in FILE_REFS:
        raise ValueError("unknown file reference (allowed: " + ", ".join(sorted(FILE_REFS)) + ")")
    op = urlopen or urllib.request.urlopen
    tok = Path(token_file).read_text(encoding="ascii").strip()

    def call(method, path, body=None):
        req = urllib.request.Request(base + path, method=method, data=None if body is None else json.dumps(body).encode())
        req.add_header("Authorization", "Bearer " + tok)
        if host:
            req.add_header("Host", host)
        if body is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with op(req, timeout=20) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except ValueError:
                return e.code, {}
    st, js = call("GET", "/api/vault/import/keys")
    if st != 200:
        return {"ok": False, "step": "keys", "status": st, "error": js.get("error")}
    keys = [k for k in js.get("keys") or [] if (device_id is None or k["device_id"] == device_id)]
    good = [k for k in keys if verify_publication(k)]
    if not good:
        return {"ok": False, "step": "keys", "error": "no_verified_import_key", "published": len(keys)}
    submitter = js["submitter"]
    title, typ, fields = _ref_plaintext(ref)
    iid = secrets.token_hex(16)
    pt = json.dumps({"v": 1, "type": typ, "title": title, "fields": fields}, sort_keys=True, separators=(",", ":")).encode()
    fields.clear()
    sealed = {k["device_id"]: seal(base64.b64decode(k["pub"]), pt, iid, submitter, k["device_id"]) for k in good}
    del pt
    st, js = call("POST", "/api/vault/import/submit", {"import_id": iid, "title": title, "type": typ, "sealed": sealed})
    return {"ok": st == 201, "status": st, "import_id": iid, "devices": sorted(sealed), "kids": [k["kid"] for k in good],
            "error": js.get("error"), "expires_at": js.get("expires_at")}
