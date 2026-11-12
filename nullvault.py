"""NullVault device API (DESIGN v0.3 / API.md v1). OFF unless NULLVAULT_ENABLED=1.

John's rules (2026-11-12, vault room): his authenticator code is used once, to register a phone.
After that the phone's hardware key (K_dev, fingerprint per use) signs every sync and write.
Root, unlocked bootloaders, Developer options and ADB are allowed and only recorded; anything
aimed at the app itself (modified APK, wrong signature/hash, debuggable build, debugger or hooks in
our process) is refused and the device is flagged.

Routes (all 404 while the flag is off):
  POST /api/vault/device/register-challenge   TOTP -> register nonce (120 s)
  POST /api/vault/device/register             signed envelope + attestation -> device token
  POST /api/vault/sync-challenge              Bearer nvd_ -> sync/write nonce (60 s)
  POST /api/vault/sync                        Bearer + signed envelope + fresh attestation -> entries + lease
  POST /api/vault/device/write                Bearer + signed envelope -> create/update/delete
  GET  /api/vault/devices                     owner cookie -> device list
  POST /api/vault/devices/<id>/revoke         owner cookie + Origin + TOTP -> revoked now

Registry: DATA/nullvault/devices.jsonl, append-only, hash-chained, mode 600 (chattr +a at deploy).
X.509 / ECDSA / Ed25519 use `cryptography`, which server.py already depends on for vault AES-GCM.
The Android KeyDescription extension is parsed with the small DER reader below (stdlib only).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

server = None  # bound by handle() / main() to the live server module

PACKAGE = "cloud.nullverse.nullvault"
TOKEN_PREFIX = "nvd_"
VAULT_ID = "nullink"
KEY_DESC_OID = "1.3.6.1.4.1.11129.2.1.17"
ROOTS_FILE = Path(__file__).resolve().parent / "nullvault_roots" / "google_roots.crt"
STATUS_URL = "https://android.googleapis.com/attestation/status"
LEASE_KEY_CRED = "nullvault_lease_key"
REGISTER_TTL = 120
SYNC_TTL = 60
TS_SKEW = 300
LEASE_SEC = 30 * 86400
MAX_BODY = 512 * 1024
VERIFIED, SELF_SIGNED, UNVERIFIED, FAILED = 0, 1, 2, 3
BOOT_STATES = {0: "Verified", 1: "SelfSigned", 2: "Unverified", 3: "Failed"}
SEC_LEVELS = {0: "Software", 1: "TrustedEnvironment", 2: "StrongBox"}
TAMPER_KEYS = ("debugger", "tracer", "frida", "xposed", "hook", "signature_mismatch", "apk_modified")

ROUTES_POST = {
    "/api/vault/device/register-challenge", "/api/vault/device/register",
    "/api/vault/sync-challenge", "/api/vault/sync", "/api/vault/device/write",
}
REVOKE_RE = re.compile(r"^/api/vault/devices/(dev_[0-9a-f]{16})/revoke$")
FILES_RE = re.compile(r"^/api/vault/files(?:/session|/([A-Za-z0-9_-]{1,64})/download|/uploads/([a-f0-9]{24})(/chunk|/complete)?)?$")

_lock = threading.RLock()
_nonces: dict[str, dict] = {}
EXTRA_TRUSTED_ROOTS: list = []  # tests only: extra root certificates (cryptography x509 objects)


# ---------------------------------------------------------------- config

def enabled() -> bool:
    return os.environ.get("NULLVAULT_ENABLED", "0") == "1"


def device_cap() -> int:
    try:
        return max(1, int(os.environ.get("NULLVAULT_DEVICE_CAP", "2")))
    except ValueError:
        return 2


def patch_floor() -> int:
    try:
        return int(os.environ.get("NULLVAULT_PATCH_FLOOR", "202401"))
    except ValueError:
        return 202401


def nv_dir() -> Path:
    d = server.DATA / "nullvault"
    d.mkdir(parents=True, exist_ok=True)
    try:
        d.chmod(0o700)
    except OSError:
        pass
    return d


def registry_file() -> Path:
    return nv_dir() / "devices.jsonl"


def pins_file() -> Path:
    return nv_dir() / "release_pins.json"


def status_file() -> Path:
    return nv_dir() / "attestation_status.json"


def handles(method: str, path: str) -> bool:
    if path.startswith("/api/vault/files") and FILES_RE.match(path):
        return method in ("GET", "POST")
    if path in ("/api/vault/status", "/api/vault/status/token"):
        return method in ("GET", "POST")
    if method == "POST":
        return path in ROUTES_POST or bool(REVOKE_RE.match(path))
    if method == "GET":
        return path in ("/api/vault/devices", "/api/vault/links")
    return False


# ---------------------------------------------------------------- small helpers

def b64d(s) -> bytes:
    return base64.b64decode(str(s or ""), validate=True)


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _clean(v, n=200):
    return "".join(ch for ch in str(v) if ch.isprintable())[:n]


def _hexlist(v) -> list[str]:
    if not isinstance(v, list):
        return []
    return sorted({str(x).lower() for x in v if re.fullmatch(r"[0-9a-fA-F]{64}", str(x))})


# ---------------------------------------------------------------- DER reader (stdlib)

class DerError(ValueError):
    pass


def der_read(buf: bytes, i: int = 0):
    """-> (cls, constructed, tag, start, end). Supports high tag numbers and long lengths."""
    if i >= len(buf):
        raise DerError("eof")
    b0 = buf[i]; i += 1
    cls, cons, tag = b0 >> 6, bool(b0 & 0x20), b0 & 0x1F
    if tag == 0x1F:
        tag = 0
        while True:
            if i >= len(buf):
                raise DerError("eof in tag")
            b = buf[i]; i += 1
            tag = (tag << 7) | (b & 0x7F)
            if not b & 0x80:
                break
    if i >= len(buf):
        raise DerError("eof in length")
    ln = buf[i]; i += 1
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or n > 4 or i + n > len(buf):
            raise DerError("bad length")
        ln = int.from_bytes(buf[i:i + n], "big"); i += n
    if i + ln > len(buf):
        raise DerError("truncated")
    return cls, cons, tag, i, i + ln


def der_children(buf: bytes, start: int, end: int) -> list:
    out, i = [], start
    while i < end:
        t = der_read(buf, i)
        out.append(t)
        i = t[4]
        if i > end:
            raise DerError("overrun")
    return out


def _int(buf, t) -> int:
    return int.from_bytes(buf[t[3]:t[4]], "big", signed=True)


def parse_key_description(ext: bytes) -> dict:
    top = der_read(ext, 0)
    if top[2] != 0x10:
        raise DerError("KeyDescription not a SEQUENCE")
    f = der_children(ext, top[3], top[4])
    if len(f) < 8:
        raise DerError("KeyDescription too short")
    kd = {
        "attestation_version": _int(ext, f[0]),
        "attestation_security_level": _int(ext, f[1]),
        "keymint_version": _int(ext, f[2]),
        "keymint_security_level": _int(ext, f[3]),
        "challenge": ext[f[4][3]:f[4][4]],
        "sw": _auth_list(ext, f[6]),
        "hw": _auth_list(ext, f[7]),
    }
    return kd


def _auth_list(buf, t) -> dict:
    out = {}
    for c in der_children(buf, t[3], t[4]):
        if c[0] != 2:  # context-specific
            continue
        inner = der_read(buf, c[3])
        out[c[2]] = (inner, buf)
    return out


def _al_int(al: dict, tag: int):
    v = al.get(tag)
    return _int(v[1], v[0]) if v else None


def _al_bytes(al: dict, tag: int):
    v = al.get(tag)
    return v[1][v[0][3]:v[0][4]] if v else None


def _root_of_trust(al: dict):
    v = al.get(704)
    if not v:
        return None
    (t, buf) = v
    f = der_children(buf, t[3], t[4])
    return {"verified_boot_key": buf[f[0][3]:f[0][4]].hex(),
            "device_locked": buf[f[1][3]] != 0 if f[1][4] > f[1][3] else False,
            "verified_boot_state": _int(buf, f[2]),
            "verified_boot_hash": buf[f[3][3]:f[3][4]].hex() if len(f) > 3 else None}


def parse_app_id(raw: bytes | None) -> dict:
    if not raw:
        return {"packages": [], "signature_digests": []}
    top = der_read(raw, 0)
    f = der_children(raw, top[3], top[4])
    pkgs = []
    for p in der_children(raw, f[0][3], f[0][4]):
        pf = der_children(raw, p[3], p[4])
        pkgs.append([raw[pf[0][3]:pf[0][4]].decode("utf-8", "replace"), _int(raw, pf[1])])
    digs = sorted(raw[d[3]:d[4]].hex() for d in der_children(raw, f[1][3], f[1][4])) if len(f) > 1 else []
    return {"packages": pkgs, "signature_digests": digs}


# ---------------------------------------------------------------- attestation chain

class AttestationError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def trusted_roots() -> list:
    from cryptography import x509
    certs = []
    try:
        certs = x509.load_pem_x509_certificates(ROOTS_FILE.read_bytes())
    except (OSError, ValueError):
        pass
    return certs + list(EXTRA_TRUSTED_ROOTS)


def _spki(cert) -> bytes:
    from cryptography.hazmat.primitives import serialization
    return cert.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)


def revoked_serials() -> set[str]:
    """Google's attestation status list, cached 24 h. Fetch failures fall back to the cache."""
    fp = status_file()
    data = None
    try:
        if fp.exists() and time.time() - fp.stat().st_mtime < 86400:
            data = json.loads(fp.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = None
    if data is None and os.environ.get("NULLVAULT_STATUS_FETCH", "1") == "1":
        try:
            with urllib.request.urlopen(STATUS_URL, timeout=6) as r:
                data = json.loads(r.read(4 * 1024 * 1024).decode("utf-8"))
            server._atomic_write_json(fp, data)
        except Exception:  # noqa: BLE001 - network is best effort; cache below
            data = None
    if data is None:
        try:
            data = json.loads(fp.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return set()
    return {str(k).lower().lstrip("0") for k, v in (data.get("entries") or {}).items()
            if str((v or {}).get("status", "")).upper() in ("REVOKED", "SUSPENDED")}


def verify_chain(chain_b64, challenge: bytes, now: float | None = None) -> dict:
    """Verifies an Android hardware key attestation chain. Returns a summary dict plus the leaf."""
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    if not isinstance(chain_b64, list) or not 2 <= len(chain_b64) <= 10:
        raise AttestationError("chain_length")
    try:
        certs = [x509.load_der_x509_certificate(b64d(c)) for c in chain_b64]
    except (ValueError, TypeError):
        raise AttestationError("chain_parse")
    now_dt = datetime.fromtimestamp(time.time() if now is None else now, tz=timezone.utc)
    for i in range(len(certs) - 1):
        try:
            certs[i].verify_directly_issued_by(certs[i + 1])
        except (InvalidSignature, ValueError, TypeError):
            raise AttestationError(f"chain_signature_{i}")
    root = certs[-1]
    try:
        root.verify_directly_issued_by(root)
    except (InvalidSignature, ValueError, TypeError):
        raise AttestationError("root_not_self_signed")
    if _spki(root) not in {_spki(r) for r in trusted_roots()}:
        raise AttestationError("untrusted_root")
    for c in certs[1:]:
        if not (c.not_valid_before_utc <= now_dt <= c.not_valid_after_utc):
            raise AttestationError("cert_expired")
    revoked = revoked_serials()
    for c in certs:
        if format(c.serial_number, "x") in revoked:
            raise AttestationError("cert_revoked")
    oid = x509.ObjectIdentifier(KEY_DESC_OID)
    for c in certs[1:]:
        try:
            c.extensions.get_extension_for_oid(oid)
            raise AttestationError("attestation_ext_in_ca")
        except x509.ExtensionNotFound:
            pass
    try:
        ext = certs[0].extensions.get_extension_for_oid(oid).value.value
    except x509.ExtensionNotFound:
        raise AttestationError("no_attestation_ext")
    try:
        kd = parse_key_description(ext)
        hw, sw = kd["hw"], kd["sw"]
        rot = _root_of_trust(hw)
        app_id = parse_app_id(_al_bytes(sw, 709) or _al_bytes(hw, 709))
    except (DerError, IndexError, UnicodeDecodeError):
        raise AttestationError("attestation_parse")
    if kd["attestation_security_level"] not in (1, 2) or kd["keymint_security_level"] not in (1, 2):
        raise AttestationError("software_attestation")
    if not hmac.compare_digest(kd["challenge"], challenge):
        raise AttestationError("challenge_mismatch")
    if _al_int(hw, 702) not in (0,):  # KeyOrigin GENERATED
        raise AttestationError("key_not_generated")
    if not rot:
        raise AttestationError("no_root_of_trust")
    if rot["verified_boot_state"] not in (VERIFIED, SELF_SIGNED, UNVERIFIED):
        raise AttestationError("boot_failed")
    ids = {}
    for tag, name in ((710, "brand"), (711, "device"), (712, "product"), (716, "manufacturer"), (717, "model")):
        v = _al_bytes(hw, tag)
        if v is not None:
            ids[name] = v.decode("utf-8", "replace")
    return {
        "leaf": certs[0],
        "security_level": SEC_LEVELS.get(kd["attestation_security_level"]),
        "keymint_security_level": SEC_LEVELS.get(kd["keymint_security_level"]),
        "attestation_version": kd["attestation_version"],
        "verified_boot_key": rot["verified_boot_key"],
        "verified_boot_state": BOOT_STATES.get(rot["verified_boot_state"]),
        "device_locked": rot["device_locked"],
        "os_version": _al_int(hw, 705),
        "os_patch_level": _al_int(hw, 706),
        "vendor_patch_level": _al_int(hw, 718),
        "boot_patch_level": _al_int(hw, 719),
        "app_id": app_id,
        "attested_ids": ids,
        "chain_sha256": [sha256_hex(c.public_bytes(_der_enc())) for c in certs],
    }


def _der_enc():
    from cryptography.hazmat.primitives import serialization
    return serialization.Encoding.DER


def verify_sig(public_key, payload: bytes, sig: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or public_key.curve.name != "secp256r1":
        return False
    try:
        public_key.verify(sig, payload, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------- lease key / signing

class LeaseKeyUnavailable(Exception):
    pass


def _lease_key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    paths = []
    if os.environ.get("CREDENTIALS_DIRECTORY"):
        paths.append(Path(os.environ["CREDENTIALS_DIRECTORY"]) / LEASE_KEY_CRED)
    if os.environ.get("NULLVAULT_LEASE_KEY_FILE"):
        paths.append(Path(os.environ["NULLVAULT_LEASE_KEY_FILE"]))
    for p in paths:
        try:
            raw = base64.b64decode(p.read_text(encoding="ascii").strip(), validate=True)
        except (OSError, ValueError):
            continue
        if len(raw) == 32:
            return Ed25519PrivateKey.from_private_bytes(raw)
    raise LeaseKeyUnavailable()


def lease_public_key_b64() -> str:
    from cryptography.hazmat.primitives import serialization
    return b64e(_lease_key().public_key().public_bytes(serialization.Encoding.Raw,
                                                       serialization.PublicFormat.Raw))


def sign_obj(obj: dict) -> dict:
    payload = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
    return {"payload": b64e(payload), "sig": b64e(_lease_key().sign(payload))}


def make_lease(device_id: str, now: float) -> dict:
    t = int(now)
    return sign_obj({"v": 1, "device_id": device_id, "vault_id": VAULT_ID, "synced_at": t,
                     "offline_until": t + LEASE_SEC, "server_time": t})


# ---------------------------------------------------------------- release pins

def load_pins() -> dict:
    try:
        d = json.loads(pins_file().read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def check_apk(apk: dict, att: dict) -> tuple[str | None, dict | None]:
    """-> (reason or None, pin). The attestation's app id is the hardware-vouched copy."""
    if not isinstance(apk, dict):
        return "apk_report_missing", None
    pins = load_pins()
    pkg = pins.get("package") or PACKAGE
    if apk.get("package") != pkg:
        return "package_mismatch", None
    vc = str(apk.get("version_code"))
    pin = (pins.get("releases") or {}).get(vc)
    if not isinstance(pin, dict):
        return "version_not_pinned", None
    if pin.get("revoked"):
        return "version_revoked", pin
    want_certs = _hexlist(pin.get("signing_cert_sha256"))
    if not want_certs or _hexlist(apk.get("signing_cert_sha256")) != want_certs:
        return "signature_mismatch", pin
    hashes_ok = set(_hexlist(pin.get("apk_sha256")))
    got = [str(apk.get("base_apk_sha256") or "").lower()] + [str(x).lower() for x in apk.get("split_apk_sha256") or []]
    if not hashes_ok or any(h not in hashes_ok for h in got):
        return "apk_hash_mismatch", pin
    if apk.get("debuggable") is not False:
        return "debuggable", pin
    app_id = att.get("app_id") or {}
    if [pkg, int(vc)] not in [[p, v] for p, v in app_id.get("packages") or []]:
        return "attested_package_mismatch", pin
    if sorted(app_id.get("signature_digests") or []) != want_certs:
        return "attested_signature_mismatch", pin
    return None, pin


def pins_manifest(pin: dict, version_code) -> dict:
    return sign_obj({"package": load_pins().get("package") or PACKAGE, "version_code": int(version_code),
                     "signing_cert_sha256": _hexlist(pin.get("signing_cert_sha256")),
                     "apk_sha256": _hexlist(pin.get("apk_sha256")), "channel": str(pin.get("channel") or "")})


def tamper_findings(apk: dict, state: dict) -> list[str]:
    out = []
    if isinstance(apk, dict) and apk.get("debuggable"):
        out.append("debuggable")
    t = (state or {}).get("tamper") if isinstance(state, dict) else None
    if isinstance(t, dict):
        for k, v in t.items():
            if k == "tracer_pid":
                if isinstance(v, int) and v > 0:
                    out.append("tracer")
            elif v is True:
                out.append(_clean(k, 32))
    return out


# ---------------------------------------------------------------- registry (append-only, hash-chained)

def _registry_lines() -> list[bytes]:
    try:
        return [ln for ln in registry_file().read_bytes().split(b"\n") if ln.strip()]
    except FileNotFoundError:
        return []


def registry_append(kind: str, **fields) -> dict:
    with _lock:
        lines = _registry_lines()
        prev = sha256_hex(lines[-1]) if lines else "0" * 64
        row = {"kind": kind, "ts": server.iso_now(), "t": int(time.time()), "prev": prev, **fields}
        row["h"] = sha256_hex(json.dumps(row, sort_keys=True, separators=(",", ":")).encode())
        line = json.dumps(row, sort_keys=True, separators=(",", ":"))
        fd = os.open(str(registry_file()), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        return row


def registry_verify() -> bool:
    prev = "0" * 64
    for ln in _registry_lines():
        row = json.loads(ln)
        h = row.pop("h", None)
        if row.get("prev") != prev or h != sha256_hex(json.dumps(row, sort_keys=True, separators=(",", ":")).encode()):
            return False
        prev = sha256_hex(ln)
    return True


def devices() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for ln in _registry_lines():
        try:
            r = json.loads(ln)
        except ValueError:
            continue
        did = r.get("device_id")
        k = r.get("kind")
        if k == "register" and did:
            att = r.get("attestation") or {}
            dev = r.get("device") or {}
            out[did] = {"device_id": did, "status": "active", "token_sha256": r.get("token_sha256"),
                        "pubkey_spki": r.get("pubkey_spki"), "install_id": r.get("install_id"),
                        "name": dev.get("name") or dev.get("model") or "phone",
                        "model": dev.get("model"), "manufacturer": dev.get("manufacturer"),
                        "attested_ids": att.get("attested_ids") or {},
                        "verified_boot_key": att.get("verified_boot_key"),
                        "security_level": att.get("security_level"),
                        "patch_level": att.get("os_patch_level"), "assurance": r.get("assurance"),
                        "version_code": (r.get("apk") or {}).get("version_code"),
                        "registered_at": r.get("ts"), "last_seen_at": r.get("ts"), "last_ip": r.get("ip"),
                        "flags": []}
        elif did in out:
            d = out[did]
            if k == "sync_report":
                d["last_seen_at"] = r.get("ts"); d["last_ip"] = r.get("ip")
                d["patch_level"] = (r.get("attestation") or {}).get("os_patch_level") or d["patch_level"]
                d["version_code"] = (r.get("apk") or {}).get("version_code") or d["version_code"]
                d["assurance"] = r.get("assurance") or d["assurance"]
            elif k == "flag" and d["status"] == "active":
                d["status"] = "flagged"; d["flags"].append(r.get("reason"))
            elif k == "revoke":
                d["status"] = "revoked"
    return out


def device_by_token(token: str | None) -> dict | None:
    if not token or not token.startswith(TOKEN_PREFIX):
        return None
    h = sha256_hex(token.encode())
    for d in devices().values():
        if d.get("token_sha256") and hmac.compare_digest(d["token_sha256"], h):
            return d
    return None


def active_count() -> int:
    return sum(1 for d in devices().values() if d["status"] != "revoked")


# ---------------------------------------------------------------- nonces (single use + TTL)

def nonce_issue(purpose: str, binding: str, ttl: int) -> str:
    n = b64url(secrets.token_bytes(32))
    now = time.time()
    with _lock:
        for k in [k for k, v in _nonces.items() if v["exp"] < now]:
            _nonces.pop(k, None)
        _nonces[n] = {"purpose": purpose, "binding": binding, "exp": now + ttl}
    return n


def nonce_take(n: str, purpose: str, binding: str) -> bool:
    with _lock:
        rec = _nonces.pop(str(n or ""), None)
    return bool(rec and rec["purpose"] == purpose and hmac.compare_digest(rec["binding"], binding)
                and rec["exp"] >= time.time())


def nonce_bytes(n: str) -> bytes:
    """The attestation challenge is the UTF-8 bytes of the nonce string (43 chars)."""
    return str(n).encode("ascii")


# ---------------------------------------------------------------- alerts (existing Slack DM path)

def alert(text: str) -> None:
    if not enabled() or os.environ.get("NULLVAULT_ALERTS", "1") == "0":
        return
    send_alert(text)


def send_alert(text: str) -> None:  # tests patch this
    srv = server

    def run():
        try:
            ch = srv._slack_dm_channel()
            if ch:
                srv.slack_call("chat.postMessage", {"channel": ch, "text": text, "mrkdwn": True})
        except Exception:  # noqa: BLE001
            pass
    threading.Thread(target=run, daemon=True).start()


# ---------------------------------------------------------------- HTTP

def handle(h, method: str, path: str) -> None:
    global server
    server = sys.modules[type(h).__module__]
    import nullvault_ext as ext
    ext.bind(sys.modules[__name__], server)
    if not enabled():
        return h._json(404, {"error": "not_found"})
    if path.startswith("/api/vault/files"):
        if not ext.files_enabled():
            return h._json(404, {"error": "not_found"})
        return _files_route(h, method, path, ext)
    if path in ("/api/vault/status", "/api/vault/status/token"):
        import nullvault_status as st
        st.bind(sys.modules[__name__], server)
        try:
            return st.route(h, method, path)
        except LeaseKeyUnavailable:
            return h._json(503, {"error": "lease_key_unavailable"})
    if path == "/api/vault/links":
        if not ext.links_enabled():
            return h._json(404, {"error": "not_found"})
        return _admin_links(h, ext)
    if int(h.headers.get("Content-Length") or 0) > MAX_BODY and not path.endswith("/chunk"):
        return h._json(413, {"error": "too_large"})
    try:
        if method == "GET":
            return _admin_list(h)
        m = REVOKE_RE.match(path)
        if m:
            return _admin_revoke(h, m.group(1))
        return {
            "/api/vault/device/register-challenge": _register_challenge,
            "/api/vault/device/register": _register,
            "/api/vault/sync-challenge": _sync_challenge,
            "/api/vault/sync": _sync,
            "/api/vault/device/write": _write,
        }[path](h)
    except LeaseKeyUnavailable:
        return h._json(503, {"error": "lease_key_unavailable"})
    except server.VaultKeyUnavailable:
        return h._json(503, {"error": "vault_key_unavailable"})
    except server.VaultIntegrityError:
        server.vault_audit("nullvault_integrity_error", path=path)
        return h._json(500, {"error": "vault_integrity"})


def _ctx(h):
    return server.client_ip(h), str(h.headers.get("User-Agent") or "")[:160]


def _totp_gate(h, code: str):
    """Same lockout as login / step-up: rate_locked + rate_record_failure, consume=True."""
    ip, _ = _ctx(h)
    if not server.totp_enabled():
        return (409, {"error": "totp_not_enabled"})
    code = str(code or "").replace(" ", "").strip()
    now = time.time()
    with server._auth_lock:
        rate = server.load_rate()
        server._prune_rate(rate, now)
        locked, retry, _scope = server.rate_locked(rate, ip, now)
        if locked:
            return (429, {"error": "locked", "retry_after_sec": retry})
        ok = bool(code.isdigit() and len(code) == server.TOTP_DIGITS
                  and server.verify_totp(code, server.load_totp() or {}, now, consume=True))
        if not ok:
            info = server.rate_record_failure(rate, ip, now)
            server.save_rate(rate)
            if info["locked"]:
                return (429, {"error": "locked", "retry_after_sec": info["retry_after"]})
            return (401, {"error": "wrong_code", "attempts_left": info["attempts_left"]})
        server.rate_record_success(rate, ip)
        server.save_rate(rate)
    return None


def _envelope(h):
    body = h._read_json() or {}
    try:
        raw = b64d(body.get("payload"))
        sig = b64d(body.get("signature"))
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, TypeError):
        return None, None, None
    if not isinstance(payload, dict):
        return None, None, None
    return raw, sig, payload


def _ts_ok(payload) -> bool:
    try:
        return abs(int(payload.get("ts")) - time.time()) <= TS_SKEW
    except (TypeError, ValueError):
        return False


def _att_record(att: dict) -> dict:
    return {k: v for k, v in att.items() if k != "leaf"}


def _assurance(att: dict, state: dict) -> str:
    rooted = bool(isinstance(state, dict) and state.get("root_indicators"))
    if att.get("verified_boot_state") != "Verified" or not att.get("device_locked") or rooted:
        return "reduced"
    return "full"


def _safe_dict(d, n=40) -> dict:
    if not isinstance(d, dict):
        return {}
    out = {}
    for k, v in list(d.items())[:n]:
        k = _clean(k, 40)
        if isinstance(v, (bool, int, float)) or v is None:
            out[k] = v
        elif isinstance(v, list):
            out[k] = [_clean(x, 120) if not isinstance(x, (bool, int)) else x for x in v[:16]]
        elif isinstance(v, dict):
            out[k] = _safe_dict(v, 16)
        else:
            out[k] = _clean(v, 200)
    return out


def _refuse(h, code, reason, *, device_id=None, wipe=False, flag=False, **ctx):
    ip, ua = _ctx(h)
    if flag and device_id:
        registry_append("flag", device_id=device_id, reason=reason, ip=ip, ua=ua)
        server.vault_audit("device_flagged", device=device_id, reason=reason, ip=ip, ua=ua)
        alert(f":rotating_light: *NullVault* flagged device `{device_id}`: {reason}. Syncs are refused until you review it.")
    else:
        registry_append("refused", device_id=device_id, reason=reason, ip=ip, ua=ua, **ctx)
        server.vault_audit("device_refused", device=device_id, reason=reason, ip=ip, ua=ua)
        alert(f":no_entry: *NullVault* refused a {ctx.get('step', 'device')} request"
              f"{f' from `{device_id}`' if device_id else ''}: {reason}.")
    out = {"error": reason}
    if wipe:
        out["wipe"] = True
    return h._json(code, out)


def _register_challenge(h):
    body = h._read_json() or {}
    install_id = str(body.get("install_id") or "")
    if not re.fullmatch(r"[0-9a-f-]{36}", install_id):
        return h._json(400, {"error": "bad_request", "message": "install_id (uuid4) required"})
    _lease_key()  # 503 before John's code is spent on a register that could not finish
    err = _totp_gate(h, body.get("code"))
    if err:
        server.vault_audit("device_challenge_refused", reason=err[1]["error"], ip=_ctx(h)[0])
        return h._json(*err)
    if active_count() >= device_cap():
        return h._json(409, {"error": "device_cap", "cap": device_cap(),
                             "message": "Device limit reached. Revoke a device first."})
    n = nonce_issue("register", install_id, REGISTER_TTL)
    server.vault_audit("device_challenge", ip=_ctx(h)[0])
    return h._json(200, {"nonce": n, "expires_in": REGISTER_TTL, "purpose": "register"})


def _register(h):
    ip, ua = _ctx(h)
    raw, sig, p = _envelope(h)
    if p is None or p.get("purpose") != "register":
        return h._json(400, {"error": "bad_request"})
    install_id = str(p.get("install_id") or "")
    if not nonce_take(p.get("nonce"), "register", install_id):
        return h._json(403, {"error": "nonce_invalid"})
    if not _ts_ok(p):
        return h._json(403, {"error": "clock_skew"})
    apk, state, dev = p.get("apk") or {}, p.get("state") or {}, _safe_dict(p.get("device"))
    try:
        att = verify_chain(p.get("attestation_chain"), nonce_bytes(p["nonce"]))
    except AttestationError as e:
        return _refuse(h, 403, "attestation_invalid:" + e.reason, step="register")
    if not verify_sig(att["leaf"].public_key(), raw, sig):
        return _refuse(h, 403, "bad_signature", step="register")
    found = tamper_findings(apk, state)
    if found:
        return _refuse(h, 403, "tamper_detected:" + ",".join(found), step="register", wipe=True)
    reason, pin = check_apk(apk, att)
    if reason:
        return _refuse(h, 403, "apk_mismatch:" + reason, step="register", wipe=True)
    if (att.get("os_patch_level") or 0) < patch_floor():
        return _refuse(h, 403, "patch_below_floor", step="register")
    from cryptography.hazmat.primitives import serialization
    with _lock:
        if active_count() >= device_cap():
            return h._json(409, {"error": "device_cap", "cap": device_cap()})
        device_id = "dev_" + secrets.token_hex(8)
        token = TOKEN_PREFIX + b64url(secrets.token_bytes(32))
        assurance = _assurance(att, state)
        spki = att["leaf"].public_key().public_bytes(serialization.Encoding.DER,
                                                     serialization.PublicFormat.SubjectPublicKeyInfo)
        registry_append("register", device_id=device_id, token_sha256=sha256_hex(token.encode()),
                        install_id=install_id, pubkey_spki=b64e(spki), attestation=_att_record(att),
                        attestation_chain=[_clean(c, 8000) for c in p.get("attestation_chain")],
                        device=dev, apk=_safe_dict(apk), state=_safe_dict(state), assurance=assurance,
                        play_integrity=bool(p.get("play_integrity")), ip=ip, ua=ua)
    server.vault_audit("device_register", device=device_id, assurance=assurance, ip=ip, ua=ua)
    alert(f":iphone: *NullVault* registered `{device_id}` ({_clean(dev.get('manufacturer'), 40)} "
          f"{_clean(dev.get('model'), 40)}, {att['security_level']})"
          + (" — *reduced assurance* (rooted/unlocked/unverified boot)" if assurance == "reduced" else "")
          + f". Active devices: {active_count()}/{device_cap()}.")
    now = time.time()
    return h._json(201, {"device_id": device_id, "device_token": token,
                         "lease_public_key": lease_public_key_b64(), "assurance": assurance,
                         "lease": make_lease(device_id, now),
                         "pins": pins_manifest(pin, apk.get("version_code")), "server_time": int(now)})


def _device_from_bearer(h):
    d = device_by_token(h._bearer_token())
    if not d:
        server.vault_audit("device_auth_failed", ip=_ctx(h)[0])
        h._json(401, {"error": "unauthorized", "wipe": True})
        return None
    if d["status"] == "revoked":
        h._json(403, {"error": "revoked", "wipe": True})
        return None
    if d["status"] == "flagged":
        h._json(403, {"error": "flagged", "wipe": True})
        return None
    return d


def _sync_challenge(h):
    d = _device_from_bearer(h)
    if not d:
        return
    purpose = str((h._read_json() or {}).get("purpose") or "sync")
    if purpose not in ("sync", "write", "files", "status"):
        return h._json(400, {"error": "bad_request"})
    n = nonce_issue(purpose, d["device_id"], SYNC_TTL)
    return h._json(200, {"nonce": n, "expires_in": SYNC_TTL, "purpose": purpose})


def _verify_device_request(h, purpose: str):
    """Shared sync/write checks. Returns (device, payload, att, pin) or None (response already sent)."""
    from cryptography.hazmat.primitives import serialization
    d = _device_from_bearer(h)
    if not d:
        return None
    did = d["device_id"]
    raw, sig, p = _envelope(h)
    if p is None or p.get("purpose") != purpose or p.get("device_id") != did:
        h._json(400, {"error": "bad_request"})
        return None
    if not nonce_take(p.get("nonce"), purpose, did):
        h._json(403, {"error": "nonce_invalid"})
        return None
    if not _ts_ok(p):
        h._json(403, {"error": "clock_skew"})
        return None
    pub = serialization.load_der_public_key(b64d(d["pubkey_spki"]))
    if not verify_sig(pub, raw, sig):
        _refuse(h, 403, "bad_signature", device_id=did, wipe=True, flag=True)
        return None
    apk, state, dev = p.get("apk") or {}, p.get("state") or {}, p.get("device") or {}
    try:
        att = verify_chain(p.get("attestation_chain"), nonce_bytes(p["nonce"]))
    except AttestationError as e:
        _refuse(h, 403, "attestation_invalid:" + e.reason, device_id=did, wipe=True, flag=True)
        return None
    if att["verified_boot_key"] != d["verified_boot_key"] or att["security_level"] != d["security_level"]:
        _refuse(h, 403, "reregister_required:hardware_changed", device_id=did, wipe=True, flag=True)
        return None
    for k in ("manufacturer", "model"):
        a0, a1 = (d.get("attested_ids") or {}).get(k), (att.get("attested_ids") or {}).get(k)
        if (a0 or a1) and a0 != a1:
            _refuse(h, 403, f"reregister_required:attested_{k}_changed", device_id=did, wipe=True, flag=True)
            return None
        if str(dev.get(k) or "") != str(d.get(k) or ""):
            _refuse(h, 403, f"reregister_required:{k}_changed", device_id=did, wipe=True, flag=True)
            return None
    if str(dev.get("install_id") or "") != str(d.get("install_id") or ""):
        _refuse(h, 403, "reregister_required:install_changed", device_id=did, wipe=True, flag=True)
        return None
    if (att.get("os_patch_level") or 0) < (d.get("patch_level") or 0):
        _refuse(h, 403, "patch_downgrade", device_id=did, wipe=True, flag=True)
        return None
    found = tamper_findings(apk, state)
    if found:
        _refuse(h, 403, "tamper_detected:" + ",".join(found), device_id=did, wipe=True, flag=True)
        return None
    reason, pin = check_apk(apk, att)
    if reason == "version_not_pinned":
        # A newer build installed before its pins were added: refuse, but don't flag or wipe the phone.
        server.vault_audit("device_refused", device=did, reason="version_not_pinned", ip=_ctx(h)[0])
        h._json(403, {"error": "apk_mismatch:version_not_pinned",
                      "message": "This app version is not approved on the server yet. Try again after the server is updated."})
        return None
    if reason:
        _refuse(h, 403, "apk_mismatch:" + reason, device_id=did, wipe=True, flag=True)
        return None
    ip, ua = _ctx(h)
    patch_note = "newer_patch" if (att.get("os_patch_level") or 0) > (d.get("patch_level") or 0) else None
    registry_append("sync_report", device_id=did, purpose=purpose, attestation=_att_record(att),
                    apk=_safe_dict(apk), state=_safe_dict(state), assurance=_assurance(att, state),
                    note=patch_note, ip=ip, ua=ua)
    return d, p, att, pin


def _sync(h):
    r = _verify_device_request(h, "sync")
    if not r:
        return
    d, p, _att, pin = r
    ip, ua = _ctx(h)
    entries = []
    for meta in server.list_vault_snippets():
        try:
            item = server.load_vault_snippet(meta["id"], decrypt=True)
        except server.VaultIntegrityError:
            server.vault_audit("integrity_failure", id=meta["id"], device=d["device_id"], ip=ip, ua=ua)
            continue
        if item:
            entries.append({k: item.get(k) for k in ("id", "title", "tags", "body", "created_at", "updated_at")})
    server.vault_audit("device_sync", device=d["device_id"], count=len(entries), ip=ip, ua=ua)
    now = time.time()
    import nullvault_ext as ext
    return h._json(200, {"entries": entries, "count": len(entries), "lease": make_lease(d["device_id"], now),
                         "pins": pins_manifest(pin, p["apk"]["version_code"]), "server_time": int(now),
                         **ext.sync_extras()})


def _write(h):
    r = _verify_device_request(h, "write")
    if not r:
        return
    d, p, _att, _pin = r
    ip, ua = _ctx(h)
    op = p.get("op")
    kind = p.get("kind") or "entry"
    if kind != "entry":
        return _write_ext(h, d, p, kind, op)
    e = p.get("entry") if isinstance(p.get("entry"), dict) else {}
    meta = lambda x: {k: x.get(k) for k in ("id", "title", "tags", "created_at", "updated_at")}  # noqa: E731
    if op == "create":
        body = str(e.get("body") or "")
        if len(body) > 100_000:
            return h._json(413, {"error": "too_large"})
        saved = server.save_vault_snippet({"title": e.get("title"), "body": body, "tags": e.get("tags")})
    elif op in ("update", "delete"):
        vid = server._vault_safe_id(str(e.get("id") or ""))
        cur = server.load_vault_snippet(vid, decrypt=False) if vid else None
        if not cur:
            return h._json(404, {"error": "not_found"})
        base = p.get("base_updated_at")
        if base and base != cur.get("updated_at"):
            return h._json(409, {"error": "conflict", "entry": meta(cur)})
        if op == "delete":
            server.delete_vault_snippet(vid)
            saved = cur
        else:
            full = server.load_vault_snippet(vid, decrypt=True)
            body = str(e["body"]) if "body" in e else full["body"]
            if len(body) > 100_000:
                return h._json(413, {"error": "too_large"})
            saved = server.save_vault_snippet({"id": vid, "title": e.get("title", full["title"]),
                                               "tags": e.get("tags", full["tags"]), "body": body,
                                               "created_at": full.get("created_at")})
    else:
        return h._json(400, {"error": "bad_request"})
    registry_append("write", device_id=d["device_id"], op=op, entry_id=saved["id"], ip=ip, ua=ua)
    server.vault_audit("device_write", device=d["device_id"], op=op, id=saved["id"], ip=ip, ua=ua)
    return h._json(200, {"ok": True, "op": op, "entry": meta(saved), "lease": make_lease(d["device_id"], time.time())})


def _write_ext(h, d, p, kind, op):
    import nullvault_ext as ext
    ip, ua = _ctx(h)
    if kind in ("link", "project", "note"):
        if not ext.links_enabled() or (kind == "note" and not ext.notes_enabled()):
            return h._json(404, {"error": "not_found"})
        rec = p.get(kind) if isinstance(p.get(kind), dict) else {}
        st, body = ext.write_record(kind, op, rec, p.get("base_updated_at"))
        if st != 200:
            return h._json(st, body)
        rid = body[kind]["id"]
    elif kind == "file":
        if not ext.files_enabled():
            return h._json(404, {"error": "not_found"})
        f = p.get("file") if isinstance(p.get("file"), dict) else {}
        if op == "upload_begin":
            registry_append("write", device_id=d["device_id"], record="file", op=op, ip=ip, ua=ua)
            return ext.upload_begin(h, d, f)
        if op != "delete":
            return h._json(400, {"error": "bad_request"})
        rid = str(f.get("id") or "")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", rid) or not ext.file_trash(rid):
            return h._json(404, {"error": "not_found"})
        body = {"file": {"id": rid, "trashed": True}}
    else:
        return h._json(400, {"error": "bad_request"})
    registry_append("write", device_id=d["device_id"], record=kind, op=op, entry_id=rid, ip=ip, ua=ua)
    server.vault_audit("device_write", device=d["device_id"], kind=kind, op=op, id=rid, ip=ip, ua=ua)
    return h._json(200, {"ok": True, "op": op, **body, "lease": make_lease(d["device_id"], time.time())})


def _files_route(h, method, path, ext):
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(h.path).query)
    if path == "/api/vault/files/session":
        if method != "POST":
            return h._json(405, {"error": "method_not_allowed"})
        r = _verify_device_request(h, "files")
        if not r:
            return
        tok, ttl = ext.files_session_issue(r[0]["device_id"])
        server.vault_audit("device_files_session", device=r[0]["device_id"], ip=_ctx(h)[0])
        return h._json(200, {"files_session": tok, "expires_in": ttl})
    d = ext.files_session(h)
    if not d:
        return
    m = FILES_RE.match(path)
    fid, uid, sub = m.group(1), m.group(2), m.group(3)
    if path == "/api/vault/files" and method == "GET":
        return h._json(200, ext.files_list())
    if fid and method == "GET":
        return ext.send_file_range(h, fid, d["device_id"])
    if uid and not sub and method == "GET":
        return ext.upload_status(h, d, uid)
    if uid and sub == "/chunk" and method == "POST":
        return ext.upload_chunk(h, d, uid, qs)
    if uid and sub == "/complete" and method == "POST":
        return ext.upload_complete(h, d, uid)
    return h._json(404, {"error": "not_found"})


def _admin_links(h, ext):
    if h._require_owner() is None:
        return
    disc = ext.discover()
    return h._json(200, {"links": ext._load_list("links.json"), "projects": ext._load_list("projects.json"),
                         "suggestions": {"sites": disc["sites"], "source": disc["source"], "repos": ext.repo_suggestions()}})


def _admin_list(h):
    if h._require_owner() is None:
        return
    keep = ("device_id", "name", "status", "assurance", "model", "manufacturer", "security_level",
            "patch_level", "version_code", "registered_at", "last_seen_at", "last_ip", "flags")
    return h._json(200, {"cap": device_cap(), "registry_intact": registry_verify(),
                         "devices": [{k: d.get(k) for k in keep} for d in devices().values()]})


def _admin_revoke(h, device_id):
    ip, ua = _ctx(h)
    if h.headers.get("Authorization") is not None:
        return h._json(403, {"error": "forbidden", "message": "Owner browser session only."})
    if h.headers.get("Origin") not in server.SSH_ALLOWED_ORIGINS:
        return h._json(403, {"error": "bad_origin"})
    if h._require_owner() is None:
        return
    err = _totp_gate(h, (h._read_json() or {}).get("code"))
    if err:
        return h._json(*err)
    d = devices().get(device_id)
    if not d:
        return h._json(404, {"error": "not_found"})
    if d["status"] != "revoked":
        registry_append("revoke", device_id=device_id, by="owner", ip=ip, ua=ua)
        server.vault_audit("device_revoke", device=device_id, ip=ip, ua=ua)
        alert(f":lock: *NullVault* revoked `{device_id}`. It wipes at next contact.")
    return h._json(200, {"ok": True, "device_id": device_id, "status": "revoked"})


# ---------------------------------------------------------------- CLI (root / nullink on the box)

def main(argv):
    import argparse
    global server
    import server as _srv
    server = _srv
    ap = argparse.ArgumentParser(description="NullVault admin (never prints secrets)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("pin-add", help="pin a release: cert + APK SHA-256 for a versionCode")
    a.add_argument("--version-code", type=int, required=True)
    a.add_argument("--version-name", default="")
    a.add_argument("--channel", default="release")
    a.add_argument("--cert-sha256", action="append", required=True)
    a.add_argument("--apk-sha256", action="append", required=True)
    r = sub.add_parser("pin-revoke"); r.add_argument("--version-code", type=int, required=True)
    sub.add_parser("list"); sub.add_parser("verify")
    g = sub.add_parser("gen-lease-key", help="write a new Ed25519 lease key (base64) to a 0600 file")
    g.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    server.ensure_dirs()
    if args.cmd == "pin-add":
        pins = load_pins() or {"package": PACKAGE, "releases": {}}
        pins.setdefault("releases", {})[str(args.version_code)] = {
            "version_name": args.version_name, "channel": args.channel,
            "signing_cert_sha256": _hexlist(args.cert_sha256), "apk_sha256": _hexlist(args.apk_sha256),
            "revoked": False}
        server._atomic_write_json(pins_file(), pins)
        print(f"pinned versionCode {args.version_code}")
    elif args.cmd == "pin-revoke":
        pins = load_pins()
        rel = (pins.get("releases") or {}).get(str(args.version_code))
        if rel:
            rel["revoked"] = True
            server._atomic_write_json(pins_file(), pins)
        print("revoked" if rel else "not found")
    elif args.cmd == "list":
        for d in devices().values():
            print(d["device_id"], d["status"], d.get("assurance"), d.get("manufacturer"), d.get("model"), d.get("last_seen_at"))
    elif args.cmd == "verify":
        print("registry intact" if registry_verify() else "REGISTRY CHAIN BROKEN")
    elif args.cmd == "gen-lease-key":
        out = Path(args.out)
        if out.exists():
            print("refusing to overwrite existing key file"); return 1
        fd = os.open(str(out), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(b64e(secrets.token_bytes(32)) + "\n")
        print(f"wrote {out} (0600); public key not printed here, it is returned to devices at registration")
    return 0


def _boot_status_monitor():
    """Server status down-alerts (Stage 2): start the 60 s monitor thread when the service runs with both flags on."""
    if not (enabled() and os.environ.get("NULLVAULT_STATUS", "0") == "1"):
        return
    try:
        import nullvault_status as st
        st.bind(sys.modules[__name__], server)
        st.start_monitor()
    except Exception:  # noqa: BLE001
        pass


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]) or 0)
else:
    _boot_status_monitor()
