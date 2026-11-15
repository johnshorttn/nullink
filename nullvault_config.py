"""NullVault 0.7.0: signed, server-defined config bundle (John 2026-11-14 9:43 PM ET, "Yes" to Morc's proposal).

The phone pulls one bundle on sync: status checks, alert rules, approval types, the Bot chat list, Files tag and
Links category rules, and password health rules (evaluated on the phone; only the rules come down). The bundle is
signed with a DEDICATED Ed25519 config key (not the lease, device or E2E keys) kept in
/opt/nullink/secrets/nullvault_config_signing.key (nullink 600, never printed); the phone pins the public key.

Security policy is NOT configurable: the auth window, tamper checks, E2E crypto, wipe/lock, the cert pin and the
device cap stay in the APK and in nullvault.py. The bundle schema has no place for them; build() refuses any
section or key outside the schema, and the phone ignores unknown or forbidden keys anyway.
No vault data goes in: every value is a rule, a name or a number from the schema below.

Version: a counter in data/nullvault/config_state.json that goes up whenever the signed content changes; the phone
refuses anything older than what it has (rollback). Owner overrides: data/nullvault/config.json (same sections).

Route: GET /api/vault/config (device bearer) -> {"bundle": {"payload", "sig"}, "version": int}
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
import threading
import time
from pathlib import Path

nv = None
server = None

KIND = "nullvault-config"
KEY_NAME = "nullvault_config_signing.key"
STATE = "config_state.json"
OVERRIDES = "config.json"
_lock = threading.Lock()

SECTIONS = ("status_checks", "alerts", "approvals", "chat", "files", "links", "password_health")
# Never allowed anywhere in a bundle (the phone hardcodes these; listed so tests and reviews can see the line).
FORBIDDEN = ("auth_window", "window_minutes", "tamper", "wipe", "lock", "lockout", "e2e", "crypto", "kdf", "cert_pin",
             "pinned_cert", "signing_cert", "device_cap", "max_devices", "screenshots", "lease", "pins", "allowlist",
             "actions_allow", "biometric", "fingerprint")
ID = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,39}$")
HHMM = re.compile(r"^([01][0-9]|2[0-3]):[0-5][0-9]$")
TZ = re.compile(r"^[A-Za-z_]+(/[A-Za-z_+-]+){0,2}$")


def bind(nv_mod, srv):
    global nv, server
    nv, server = nv_mod, srv


class ConfigKeyUnavailable(Exception):
    pass


class ConfigInvalid(ValueError):
    pass


# ---------------------------------------------------------------- key

def key_path() -> Path:
    return Path(os.environ.get("NULLVAULT_CONFIG_KEY_FILE") or (server.BASE / "secrets" / KEY_NAME))


def _key():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    try:
        raw = base64.b64decode(key_path().read_text(encoding="ascii").strip(), validate=True)
    except (OSError, ValueError):
        raise ConfigKeyUnavailable()
    if len(raw) != 32:
        raise ConfigKeyUnavailable()
    return Ed25519PrivateKey.from_private_bytes(raw)


def public_key_b64() -> str:
    from cryptography.hazmat.primitives import serialization
    return base64.b64encode(_key().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


def gen_key(out: Path) -> str:
    """Writes a new key (0600, refuses to overwrite) and returns ONLY the public key (for the APK pin)."""
    import secrets as _s
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    raw = _s.token_bytes(32)
    fd = os.open(str(out), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(base64.b64encode(raw).decode() + "\n")
    pub = Ed25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(pub).decode()


# ---------------------------------------------------------------- schema (same rules as the phone's ConfigBundle.kt)

def _int(v, lo, hi):
    if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
        raise ConfigInvalid(f"int out of range {lo}..{hi}")
    return v


def _bool(v):
    if not isinstance(v, bool):
        raise ConfigInvalid("bool expected")
    return v


def _str(v, n, pat=None):
    if not isinstance(v, str) or not 0 < len(v) <= n or any(ord(c) < 32 for c in v) or (pat and not pat.match(v)):
        raise ConfigInvalid("bad string")
    return v


def _list(v, n):
    if not isinstance(v, list) or len(v) > n:
        raise ConfigInvalid("bad list")
    return v


def _obj(v, keys):
    if not isinstance(v, dict):
        raise ConfigInvalid("object expected")
    bad = set(v) - set(keys)
    if bad:
        raise ConfigInvalid("unknown keys: " + ",".join(sorted(bad)))
    return v


def clean(cfg: dict) -> dict:
    """Validates a whole config; raises ConfigInvalid. Output has only schema keys."""
    try:
        return _clean(cfg)
    except (KeyError, TypeError, AttributeError, ValueError) as e:
        if isinstance(e, ConfigInvalid):
            raise
        raise ConfigInvalid("malformed: " + type(e).__name__)


def _clean(cfg: dict) -> dict:
    _obj(cfg, SECTIONS)
    out = {}
    if "status_checks" in cfg:
        s = _obj(cfg["status_checks"], ("interval_minutes", "down_after_failures", "timeout_seconds", "checks"))
        out["status_checks"] = {
            "interval_minutes": _int(s.get("interval_minutes", 15), 15, 1440),
            "down_after_failures": _int(s.get("down_after_failures", 1), 1, 10),
            "timeout_seconds": _int(s.get("timeout_seconds", 10), 1, 60),
            "checks": [{"id": _str(_obj(c, ("id", "name", "kind", "detail"))["id"], 40, ID), "name": _str(c["name"], 60),
                        "kind": _str(c["kind"], 10, re.compile(r"^(systemd|disk|tls|http)$")),
                        **({"detail": _str(c["detail"], 120)} if "detail" in c else {})}
                       for c in _list(s.get("checks", []), 60)]}
    if "alerts" in cfg:
        a = _obj(cfg["alerts"], ("server_down", "approval_waiting", "quick_action_run", "quiet_hours"))
        q = _obj(a.get("quiet_hours", {}), ("enabled", "start", "end", "tz"))
        out["alerts"] = {k: _bool(a.get(k, True)) for k in ("server_down", "approval_waiting", "quick_action_run")}
        out["alerts"]["quiet_hours"] = {"enabled": _bool(q.get("enabled", False)), "start": _str(q.get("start", "22:00"), 5, HHMM),
                                        "end": _str(q.get("end", "07:00"), 5, HHMM), "tz": _str(q.get("tz", "America/New_York"), 40, TZ)}
    if "approvals" in cfg:
        ap = _obj(cfg["approvals"], ("types",))
        out["approvals"] = {"types": [{"kind": _str(_obj(t, ("kind", "source", "label", "confirm", "decide"))["kind"], 40, ID),
                                       "source": _str(t["source"], 40, ID), "label": _str(t["label"], 60),
                                       "confirm": _str(t["confirm"], 240), "decide": _bool(t.get("decide", False))}
                                      for t in _list(ap.get("types", []), 20)]}
    if "chat" in cfg:
        c = _obj(cfg["chat"], ("session_minutes", "bots"))
        out["chat"] = {"session_minutes": _int(c.get("session_minutes", 10), 1, 60),
                       "bots": [{"id": _str(_obj(b, ("id", "title", "category"))["id"], 60), "title": _str(b["title"], 80),
                                 **({"category": _str(b["category"], 60)} if "category" in b else {})}
                                for b in _list(c.get("bots", []), 100)]}
    if "files" in cfg:
        f = _obj(cfg["files"], ("tag_rules",))
        out["files"] = {"tag_rules": [{"name": _str(_obj(r, ("name", "contains"))["name"], 40),
                                       "contains": [_str(x, 60) for x in _list(r["contains"], 10)]}
                                      for r in _list(f.get("tag_rules", []), 50)]}
    if "links" in cfg:
        lk = _obj(cfg["links"], ("category_rules",))
        out["links"] = {"category_rules": [{"category": _str(_obj(r, ("category", "host_suffix", "url_contains"))["category"], 40),
                                            "host_suffix": [_str(x, 100) for x in _list(r.get("host_suffix", []), 10)],
                                            "url_contains": [_str(x, 100) for x in _list(r.get("url_contains", []), 10)]}
                                           for r in _list(lk.get("category_rules", []), 50)]}
    if "password_health" in cfg:
        p = _obj(cfg["password_health"], ("min_length", "stale_days", "reuse_check", "weak_bits"))
        out["password_health"] = {"min_length": _int(p.get("min_length", 12), 8, 128),
                                  "stale_days": _int(p.get("stale_days", 365), 30, 3650),
                                  "reuse_check": _bool(p.get("reuse_check", True)),
                                  "weak_bits": _int(p.get("weak_bits", 50), 28, 128)}
    _no_forbidden(out)
    return out


def _no_forbidden(o):
    if isinstance(o, dict):
        for k, v in o.items():
            if k in FORBIDDEN:
                raise ConfigInvalid("forbidden key " + k)
            _no_forbidden(v)
    elif isinstance(o, list):
        for v in o:
            _no_forbidden(v)


# ---------------------------------------------------------------- content

def defaults() -> dict:
    import nullvault_status as st
    st.bind(nv, server)
    checks = [{"id": s.lower(), "name": s, "kind": "systemd"} for s in st.services() if ID.match(s.lower())]
    checks.append({"id": "disk", "name": "Disk space", "kind": "disk", "detail": f"down at {st.DISK_ALERT_PCT}% used"})
    try:
        import nullvault_chat as chat
        chat.bind(nv, server)
        bots = [{"id": str(r["id"])[:60], "title": str(r.get("title") or r["id"])[:80],
                 **({"category": str(r["category"])[:60]} if r.get("category") else {})} for r in chat.rooms()][:100]
    except Exception:  # roster unreadable: an empty list means "no filter" on the phone
        bots = []
    return {
        "status_checks": {"interval_minutes": 15, "down_after_failures": 1, "timeout_seconds": 10, "checks": checks[:60]},
        "alerts": {"server_down": True, "approval_waiting": True, "quick_action_run": True,
                   "quiet_hours": {"enabled": False, "start": "22:00", "end": "07:00", "tz": "America/New_York"}},
        "approvals": {"types": [
            {"kind": "github_pr", "source": "github", "label": "GitHub pull request",
             "confirm": "Approve this pull request? NullVault submits an approving review as you.", "decide": True},
            {"kind": "nullaxis", "source": "nullaxis", "label": "Nullaxis request",
             "confirm": "Nullaxis requests are read-only on the phone.", "decide": False}]},
        "chat": {"session_minutes": 10, "bots": bots},
        "files": {"tag_rules": [{"name": "APKs", "contains": [".apk"]}, {"name": "Backups", "contains": ["backup", ".tgz", ".bundle"]},
                                {"name": "Screenshots", "contains": ["screenshot"]}]},
        "links": {"category_rules": [{"category": "GitHub", "host_suffix": ["github.com"], "url_contains": []},
                                     {"category": "Nullverse", "host_suffix": ["nullverse.cloud"], "url_contains": []}]},
        "password_health": {"min_length": 12, "stale_days": 365, "reuse_check": True, "weak_bits": 50},
    }


def _overrides() -> dict:
    try:
        d = json.loads((nv.nv_dir() / OVERRIDES).read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def current() -> dict:
    cfg = defaults()
    ov = _overrides()
    for k, v in ov.items():
        if k not in SECTIONS:
            raise ConfigInvalid("unknown section " + str(k))
        cfg[k] = copy.deepcopy(v)
    return clean(cfg)


def _canon(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def bundle(now: float | None = None) -> dict:
    """Signed bundle. The version goes up by one whenever the content changes (never down)."""
    cfg = current()
    key = _key()
    h = hashlib.sha256(_canon(cfg)).hexdigest()
    with _lock:
        p = nv.nv_dir() / STATE
        try:
            stt = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            stt = {"version": 0, "sha256": ""}
        if stt.get("sha256") != h:
            stt = {"version": int(stt.get("version") or 0) + 1, "sha256": h, "changed_at": int(now or time.time())}
            server._atomic_write_json(p, stt)
    payload = _canon({"kind": KIND, "v": 1, "version": stt["version"], "issued_at": int(stt.get("changed_at") or 0), "config": cfg})
    return {"payload": base64.b64encode(payload).decode(), "sig": base64.b64encode(key.sign(payload)).decode(), "version": stt["version"]}


def route(h, method: str, path: str):
    d = nv._device_from_bearer(h)
    if not d:
        return
    if method != "GET":
        return h._json(405, {"error": "method_not_allowed"})
    try:
        b = bundle()
    except ConfigKeyUnavailable:
        return h._json(503, {"error": "config_key_unavailable"})
    except ConfigInvalid as e:
        server.vault_audit("nullvault_config_invalid", reason=str(e)[:120])
        return h._json(503, {"error": "config_invalid"})
    except Exception as e:  # never a dropped connection; the phone keeps its last good bundle
        server.vault_audit("nullvault_config_error", error=type(e).__name__)
        return h._json(503, {"error": "config_unavailable"})
    return h._json(200, {"bundle": {"payload": b["payload"], "sig": b["sig"]}, "version": b["version"]})
