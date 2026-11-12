"""NullVault server status (Stage 2, 2026-11-12). Flag NULLVAULT_STATUS=1 (default OFF), under NULLVAULT_ENABLED.

A per-server card for the phone: health, uptime, load, memory, disk, key services (systemd ActiveState through an
unprivileged `systemctl show`, the same thing any local user can read), and expiry DATES for TLS certificates and
admin-listed tokens. Never token values: TLS expiry comes from the public certificate; the admin seed file
data/nullvault/token_expiry.json is reduced to name/kind/expires_at before anything leaves this module.

Auth: Bearer device token (nvd_) or a status-only token (nvs_) issued for a fingerprint-signed request, so the
phone's opt-in background check can read status without unlocking the vault. Both die with a revoke/flag.

Down alerts: no push service (no Firebase/FCM). A server thread checks every 60 s and sends a Slack DM through the
existing NullVault alert path on active -> not-active transitions (and recovery), rate-limited per item.
Left out because they need privileges nullink does not have: other units' journal errors, docker container state
(docker socket), SMART/disk health, other users' process details, failed-login counts.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

nv = None
server = None

DEFAULT_SERVICES = ["nullink", "caddy", "nullmail", "nullink-mcp", "mcp-gateway", "linguasheet", "storycast-app",
                    "postfix", "docker", "ssh", "tailscaled", "nullink-deploy-hook"]
STATUS_TOKEN_TTL = 90 * 86400
CACHE_TTL = 30
TLS_CACHE_TTL = 6 * 3600
ALERT_GAP = 1800
DISK_ALERT_PCT = 95
OMITTED = ["journal errors of other units (needs adm/systemd-journal group)",
           "docker container state (needs the docker socket)",
           "SMART / disk hardware health (needs root)",
           "other users' process details and failed-login counts (needs root)"]
_UNIT = re.compile(r"^[A-Za-z0-9@_.:-]{1,80}$")
_lock = threading.RLock()
_cache: dict = {"t": 0.0, "data": None}
_tls_cache: dict = {"t": 0.0, "certs": []}
_mon: dict = {"state": {}, "last_alert": {}, "thread": None}


def bind(nv_mod, srv):
    global nv, server
    nv, server = nv_mod, srv


def enabled() -> bool:
    return os.environ.get("NULLVAULT_STATUS", "0") == "1"


def _now_iso(t=None) -> str:
    return datetime.fromtimestamp(t if t is not None else time.time(), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def services() -> list[str]:
    raw = os.environ.get("NULLVAULT_STATUS_SERVICES")
    names = [s.strip() for s in raw.split(",")] if raw else list(DEFAULT_SERVICES)
    try:
        d = json.loads((nv.nv_dir() / "status_services.json").read_text(encoding="utf-8"))
        names = [str(s) for s in d.get("services", [])] or names
    except (OSError, ValueError, AttributeError):
        pass
    return [n for n in names if _UNIT.match(n)][:40]


# ---------------------------------------------------------------- metrics (read-only, unprivileged)

def run_systemctl_show(units: list[str]) -> str:  # tests patch this
    if not units:
        return ""
    r = subprocess.run(["systemctl", "show", "--no-pager", "-p", "Id", "-p", "ActiveState", "-p", "SubState",
                        "-p", "ActiveEnterTimestamp", "-p", "LoadState", *[u if "." in u else u + ".service" for u in units]],
                       capture_output=True, text=True, timeout=5, check=False)
    return r.stdout


def parse_show(text: str) -> list[dict]:
    out, cur = [], {}
    for line in (text or "").splitlines() + [""]:
        if not line.strip():
            if cur:
                out.append(cur)
            cur = {}
            continue
        k, _, v = line.partition("=")
        cur[k] = v
    res = []
    for c in out:
        name = c.get("Id", "").removesuffix(".service")
        if not name:
            continue
        state = c.get("ActiveState") or "unknown"
        if c.get("LoadState") == "not-found":
            state = "not-found"
        res.append({"name": name, "active": state, "sub": c.get("SubState") or "", "since": c.get("ActiveEnterTimestamp") or None,
                    "ok": state == "active"})
    return res


def service_states() -> list[dict]:
    try:
        return parse_show(run_systemctl_show(services()))
    except (OSError, subprocess.SubprocessError):
        return [{"name": n, "active": "unknown", "sub": "", "since": None, "ok": False} for n in services()]


def _read(p: str) -> str:
    try:
        return Path(p).read_text(encoding="ascii")
    except OSError:
        return ""


def host_metrics() -> dict:
    up = _read("/proc/uptime").split()
    la = _read("/proc/loadavg").split()
    mem = {}
    for line in _read("/proc/meminfo").splitlines():
        k, _, v = line.partition(":")
        if k in ("MemTotal", "MemAvailable"):
            mem[k] = int(v.split()[0]) * 1024
    disks = []
    seen = set()
    for mount in ("/", str(server.BASE) if server else "/opt/nullink"):
        try:
            st = os.stat(mount)
            if st.st_dev in seen:
                continue
            seen.add(st.st_dev)
            du = shutil.disk_usage(mount)
            disks.append({"mount": mount, "total": du.total, "used": du.used, "free": du.free,
                          "pct": round(du.used * 100 / du.total, 1) if du.total else 0.0})
        except OSError:
            continue
    return {"uptime_s": int(float(up[0])) if up else None,
            "load": [float(x) for x in la[:3]] if len(la) >= 3 else None,
            "mem": {"total": mem.get("MemTotal"), "available": mem.get("MemAvailable")} if mem else None,
            "disk": disks}


def cert_expiry(host: str, port: int = 443, connect: str = "127.0.0.1") -> str | None:  # tests patch this
    ctx = ssl.create_default_context()
    with socket.create_connection((connect, port), timeout=3) as s:
        with ctx.wrap_socket(s, server_hostname=host) as t:
            na = t.getpeercert().get("notAfter")
    return _now_iso(ssl.cert_time_to_seconds(na)) if na else None


def tls_hosts() -> list[str]:
    try:
        import nullvault_ext as ext
        return [s["host"] for s in ext.discover()["sites"]][:20]
    except Exception:  # noqa: BLE001
        return []


def tls_certs() -> list[dict]:
    now = time.time()
    with _lock:
        if now - _tls_cache["t"] < TLS_CACHE_TTL and _tls_cache["t"]:
            return _tls_cache["certs"]
    out = []
    for h in tls_hosts():
        try:
            exp = cert_expiry(h)
        except (OSError, ssl.SSLError, ValueError):
            exp = None
        out.append({"name": h, "kind": "tls_certificate", "expires_at": exp})
    with _lock:
        _tls_cache.update(t=now, certs=out)
    return out


def seeded_tokens() -> list[dict]:
    """Admin seed: {"tokens": [{"name", "kind", "expires_at"}]}. Only those three keys are ever read."""
    try:
        d = json.loads((nv.nv_dir() / "token_expiry.json").read_text(encoding="utf-8"))
    except (OSError, ValueError, AttributeError):
        return []
    out = []
    for t in (d.get("tokens") or [])[:100]:
        if not isinstance(t, dict):
            continue
        exp = str(t.get("expires_at") or "")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}([T ][0-9:]{5,8}(Z|[+-]\d{2}:?\d{2})?)?", exp):
            exp = None
        out.append({"name": str(t.get("name") or "")[:80], "kind": str(t.get("kind") or "token")[:40], "expires_at": exp})
    return out


def _days_left(exp: str | None, now: float) -> int | None:
    if not exp:
        return None
    try:
        s = exp.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s if ("T" in s or " " in s) else s + "T00:00:00+00:00")
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int((dt.timestamp() - now) // 86400)
    except ValueError:
        return None


def collect(force: bool = False) -> dict:
    now = time.time()
    with _lock:
        if not force and _cache["data"] and now - _cache["t"] < CACHE_TTL:
            return _cache["data"]
    svcs = service_states()
    tokens = [dict(t, days_left=_days_left(t["expires_at"], now)) for t in tls_certs() + seeded_tokens()]
    import nullvault_ext as ext
    hm = host_metrics()
    data = {"server_label": ext.server_label(), "time": _now_iso(now),
            "health": {"ok": True, "services_ok": all(s["ok"] for s in svcs) if svcs else None,
                       "down": [s["name"] for s in svcs if not s["ok"]]},
            **hm, "services": svcs, "tokens": tokens, "omitted": OMITTED}
    with _lock:
        _cache.update(t=now, data=data)
    return data


# ---------------------------------------------------------------- status tokens (nvs_)

def _tok_file() -> Path:
    return nv.nv_dir() / "status_tokens.json"


def _load_toks() -> dict:
    try:
        d = json.loads(_tok_file().read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def issue_token(device_id: str) -> tuple[str, int]:
    tok = "nvs_" + nv.b64url(secrets.token_bytes(32))
    now = int(time.time())
    with _lock:
        d = _load_toks()
        d[device_id] = {"hash": hashlib.sha256(tok.encode()).hexdigest(), "issued_at": now, "expires_at": now + STATUS_TOKEN_TTL}
        server._atomic_write_json(_tok_file(), d)
    return tok, STATUS_TOKEN_TTL


def device_for_status(h):
    """nvd_ device token or nvs_ status token -> active device, else None (response sent)."""
    tok = h._bearer_token() or ""
    if tok.startswith("nvs_"):
        hsh = hashlib.sha256(tok.encode()).hexdigest()
        now = time.time()
        did = next((k for k, v in _load_toks().items()
                    if isinstance(v, dict) and secrets.compare_digest(v.get("hash", ""), hsh) and v.get("expires_at", 0) > now), None)
        d = nv.devices().get(did) if did else None
        if not d:
            h._json(401, {"error": "unauthorized"})
            return None
        if d["status"] != "active":
            h._json(403, {"error": d["status"], "wipe": True})
            return None
        return d
    return nv._device_from_bearer(h)


# ---------------------------------------------------------------- down monitor -> existing Slack alert path

def _send(key: str, text: str, now: float) -> bool:
    last = _mon["last_alert"].get(key)
    if last is not None and now - last < ALERT_GAP:
        return False
    _mon["last_alert"][key] = now
    nv.alert(text)
    return True


def monitor_tick(now: float | None = None) -> list[str]:
    """One check. Alerts on active -> not-active (and back), and disk crossing DISK_ALERT_PCT. Returns texts sent."""
    now = now or time.time()
    sent = []
    import nullvault_ext as ext
    label = ext.server_label()
    items = {("svc:" + s["name"]): (s["ok"], s["active"]) for s in service_states() if s["active"] != "not-found"}
    for dk in host_metrics()["disk"]:
        items["disk:" + dk["mount"]] = (dk["pct"] < DISK_ALERT_PCT, f"{dk['pct']}% used")
    with _lock:
        for key, (ok, detail) in items.items():
            prev = _mon["state"].get(key)
            _mon["state"][key] = ok
            if prev is None or prev == ok:
                continue  # first sighting is the baseline; only transitions alert
            what = key.split(":", 1)[1]
            text = (f":red_circle: NullVault status: *{what}* on {label} is DOWN ({detail})" if not ok
                    else f":large_green_circle: NullVault status: *{what}* on {label} is back ({detail})")
            if _send(key + (":down" if not ok else ":up"), text, now):
                sent.append(text)
    return sent


def start_monitor() -> bool:
    if _mon["thread"] or os.environ.get("NULLVAULT_STATUS_MONITOR", "1") == "0":
        return False

    def loop():
        while True:
            time.sleep(60)
            try:
                if nv and nv.enabled() and enabled():
                    if nv.server is None:  # alerts need the live server module (Slack); bind once
                        for m in (sys.modules.get("__main__"), sys.modules.get("server")):
                            if m is not None and hasattr(m, "_slack_dm_channel"):
                                nv.server = m
                                globals()["server"] = m
                                break
                    if nv.server is not None:
                        import nullvault_ext as ext
                        ext.bind(nv, nv.server)
                        globals()["server"] = nv.server
                        monitor_tick()
            except Exception:  # noqa: BLE001 - never take the server down
                pass
    t = threading.Thread(target=loop, name="nullvault-status", daemon=True)
    _mon["thread"] = t
    t.start()
    return True


# ---------------------------------------------------------------- HTTP

def route(h, method: str, path: str):
    if not enabled():
        return h._json(404, {"error": "not_found"})
    if path == "/api/vault/status" and method == "GET":
        d = device_for_status(h)
        if not d:
            return
        return h._json(200, collect())
    if path == "/api/vault/status/token" and method == "POST":
        r = nv._verify_device_request(h, "status")
        if not r:
            return
        tok, ttl = issue_token(r[0]["device_id"])
        server.vault_audit("device_status_token", device=r[0]["device_id"], ip=nv._ctx(h)[0])
        return h._json(200, {"status_token": tok, "expires_in": ttl})
    return h._json(405, {"error": "method_not_allowed"})
