"""NullVault Stage 3: quick actions framework (flag NULLVAULT_ACTIONS, default 0; allowlist EMPTY by default).

Shipped switched off with an empty allowlist: turning any action on needs John's own OK, by adding
  Environment=NULLVAULT_ACTIONS=1
  Environment=NULLVAULT_ACTIONS_ALLOW=<comma list of CATALOG names>
to the root-owned systemd drop-in (the Nullink process cannot change its own allowlist).

Rules: every action is a fixed name mapped to a fixed argv in CATALOG below. No shell, no user-supplied
commands or paths; the only caller input is validated arguments (enums or bounded ints) substituted into
fixed argv slots. Each run needs a fingerprint + fresh device signature (sync-challenge purpose "action"),
is rate-limited (per action and per device), and is written to data/nullvault/actions.jsonl (O_APPEND,
hash-chained) before and after it runs. Output is returned to the phone (truncated) but only its hash is logged.

Permission note (checked read-only 2026-11-12): `sudo -l` as nullink allows /usr/local/sbin/nulldo, but the
nullink.service unit sets NoNewPrivileges=yes (and an empty CapabilityBoundingSet), so sudo cannot run from
inside the Nullink process. nulldo-* entries therefore fail with "needs_privilege" until John approves a
change (see docs/NULLVAULT.md, "Quick actions: proposed allowlist").
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time

import nullvault_ext as ext

nv = None
server = None

LOG = "actions.jsonl"
OUT_MAX = 4000
DEVICE_LIMIT = (10, 3600)
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "SYSTEMD_PAGER": "", "SYSTEMD_COLORS": "0"}
SUDO = "/usr/bin/sudo"
NULLDO = "/usr/local/sbin/nulldo"

# name -> label, description, group, confirm text, argv template ("{param}" slots only), params (schema), per-action
#         limit (n, window s), timeout s, privilege: "none" (runs as nullink today) | "nulldo" (needs sudo from the
#         service; blocked by NoNewPrivileges).
# 0.7.0 (John 2026-11-14 9:37 PM ET): the phone renders ONLY what listing() sends (label, description, group, confirm,
# params schema); nothing about a command is coded into the APK. The server stays the authority: allowlist, signed run
# with purpose "action", parameter validation against the same schema, rate limits and audit are all server side.
# Param schema (JSON-Schema subset): {"type": "integer", "minimum", "maximum", "default", "title"} or
# {"type": "string", "enum": [...], "default", "title"}. Anything else is refused.
CATALOG: dict[str, dict] = {
    "nullink-health": {"label": "Nullink health", "group": "Nullink",
                       "description": "Calls Nullink's local /health endpoint and shows the reply and HTTP code.",
                       "confirm": "Check Nullink's local health endpoint?",
                       "privilege": "none", "timeout": 10, "limit": (12, 60),
                       "argv": ["/usr/bin/curl", "-sS", "-m", "5", "-o", "-", "-w", "\\nHTTP %{http_code}\\n",
                                "http://127.0.0.1:8766/health"], "params": {}},
    "nullink-status": {"label": "Nullink service state", "group": "Nullink",
                       "description": "Reads the nullink.service state (active, PID, start time, restarts) with systemctl show.",
                       "confirm": "Read the Nullink service state?",
                       "privilege": "none", "timeout": 15, "limit": (12, 60),
                       "argv": ["/usr/bin/systemctl", "show", "nullink.service", "--no-pager",
                                "--property=Id,ActiveState,SubState,MainPID,ExecMainStartTimestamp,NRestarts,Result"], "params": {}},
    "nulldo-status": {"label": "nulldo status", "group": "nulldo", "description": "Service status through nulldo.",
                      "confirm": "Run nulldo status?", "privilege": "nulldo", "timeout": 30, "limit": (6, 60),
                      "argv": [SUDO, "-n", NULLDO, "status"], "params": {}},
    "nulldo-health": {"label": "nulldo health", "group": "nulldo", "description": "Health check through nulldo.",
                      "confirm": "Run nulldo health?", "privilege": "nulldo", "timeout": 30, "limit": (6, 60),
                      "argv": [SUDO, "-n", NULLDO, "health"], "params": {}},
    "nulldo-journal": {"label": "nulldo journal", "group": "nulldo", "description": "The last N lines of the Nullink journal.",
                       "confirm": "Read the last {lines} journal lines?", "privilege": "nulldo", "timeout": 30, "limit": (6, 60),
                       "argv": [SUDO, "-n", NULLDO, "journal", "{lines}"],
                       "params": {"lines": {"type": "integer", "minimum": 1, "maximum": 200, "default": 50, "title": "Lines"}}},
    "nulldo-restart": {"label": "Restart Nullink", "group": "nulldo", "description": "Restarts the Nullink service (nulldo restart).",
                       "confirm": "Restart Nullink now? Open sessions keep working; requests in flight may fail.",
                       "privilege": "nulldo", "timeout": 100, "limit": (1, 600),
                       "argv": [SUDO, "-n", NULLDO, "restart"], "params": {}},
}
limits = ext.RateLimit()


def bind(nv_mod, srv):
    global nv, server
    nv, server = nv_mod, srv
    ext.bind(nv_mod, srv)


def enabled() -> bool:
    return nv.enabled() and os.environ.get("NULLVAULT_ACTIONS", "0") == "1"


def allowlist() -> list[str]:
    raw = os.environ.get("NULLVAULT_ACTIONS_ALLOW", "")
    return [n for n in (x.strip() for x in raw.split(",")) if n in CATALOG]


PARAM_NAME = re.compile(r"^[a-z_]{1,32}$")


def schema_ok(params: dict) -> bool:
    """CATALOG self-check (tests): every param uses the supported schema subset."""
    for k, s in params.items():
        if not PARAM_NAME.match(k) or not isinstance(s, dict):
            return False
        if s.get("type") == "integer":
            if not (isinstance(s.get("minimum"), int) and isinstance(s.get("maximum"), int) and s["minimum"] <= s["maximum"]):
                return False
            if "default" in s and not s["minimum"] <= s["default"] <= s["maximum"]:
                return False
        elif s.get("type") == "string":
            if not (isinstance(s.get("enum"), list) and s["enum"] and all(isinstance(x, str) for x in s["enum"])):
                return False
            if "default" in s and s["default"] not in s["enum"]:
                return False
        else:
            return False
    return True


def validate_args(spec: dict, given) -> dict | None:
    """Validate against the param schema: only declared params; integers (not bools/floats/strings) within
    [minimum, maximum]; strings from the declared enum; a missing param takes its default or is refused."""
    if given is None:
        given = {}
    if not isinstance(given, dict) or set(given) - set(spec):
        return None
    out = {}
    for k, s in spec.items():
        if k in given:
            v = given[k]
        elif "default" in s:
            v = s["default"]
        else:
            return None
        t = s.get("type")
        if t in ("integer", "int"):
            lo, hi = s.get("minimum", s.get("min")), s.get("maximum", s.get("max"))
            if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
                return None
            out[k] = str(v)
        elif t in ("string", "enum"):
            if not isinstance(v, str) or v not in s.get("enum", s.get("values", [])):
                return None
            out[k] = v
        else:
            return None
    return out


def legacy_args(params: dict) -> dict:
    """0.6.0 apps read {"type": "int", "min", "max", "default"}; integer params only."""
    return {k: {"type": "int", "min": s["minimum"], "max": s["maximum"], "default": s.get("default")}
            for k, s in params.items() if s.get("type") == "integer"}


def build_argv(name: str, args: dict) -> list[str]:
    argv = []
    for part in CATALOG[name]["argv"]:
        m = re.fullmatch(r"\{([a-z_]+)\}", part)
        argv.append(args[m.group(1)] if m else part)
    return argv


def run_argv(argv: list[str], timeout: int) -> tuple[int, str]:  # tests patch this
    try:
        p = subprocess.run(argv, shell=False, env=ENV, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                           timeout=timeout, check=False, cwd="/")
        return p.returncode, (p.stdout + ("\n" + p.stderr if p.stderr else ""))
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except OSError as e:
        return 127, type(e).__name__


def _needs_privilege(rc: int, out: str) -> bool:
    return rc != 0 and ("no new privileges" in out.lower() or "a password is required" in out.lower())


def command(n: str) -> dict:
    c = CATALOG[n]
    params = c["params"]
    return {"id": n, "name": n, "label": c["label"], "description": c.get("description", ""), "group": c.get("group", ""),
            "confirm": c.get("confirm", ""), "privilege": c["privilege"],
            "params": {"type": "object", "properties": params,
                       "required": [k for k, s in params.items() if "default" not in s], "additionalProperties": False},
            "args": legacy_args(params)}


def listing() -> dict:
    """Only allowlisted commands, in allowlist order. `version` changes whenever the list or any command changes."""
    cmds = [command(n) for n in allowlist()]
    ver = hashlib.sha256(json.dumps(cmds, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]
    return {"enabled": enabled(), "version": ver, "actions": cmds}


def _run(h):
    r = nv._verify_device_request(h, "action")
    if not r:
        return
    d, p, _att, _pin = r
    a = p.get("action") if isinstance(p.get("action"), dict) else {}
    name = str(a.get("name") or "")
    if name not in allowlist():
        return h._json(403, {"error": "action_not_allowed"})
    spec = CATALOG[name]
    args = validate_args(spec["params"], a.get("args"))
    if args is None:
        return h._json(400, {"error": "bad_args"})
    if not limits.hit("dev:" + d["device_id"], *DEVICE_LIMIT) or not limits.hit("act:" + name, *spec["limit"]):
        ext.chained_append(LOG, {"event": "refused", "action": name, "reason": "rate_limited", "device_id": d["device_id"]})
        return h._json(429, {"error": "rate_limited"})
    ip, _ua = nv._ctx(h)
    ext.chained_append(LOG, {"event": "run", "action": name, "args": args, "device_id": d["device_id"], "ip": ip})
    t0 = time.time()
    rc, out = run_argv(build_argv(name, args), spec["timeout"])
    out = out[-OUT_MAX:]
    result = "ok" if rc == 0 else ("needs_privilege" if _needs_privilege(rc, out) else "failed")
    ext.chained_append(LOG, {"event": "result", "action": name, "rc": rc, "result": result, "secs": round(time.time() - t0, 2),
                             "output_sha256": hashlib.sha256(out.encode()).hexdigest(), "device_id": d["device_id"]})
    server.vault_audit("device_action", device=d["device_id"], action=name, rc=rc, result=result, ip=ip)
    nv.alert(f"NullVault quick action `{name}` from device {d['device_id'][:12]}: {result} (rc {rc}).")
    return h._json(200, {"ok": rc == 0, "action": name, "rc": rc, "result": result, "output": out})


def route(h, method: str, path: str):
    if not enabled():
        return h._json(404, {"error": "not_found"})
    if path == "/api/vault/actions" and method == "GET":
        d = nv._device_from_bearer(h)
        if not d:
            return
        return h._json(200, listing())
    if path == "/api/vault/actions/run" and method == "POST":
        return _run(h)
    return h._json(404, {"error": "not_found"})
