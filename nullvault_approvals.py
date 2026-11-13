"""NullVault Stage 3: approvals queue (flag NULLVAULT_APPROVALS, under NULLVAULT_ENABLED).

(a) GitHub pull requests, through the GitHub access the server already has: secrets/github_token.txt (the same
    file github_drive.py uses). No token, or not readable -> PRs are shown as unavailable and none are listed.
    No token is ever added, returned or logged.
    A decision (approve / reject) is a fingerprint + device-signed request (sync-challenge purpose "approve") bound
    to repo, PR number and head SHA. It is appended to data/nullvault/approvals.jsonl (O_APPEND, hash-chained,
    with the signed payload and signature so it can be re-verified later).
    Only for "approve", and only when that token exists: the server then submits a GitHub review with
    event APPROVE pinned to the signed head SHA. If the token lacks the scope GitHub answers 403/404 and nothing
    else happens; GitHub also refuses approving your own PR (skipped up front). Never merges: there is no merge
    call anywhere in this module.
(b) NullAxis requests: John has the NullAxis gateway work on hold. Read-only placeholder: no local NullAxis
    endpoint exists on this server, so it lists nothing and never connects anywhere.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import nullvault_ext as ext

nv = None
server = None

LOG = "approvals.jsonl"
API = "https://api.github.com"
LIST_TTL = 120
MAX_PRS = 30
DECIDE_LIMIT = (30, 3600)
_REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_cache: dict = {"t": 0.0, "data": None}
_login: dict = {"t": 0.0, "login": None}
_lock = threading.Lock()
limits = ext.RateLimit()


def bind(nv_mod, srv):
    global nv, server
    nv, server = nv_mod, srv
    ext.bind(nv_mod, srv)


def enabled() -> bool:
    return nv.enabled() and os.environ.get("NULLVAULT_APPROVALS", "0") == "1"


def owner() -> str:
    o = os.environ.get("NULLVAULT_APPROVALS_GITHUB_OWNER", "johnshorttn")
    return o if re.fullmatch(r"[A-Za-z0-9-]{1,39}", o) else "johnshorttn"


def token_file():
    p = os.environ.get("NULLVAULT_GITHUB_TOKEN_FILE")
    return p if p else str(server.BASE / "secrets" / "github_token.txt")


def _token() -> str | None:
    try:
        with open(token_file(), encoding="utf-8") as f:
            t = f.read().strip()
    except OSError:
        return None
    return t or None


def token_available() -> bool:
    return _token() is not None


def gh(method: str, path: str, body: dict | None = None):
    """GitHub REST call -> (status, json). Patched in tests. The token never leaves this function."""
    tok = _token()
    if not tok:
        return 0, {"error": "no_token"}
    req = urllib.request.Request(API + path, method=method, data=None if body is None else json.dumps(body).encode())
    req.add_header("Authorization", "Bearer " + tok)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("User-Agent", "nullink-nullvault")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            js = json.loads(e.read() or b"{}")
        except ValueError:
            js = {}
        return e.code, {"message": str(js.get("message") or "")[:200]}
    except (urllib.error.URLError, OSError, ValueError):
        return 0, {"error": "network"}


def token_login() -> str | None:
    if time.time() - _login["t"] < 3600 and _login["login"]:
        return _login["login"]
    st, js = gh("GET", "/user")
    if st == 200 and isinstance(js, dict):
        _login.update(t=time.time(), login=str(js.get("login") or "") or None)
    return _login["login"]


def _pr_item(pr: dict) -> dict:
    base = pr.get("base") or {}
    return {"source": "github", "repo": str((base.get("repo") or {}).get("full_name") or ""),
            "number": int(pr.get("number") or 0), "title": str(pr.get("title") or "")[:300],
            "author": str((pr.get("user") or {}).get("login") or ""), "url": str(pr.get("html_url") or ""),
            "head_sha": str((pr.get("head") or {}).get("sha") or ""), "draft": bool(pr.get("draft")),
            "updated_at": pr.get("updated_at"), "state": pr.get("state")}


def github_queue(force: bool = False) -> dict:
    if not token_available():
        return {"available": False, "reason": "no_token", "items": []}
    with _lock:
        if not force and _cache["data"] is not None and time.time() - _cache["t"] < LIST_TTL:
            return _cache["data"]
    q = urllib.parse.quote(f"is:pr is:open archived:false user:{owner()}")
    st, js = gh("GET", f"/search/issues?q={q}&sort=updated&order=desc&per_page={MAX_PRS}")
    if st != 200 or not isinstance(js, dict):
        return {"available": False, "reason": "github_error" if st else "github_unreachable", "status": st, "items": []}
    items = []
    for it in (js.get("items") or [])[:MAX_PRS]:
        m = re.match(r"^https://api\.github\.com/repos/([^/]+/[^/]+)$", str(it.get("repository_url") or ""))
        if not m or not _REPO.match(m.group(1)):
            continue
        st2, pr = gh("GET", f"/repos/{m.group(1)}/pulls/{int(it.get('number') or 0)}")
        if st2 == 200 and isinstance(pr, dict):
            items.append(_pr_item(pr))
    me = token_login()
    for i in items:
        i["own_pr"] = bool(me and i["author"] == me)
    data = {"available": True, "items": items, "token_login": me}
    with _lock:
        _cache.update(t=time.time(), data=data)
    return data


def nullaxis_queue() -> dict:
    return {"available": False, "reason": "on_hold", "items": [],
            "note": "NullAxis gateway work is on hold; no local NullAxis endpoint exists on this server."}


def decisions(n: int = 50) -> list[dict]:
    return [{k: r.get(k) for k in ("ts", "event", "source", "repo", "number", "head_sha", "decision", "review", "device_id")}
            for r in ext.chain_tail(LOG, n)]


def _decide(h):
    body = ext.capture_body(h)
    r = nv._verify_device_request(h, "approve")
    if not r:
        return
    d, p, _att, _pin = r
    a = p.get("approval") if isinstance(p.get("approval"), dict) else {}
    source, repo, dec = a.get("source"), str(a.get("repo") or ""), a.get("decision")
    sha, note = str(a.get("head_sha") or ""), str(a.get("note") or "")[:500]
    try:
        number = int(a.get("number"))
    except (TypeError, ValueError):
        number = 0
    if source != "github" or dec not in ("approve", "reject") or not _REPO.match(repo) or not _SHA.match(sha) or number <= 0:
        return h._json(400, {"error": "bad_request"})
    if not limits.hit(d["device_id"], *DECIDE_LIMIT):
        return h._json(429, {"error": "rate_limited"})
    if not token_available():
        return h._json(409, {"error": "github_unavailable"})
    st, pr = gh("GET", f"/repos/{repo}/pulls/{number}")
    if st != 200 or not isinstance(pr, dict):
        return h._json(502 if st == 0 else 404, {"error": "pr_unavailable", "status": st})
    cur = _pr_item(pr)
    if cur["state"] != "open":
        return h._json(409, {"error": "pr_not_open"})
    if cur["head_sha"] != sha:
        return h._json(409, {"error": "stale_head", "head_sha": cur["head_sha"]})
    ip, ua = nv._ctx(h)
    raw = base64.b64decode(str(body.get("payload") or ""))
    rec = ext.chained_append(LOG, {"event": "decision", "source": "github", "repo": repo, "number": number,
                                   "head_sha": sha, "decision": dec, "note": note, "device_id": d["device_id"],
                                   "payload_b64": base64.b64encode(raw).decode(), "signature": str(body.get("signature") or ""),
                                   "payload_sha256": hashlib.sha256(raw).hexdigest(), "ip": ip})
    review = "not_requested"
    if dec == "approve":
        review = submit_review(repo, number, sha, cur)
        ext.chained_append(LOG, {"event": "github_review", "repo": repo, "number": number, "head_sha": sha,
                                 "review": review, "device_id": d["device_id"]})
    server.vault_audit("device_approval", device=d["device_id"], repo=repo, number=number, decision=dec, review=review, ip=ip, ua=ua)
    nv.alert(f"NullVault: {dec} recorded for {repo}#{number} from device {d['device_id'][:12]} (GitHub review: {review}).")
    with _lock:
        _cache.update(t=0.0, data=None)
    return h._json(200, {"ok": True, "decision": dec, "recorded_at": rec["ts"], "review": review})


def submit_review(repo: str, number: int, sha: str, pr: dict) -> str:
    """APPROVE review only (never merge). Returns submitted | own_pr | disabled | not_permitted | refused | error."""
    if os.environ.get("NULLVAULT_APPROVALS_GITHUB_REVIEW", "1") == "0":
        return "disabled"
    me = token_login()
    if me and pr.get("author") == me:
        return "own_pr"  # GitHub never lets an account approve its own pull request
    st, _js = gh("POST", f"/repos/{repo}/pulls/{number}/reviews",
                 {"event": "APPROVE", "commit_id": sha,
                  "body": "Approved in NullVault (fingerprint + device signature); recorded in the Nullink approvals log."})
    if st == 200:
        return "submitted"
    if st in (401, 403, 404):
        return "not_permitted"
    if st == 422:
        return "refused"
    return "error"


def route(h, method: str, path: str):
    if not enabled():
        return h._json(404, {"error": "not_found"})
    if path == "/api/vault/approvals/decide":
        if method != "POST":
            return h._json(405, {"error": "method_not_allowed"})
        return _decide(h)
    if path == "/api/vault/approvals" and method == "GET":
        d = nv._device_from_bearer(h)
        if not d:
            return
        force = "refresh=1" in (urllib.parse.urlparse(h.path).query or "")
        return h._json(200, {"github": github_queue(force), "nullaxis": nullaxis_queue(), "recent": decisions(20),
                             "log_ok": ext.chain_verify(LOG)[0]})
    return h._json(404, {"error": "not_found"})
