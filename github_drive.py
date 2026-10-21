"""GitHub drive (gh1, 2026-10-21): browse repos -> branches -> tree -> file viewer, private
repos included, through the owner's token in secrets/github_token.txt (server-side only: never
sent to the client, never logged). Read-only by default. Edit/commit needs a fresh authenticator
code (session step-up, 5 min) and a commit message; commit to the branch or to a new branch + PR.
The file's blob sha is re-checked right before committing (409 if it changed). Every edit and
refusal goes to data/github_drive_audit.jsonl (no file contents, no token). Owner cookie session
only: guests and any Authorization header (agent / AI Bearer tokens) are refused.
"""
from __future__ import annotations

import base64
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

S = None
API = "https://api.github.com"
MAX_FILE = 1024 * 1024
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
REF_RE = re.compile(r"^(?!.*\.\.)(?!/)(?!.*//)[A-Za-z0-9._/-]{1,200}(?<!/)(?<!\.lock)$")
PATH_BAD = re.compile(r"[\x00-\x1f\x7f\\]")


def bind(mod):
    global S
    S = mod


class GhErr(Exception):
    def __init__(self, code, err, **extra):
        self.code, self.err, self.extra = code, err, extra


def token_file():
    return S.BASE / "secrets" / "github_token.txt"


def token() -> str | None:
    try:
        t = token_file().read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return t or None


def audit(event: str, **fields) -> None:
    rec = {"ts": int(time.time()), "event": event,
           **{k: (str(v)[:300] if v is not None else None) for k, v in fields.items()}}
    try:
        f = S.DATA / "github_drive_audit.jsonl"
        fd = os.open(f, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
    except OSError:
        pass


def gh(method: str, path: str, body: dict | None = None, query: dict | None = None):
    """GitHub REST call. Returns (status, json). Patched in tests. Token never leaves this function."""
    tok = token()
    if not tok:
        raise GhErr(503, "token_not_configured")
    url = API + path + ("?" + urllib.parse.urlencode(query) if query else "")
    req = urllib.request.Request(url, method=method,
                                 data=None if body is None else json.dumps(body).encode())
    req.add_header("Authorization", "Bearer " + tok)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("User-Agent", "nullink-github-drive")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        try:
            data = json.loads(e.read() or b"{}")
        except ValueError:
            data = {}
        return e.code, {"message": str(data.get("message") or "")[:200]}
    except (urllib.error.URLError, TimeoutError, OSError):
        raise GhErr(502, "github_unreachable")


def _ok(st, data, what="github_error"):
    if st in (200, 201):
        return data
    if st == 401:
        raise GhErr(502, "token_rejected", message="GitHub rejected the configured token.")
    if st == 404:
        raise GhErr(404, "not_found")
    if st == 409:
        raise GhErr(409, "conflict", message=data.get("message", ""))
    if st == 422:
        raise GhErr(422, "unprocessable", message=data.get("message", ""))
    raise GhErr(502, what, status=st)


def _repo(v) -> str:
    v = str(v or "")
    if not REPO_RE.match(v) or ".." in v:
        raise GhErr(400, "bad_repo")
    return v


def _ref(v) -> str:
    v = str(v or "")
    if not REF_RE.match(v):
        raise GhErr(400, "bad_ref")
    return v


def _path(v, allow_root=True) -> str:
    v = str(v or "").strip("/")
    if (not v and not allow_root) or PATH_BAD.search(v) or any(p in ("", ".", "..") for p in v.split("/") if v) \
            or len(v) > 1000:
        raise GhErr(400, "bad_path")
    return v


def _q(qs, k):
    return (qs.get(k) or [""])[0]


def _enc(p):
    return urllib.parse.quote(p, safe="/")


def handle(h, method: str, path: str, qs) -> bool:
    if path != "/api/gh" and not path.startswith("/api/gh/"):
        return False
    ip = S.client_ip(h)
    if h.headers.get("Authorization") is not None:
        audit("refused", reason="authorization_header", path=path, ip=ip)
        h._json(403, {"error": "forbidden", "message": "owner cookie session required"})
        return True
    rec = h._require_owner()
    if rec is None:
        audit("refused", reason="not_owner", path=path, ip=ip)
        return True
    sid = rec.get("id")
    try:
        _route(h, method, path, qs, rec, ip, sid)
    except GhErr as e:
        if e.code not in (404,):
            audit("error", path=path, err=e.err, ip=ip, session=sid)
        h._json(e.code, {"error": e.err, **e.extra})
    return True


def _stepped(rec) -> bool:
    return time.time() - float(rec.get("stepup_at") or 0) <= S.STEPUP_WINDOW_SEC


def _route(h, method, path, qs, rec, ip, sid):
    if method == "GET" and path == "/api/gh/status":
        if not token():
            return h._json(200, {"configured": False, "read_only_default": True,
                                 "message": "GitHub token not configured: add secrets/github_token.txt on the server."})
        st, me = gh("GET", "/user")
        me = _ok(st, me)
        return h._json(200, {"configured": True, "login": me.get("login"), "read_only_default": True,
                             "edit_ready": _stepped(rec)})
    if method == "GET" and path == "/api/gh/repos":
        page = max(1, min(int(_q(qs, "page") or 1), 50))
        st, data = gh("GET", "/user/repos", query={"per_page": 100, "page": page, "sort": "pushed",
                                                    "affiliation": "owner,collaborator,organization_member"})
        repos = [{"full_name": r.get("full_name"), "private": bool(r.get("private")),
                  "default_branch": r.get("default_branch"), "description": (r.get("description") or "")[:200],
                  "pushed_at": r.get("pushed_at"), "permissions": {"push": bool((r.get("permissions") or {}).get("push"))}}
                 for r in _ok(st, data) if isinstance(r, dict)]
        return h._json(200, {"repos": repos, "page": page, "more": len(repos) == 100})
    if method == "GET" and path == "/api/gh/branches":
        repo = _repo(_q(qs, "repo"))
        st, data = gh("GET", f"/repos/{repo}/branches", query={"per_page": 100})
        return h._json(200, {"branches": [{"name": b.get("name"), "sha": (b.get("commit") or {}).get("sha"),
                                           "protected": bool(b.get("protected"))} for b in _ok(st, data)]})
    if method == "GET" and path == "/api/gh/tree":
        repo, ref, p = _repo(_q(qs, "repo")), _ref(_q(qs, "ref")), _path(_q(qs, "path"))
        st, data = gh("GET", f"/repos/{repo}/contents/{_enc(p)}", query={"ref": ref})
        data = _ok(st, data)
        if not isinstance(data, list):
            raise GhErr(400, "not_a_directory")
        items = sorted(({"name": e.get("name"), "path": e.get("path"), "type": e.get("type"),
                         "size": e.get("size"), "sha": e.get("sha")} for e in data),
                       key=lambda e: (e["type"] != "dir", str(e["name"]).lower()))
        audit("list", repo=repo, ref=ref, path=p, ip=ip, session=sid)
        return h._json(200, {"repo": repo, "ref": ref, "path": p, "items": items})
    if method == "GET" and path == "/api/gh/file":
        repo, ref, p = _repo(_q(qs, "repo")), _ref(_q(qs, "ref")), _path(_q(qs, "path"), False)
        st, data = gh("GET", f"/repos/{repo}/contents/{_enc(p)}", query={"ref": ref})
        data = _ok(st, data)
        if not isinstance(data, dict) or data.get("type") != "file":
            raise GhErr(400, "not_a_file")
        size = int(data.get("size") or 0)
        out = {"repo": repo, "ref": ref, "path": p, "name": data.get("name"), "sha": data.get("sha"),
               "size": size, "binary": False, "too_large": False, "content": None}
        if size > MAX_FILE or not data.get("content"):
            out["too_large"] = size > MAX_FILE
        else:
            raw = base64.b64decode(data.get("content") or "")
            try:
                out["content"] = raw.decode("utf-8")
            except UnicodeDecodeError:
                out["binary"] = True
        audit("view", repo=repo, ref=ref, path=p, ip=ip, session=sid)
        return h._json(200, out)
    if method != "POST":
        raise GhErr(404, "not_found")
    b = h._read_json()
    b = b if isinstance(b, dict) else {}
    if path in ("/api/gh/edit", "/api/gh/commit") and not _stepped(rec):
        audit("refused", reason="step_up_required", path=path, ip=ip, session=sid)
        raise GhErr(403, "step_up_required", stepup_endpoint="/api/auth/stepup",
                    message="Enter an authenticator code to edit on GitHub.")
    if path == "/api/gh/edit":
        audit("edit_unlocked", repo=b.get("repo"), path=b.get("path"), ip=ip, session=sid)
        return h._json(200, {"ok": True, "window_sec": S.STEPUP_WINDOW_SEC})
    if path == "/api/gh/commit":
        return _commit(h, b, ip, sid)
    raise GhErr(404, "not_found")


def _commit(h, b, ip, sid):
    repo, branch, p = _repo(b.get("repo")), _ref(b.get("branch")), _path(b.get("path"), False)
    message = " ".join(str(b.get("message") or "").split())[:500]
    if not message:
        raise GhErr(400, "message_required")
    content = b.get("content")
    if not isinstance(content, str) or len(content.encode("utf-8")) > MAX_FILE:
        raise GhErr(400, "bad_content")
    base_sha = str(b.get("sha") or "")
    if not re.fullmatch(r"[0-9a-f]{40}", base_sha):
        raise GhErr(400, "bad_sha")
    mode = b.get("mode") or "branch"
    if mode not in ("branch", "pr"):
        raise GhErr(400, "bad_mode")
    # sha check against the branch we started from
    st, cur = gh("GET", f"/repos/{repo}/contents/{_enc(p)}", query={"ref": branch})
    cur = _ok(st, cur)
    if not isinstance(cur, dict) or cur.get("sha") != base_sha:
        audit("commit_conflict", repo=repo, branch=branch, path=p, ip=ip, session=sid)
        raise GhErr(409, "changed_since_open", current_sha=(cur or {}).get("sha"),
                    message="The file changed on GitHub since you opened it.")
    target = branch
    if mode == "pr":
        target = _ref(b.get("new_branch"))
        st, refd = gh("GET", f"/repos/{repo}/git/ref/heads/{_enc(branch)}")
        head = _ok(st, refd).get("object", {}).get("sha")
        st, made = gh("POST", f"/repos/{repo}/git/refs", {"ref": f"refs/heads/{target}", "sha": head})
        if st == 422:
            raise GhErr(409, "branch_exists")
        _ok(st, made)
    st, res = gh("PUT", f"/repos/{repo}/contents/{_enc(p)}", {
        "message": message, "content": base64.b64encode(content.encode("utf-8")).decode(),
        "sha": base_sha, "branch": target})
    if st == 409:
        audit("commit_conflict", repo=repo, branch=target, path=p, ip=ip, session=sid)
        raise GhErr(409, "changed_since_open")
    res = _ok(st, res)
    commit_sha = (res.get("commit") or {}).get("sha")
    out = {"ok": True, "branch": target, "commit": commit_sha, "sha": (res.get("content") or {}).get("sha")}
    if mode == "pr":
        st, pr = gh("POST", f"/repos/{repo}/pulls", {"title": str(b.get("pr_title") or message)[:200],
                                                      "head": target, "base": branch,
                                                      "body": "Edited in Nullink GitHub drive."})
        pr = _ok(st, pr)
        out["pr_url"], out["pr_number"] = pr.get("html_url"), pr.get("number")
    audit("commit", repo=repo, branch=target, base=branch, path=p, mode=mode, commit=commit_sha,
          pr=out.get("pr_number"), message=message, ip=ip, session=sid)
    return h._json(200, out)
