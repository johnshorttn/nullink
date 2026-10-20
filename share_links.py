"""Report share links (2026-10-14): owner-only PDF + single-device 24 h share links with
extension / teammate requests approved from John's Slack DM. Bound to the server module."""
from __future__ import annotations
import hashlib, hmac, html, json, os, re, secrets, subprocess, tempfile, threading, time, urllib.parse
from http.cookies import SimpleCookie
from pathlib import Path

S = None  # server module
_lock = threading.RLock()
_pdf_lock = threading.Lock()
LINK_TTL = 24 * 3600
UNOPENED_TTL = 7 * 24 * 3600
AI_TTLS = {"1h": 3600, "24h": 86400, "7d": 7 * 86400}
AI_MAX_OPENS = 50
AI_COPYRIGHT = "\u00a9 Nullfinity \u2014 shared for review, do not redistribute"
REQ_TTL = 24 * 3600
SHARED_BY = "John Short"
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{40,64}$")
REPORT_RE = re.compile(r"^[A-Za-z0-9._-]+\.html$")
EMAIL_RE = re.compile(r"^[^@\s<>\"']{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
IP_LIMIT, IP_WINDOW = 5, 3600
A_RE = re.compile(r"^/a/([A-Za-z0-9_-]{1,80}?)(\.md|\.txt)?$")
LINK_DAY_LIMIT, LINK_PENDING_MAX = 10, 3
_ip_hits: dict = {}


def bind(mod):
    global S
    S = mod


def _f(name):
    return S.DATA / name


def _now():
    return time.time()


def audit(event, **kw):
    rec = {"ts": int(_now()), "event": event, **{k: (str(v)[:300] if v is not None else None) for k, v in kw.items()}}
    try:
        with open(_f("share_audit.jsonl"), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
        os.chmod(_f("share_audit.jsonl"), 0o600)
    except OSError:
        pass


def load():
    try:
        d = json.loads(_f("share_links.json").read_text("utf-8"))
    except (OSError, ValueError):
        d = {}
    d.setdefault("links", {}); d.setdefault("requests", {})
    return d


def save(d):
    S._atomic_write_json(_f("share_links.json"), d)


def _th(token):
    return hashlib.sha256(token.encode()).hexdigest()


def _rid(prefix):
    return prefix + "-" + "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(6))


def link_status(l, now=None):
    now = now or _now()
    if l.get("revoked_at"):
        return "revoked"
    if l.get("kind") == "ai":
        if now >= l["expires_at"]:
            return "expired"
        return "exhausted" if l.get("opens", 0) >= l.get("max_opens", AI_MAX_OPENS) else "active"
    if l.get("first_open_at"):
        return "active" if now < l["expires_at"] else "expired"
    return "unopened" if now < l["created_at"] + UNOPENED_TTL else "expired"


def report_path(name):
    if not REPORT_RE.match(name or ""):
        return None
    p = S.PORTAL_REPORTS_DIR / name
    return p if p.is_file() else None


def report_title(p):
    m = re.search(r"<title[^>]*>(.*?)</title>", p.read_text("utf-8", "replace")[:65536], re.I | re.S)
    return html.unescape(m.group(1)).strip()[:200] if m else p.stem


def base_url(host=None):
    return "https://" + (host if host in getattr(S, "PORTAL_HOSTS", set()) else "nullverse.cloud")


def create_link(report, by, parent=None, for_name=None, for_email=None, host=None):
    token = secrets.token_urlsafe(32)
    lid = _rid("SL")
    with _lock:
        d = load()
        d["links"][lid] = {"id": lid, "token_sha": _th(token), "report": report, "created_at": _now(),
                           "created_by": by, "parent": parent, "for_name": for_name, "for_email": for_email,
                           "first_open_at": None, "expires_at": None, "device_sha": None, "ip": None,
                           "ua": None, "extensions": 0, "revoked_at": None}
        save(d)
    audit("link_created", link_id=lid, report=report, by=by, parent=parent, for_name=for_name)
    return lid, f"{base_url(host)}/s/{token}"


def create_ai_link(report, by, ttl="24h", max_opens=AI_MAX_OPENS, host=None):
    secs = AI_TTLS.get(ttl, AI_TTLS["24h"])
    max_opens = max(1, min(int(max_opens or AI_MAX_OPENS), 1000))
    token = secrets.token_urlsafe(32)
    lid = _rid("SA")
    now = _now()
    with _lock:
        d = load()
        d["links"][lid] = {"id": lid, "kind": "ai", "token_sha": _th(token), "report": report, "created_at": now,
                           "created_by": by, "expires_at": now + secs, "ttl": ttl, "max_opens": max_opens,
                           "opens": 0, "extensions": 0, "revoked_at": None, "ip": None, "ua": None,
                           "first_open_at": None, "parent": None, "for_name": None, "for_email": None}
        save(d)
    audit("ai_link_created", link_id=lid, report=report, by=by, ttl=ttl, max_opens=max_opens)
    return lid, f"{base_url(host)}/a/{token}"


def find_by_token(token, kind="person"):
    if not TOKEN_RE.match(token or ""):
        return None
    h = _th(token)
    for l in load()["links"].values():
        if hmac.compare_digest(l["token_sha"], h) and (l.get("kind") or "person") == kind:
            return l
    return None


def extend_link(lid, by):
    with _lock:
        d = load(); l = d["links"].get(lid)
        if not l or l.get("revoked_at"):
            return None
        if l.get("kind") == "ai" or l.get("first_open_at"):
            l["expires_at"] = max(l["expires_at"], _now()) + LINK_TTL
        else:
            l["created_at"] = _now()
        l["extensions"] = l.get("extensions", 0) + 1
        save(d)
    audit("link_extended", link_id=lid, by=by)
    return l


def revoke_link(lid, by):
    with _lock:
        d = load(); l = d["links"].get(lid)
        if not l:
            return False
        l["revoked_at"] = l.get("revoked_at") or _now()
        save(d)
    audit("link_revoked", link_id=lid, by=by)
    return True


# ---- device cookie ----
def _cookie_name(h, lid):
    return ("__Host-nvs_" if h._is_https() else "nvs_") + lid.replace("-", "")


def _dev_sig(lid, dev):
    return hmac.new(S.session_secret(), f"share-device.{lid}.{dev}".encode(), hashlib.sha256).hexdigest()


def _device_from_cookie(h, lid):
    raw = h.headers.get("Cookie")
    if not raw:
        return None
    c = SimpleCookie()
    try:
        c.load(raw)
    except Exception:
        return None
    n = _cookie_name(h, lid)
    if n not in c:
        return None
    dev, _, sig = c[n].value.partition(".")
    if dev and sig and hmac.compare_digest(_dev_sig(lid, dev), sig):
        return dev
    return None


def _set_cookie(h, lid, dev):
    sec = "; Secure" if h._is_https() else ""
    return ("Set-Cookie", f"{_cookie_name(h, lid)}={dev}.{_dev_sig(lid, dev)}; Path=/; HttpOnly{sec}; "
                          f"SameSite=Lax; Max-Age={30 * 86400}")


def access(h, l):
    """Returns (state, link, extra_headers). state: ok|other_device|expired|revoked."""
    st = link_status(l)
    if st == "revoked":
        return "revoked", l, []
    dev = _device_from_cookie(h, l["id"])
    if st == "unopened":
        dev = secrets.token_urlsafe(18)
        with _lock:
            d = load(); cur = d["links"][l["id"]]
            if cur.get("first_open_at"):  # race: someone else won
                return ("ok" if False else "other_device"), cur, []
            now = _now()
            cur.update(first_open_at=now, expires_at=now + LINK_TTL, device_sha=_th(dev),
                       ip=S.client_ip(h), ua=(h.headers.get("User-Agent") or "")[:300])
            save(d)
        audit("link_registered", link_id=l["id"], ip=S.client_ip(h), ua=(h.headers.get("User-Agent") or "")[:120])
        return "ok", cur, [_set_cookie(h, l["id"], dev)]
    if not l.get("device_sha"):
        return "expired", l, []
    if not dev or not hmac.compare_digest(_th(dev), l["device_sha"]):
        audit("open_rejected_other_device", link_id=l["id"], ip=S.client_ip(h))
        return "other_device", l, []
    if st == "expired":
        audit("open_rejected_expired", link_id=l["id"], ip=S.client_ip(h))
        return "expired", l, []
    return "ok", l, []


# ---- requests ----
def _clean(v, n):
    v = re.sub(r"[\x00-\x1f\x7f]", " ", str(v or "")).strip()
    return v[:n]


def validate(kind, body):
    name, email, reason = _clean(body.get("name"), 80), _clean(body.get("email"), 254), _clean(body.get("reason"), 500)
    errs = {}
    if len(name) < 2: errs["name"] = "Enter your name."
    if not EMAIL_RE.match(email): errs["email"] = "Enter a valid email."
    if len(reason) < 5: errs["reason"] = "Give a short reason (5+ characters)."
    out = {"kind": kind, "name": name, "email": email, "reason": reason}
    if kind == "teammate":
        tn, te = _clean(body.get("teammate_name"), 80), _clean(body.get("teammate_email"), 254)
        if len(tn) < 2: errs["teammate_name"] = "Enter your teammate's name."
        if not EMAIL_RE.match(te): errs["teammate_email"] = "Enter your teammate's valid email."
        out.update(teammate_name=tn, teammate_email=te)
    return out, errs


def create_request(h, l, kind, body):
    if kind not in ("extend", "teammate", "access"):
        return 400, {"error": "bad_kind"}
    ip = S.client_ip(h)
    now = _now()
    with _lock:
        hits = [t for t in _ip_hits.get(ip, []) if now - t < IP_WINDOW]
        if len(hits) >= IP_LIMIT:
            audit("request_rate_limited", link_id=l["id"], ip=ip)
            return 429, {"error": "rate_limited", "message": "Too many requests. Try again later."}
        data, errs = validate(kind, body)
        if errs:
            return 400, {"error": "invalid", "fields": errs}
        d = load()
        mine = [r for r in d["requests"].values() if r["link_id"] == l["id"]]
        if sum(1 for r in mine if now - r["created_at"] < 86400) >= LINK_DAY_LIMIT or \
                sum(1 for r in mine if r["status"] == "pending") >= LINK_PENDING_MAX:
            audit("request_rate_limited", link_id=l["id"], ip=ip)
            return 429, {"error": "rate_limited", "message": "Too many open requests for this link."}
        hits.append(now); _ip_hits[ip] = hits
        rid, key = _rid("SR"), secrets.token_urlsafe(18)
        rec = {**data, "id": rid, "link_id": l["id"], "report": l["report"], "ip": ip,
               "ua": (h.headers.get("User-Agent") or "")[:200], "created_at": now, "status": "pending",
               "poll_sha": _th(key)}
        d["requests"][rid] = rec
        save(d)
    audit("request_created", request_id=rid, link_id=l["id"], kind=kind, name=data["name"], email=data["email"],
          reason=data["reason"], ip=ip, teammate=data.get("teammate_email"))
    notify_slack(rid)
    return 201, {"request_id": rid, "poll_key": key, "status": "pending"}


def request_status(l, rid, key):
    d = load(); r = d["requests"].get(rid)
    if not r or r["link_id"] != l["id"] or not key or not hmac.compare_digest(_th(key), r["poll_sha"]):
        return 404, {"error": "not_found"}
    st = r["status"]
    if st == "pending" and _now() - r["created_at"] > REQ_TTL:
        st = "expired"
    out = {"request_id": rid, "kind": r["kind"], "status": st}
    if st == "approved":
        if r["kind"] == "extend":
            out["expires_at"] = d["links"][l["id"]].get("expires_at")
        elif r.get("issued_url"):
            out["url"] = r["issued_url"]
    return 200, out


def decide(rid, approve, by):
    with _lock:
        d = load(); r = d["requests"].get(rid)
        if not r:
            return {"ok": False, "status": "unknown"}
        if r["status"] != "pending" or _now() - r["created_at"] > REQ_TTL:
            return {"ok": False, "status": r["status"] if r["status"] != "pending" else "expired", "req": r}
        r["status"] = "approved" if approve else "denied"
        r["decided_at"], r["decided_by"] = _now(), by
        save(d)
    if not approve:
        audit("request_denied", request_id=rid, by=by)
        return {"ok": True, "status": "denied", "req": r}
    if r["kind"] == "extend":
        l = extend_link(r["link_id"], by)
        audit("request_approved", request_id=rid, by=by, kind="extend")
        return {"ok": True, "status": "approved", "req": r, "expires_at": l and l.get("expires_at")}
    who = (r.get("teammate_name"), r.get("teammate_email")) if r["kind"] == "teammate" else (r["name"], r["email"])
    lid, url = create_link(r["report"], by, parent=r["link_id"], for_name=who[0], for_email=who[1])
    with _lock:
        d = load(); d["requests"][rid].update(issued_link=lid, issued_url=url); save(d)
    audit("request_approved", request_id=rid, by=by, kind=r["kind"], issued_link=lid)
    return {"ok": True, "status": "approved", "req": r, "url": url, "link_id": lid}


# ---- Slack ----
_KIND = {"extend": "24h extension", "teammate": "link for a teammate", "access": "access from another device"}


def _req_text(r):
    e = S._sesc
    t = (f":link: *Report share request* `{e(r['id'])}` — {e(_KIND.get(r['kind'], r['kind']))}\n"
         f"*Report:* {e(r['report'])}\n*From:* {e(r['name'])} ({e(r['email'])})\n*Reason:* {e(r['reason'])}\n")
    if r["kind"] == "teammate":
        t += f"*Teammate:* {e(r['teammate_name'])} ({e(r['teammate_email'])})\n"
    return t + f"*IP:* {e(r['ip'])}"


def req_blocks(r, outcome=None):
    b = [{"type": "section", "text": {"type": "mrkdwn", "text": _req_text(r)}}]
    if outcome is None:
        b.append({"type": "actions", "block_id": "share_req", "elements": [
            {"type": "button", "action_id": "share_approve", "style": "primary", "value": r["id"],
             "text": {"type": "plain_text", "text": "Approve"}},
            {"type": "button", "action_id": "share_deny", "style": "danger", "value": r["id"],
             "text": {"type": "plain_text", "text": "Deny"}}]})
    else:
        b.append({"type": "context", "elements": [{"type": "mrkdwn", "text": outcome}]})
    return b


def notify_slack(rid):
    def run():
        r = load()["requests"].get(rid)
        ch = S._slack_dm_channel()
        res = S.slack_call("chat.postMessage", {"channel": ch, "text": f"Report share request {rid}",
                                                "blocks": req_blocks(r)}) if ch else {"ok": False, "error": "dm_open_failed"}
        if res.get("ok"):
            with _lock:
                d = load(); d["requests"][rid].update(slack_channel=res.get("channel"), slack_ts=res.get("ts")); save(d)
            audit("slack_notified", request_id=rid)
        else:
            audit("slack_notify_failed", request_id=rid, error=str(res.get("error"))[:60])
    threading.Thread(target=run, daemon=True).start()


def slack_action(aid, val, by, channel, msg_ts):
    if aid not in ("share_approve", "share_deny") or not re.match(r"^SR-[A-Z0-9]{6}$", val):
        return {"ok": False, "error": "unsupported"}
    out = decide(val, aid == "share_approve", by)
    r = out.get("req")
    if out.get("ok") and out["status"] == "approved":
        if r["kind"] == "extend":
            line = (":white_check_mark: Approved — link extended to "
                    f"{time.strftime('%b %d %I:%M %p', time.localtime(out['expires_at']))} ET.")
        else:
            line = (f":white_check_mark: Approved — new single-device 24 h link (shown on their waiting page; "
                    f"forward if needed): {out['url']}")
    elif out.get("ok"):
        line = ":no_entry: Denied."
    else:
        line = f":hourglass: Already {out.get('status')}."
    ch = channel or (r or {}).get("slack_channel")
    ts = msg_ts or (r or {}).get("slack_ts")
    if r and ch and ts:
        S.slack_call("chat.update", {"channel": ch, "ts": ts, "text": f"Report share request {val}",
                                     "blocks": req_blocks(r, line)})
    return {"ok": out.get("ok", False), "status": out.get("status")}


# ---- PDF (owner only) ----
def render_pdf(p):
    cache = S.DATA / "pdf_cache"; cache.mkdir(exist_ok=True)
    out = cache / f"{p.stem}-{int(p.stat().st_mtime)}.pdf"
    if out.is_file() and out.stat().st_size > 0:
        return out
    with _pdf_lock:
        if out.is_file() and out.stat().st_size > 0:
            return out
        for old in cache.glob(p.stem + "-*.pdf"):
            old.unlink(missing_ok=True)
        with tempfile.TemporaryDirectory() as prof:
            tmp = out.with_suffix(".tmp")
            subprocess.run(["/usr/bin/google-chrome", "--headless=new", "--disable-gpu", "--no-first-run",
                            f"--user-data-dir={prof}", "--no-pdf-header-footer", "--virtual-time-budget=5000",
                            f"--print-to-pdf={tmp}", p.resolve().as_uri()],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=90, check=False)
            if not tmp.is_file() or tmp.stat().st_size == 0:
                raise RuntimeError("pdf_failed")
            tmp.replace(out)
    return out


# ---- HTML ----
SEC_HEADERS = [("X-Robots-Tag", "noindex, nofollow, noarchive"), ("Referrer-Policy", "no-referrer"),
               ("X-Frame-Options", "DENY"), ("X-Content-Type-Options", "nosniff")]


def _inject(doc, head_extra, body_top, body_end):
    if re.search(r"</head>", doc, re.I):
        doc = re.sub(r"</head>", lambda m: head_extra + m.group(0), doc, count=1, flags=re.I)
    else:
        doc = head_extra + doc
    m = re.search(r"<body[^>]*>", doc, re.I)
    doc = (doc[:m.end()] + body_top + doc[m.end():]) if m else body_top + doc
    if re.search(r"</body>", doc, re.I):
        doc = re.sub(r"</body>(?![\s\S]*</body>)", lambda m: body_end + m.group(0), doc, count=1, flags=re.I)
    else:
        doc += body_end
    return doc


BAR_CSS = """<style id="nvbar-css">
#nvbar{position:sticky;top:0;z-index:2147483000;font:14px/1.4 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
background:#0f1220;color:#eef;border-bottom:1px solid #2b3150;padding:10px 14px;box-sizing:border-box}
#nvbar *{box-sizing:border-box}#nvbar .row{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
#nvbar .grow{flex:1 1 200px;min-width:0}#nvbar b{color:#fff}
#nvbar button,#nvbar a.btn{font:inherit;border:1px solid #4b5bd6;background:#1c2350;color:#fff;border-radius:8px;
padding:7px 12px;cursor:pointer;text-decoration:none;display:inline-block}
#nvbar button.pri{background:#4b5bd6}#nvbar .cd{font-variant-numeric:tabular-nums;font-weight:600;color:#ffd479}
#nvbar form{display:none;margin-top:10px;gap:8px;flex-direction:column;max-width:520px}
#nvbar form.on{display:flex}#nvbar input,#nvbar textarea{font:inherit;width:100%;padding:8px;border-radius:6px;
border:1px solid #3a4170;background:#161a30;color:#fff}#nvbar textarea{min-height:60px}
#nvbar .msg{margin-top:8px;color:#9fe0b0}#nvbar .err{color:#ff9a9a;font-size:13px}
#nvbar .url{word-break:break-all;background:#161a30;padding:6px 8px;border-radius:6px;display:block;margin-top:6px}
#nvbar table{border-collapse:collapse;width:100%;margin-top:8px;font-size:13px}
#nvbar td,#nvbar th{border-bottom:1px solid #2b3150;padding:4px;text-align:left}
</style>"""


def owner_bar(report):
    r = html.escape(report)
    return BAR_CSS, f"""<div id="nvbar" data-report="{r}"><div class="row"><span class="grow"><b>Nullverse report</b></span>
<a class="btn" id="nv-pdf" href="/api/share/pdf/{r}">Download PDF</a>
<button class="pri" id="nv-share" type="button">Share link</button>
<span id="nv-pick" style="display:none;gap:6px;flex-wrap:wrap"><button type="button" id="nv-person">For a person (protected)</button>
<button type="button" id="nv-ai">For an AI</button><select id="nv-ttl" aria-label="AI link lifetime"><option>1h</option><option selected>24h</option><option>7d</option></select>
<input id="nv-max" type="number" min="1" max="1000" value="50" aria-label="Max opens" style="width:80px" title="Max opens"></span>
<a class="btn" href="/share-links">Manage links</a></div><div id="nv-out"></div></div>""", """<script>
(function(){var rep=document.getElementById('nvbar').dataset.report,o=document.getElementById('nv-out');
document.getElementById('nv-share').onclick=function(){var p=document.getElementById('nv-pick');p.style.display=p.style.display==='none'?'inline-flex':'none'};
document.getElementById('nv-person').onclick=function(){mk({report:rep})};
document.getElementById('nv-ai').onclick=function(){mk({report:rep,type:'ai',ttl:document.getElementById('nv-ttl').value,max_opens:+document.getElementById('nv-max').value||50})};
function mk(payload){o.textContent='Creating…';
fetch('/api/share/links',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
body:JSON.stringify(payload)}).then(function(r){return r.json()}).then(function(j){o.textContent='';
if(!j.url){o.textContent='Could not create link.';return}var d=document.createElement('div');d.className='msg';
d.textContent=j.type==='ai'?('AI link (no device lock; expires per lifetime, open cap applies). Markdown: '+j.markdown_url):'New link (registers to the first device that opens it; 24 h from first open):';
var u=document.createElement('code');u.className='url';u.textContent=j.url;var b=document.createElement('button');
b.textContent='Copy';b.type='button';b.onclick=function(){navigator.clipboard&&navigator.clipboard.writeText(j.url);b.textContent='Copied'};
o.appendChild(d);o.appendChild(u);o.appendChild(b)}).catch(function(){o.textContent='Could not create link.'})}})();
</script>"""


SHARED_JS = """<script>
(function(){var bar=document.getElementById('nvbar'),base=bar.dataset.base,exp=+bar.dataset.exp*1000,cd=document.getElementById('nv-cd');
function tick(){var s=Math.max(0,Math.floor((exp-Date.now())/1000));var h=Math.floor(s/3600),m=Math.floor(s%3600/60),x=s%60;
cd.textContent=s?(h+'h '+(m<10?'0':'')+m+'m '+(x<10?'0':'')+x+'s'):'expired';if(!s&&!bar.dataset.reloaded){bar.dataset.reloaded=1;setTimeout(function(){location.reload()},1500)}}
setInterval(tick,1000);tick();
setInterval(function(){fetch(base+'/status',{credentials:'same-origin',cache:'no-store'}).then(function(r){return r.json()}).then(function(j){if(j.expires_at)exp=j.expires_at*1000})},30000);
document.querySelectorAll('#nvbar [data-open]').forEach(function(b){b.onclick=function(){document.querySelectorAll('#nvbar form').forEach(function(f){f.classList.toggle('on',f.id===b.dataset.open&&!f.classList.contains('on'))})}});
document.querySelectorAll('#nvbar form').forEach(function(f){f.onsubmit=function(e){e.preventDefault();var data={};new FormData(f).forEach(function(v,k){data[k]=v});
var out=f.querySelector('.res');out.className='res msg';out.textContent='Sending…';f.querySelectorAll('.err').forEach(function(x){x.textContent=''});
fetch(base+'/request',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)}).then(function(r){return r.json().then(function(j){return[r.status,j]})}).then(function(a){var j=a[1];
if(a[0]!==201){out.className='res err';out.textContent=j.message||'Please fix the highlighted fields.';Object.keys(j.fields||{}).forEach(function(k){var x=f.querySelector('[data-err='+k+']');if(x)x.textContent=j.fields[k]});return}
f.querySelector('button[type=submit]').disabled=true;out.textContent='Request sent to John. Waiting for approval… (keep this page open)';
var iv=setInterval(function(){fetch(base+'/request/'+j.request_id+'?key='+encodeURIComponent(j.poll_key),{cache:'no-store'}).then(function(r){return r.json()}).then(function(s){
if(s.status==='pending')return;clearInterval(iv);if(s.status==='approved'){if(s.expires_at){exp=s.expires_at*1000;out.textContent='Approved — this link now has another 24 hours.'}
else if(s.url){out.textContent='Approved. Single-device link (works on the first device that opens it, 24 h): ';var c=document.createElement('code');c.className='url';c.textContent=s.url;out.appendChild(c)}}
else{out.className='res err';out.textContent='Request '+s.status+'.'}})},5000)}).catch(function(){out.className='res err';out.textContent='Could not send. Try again.'})}})})();
</script>"""


def _form(fid, title, kind, teammate):
    fields = ""
    if teammate:
        fields += ('<input name="teammate_name" placeholder="Teammate\'s name" maxlength="80" required><span class="err" data-err="teammate_name"></span>'
                   '<input name="teammate_email" type="email" placeholder="Teammate\'s email" maxlength="254" required><span class="err" data-err="teammate_email"></span>')
    return (f'<form id="{fid}"><b>{title}</b><input type="hidden" name="kind" value="{kind}">'
            '<input name="name" placeholder="Your name" maxlength="80" required><span class="err" data-err="name"></span>'
            '<input name="email" type="email" placeholder="Your email" maxlength="254" required><span class="err" data-err="email"></span>'
            f'{fields}<textarea name="reason" placeholder="Reason" maxlength="500" required></textarea><span class="err" data-err="reason"></span>'
            '<button class="pri" type="submit">Send request</button><div class="res"></div></form>')


def shared_bar(l, base):
    head = BAR_CSS + '<meta name="robots" content="noindex,nofollow,noarchive"><meta name="referrer" content="no-referrer">'
    top = (f'<div id="nvbar" data-base="{html.escape(base)}" data-exp="{int(l["expires_at"])}">'
           f'<div class="row"><span class="grow"><b>{html.escape(SHARED_BY)}</b> shared this report with you. '
           'This link works only on this device and expires 24 hours after it was first opened. '
           'Time left: <span class="cd" id="nv-cd">…</span></span></div>'
           '<div class="row" style="margin-top:8px"><button type="button" data-open="f-ext">Request 24h extension</button>'
           '<button type="button" data-open="f-team">Request link for a teammate</button></div>'
           + _form("f-ext", "Request a 24-hour extension", "extend", False)
           + _form("f-team", "Request a link for a teammate", "teammate", True) + '</div>')
    who = " ".join(x for x in (l.get("for_name"), l.get("for_email")) if x) or f"{l['id']} {l.get('ip') or ''}"
    label = (l.get("for_name") or l["id"])[:60]
    return (head + DETER_CSS + scroll_css(label), DETER_HTML + top + scroll_open(label),
            SCROLL_CLOSE + SHARED_JS + DETER_JS.replace("__WHO__", json.dumps(who[:120])) + SCROLL_JS)


def page(title, body_html, base=None, form_kind=None):
    form = ""
    if base and form_kind:
        form = (f'<div id="nvbar" data-base="{html.escape(base)}" data-exp="0" style="position:static">'
                '<span id="nv-cd" style="display:none"></span>'
                + _form("f-x", "Request access", form_kind, False).replace('<form id="f-x">', '<form id="f-x" class="on">')
                + '</div>' + SHARED_JS.replace("setInterval(tick,1000);tick();", "").replace(
                    "setInterval(function(){fetch(base+'/status'", "0&&setInterval(function(){fetch(base+'/status'"))
    return (f'<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<meta name="robots" content="noindex,nofollow"><title>{html.escape(title)}</title>{BAR_CSS}'
            '<style>body{margin:0;background:#0b0d18;color:#eef;font:15px/1.5 system-ui,sans-serif}main{max-width:560px;margin:40px auto;padding:0 16px}</style>'
            f'</head><body><main><h1>{html.escape(title)}</h1>{body_html}{form}</main></body></html>').encode()


# ---- HTTP dispatch ----
def handle(h, method, path, qs) -> bool:
    if method == "GET" and path.startswith("/reports/"):
        return _owner_report(h, path[len("/reports/"):])
    if path.startswith("/api/share/") or path == "/share-links":
        return _owner_api(h, method, path, qs)
    m = A_RE.match(path)
    if m and method == "GET":
        return _ai(h, m.group(1), m.group(2), qs)
    if path.startswith("/a/"):
        h._json(404, {"error": "not_found"}); return True
    m = re.match(r"^/s/([A-Za-z0-9_-]{1,80})(/.*)?$", path)
    if m:
        return _shared(h, method, m.group(1), m.group(2) or "", qs)
    return False


def _owner_report(h, name):
    if not S.verify_session(h._cookie_token()):
        h._send(302, b"", extra_headers=[("Location", "/?next=" + urllib.parse.quote("/reports/" + name, safe="/"))])
        return True
    p = report_path(name)
    if not p:
        h._json(404, {"error": "not_found"}); return True
    doc = p.read_text("utf-8", "replace")
    rec = S.get_session(h._cookie_token()) or {}
    if rec.get("method") != "guest":
        doc = _inject(doc, *owner_bar(name))
    h._send(200, doc.encode(), "text/html; charset=utf-8", SEC_HEADERS)
    return True


def _owner_api(h, method, path, qs):
    if h._guest_gate(method, path):
        return True
    rec = h._require_owner()
    if rec is None:
        return True
    by = "owner:" + str(rec.get("id"))
    m = re.match(r"^/api/share/pdf/([A-Za-z0-9._-]+\.html)$", path)
    if m and method == "GET":
        p = report_path(m.group(1))
        if not p:
            h._json(404, {"error": "not_found"}); return True
        try:
            pdf = render_pdf(p)
        except Exception as e:  # noqa: BLE001
            audit("pdf_failed", report=p.name, error=type(e).__name__)
            h._json(500, {"error": "pdf_failed"}); return True
        audit("pdf_downloaded", report=p.name, by=by)
        h._send(200, pdf.read_bytes(), "application/pdf",
                [("Content-Disposition", f'attachment; filename="{p.stem}.pdf"')])
        return True
    if path == "/share-links" and method == "GET":
        h._send(200, (S.STATIC / "share-links.html").read_bytes(), "text/html; charset=utf-8", SEC_HEADERS)
        return True
    if path == "/api/share/links" and method == "GET":
        d = load(); now = _now()
        rows = []
        for l in sorted(d["links"].values(), key=lambda x: -x["created_at"]):
            rows.append({k: l.get(k) for k in ("id", "kind", "ttl", "opens", "max_opens", "report", "created_at", "created_by", "parent", "for_name",
                                                "for_email", "first_open_at", "expires_at", "ip", "ua", "extensions",
                                                "revoked_at")} | {"status": link_status(l, now)})
        rep = (qs.get("report") or [""])[0]
        if rep:
            rows = [r for r in rows if r["report"] == rep]
        reqs = [{k: r.get(k) for k in ("id", "link_id", "report", "kind", "name", "email", "reason", "teammate_name",
                                       "teammate_email", "ip", "created_at", "status", "decided_at")}
                for r in sorted(d["requests"].values(), key=lambda x: -x["created_at"])[:200]]
        h._json(200, {"links": rows, "requests": reqs}); return True
    if path == "/api/share/links" and method == "POST":
        body = h._read_json()
        rep = str(body.get("report") or "")
        if not report_path(rep):
            h._json(400, {"error": "unknown_report"}); return True
        if body.get("type") == "ai":
            ttl = str(body.get("ttl") or "24h")
            if ttl not in AI_TTLS:
                h._json(400, {"error": "bad_ttl"}); return True
            try:
                mo = int(body.get("max_opens") or AI_MAX_OPENS)
            except (TypeError, ValueError):
                h._json(400, {"error": "bad_max_opens"}); return True
            lid, url = create_ai_link(rep, by, ttl, mo, host=getattr(h, "req_host", None))
            h._json(201, {"id": lid, "url": url, "type": "ai", "markdown_url": url + ".md",
                          "text_url": url + "?format=text"}); return True
        lid, url = create_link(rep, by, host=getattr(h, "req_host", None))
        h._json(201, {"id": lid, "url": url, "type": "person"}); return True
    m = re.match(r"^/api/share/links/(S[LA]-[A-Z0-9]{6})/(revoke|extend)$", path)
    if m and method == "POST":
        ok = revoke_link(m.group(1), by) if m.group(2) == "revoke" else bool(extend_link(m.group(1), by))
        h._json(200 if ok else 404, {"ok": ok}); return True
    if path == "/api/share/audit" and method == "GET":
        rows = []
        try:
            lines = _f("share_audit.jsonl").read_text("utf-8").splitlines()[-500:]
            rows = [json.loads(x) for x in reversed(lines) if x.strip()]
        except (OSError, ValueError):
            pass
        h._json(200, {"rows": rows}); return True
    h._json(404, {"error": "not_found"}); return True


def _shared(h, method, token, sub, qs):
    l = find_by_token(token)
    base = "/s/" + token
    hdrs = SEC_HEADERS
    if not l:
        audit("open_rejected_unknown", ip=S.client_ip(h))
        h._send(404, page("Link not found", "<p>This share link is not valid.</p>"), "text/html; charset=utf-8", hdrs)
        return True
    if sub == "/pdf":
        audit("pdf_rejected_share", link_id=l["id"], ip=S.client_ip(h))
        h._json(403, {"error": "forbidden"}); return True
    st, l, extra = access(h, l) if not (method == "POST" and sub == "/request") else (None, l, [])
    if method == "POST" and sub == "/request":
        st, l, extra = _peek(h, l)
        body = h._read_json()
        kind = str(body.get("kind") or "")
        allowed = {"ok": ("extend", "teammate"), "expired": ("extend",), "other_device": ("access",)}.get(st, ())
        if kind not in allowed:
            h._json(403, {"error": "not_allowed"}); return True
        code, out = create_request(h, l, kind, body)
        h._json(code, out); return True
    if method != "GET":
        h._json(405, {"error": "method"}); return True
    m = re.match(r"^/request/(SR-[A-Z0-9]{6})$", sub)
    if m:
        code, out = request_status(l, m.group(1), (qs.get("key") or [""])[0])
        h._json(code, out); return True
    if sub == "/status":
        h._json(200 if st == "ok" else 403, {"state": st, "expires_at": l.get("expires_at") if st == "ok" else None})
        return True
    if sub:
        h._json(404, {"error": "not_found"}); return True
    if st == "ok":
        p = report_path(l["report"])
        if not p:
            h._send(410, page("Report unavailable", "<p>This report is no longer available.</p>"), "text/html; charset=utf-8", hdrs)
            return True
        audit("link_opened", link_id=l["id"], ip=S.client_ip(h))
        doc = _inject(p.read_text("utf-8", "replace"), *shared_bar(l, base))
        h._send(200, doc.encode(), "text/html; charset=utf-8", hdrs + extra)
    elif st == "other_device":
        h._send(403, page("This link is registered to another device",
                          "<p>Share links work only on the first device that opens them. Ask John for your own link below.</p>",
                          base, "access"), "text/html; charset=utf-8", hdrs)
    elif st == "expired":
        mine = _device_from_cookie(h, l["id"]) and l.get("device_sha")
        h._send(410, page("This link has expired", "<p>Share links last 24 hours from first open.</p>",
                          base if mine else None, "extend"), "text/html; charset=utf-8", hdrs)
    else:
        h._send(410, page("This link was revoked", "<p>The owner turned this link off.</p>"), "text/html; charset=utf-8", hdrs)
    return True


def _peek(h, l):
    """Device state without registering an unopened link."""
    st = link_status(l)
    if st in ("revoked", "unopened"):
        return st, l, []
    dev = _device_from_cookie(h, l["id"])
    if not dev or not l.get("device_sha") or not hmac.compare_digest(_th(dev), l["device_sha"]):
        return "other_device", l, []
    return st if st == "expired" else "ok", l, []


# ---- shared-view deterrents (not guarantees) ----
DETER_CSS = """<style id="nvdet-css">
html,body{-webkit-user-select:none!important;user-select:none!important;-webkit-touch-callout:none!important}
img,a{-webkit-user-drag:none!important}
#nvbar input,#nvbar textarea{-webkit-user-select:text!important;user-select:text!important}
.nvwm{position:fixed!important;inset:0!important;pointer-events:none!important;z-index:2147482000!important;
opacity:.09!important;display:block!important;overflow:hidden!important;mix-blend-mode:normal}
#nvpf{position:fixed;inset:0;z-index:2147483647;background:#0b0d18 radial-gradient(circle at 50% 40%,#1c2350,#0b0d18 70%);
color:#eef;display:none;align-items:center;justify-content:center;flex-direction:column;text-align:center;
font:600 26px/1.3 system-ui,sans-serif}#nvpf small{font:400 14px system-ui,sans-serif;color:#aab;margin-top:8px}
#nvpf.on{display:flex!important}
@media print{body>*{display:none!important}body::before{content:"Printing disabled";display:block!important;
font:600 28px system-ui,sans-serif;padding:40px;color:#000}}
</style>"""
DETER_HTML = '<div id="nvpf" aria-hidden="true">Privacy filter<small>Return to this tab to continue reading</small></div>'
DETER_JS = """<script>
(function(){var who=__WHO__;
function svg(){var t=(who+' · '+new Date().toLocaleString()).replace(/[<&>]/g,'');
var s='<svg xmlns="http://www.w3.org/2000/svg" width="420" height="220"><text x="10" y="150" transform="rotate(-25 210 110)" font-family="sans-serif" font-size="15" fill="#888">'+t+'</text></svg>';
return 'url("data:image/svg+xml;charset=utf-8,'+encodeURIComponent(s)+'")'}
var ids=['nvwm-a','nvwm-b','nvwm-c'];
function put(){var bg=svg();ids.forEach(function(id,i){var e=document.getElementById(id);
if(!e){e=document.createElement('div');e.id=id;e.className='nvwm';(i===1?document.documentElement:document.body).appendChild(e)}
e.style.setProperty('background-image',bg,'important');e.style.setProperty('background-position',(i*140)+'px '+(i*70)+'px','important');
e.style.setProperty('display','block','important');e.style.setProperty('pointer-events','none','important')});
if(!document.getElementById('nvdet-css')&&window.__nvcss)document.head.appendChild(window.__nvcss.cloneNode(true))}
window.__nvcss=document.getElementById('nvdet-css').cloneNode(true);
put();setInterval(put,30000);
new MutationObserver(function(){var bad=ids.some(function(id){var e=document.getElementById(id);return !e||getComputedStyle(e).display==='none'||+getComputedStyle(e).opacity<.05});
if(bad||!document.getElementById('nvdet-css')||!document.getElementById('nvpf'))put()}).observe(document.documentElement,{childList:true,subtree:true,attributes:true,attributeFilter:['style','class']});
['contextmenu','dragstart','copy','cut','selectstart'].forEach(function(ev){document.addEventListener(ev,function(e){
if(e.target&&e.target.closest&&e.target.closest('#nvbar input,#nvbar textarea'))return;e.preventDefault()},true)});
document.addEventListener('keydown',function(e){var k=(e.key||'').toLowerCase();if((e.ctrlKey||e.metaKey)&&(k==='p'||k==='s')){e.preventDefault();e.stopPropagation()}},true);
window.addEventListener('beforeprint',function(){document.body.style.visibility='hidden'});
window.addEventListener('afterprint',function(){document.body.style.visibility=''});
var pf=document.getElementById('nvpf');function show(){pf.classList.add('on')}function hide(){if(location.hash==='#nvpf-demo')return;if(!document.hidden&&document.hasFocus())pf.classList.remove('on')}
document.addEventListener('visibilitychange',function(){document.hidden?show():hide()});
window.addEventListener('blur',show);window.addEventListener('pagehide',show);window.addEventListener('focus',hide);window.addEventListener('pageshow',hide);
if(location.hash==='#nvpf-demo')show();})();
</script>"""


# ---- two-way scroll viewport + copyright scrollbars/bands (shared view only) ----
def _svg_uri(text, w, h, vertical=False, fill="#c9d0ff", bg="#151a33", size=10):
    t = html.escape(text)
    if vertical:
        body = (f'<rect width="{w}" height="{h}" fill="{bg}"/><text transform="translate({w * 0.72:.1f},{h - 4}) rotate(-90)" '
                f'font-family="sans-serif" font-size="{size}" fill="{fill}">{t}</text>')
    else:
        body = (f'<rect width="{w}" height="{h}" fill="{bg}"/><text x="4" y="{h * 0.72:.1f}" font-family="sans-serif" '
                f'font-size="{size}" fill="{fill}">{t}</text>')
    svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}">{body}</svg>'
    return 'url("data:image/svg+xml;charset=utf-8,' + urllib.parse.quote(svg, safe="") + '")'


def copyright_text(label):
    return f"\u00a9 Nullfinity \u00b7 Confidential \u00b7 {label}"


def scroll_css(label):
    t = copyright_text(label) + "   "
    tw = 9 + len(t) * 6
    h_tr = _svg_uri(t, tw, 16)
    v_tr = _svg_uri(t, 16, tw, vertical=True)
    h_th = _svg_uri(t, tw, 16, fill="#ffffff", bg="#4b5bd6")
    v_th = _svg_uri(t, 16, tw, vertical=True, fill="#ffffff", bg="#4b5bd6")
    band_h = _svg_uri(t, tw, 14, fill="#d7dcff", bg="#0f1220", size=9)
    band_v = _svg_uri(t, 14, tw, vertical=True, fill="#d7dcff", bg="#0f1220", size=9)
    return f"""<style id="nvscroll-css">
html,body{{height:100%!important;overflow:hidden!important}}
#nvbar{{position:relative!important}}
#nvscroll{{position:fixed!important;left:0;right:0;bottom:0;top:var(--nvtop,120px);overflow:scroll!important;
-webkit-overflow-scrolling:touch;overscroll-behavior:contain;padding:14px 0 0 14px;box-sizing:border-box}}
#nvcontent{{width:max(160vw,1400px);min-height:max(170vh,1600px);box-sizing:border-box;padding:0 24px 40px}}
#nvcontent>*{{max-width:none!important}}
#nvscroll::-webkit-scrollbar{{width:16px;height:16px}}
#nvscroll::-webkit-scrollbar-track:horizontal{{background:{h_tr} repeat-x}}
#nvscroll::-webkit-scrollbar-track:vertical{{background:{v_tr} repeat-y}}
#nvscroll::-webkit-scrollbar-thumb:horizontal{{background:{h_th} repeat-x;border-radius:8px;min-width:60px}}
#nvscroll::-webkit-scrollbar-thumb:vertical{{background:{v_th} repeat-y;border-radius:8px;min-height:60px}}
#nvscroll::-webkit-scrollbar-corner{{background:#0f1220}}
@supports (-moz-appearance:none){{#nvscroll{{scrollbar-color:#4b5bd6 #151a33;scrollbar-width:auto}}}}
.nvcb{{position:fixed!important;z-index:2147482500!important;pointer-events:none!important;display:block!important}}
#nvcb-top{{left:0;right:16px;top:var(--nvtop,120px);height:14px;background:{band_h} repeat-x}}
#nvcb-left{{left:0;width:14px;top:var(--nvtop,120px);bottom:16px;background:{band_v} repeat-y}}
#nvcb-bottom{{left:0;right:16px;bottom:16px;height:14px;background:{band_h} repeat-x;opacity:.9}}
@media print{{body::before{{content:"Printing disabled\\A {html.escape(copyright_text(label)).replace('"', '')}"!important;white-space:pre!important}}}}
</style>"""


def scroll_open(label):
    return ('<div class="nvcb" id="nvcb-top"></div><div class="nvcb" id="nvcb-left"></div>'
            '<div class="nvcb" id="nvcb-bottom"></div><div id="nvscroll"><div id="nvcontent">')


SCROLL_CLOSE = "</div></div>"
SCROLL_JS = """<script>
(function(){var bar=document.getElementById('nvbar');function set(){document.documentElement.style.setProperty('--nvtop',bar.offsetHeight+'px')}
set();window.addEventListener('resize',set);if(window.ResizeObserver)new ResizeObserver(set).observe(bar);
var keep=['nvcb-top','nvcb-left','nvcb-bottom'],css=document.getElementById('nvscroll-css').cloneNode(true),tpl={};
keep.forEach(function(id){tpl[id]=document.getElementById(id).cloneNode(true)});
new MutationObserver(function(){keep.forEach(function(id){var e=document.getElementById(id);
if(!e||getComputedStyle(e).display==='none'){if(e)e.remove();document.body.appendChild(tpl[id].cloneNode(true))}});
if(!document.getElementById('nvscroll-css'))document.head.appendChild(css.cloneNode(true))}).observe(document.documentElement,{childList:true,subtree:true,attributes:true,attributeFilter:['style','class']});
})();
</script>"""


# ---- AI share links (/a/<token>, .md, ?format=text) ----
from html.parser import HTMLParser


class _MD(HTMLParser):
    BLOCK = {"p", "div", "section", "article", "header", "footer", "main", "table", "tr", "br", "ul", "ol", "blockquote"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out, self.skip, self.href, self.pre = [], 0, None, 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("script", "style", "noscript", "svg", "head", "title"):
            self.skip += 1; return
        if self.skip:
            return
        if re.fullmatch(r"h[1-6]", tag):
            self.out.append("\n\n" + "#" * int(tag[1]) + " ")
        elif tag == "li":
            self.out.append("\n- ")
        elif tag in ("td", "th"):
            self.out.append(" | ")
        elif tag == "pre":
            self.pre += 1; self.out.append("\n\n```\n")
        elif tag == "code" and not self.pre:
            self.out.append("`")
        elif tag in ("strong", "b"):
            self.out.append("**")
        elif tag == "a":
            self.href = a.get("href"); self.out.append("[")
        elif tag in self.BLOCK:
            self.out.append("\n\n" if tag != "br" else "\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript", "svg", "head", "title"):
            self.skip = max(0, self.skip - 1); return
        if self.skip:
            return
        if tag == "pre":
            self.pre = max(0, self.pre - 1); self.out.append("\n```\n\n")
        elif tag == "code" and not self.pre:
            self.out.append("`")
        elif tag in ("strong", "b"):
            self.out.append("**")
        elif tag == "a":
            self.out.append(f"]({self.href})" if self.href and not self.href.startswith("javascript:") else "]")
            self.href = None
        elif re.fullmatch(r"h[1-6]", tag) or tag in self.BLOCK:
            self.out.append("\n")

    def handle_data(self, data):
        if self.skip:
            return
        self.out.append(data if self.pre else re.sub(r"\s+", " ", data))


def report_markdown(p):
    m = _MD(); m.feed(p.read_text("utf-8", "replace"))
    text = "".join(m.out)
    text = re.sub(r"[ \t]+\n", "\n", text); text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return f"{AI_COPYRIGHT}\n\nSource: {report_title(p)}\n\n{text}\n"


AI_CSS = """<style id="nvai-css">#nvai{font:13px/1.4 system-ui,sans-serif;background:#0f1220;color:#eef;padding:8px 14px;
border-bottom:1px solid #2b3150}</style>"""


def _ai(h, token, ext, qs):
    l = find_by_token(token, "ai")
    ip, ua = S.client_ip(h), (h.headers.get("User-Agent") or "")[:200]
    hdr = SEC_HEADERS
    if not l:
        audit("ai_fetch_rejected", reason="unknown", ip=ip, ua=ua)
        h._send(404, b"Not found\n", "text/plain; charset=utf-8", hdr); return True
    fmt = "md" if ext in (".md",) else "text" if ext == ".txt" else ((qs.get("format") or ["html"])[0] or "html")
    if fmt not in ("html", "text", "md", "markdown"):
        fmt = "html"
    with _lock:
        d = load(); cur = d["links"][l["id"]]
        st = link_status(cur)
        if st == "active":
            cur["opens"] = cur.get("opens", 0) + 1
            cur["first_open_at"] = cur.get("first_open_at") or _now()
            cur["ip"], cur["ua"] = ip, ua
            save(d)
    if st != "active":
        audit("ai_fetch_rejected", link_id=l["id"], reason=st, ip=ip, ua=ua)
        h._send(410, f"This AI share link is {st}.\n".encode(), "text/plain; charset=utf-8", hdr); return True
    audit("ai_fetch", link_id=l["id"], fmt=fmt, ip=ip, ua=ua, opens=cur["opens"])
    p = report_path(l["report"])
    if not p:
        h._send(410, b"Report unavailable\n", "text/plain; charset=utf-8", hdr); return True
    if fmt == "html":
        doc = _inject(p.read_text("utf-8", "replace"),
                      AI_CSS + '<meta name="robots" content="noindex,nofollow,noarchive"><meta name="referrer" content="no-referrer">',
                      f'<div id="nvai">{html.escape(AI_COPYRIGHT)}</div>', "")
        h._send(200, doc.encode(), "text/html; charset=utf-8", hdr)
    else:
        ct = "text/markdown; charset=utf-8" if fmt in ("md", "markdown") else "text/plain; charset=utf-8"
        h._send(200, report_markdown(p).encode(), ct, hdr)
    return True
