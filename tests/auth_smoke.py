#!/usr/bin/env python3
"""HTTP-level auth smoke test against a RUNNING Nullink (staging or live).

  staging (on the VPS, simulating Caddy headers):
    python3 tests/auth_smoke.py --mode staging --base http://127.0.0.1:8796 --pin-via-admin
  live (from anywhere, internet, safe read-only subset + 2 harmless failed attempts):
    python3 tests/auth_smoke.py --mode live [--cookie-file F] [--bearer-file F]

Never prints cookies, tokens or PINs.
"""
import argparse
import json
import ssl
import sys
import urllib.error
import urllib.request

HOSTS = ["nullink.216.158.238.236.sslip.io", "nullink.nullverse.cloud", "nullverse.cloud"]
RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail and not cond else ""))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


OPENER = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ssl.create_default_context()))


def call(url, method="GET", body=None, headers=None, host=None, read=True, timeout=15):
    h = dict(headers or {})
    if host:
        h["Host"] = host
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        r = OPENER.open(req, timeout=timeout)
        status, hdrs = r.status, r.headers
        raw = r.read(65536) if read else b""
    except urllib.error.HTTPError as e:
        status, hdrs, raw = e.code, e.headers, e.read()
    try:
        js = json.loads(raw) if raw else {}
    except ValueError:
        js = {}
    return status, hdrs, js, raw


def live(args):
    for host in HOSTS:
        base = f"https://{host}"
        st, hd, _, html = call(base + "/")
        check(f"{host} GET / 200", st == 200, st)
        check(f"{host} HSTS max-age=31536000", "max-age=31536000" in (hd.get("Strict-Transport-Security") or ""),
              hd.get("Strict-Transport-Security"))
        check(f"{host} UI has PIN form + sign-out-everywhere, no Fill login",
              b'id="pin-form"' in html and b'logout-all-btn' in html and b"btn-apps-fill" not in html)
        st, _, js, _ = call(base + "/api/auth/method")
        check(f"{host} /api/auth/method 200", st == 200 and "totp_enabled" in js, st)
        for path in ("/api/admin/set-otp", "/api/admin/reply", "/api/files/register"):
            st, *_ = call(base + path, "POST", {"pin": "x"})
            check(f"{host} POST {path} -> 403", st == 403, st)
        st, *_ = call(base + "/api/me", headers={"Cookie": "morc_session=ok:9999999999.deadbeef"})
        check(f"{host} legacy cookie rejected", st == 401 or (host == "nullverse.cloud" and st == 401), st)
        st, *_ = call(base + "/api/me", headers={"Cookie": "__Host-nullink_session=v2." + "A" * 43 + "." + "0" * 64})
        check(f"{host} forged v2 cookie rejected", st == 401, st)
    base = "https://nullink.216.158.238.236.sslip.io"
    st, *_ = call(base + "/api/desktop/credentials")
    check("desktop/credentials unauthenticated -> 401", st == 401, st)
    st, hd, _, _ = call("https://nullverse.cloud/projects")
    check("portal /projects without session -> 302 /", st == 302 and hd.get("Location") == "/", st)
    # Spoofed XFF lands in the same (real-IP) bucket: two failures, counter drops by one each time.
    bad = "ZZZZZ-ZZZZZ"
    st1, _, j1, _ = call(base + "/api/auth/verify", "POST", {"code": bad}, headers={"X-Forwarded-For": "10.1.1.1"})
    st2, _, j2, _ = call(base + "/api/auth/verify", "POST", {"code": bad}, headers={"X-Forwarded-For": "10.2.2.2, 8.8.8.8"})
    ok = st1 == 401 and st2 == 401 and j2.get("attempts_left") == j1.get("attempts_left", 0) - 1
    check("spoofed X-Forwarded-For cannot pick a fresh bucket", ok, f"{st1},{j1.get('attempts_left')} {st2},{j2.get('attempts_left')}")
    if args.cookie_file:
        val = open(args.cookie_file).read().strip()
        ck = {"Cookie": f"__Host-nullink_session={val}"}
        st, _, js, _ = call(base + "/api/me", headers=ck)
        check("temp session /api/me 200", st == 200 and js.get("auth_type") == "session", st)
        st, _, js, _ = call(base + "/api/desktop/launch", headers=ck)
        check("desktop launch works (auto sign-in URL)", st == 200 and str(js.get("embedUrl", "")).startswith("/desktop/"), st)
        st, _, js, _ = call(base + "/api/desktop/credentials", headers=ck)
        check("desktop/credentials -> 410, no password", st == 410 and "password" not in js, st)
        st, _, js, _ = call(base + "/api/auth/tokens", "POST", {"name": "should-not-exist", "sessions": ["chatgpt"]}, headers=ck)
        check("token create needs step-up (stale session)", st == 403 and js.get("error") == "step_up_required", st)
        st, _, js, _ = call(base + "/api/auth/totp/disable", "POST", {"code": "000000"}, headers=ck)
        check("TOTP disable needs step-up", st == 403 and js.get("error") == "step_up_required", st)
        st, hd, _, _ = call(base + "/api/auth/logout", "POST", headers=ck)
        check("logout 200", st == 200, st)
        st, *_ = call(base + "/api/me", headers=ck)
        check("copied cookie revoked after logout", st == 401, st)
    if args.bearer_file:
        tok = open(args.bearer_file).read().strip()
        bh = {"Authorization": f"Bearer {tok}"}
        st, _, js, _ = call(base + "/api/me", headers=bh)
        check("bearer /api/me 200", st == 200 and js.get("auth_type") == "bearer", st)
        st, *_ = call(base + "/api/messages?session=chatgpt&limit=1", headers=bh)
        check("bearer GET messages (chatgpt) 200", st == 200, st)
        st, *_ = call(base + "/api/messages?session=morc&limit=1", headers=bh)
        check("bearer scoped: morc session 403", st == 403, st)
        st, hd, _, _ = call(base + "/api/messages/stream?session=chatgpt&after=999999999", headers=bh, read=False)
        check("bearer SSE stream 200 event-stream", st == 200 and "event-stream" in (hd.get("Content-Type") or ""), st)


def staging(args):
    base = args.base.rstrip("/")
    caddy = lambda ip: {"X-Forwarded-For": ip, "X-Forwarded-Proto": "https", "Host": HOSTS[0]}
    # local admin (no proxy headers) works; with proxy headers it is refused
    st, _, js, _ = call(base + "/api/admin/set-otp", "POST", {"pin": "x"})
    check("staging admin local -> 400 invalid_pin", st == 400 and js.get("error") == "invalid_pin", st)
    st, *_ = call(base + "/api/admin/set-otp", "POST", {"pin": "x"}, headers={"X-Forwarded-For": "127.0.0.1"})
    check("staging admin with XFF -> 403", st == 403, st)
    st, *_ = call(base + "/api/admin/set-otp", "POST", {"pin": "x"}, headers={"X-Forwarded-Host": "localhost"})
    check("staging admin with X-Forwarded-Host -> 403", st == 403, st)
    pin = "314159"
    st, _, js, _ = call(base + "/api/admin/set-otp", "POST", {"pin": pin, "ttl_sec": 600})
    check("staging set test PIN via local admin", st == 200 and js.get("single_use"), st)
    st, hd, js, _ = call(base + "/api/auth/verify", "POST", {"code": pin}, headers=caddy("198.51.100.50"))
    cookies = hd.get_all("Set-Cookie") or []
    sess = [c for c in cookies if c.startswith("__Host-nullink_session=") and "Max-Age=86400" in c]
    check("staging PIN login 200 + __Host- Secure HttpOnly cookie",
          st == 200 and sess and "Secure" in sess[0] and "HttpOnly" in sess[0], st)
    ck = {"Cookie": sess[0].split(";")[0]} if sess else {}
    st, *_ = call(base + "/api/auth/verify", "POST", {"code": pin}, headers=caddy("198.51.100.50"))
    check("staging PIN second use fails", st in (401, 503), st)
    st, _, js, _ = call(base + "/api/me", headers={**caddy("198.51.100.50"), **ck})
    check("staging /api/me with session 200", st == 200 and js.get("auth_type") == "session", st)
    st, _, js, _ = call(base + "/api/auth/tokens", "POST", {"name": "staging-bot", "sessions": ["chatgpt"]},
                        headers={**caddy("198.51.100.50"), **ck})
    check("staging token create (fresh login = step-up)", st == 200 and js.get("token", "").startswith("nlk_"), st)
    tok = js.get("token", "")
    st, *_ = call(base + "/api/messages?session=chatgpt", headers={"Authorization": f"Bearer {tok}"})
    check("staging bearer messages 200", st == 200, st)
    call(base + "/api/admin/set-otp", "POST", {"pin": "271828", "ttl_sec": 600})  # fresh PIN so guesses count
    for i in range(4):
        call(base + "/api/auth/verify", "POST", {"code": "000000"}, headers=caddy("1.2.3.4, 203.0.113.60"))
    st, _, js, _ = call(base + "/api/auth/verify", "POST", {"code": "000000"}, headers=caddy("9.9.9.9, 203.0.113.60"))
    check("staging per-IP lockout after 5 (spoofed left hops ignored)", st == 429 and js.get("scope") == "client", st)
    st, _, js, _ = call(base + "/api/auth/verify", "POST", {"code": "000000"}, headers=caddy("203.0.113.61"))
    check("staging other IP unaffected", st in (401, 503), st)
    st, *_ = call(base + "/api/auth/logout", "POST", headers={**caddy("198.51.100.50"), **ck})
    check("staging logout 200", st == 200, st)
    st, *_ = call(base + "/api/me", headers={**caddy("198.51.100.50"), **ck})
    check("staging copied cookie revoked", st == 401, st)
    st, *_ = call(base + "/", headers=caddy("198.51.100.50"))
    check("staging UI 200", st == 200, st)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["live", "staging"], required=True)
    ap.add_argument("--base", default="http://127.0.0.1:8796")
    ap.add_argument("--cookie-file")
    ap.add_argument("--bearer-file")
    ap.add_argument("--pin-via-admin", action="store_true")
    args = ap.parse_args()
    (live if args.mode == "live" else staging)(args)
    failed = [n for n, ok in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
