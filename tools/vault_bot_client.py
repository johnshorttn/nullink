#!/usr/bin/env python3
"""Box-side client for the scoped vault bot API. Never prints secret values.

  deposit --title "Gemini API key" --from-env GEMINI_API_KEY [--tags api,gemini]
  read --id <entry-id> --code <John's fresh 6-digit code> --out <file>   (body written 0600, not printed)
"""
import argparse, json, os, sys, urllib.request

BASE = os.environ.get("NULLINK_URL", "https://nullink.216.158.238.236.sslip.io")
TOKEN_FILE = os.environ.get("NULLINK_VAULT_BOT_TOKEN_FILE", "/workspace/server/secrets/nullink_vault_bot_morc.token")


def call(path, payload):
    tok = open(TOKEN_FILE).read().strip()
    req = urllib.request.Request(BASE + path, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def main():
    p = argparse.ArgumentParser(); sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("deposit"); d.add_argument("--title", required=True); d.add_argument("--from-env", required=True)
    d.add_argument("--tags", default="")
    r = sub.add_parser("read"); r.add_argument("--id", required=True); r.add_argument("--code", required=True)
    r.add_argument("--out", required=True)
    a = p.parse_args()
    if a.cmd == "deposit":
        val = os.environ.get(a.from_env)
        if not val:
            sys.exit(f"env {a.from_env} is empty")
        st, js = call("/api/vault/deposit", {"title": a.title, "body": val, "tags": a.tags})
        print(st, {k: js.get(k) for k in ("id", "title", "created_at", "error")})
    else:
        st, js = call("/api/vault/bot-read", {"id": a.id, "code": a.code})
        if st == 200:
            fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(js["item"]["body"])
            print(200, "body written to", a.out, "title:", js["item"].get("title"))
        else:
            print(st, js.get("error"))


if __name__ == "__main__":
    main()
