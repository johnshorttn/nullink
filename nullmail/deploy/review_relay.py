#!/usr/bin/env python3
"""Root oneshot relay between Nullmail's sandboxed review queue and the Morc review area.

  Nullmail (sandboxed) : /var/lib/nullmail/app/mail-review/{requests,verdicts,processed}
  Morc review area     : /opt/nullink/data/mail-review/{requests,verdicts,processed}

Requests (json + eml) are copied to the Morc area (owner morc, 0600) and announced in the
Nullink *morc* room (never deepseek) when a token file is provisioned. Verdicts written by
Morc are copied back for Nullmail. Message text is never logged or posted; only the id,
sender domain, subject length and finding kinds.
"""
import json, os, pwd, shutil, sys, time, urllib.request
from pathlib import Path

SRC = Path('/var/lib/nullmail/app/mail-review'); DST = Path('/opt/nullink/data/mail-review')
TOKEN = Path('/opt/nullink/secrets/NULLINK_TOKEN_mailreview.txt'); API = 'http://127.0.0.1:8766/api/messages'; ROOM = 'morc'
LOG = DST / 'relay.log'

def own(path, user, mode=0o600):
    pw = pwd.getpwnam(user); os.chown(path, pw.pw_uid, pw.pw_gid); os.chmod(path, mode)

def log(line):
    with open(LOG, 'a') as f: f.write(time.strftime('%Y-%m-%dT%H:%M:%S%z ') + line + '\n')
    own(LOG, 'morc')

def notify(req):
    if ROOM == 'deepseek': raise SystemExit('refusing deepseek room')
    kinds = sorted({f['kind'] for f in req.get('findings', [])})
    text = ('Nullmail review request %s: email from %s with %s. Static review only, nothing runs. Files: %s/requests/%s.json (+ .eml). '
            'Write verdict JSON to %s/verdicts/%s.json with format nullmail-review/1, verdict clean|suspicious|malicious and a reason.') % (
            req['request_id'], (str(req.get('from', '')).rsplit('@', 1)[-1].strip('> ') or 'unknown'), ', '.join(kinds) or 'script findings',
            DST, req['request_id'], DST, req['request_id'])
    if not TOKEN.exists(): return 'queued (no morc-room token provisioned; notification pending)'
    token = TOKEN.read_text().strip()
    r = urllib.request.Request(API, data=json.dumps({'session_id': ROOM, 'text': text}).encode(), method='POST',
                               headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token})
    with urllib.request.urlopen(r, timeout=15) as resp: return 'notified morc room (HTTP %d)' % resp.status

def main():
    for sub in ('requests', 'verdicts', 'processed'):
        (DST / sub).mkdir(parents=True, exist_ok=True); own(DST / sub, 'morc', 0o700)
    own(DST, 'morc', 0o700)
    if not SRC.exists(): return 0
    for req_path in sorted((SRC / 'requests').glob('*.json')):
        rid = req_path.stem
        try: req = json.loads(req_path.read_text()[:200000])
        except ValueError: continue
        for suffix in ('.json', '.eml'):
            s = SRC / 'requests' / (rid + suffix)
            if s.exists(): d = DST / 'requests' / (rid + suffix); shutil.copyfile(s, d); own(d, 'morc')
        try: status = notify(req)
        except Exception as e: status = 'notify failed: ' + type(e).__name__
        log('request %s relayed; %s' % (rid, status))
        os.replace(req_path, SRC / 'processed' / (rid + '.json.relayed'))
        eml = SRC / 'requests' / (rid + '.eml')
        if eml.exists(): os.replace(eml, SRC / 'processed' / (rid + '.eml'))
    for v in sorted((DST / 'verdicts').glob('*.json')):
        d = SRC / 'verdicts' / v.name; tmp = SRC / 'verdicts' / ('.tmp-' + v.name)
        shutil.copyfile(v, tmp); own(tmp, 'nullmail'); os.replace(tmp, d)
        os.replace(v, DST / 'processed' / v.name); log('verdict %s returned to Nullmail' % v.stem)
    return 0

if __name__ == '__main__': sys.exit(main())
