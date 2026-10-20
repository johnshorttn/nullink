"""Pluggable human/AI review of emails that contain scripts.

Nullmail never runs scripts and never enables them after a verdict; a verdict is
only displayed. The default reviewer writes a request to a file queue that a relay
moves to /opt/nullink/data/mail-review/ and announces in the Nullink morc room.
"""
import hashlib, json, os, re, secrets, time
from pathlib import Path

STATUSES = ('pending', 'clean', 'suspicious', 'malicious')
FORMAT = 'nullmail-review/1'
SCHEMA = '''CREATE TABLE IF NOT EXISTS mail_reviews(message_key TEXT PRIMARY KEY, request_id TEXT NOT NULL, status TEXT NOT NULL,
 reason TEXT, reviewer TEXT, findings TEXT NOT NULL, requested REAL NOT NULL, updated REAL NOT NULL)'''

class Reviewer:
    """Hook interface: submit() queues a request; verdicts() yields completed verdict dicts."""
    def submit(self, request, raw): raise NotImplementedError
    def verdicts(self): return []
    def done(self, request_id): pass

class FileQueueReviewer(Reviewer):
    def __init__(self, root):
        self.root = Path(root)
        for sub in ('requests', 'verdicts', 'processed'): (self.root / sub).mkdir(parents=True, exist_ok=True, mode=0o700)
    def submit(self, request, raw):
        rid = request['request_id']; req = self.root / 'requests'
        tmp = req / ('.tmp-' + rid)
        (tmp.with_suffix('.eml')).write_bytes(raw); os.replace(tmp.with_suffix('.eml'), req / (rid + '.eml'))
        tmp.write_text(json.dumps(request, indent=1)); os.replace(tmp, req / (rid + '.json'))
    def verdicts(self):
        out = []
        for p in sorted((self.root / 'verdicts').glob('*.json'))[:100]:
            try:
                v = json.loads(p.read_text()[:20000])
                if isinstance(v, dict) and v.get('format') == FORMAT and v.get('verdict') in STATUSES[1:] and re.fullmatch('[a-f0-9]{24}', str(v.get('request_id', ''))):
                    out.append(v)
                else: p.rename(self.root / 'processed' / (p.name + '.invalid'))
            except (OSError, ValueError): continue
        return out
    def done(self, request_id):
        p = self.root / 'verdicts' / (request_id + '.json')
        if p.exists(): os.replace(p, self.root / 'processed' / p.name)

class Reviews:
    def __init__(self, state, reviewer):
        self.state, self.reviewer = state, reviewer
        with state.db() as db: db.execute(SCHEMA)
    def get(self, key):
        with self.state.db() as db:
            r = db.execute('SELECT request_id,status,reason,reviewer,requested,updated FROM mail_reviews WHERE message_key=?', (key,)).fetchone()
        return dict(zip(('request_id', 'status', 'reason', 'reviewer', 'requested', 'updated'), r)) if r else None
    def submit(self, m, findings, raw, actor):
        if not findings: raise ValueError('No script findings; review not needed')
        old = self.get(m['id'])
        if old and old['status'] == 'pending': return old
        rid = secrets.token_hex(12); now = time.time()
        request = {'format': FORMAT, 'request_id': rid, 'message_key': m['id'], 'folder': m.get('folder'), 'provider': m.get('provider', 'local'),
                   'account': m.get('gmail_account') or 'local', 'from': m.get('from'), 'to': m.get('to'), 'subject': m.get('subject'), 'date': m.get('date'),
                   'message_id': m.get('message_id'), 'findings': findings, 'requested_by': actor, 'requested_at': now,
                   'source_file': rid + '.eml', 'source_sha256': hashlib.sha256(raw).hexdigest(), 'source_bytes': len(raw),
                   'verdict_format': {'format': FORMAT, 'request_id': rid, 'verdict': 'clean|suspicious|malicious', 'reason': 'short text', 'reviewer': 'morc'},
                   'instructions': 'Do not open links or run anything. Inspect statically. Write the verdict JSON to verdicts/<request_id>.json.'}
        self.reviewer.submit(request, raw)
        with self.state.db() as db:
            db.execute('INSERT OR REPLACE INTO mail_reviews VALUES (?,?,?,?,?,?,?,?)', (m['id'], rid, 'pending', None, None, json.dumps(findings), now, now))
        return self.get(m['id'])
    def collect(self):
        n = 0
        for v in self.reviewer.verdicts():
            with self.state.db() as db:
                c = db.execute('UPDATE mail_reviews SET status=?,reason=?,reviewer=?,updated=? WHERE request_id=?',
                               (v['verdict'], str(v.get('reason', ''))[:500], str(v.get('reviewer', 'reviewer'))[:80], time.time(), v['request_id'])).rowcount
            self.reviewer.done(v['request_id']); n += c
        return n
