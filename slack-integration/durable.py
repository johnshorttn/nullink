"""Integration library for Morc's signed receiver; no public listener or AI API.
One process owns the database lock; ingestion may run alongside one dispatcher.
Runtime adapters must implement durable idempotency for request_key.
"""
import fcntl
import hashlib
import hmac
import json
import os
import re
import sqlite3
import time
import threading
from functools import wraps
import uuid
from pathlib import Path


class Rejected(ValueError):
    pass


class Retry(Exception):
    def __init__(self, seconds=5):
        self.seconds = max(1, min(int(seconds), 3600))


class Ambiguous(Exception):
    """External side effect may have happened: reconcile, never blindly retry."""


class Pending(Retry):
    """An existing durable runtime job is still running, not a failed attempt."""


def verify(secret, headers, raw, now=None):
    headers = {k.lower(): v for k, v in headers.items()}
    if not secret or len(raw) > 262144:
        raise Rejected('missing secret or oversized body')
    try:
        stamp = headers['x-slack-request-timestamp']
        if abs((time.time() if now is None else now) - int(stamp)) > 300:
            raise Rejected('stale signature')
        expected = 'v0=' + hmac.new(secret.encode(), b'v0:' + stamp.encode() + b':' + raw, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, headers.get('x-slack-signature', '')):
            raise Rejected('invalid signature')
        return json.loads(raw)
    except (KeyError, TypeError, ValueError) as exc:
        raise Rejected('invalid signed request') from exc


def scrub(text):
    text = re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----', '[REDACTED KEY]', text, flags=re.S)
    return re.sub(r'\b(?:xox[baprs]-[\w-]+|sk-[\w-]{16,})', '[REDACTED]', text)


def synchronized(method):
    @wraps(method)
    def call(self, *args, **kwargs):
        with self.mutex:
            return method(self, *args, **kwargs)
    return call


class Store:
    def __init__(self, path, registry, clock=time.time):
        for key, default, minimum, maximum in [('max_hops', 2, 0, 4), ('job_budget', 3, 1, 10), ('ttl_seconds', 600, 1, 1800)]:
            value = registry.get(key, default)
            if type(value) is not int or not minimum <= value <= maximum:
                raise Rejected('invalid finite routing limit')
        for field in ('user_id', 'app_id', 'runtime_id'):
            values = [c[field] for c in registry['bots'].values() if c.get('enabled')]
            if len(values) != len(set(values)):
                raise Rejected('ambiguous identity mapping')
        for cfg in registry['bots'].values():
            if cfg.get('enabled') and any(not cfg.get(k) or cfg[k].startswith('REQUIRED_') or cfg[k].endswith('-unconfigured') for k in ('user_id', 'bot_id', 'app_id', 'runtime_id', 'label')):
                raise Rejected('incomplete enabled identity mapping')
        self.clock, self.registry = clock, registry
        self.mutex = threading.RLock()
        Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = open(str(path) + '.lock', 'a')
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.lock.close()
            raise
        self.db = sqlite3.connect(path, check_same_thread=False)
        os.chmod(path, 0o600)
        self.db.row_factory = sqlite3.Row
        self.db.executescript('''
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=FULL;
        CREATE TABLE IF NOT EXISTS events (bot TEXT, event TEXT, PRIMARY KEY(bot,event));
        CREATE TABLE IF NOT EXISTS chains (id TEXT PRIMARY KEY, expires REAL, remaining INTEGER);
        CREATE TABLE IF NOT EXISTS jobs (
          id TEXT PRIMARY KEY, bot TEXT, channel TEXT, thread TEXT, message TEXT,
          sender TEXT, prompt TEXT, chain TEXT, hop INTEGER, state TEXT,
          attempts INTEGER DEFAULT 0, due REAL, created REAL, result TEXT,
          reply_ts TEXT, runtime TEXT, error TEXT,
          UNIQUE(bot,channel,message));
        CREATE TABLE IF NOT EXISTS edges (chain TEXT, source TEXT, target TEXT,
          PRIMARY KEY(chain,source,target));
        CREATE TABLE IF NOT EXISTS posts (bot TEXT, channel TEXT, ts TEXT, thread TEXT,
          chain TEXT, hop INTEGER, target TEXT, PRIMARY KEY(bot,channel,ts));
        CREATE TABLE IF NOT EXISTS rates (key TEXT PRIMARY KEY, next REAL);
        ''')
        # Running runtimes are retried ONLY with their identical durable request_key.
        # A crash during Slack posting is ambiguous and never automatically re-posted.
        with self.mutex, self.db:
            self.db.execute("UPDATE jobs SET state='queued' WHERE state='running'")
            self.db.execute("UPDATE jobs SET state='uncertain',error='post interrupted; reconcile required' WHERE state='posting'")

    @synchronized
    def close(self):
        self.db.close()
        self.lock.close()

    @synchronized
    def ingest(self, bot, body):
        """Call only after verify(app-specific secret). Commit before returning 200."""
        cfg = self.registry['bots'][bot]
        if body.get('team_id') != self.registry['team_id'] or body.get('api_app_id') != cfg['app_id']:
            raise Rejected('workspace/app mismatch')
        event = body.get('event', {})
        if body.get('type') != 'event_callback' or not body.get('event_id'):
            raise Rejected('not an event callback')
        if event.get('type') not in ('app_mention', 'message') or event.get('subtype') not in (None, 'bot_message'):
            return None
        channel, ts, sender = (event.get(k) for k in ('channel', 'ts', 'user'))
        if not all(isinstance(x, str) and x for x in (channel, ts, sender)):
            raise Rejected('missing channel/message/user')
        if channel not in self.registry['channels']:
            return None
        text = event.get('text', '')
        mention = '<@' + cfg['user_id'] + '>'
        if mention not in text and event.get('channel_type') != 'im':
            return None
        thread = event.get('thread_ts', ts)
        sources = [k for k, v in self.registry['bots'].items() if v['user_id'] == sender]
        source = sources[0] if sources else None
        now = self.clock()
        with self.mutex, self.db:
            if self.db.execute('SELECT 1 FROM events WHERE bot=? AND event=?', (bot, body['event_id'])).fetchone():
                return None
            self.db.execute('INSERT INTO events VALUES (?,?)', (bot, body['event_id']))
            if self.db.execute('SELECT 1 FROM jobs WHERE bot=? AND channel=? AND message=?', (bot, channel, ts)).fetchone():
                return None
            if source:
                # Trust only our own persisted outbox, never metadata supplied in text.
                post = self.db.execute('SELECT * FROM posts WHERE bot=? AND channel=? AND ts=?', (source, channel, ts)).fetchone()
                if source == bot or [source, bot] not in self.registry['handoffs']:
                    return None
                if not post:
                    # Slack can deliver the event before chat.postMessage returns.
                    # Roll back receipt and let Slack retry if our outbox is in flight.
                    pending = self.db.execute("SELECT result FROM jobs WHERE bot=? AND channel=? AND thread=? AND state IN ('posting','uncertain')", (source, channel, thread)).fetchall()
                    if any(json.loads(p['result'] or '{}').get('handoff_to') == bot for p in pending):
                        raise Retry(2)
                    return None
                if post['target'] != bot or post['thread'] != thread:
                    return None
                if event.get('bot_id') and event['bot_id'] != self.registry['bots'][source]['bot_id']:
                    return None
                chain, hop = post['chain'], post['hop'] + 1
                if hop > self.registry.get('max_hops', 2):
                    return None
                if self.db.execute('SELECT 1 FROM edges WHERE chain=? AND source=? AND target=?', (chain, source, bot)).fetchone():
                    return None
            else:
                if event.get('bot_id') or event.get('subtype') == 'bot_message' or sender not in self.registry['human_users']:
                    return None
                chain, hop = uuid.uuid4().hex, 0
                self.db.execute('INSERT INTO chains VALUES (?,?,?)', (chain, now + self.registry.get('ttl_seconds', 600), self.registry.get('job_budget', 3)))
            budget = self.db.execute('SELECT * FROM chains WHERE id=?', (chain,)).fetchone()
            if not budget or budget['expires'] <= now or budget['remaining'] <= 0:
                return None
            if self.db.execute("SELECT count(*) FROM jobs WHERE state IN ('queued','running','ready','posting','uncertain')").fetchone()[0] >= 100:
                # Roll back event receipt so Slack may retry later.
                raise Retry(30)
            self.db.execute('UPDATE chains SET remaining=remaining-1 WHERE id=?', (chain,))
            if source:
                self.db.execute('INSERT INTO edges VALUES (?,?,?)', (chain, source, bot))
            key = hashlib.sha256(f'{bot}:{channel}:{ts}'.encode()).hexdigest()
            self.db.execute('INSERT INTO jobs(id,bot,channel,thread,message,sender,prompt,chain,hop,state,due,created,runtime) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
                            (key, bot, channel, thread, ts, sender, scrub(text)[:8000], chain, hop, 'queued', now, now, cfg['runtime_id']))
            return key

    @synchronized
    def get(self, key):
        r = self.db.execute('SELECT * FROM jobs WHERE id=?', (key,)).fetchone()
        return dict(r) if r else None

    @synchronized
    def context(self, job):
        rows = self.db.execute("SELECT sender,prompt,result FROM jobs WHERE bot=? AND channel=? AND thread=? AND state='done' ORDER BY created DESC LIMIT 8", (job['bot'], job['channel'], job['thread'])).fetchall()
        return [{'sender': r['sender'], 'message': r['prompt'][:2000], 'reply': json.loads(r['result'])['text'][:2000]} for r in reversed(rows)]

    @synchronized
    def reserve_rate(self, key, interval):
        row = self.db.execute('SELECT next FROM rates WHERE key=?', (key,)).fetchone()
        if row and row[0] > self.clock():
            return False
        self.db.execute('INSERT OR REPLACE INTO rates VALUES (?,?)', (key, self.clock() + interval))
        return True

    def tick(self, runtime, slack):
        """One step. runtime.run(request) -> {text, handoff_to?}; Slack post -> ts.
        Runtime must enforce request expiry and durable idempotency before side effects.
        Credentials never enter request/context; run runtime with no Slack credentials.
        """
        now = self.clock()
        with self.mutex, self.db:
            self.db.execute("UPDATE jobs SET state='expired' WHERE state IN ('queued','ready') AND chain IN (SELECT id FROM chains WHERE expires<=?)", (now,))
        rows = self.db.execute("SELECT * FROM jobs WHERE state IN ('queued','ready') AND due<=? ORDER BY created,rowid", (now,)).fetchall()
        for row in rows:
            job = dict(row)
            prior = self.db.execute("SELECT 1 FROM jobs WHERE bot=? AND channel=? AND thread=? AND rowid < (SELECT rowid FROM jobs WHERE id=?) AND state IN ('queued','running','ready','posting','uncertain')", (job['bot'], job['channel'], job['thread'], job['id'])).fetchone()
            if prior:
                continue
            cfg = self.registry['bots'][job['bot']]
            if not cfg.get('enabled') or job['runtime'] != cfg['runtime_id']:
                continue
            phase = job['state']
            with self.mutex, self.db:
                if not self.reserve_rate(('runtime:' + job['bot']) if phase == 'queued' else ('slack:' + job['channel']), 5 if phase == 'queued' else 1.1):
                    continue
                self.db.execute('UPDATE jobs SET state=?, attempts=attempts+1 WHERE id=?', ('running' if phase == 'queued' else 'posting', job['id']))
            try:
                if phase == 'queued':
                    expiry = self.db.execute('SELECT expires FROM chains WHERE id=?', (job['chain'],)).fetchone()[0]
                    result = runtime.run({'request_key': job['id'], 'runtime_id': job['runtime'], 'bot': job['bot'], 'channel': job['channel'], 'thread_ts': job['thread'], 'text': job['prompt'], 'context': self.context(job), 'expires_at': expiry, 'correlation_id': job['chain'], 'hop': job['hop']})
                    if not isinstance(result, dict) or not isinstance(result.get('text'), str) or not result['text'].strip():
                        raise Rejected('invalid runtime response')
                    target = result.get('handoff_to')
                    if target and ([job['bot'], target] not in self.registry['handoffs'] or job['hop'] >= self.registry.get('max_hops', 2)):
                        raise Rejected('handoff not allowed')
                    # Only structured handoff_to can create a live bot mention.
                    reply = scrub(result['text'])
                    reply = re.sub(r'<[@!][^>]*>', '[mention]', reply)[:3500]
                    if target:
                        reply = '<@' + self.registry['bots'][target]['user_id'] + '> ' + reply
                    reply += '\n[' + cfg['label'] + ']'
                    result = {'text': reply, 'handoff_to': target}
                    with self.mutex, self.db:
                        self.db.execute("UPDATE jobs SET state='ready',result=?,attempts=0 WHERE id=?", (json.dumps(result), job['id']))
                else:
                    result = json.loads(job['result'])
                    ts = slack.post(job['bot'], job['channel'], job['thread'], result['text'], str(uuid.uuid5(uuid.NAMESPACE_URL, job['id'])))
                    self.record_post(job['id'], ts)
                return job['id']
            except Pending as exc:
                with self.mutex, self.db:
                    self.db.execute('UPDATE jobs SET state=?,due=?,attempts=attempts-1 WHERE id=?', (phase, now + exc.seconds, job['id']))
            except Retry as exc:
                with self.mutex, self.db:
                    self.db.execute('UPDATE jobs SET state=?,due=?,error=? WHERE id=?', ('failed' if job['attempts'] >= 4 else phase, now + exc.seconds, 'retryable remote response', job['id']))
            except Ambiguous:
                with self.mutex, self.db:
                    self.db.execute("UPDATE jobs SET state='uncertain',error='external outcome unknown; reconcile required' WHERE id=?", (job['id'],))
            except Exception:
                # Do not log exception bodies, which may include tokens or prompt text.
                with self.mutex, self.db:
                    self.db.execute("UPDATE jobs SET state='failed',error='adapter rejected or failed' WHERE id=?", (job['id'],))
            return job['id']
        return None

    @synchronized
    def record_post(self, key, ts):
        """Also used after authoritative read-side reconciliation of ambiguous posts."""
        if not isinstance(ts, str) or not re.fullmatch(r'\d+\.\d+', ts):
            raise Ambiguous()
        job = self.get(key)
        if job['state'] not in ('posting', 'uncertain'):
            raise Rejected('post not pending')
        result = json.loads(job['result'])
        with self.mutex, self.db:
            self.db.execute('INSERT INTO posts VALUES (?,?,?,?,?,?,?)', (job['bot'], job['channel'], ts, job['thread'], job['chain'], job['hop'], result.get('handoff_to')))
            self.db.execute("UPDATE jobs SET state='done',reply_ts=?,error=NULL WHERE id=?", (ts, key))
