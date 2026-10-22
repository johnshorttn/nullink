"""Bounded Maildir access and persistent drafts. No HTML rendering or deletion."""
import email.policy
from email.parser import BytesParser
from email.message import EmailMessage
from email.utils import getaddresses, make_msgid, formatdate
import hashlib, json, os, re, secrets, sqlite3, stat, time
import compose
from contextlib import contextmanager
from pathlib import Path

ALIASES = ('admin', 'support', 'billing', 'hello', 'storycast', 'postmaster', 'abuse')
FOLDERS = {'inbox': '', 'trash': '.Trash', 'sent': '.Sent', 'archive': '.Archive', 'spam': '.Junk'}
SPAM_DAYS = 30
MAX_MAIL = 2 * 1024 * 1024

def header(value, limit=998):
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('Invalid header')
    return value

def addresses(value):
    header(value, 2000)
    parsed = getaddresses([value])
    if not 1 <= len(parsed) <= 10:
        raise ValueError('Use 1–10 recipients')
    result = []
    for _, addr in parsed:
        if not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,63}", addr) or len(addr) > 254:
            raise ValueError('Invalid email address')
        result.append(addr)
    return result

def safe_name(value):
    value = re.sub(r'[^A-Za-z0-9._ -]', '_', str(value or 'attachment'))[:120].strip(' .')
    return value or 'attachment'

class MailStore:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        for suffix in FOLDERS.values():
            for sub in ('new', 'cur', 'tmp'):
                (self.root / suffix / sub).mkdir(parents=True, exist_ok=True, mode=0o700)

    def files(self, folder):
        if folder not in FOLDERS:
            raise ValueError('Unknown folder')
        base = self.root / FOLDERS[folder]
        for sub in ('new', 'cur'):
            for p in (base / sub).iterdir():
                if not p.is_symlink() and p.is_file():
                    yield p

    @staticmethod
    def key(p):
        return hashlib.sha256(p.name.split(':2,')[0].encode()).hexdigest()

    def locate(self, folder, key):
        if not re.fullmatch('[a-f0-9]{64}', key):
            raise ValueError('Invalid message ID')
        for p in self.files(folder):
            if self.key(p) == key:
                return p
        raise FileNotFoundError('Message not found')

    def read(self, p):
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as f:
            st = os.fstat(f.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_MAIL:
                raise ValueError('Message exceeds reader limit')
            return BytesParser(policy=email.policy.default).parsebytes(f.read(MAX_MAIL + 1))

    def metadata(self, p, msg):
        recipient = str(msg.get('X-Original-To') or msg.get('To') or '')
        # Postfix virtual(8) prepends this delivery prefix ahead of untrusted
        # sender headers. Only the first original recipient is authoritative.
        prefix=[k.lower() for k,_ in list(msg.raw_items())[:4]]
        original=str(msg.get('X-Original-To','')).strip().lower()
        envelope=original if prefix==['return-path','x-original-to','delivered-to','received'] and str(msg.get('Delivered-To','')).strip().lower()=='john@nullverse.cloud' and re.fullmatch(r'[^\s<>@]+@[^\s<>@]+',original) else None
        return {'id': self.key(p), 'from': str(msg.get('From', '')), 'to': str(msg.get('To', '')),
                'recipient': recipient, 'envelope_recipient': envelope, 'subject': str(msg.get('Subject', '(No subject)')),
                'date': str(msg.get('Date', '')), 'timestamp': p.stat().st_mtime,
                'unread': 'S' not in p.name.partition(':2,')[2], 'size': p.stat().st_size}

    def listing(self, folder='inbox', query='', recipient='', unread=False):
        rows = []
        for p in self.files(folder):
            try:
                m = self.metadata(p, self.read(p))
                if unread and not m['unread']: continue
                if recipient.lower() not in m['recipient'].lower(): continue
                if query.lower() not in ' '.join(str(m[k]) for k in ('subject','from','to','recipient')).lower(): continue
                rows.append(m)
            except (OSError, ValueError, email.errors.MessageError):
                continue
        return sorted(rows, key=lambda m: m['timestamp'], reverse=True)

    def message(self, folder, key):
        p = self.locate(folder, key); msg = self.read(p); result = self.metadata(p, msg)
        text, attachments, has_html = [], [], False
        for i, part in enumerate(msg.walk()):
            if part.is_multipart(): continue
            if part.get_content_disposition() == 'attachment' or part.get_filename() or part.get_content_type() not in ('text/plain', 'text/html'):
                attachments.append({'id': i, 'name': safe_name(part.get_filename()), 'size': len(part.get_payload(decode=True) or b'')})
            elif part.get_content_type() == 'text/plain':
                raw = part.get_payload(decode=True) or b''
                try: text.append(raw.decode(part.get_content_charset() or 'utf-8', errors='replace'))
                except LookupError: text.append(raw.decode('utf-8', errors='replace'))
            else: has_html = True
        result.update(body='\n\n'.join(text) or ('This email contains HTML only. HTML is not rendered for safety.' if has_html else '(No plain-text body)'),
                      attachments=attachments, reply_to=str(msg.get('Reply-To') or msg.get('From') or ''),
                      message_id=str(msg.get('Message-ID', '')), references=str(msg.get('References','')),
                      in_reply_to=str(msg.get('In-Reply-To','')), headers='\n'.join(k+': '+str(v) for k,v in msg.items())[:200000])
        return result

    def attachment(self, folder, key, index):
        msg = self.read(self.locate(folder, key))
        allowed = {a['id']: a for a in self.message(folder, key)['attachments']}
        if index not in allowed: raise FileNotFoundError('Attachment not found')
        return allowed[index]['name'], list(msg.walk())[index].get_payload(decode=True) or b''

    def source(self, folder, key):
        return self.locate(folder, key).read_bytes()[:MAX_MAIL + 1], []

    def eml(self, folder, key):
        return self.source(folder, key)[0], False

    def flag(self, folder, key, read):
        p = self.locate(folder, key)
        flags = set(p.name.partition(':2,')[2]); flags.discard('S')
        if read: flags.add('S')
        target = p.parent.parent / 'cur' / (p.name.split(':2,')[0] + ':2,' + ''.join(sorted(flags)))
        p.rename(target)

    def delete(self, folder, key, confirm=False):
        """Permanent delete, only from Trash, only with explicit confirmation."""
        if confirm is not True: raise ValueError('Permanent delete requires confirmation')
        if folder != 'trash': raise ValueError('Move the message to Trash before deleting it permanently')
        self.locate(folder, key).unlink()

    def move(self, folder, key, target):
        if target not in ('inbox', 'trash', 'archive', 'spam') or folder not in ('inbox', 'trash', 'archive', 'spam', 'sent') or target == folder or (folder == 'sent' and target != 'trash'):
            raise ValueError('Only inbox, archive, spam and reversible trash moves are supported')
        p = self.locate(folder, key)
        dest = self.root / FOLDERS[target] / p.parent.name / p.name
        if dest.exists(): raise ValueError('Destination already exists')
        p.rename(dest)

class Drafts:
    def __init__(self, path):
        self.path = str(path)
        with self.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS drafts (id TEXT PRIMARY KEY, data TEXT NOT NULL, status TEXT NOT NULL, updated REAL NOT NULL, queue_id TEXT)')
            if 'trashed_from' not in [r[1] for r in db.execute('PRAGMA table_info(drafts)')]:
                db.execute('ALTER TABLE drafts ADD COLUMN trashed_from TEXT')
            cols=[r[1] for r in db.execute('PRAGMA table_info(drafts)')]
            for c,t in (('send_at','REAL'),('send_key','TEXT'),('send_actor','TEXT')):
                if c not in cols: db.execute('ALTER TABLE drafts ADD COLUMN %s %s'%(c,t))
    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            with db:
                yield db
        finally:
            db.close()
    def list(self):
        with self.db() as db:
            return [dict(json.loads(data), id=key, status=status, updated=updated, queue_id=queue, **({'trashed_from': prev} if prev else {}), **({'send_at': at} if status=='scheduled' and at else {})) for key,data,status,updated,queue,prev,at in db.execute('SELECT id,data,status,updated,queue_id,trashed_from,send_at FROM drafts ORDER BY updated DESC')]
    def get(self, key):
        return next((d for d in self.list() if d['id'] == key), None)
    def save(self, data, identities):
        key = data.get('id') or secrets.token_hex(16)
        if not re.fullmatch('[a-f0-9]{32}', key): raise ValueError('Invalid draft ID')
        sender = header(data.get('from', ''), 254)
        if sender not in identities: raise ValueError('From identity is not authorized')
        clean = {'from': sender, 'to': header(data.get('to', ''), 2000), 'subject': header(data.get('subject', ''), 200),
                 'body': data.get('body', ''), 'in_reply_to': header(data.get('in_reply_to', ''), 998)}
        for flag in ('read_receipt','track_opens'):
            if flag in data and not isinstance(data[flag], bool): raise ValueError(flag+' must be boolean')
            clean[flag] = data.get(flag) is True
        if not isinstance(clean['body'], str) or len(clean['body'].encode()) > 180000: raise ValueError('Draft is too large')
        if data.get('body_html'):
            # Rich text: never trust browser HTML. Sanitize, keep inline images as data: for re-editing,
            # and regenerate the plain-text alternative server-side.
            safe, images = compose.sanitize(data['body_html'])
            clean['body_html'] = compose.restore_images(safe, images); clean['body'] = compose.to_text(safe)
            if len(clean['body_html'].encode()) > 400000: raise ValueError('Draft is too large (inline images must stay small)')
            delta = data.get('body_delta')
            if isinstance(delta, str) and len(delta) <= 500000: clean['body_delta'] = delta
        with self.db() as db:
            current = db.execute('SELECT status FROM drafts WHERE id=?', (key,)).fetchone()
            if current and current[0] not in ('draft', 'paused', 'rejected'): raise ValueError('Submitted messages cannot be edited')
            db.execute('INSERT INTO drafts (id,data,status,updated,queue_id) VALUES (?,?,?,?,NULL) ON CONFLICT(id) DO UPDATE SET data=excluded.data, status=excluded.status, updated=excluded.updated', (key, json.dumps(clean), 'draft', time.time()))
        return self.get(key)
    def claim(self, key):
        with self.db() as db:
            changed=db.execute("UPDATE drafts SET status='submitting',updated=? WHERE id=? AND status IN ('draft','paused','rejected')", (time.time(),key)).rowcount
            if changed != 1: raise ValueError('Already submitted; duplicate send blocked')
    # Undo send: a scheduled item waits in the Outbox until send_at; until the worker claims it,
    # Retract returns it to Drafts. Once claimed (status 'submitting') it cannot be recalled.
    def schedule(self, key, send_at, request_key, actor):
        with self.db() as db:
            changed=db.execute("UPDATE drafts SET status='scheduled',send_at=?,send_key=?,send_actor=?,updated=? WHERE id=? AND status IN ('draft','paused','rejected')", (send_at,request_key,actor,time.time(),key)).rowcount
            if changed != 1: raise ValueError('Already submitted; duplicate send blocked')
    def retract(self, key):
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT status,send_key FROM drafts WHERE id=?', (key,)).fetchone()
            if not row: raise FileNotFoundError('Outbound message not found')
            if row[0]!='scheduled': raise ValueError('Too late to retract: the message was already handed to the mail server' if row[0] in ('submitting','accepted','unknown') else 'Message is not waiting to send')
            db.execute("UPDATE drafts SET status='draft',send_at=NULL,send_key=NULL,send_actor=NULL,updated=? WHERE id=?", (time.time(),key))
        return {'id':key,'status':'draft','request_id':row[1]}
    def due(self, now=None):
        with self.db() as db:
            return [dict(id=k,request_id=r,actor=a) for k,r,a in db.execute("SELECT id,send_key,send_actor FROM drafts WHERE status='scheduled' AND send_at<=?", (now or time.time(),))]
    def claim_scheduled(self, key):
        with self.db() as db:
            changed=db.execute("UPDATE drafts SET status='submitting',send_at=NULL,updated=? WHERE id=? AND status='scheduled'", (time.time(),key)).rowcount
            if changed != 1: raise ValueError('Retracted or already submitted')
    # Outbound delete. Trash is the default and reversible; purge needs explicit confirmation.
    # Trashing an unsent item (draft/paused/rejected) cancels its send: claim() only accepts those
    # statuses, so a trashed row can never be submitted. 'submitting' is mid-handoff and is refused.
    # accepted/unknown were already handed to Postfix/Gmail: trashing hides them but cannot recall them.
    def trash(self, key):
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT status FROM drafts WHERE id=?', (key,)).fetchone()
            if not row: raise FileNotFoundError('Outbound message not found')
            if row[0] == 'trashed': return {'id': key, 'status': 'trashed', 'cancelled': False, 'already_submitted': False}
            if row[0] == 'submitting': raise ValueError('Submission is in progress; it cannot be cancelled now')
            db.execute("UPDATE drafts SET status='trashed',trashed_from=?,send_at=NULL,updated=? WHERE id=?", (row[0], time.time(), key))
        return {'id': key, 'status': 'trashed', 'cancelled': row[0] in ('paused', 'rejected', 'draft', 'scheduled'), 'already_submitted': row[0] in ('accepted', 'unknown')}
    def restore(self, key):
        with self.db() as db:
            row = db.execute('SELECT status,trashed_from FROM drafts WHERE id=?', (key,)).fetchone()
            if not row: raise FileNotFoundError('Outbound message not found')
            if row[0] != 'trashed': raise ValueError('Message is not in Trash')
            # A restored unsent item comes back paused: nothing is transmitted until an explicit Send.
            prev = row[1] if row[1] in ('draft', 'rejected', 'accepted', 'unknown') else 'paused'
            db.execute('UPDATE drafts SET status=?,trashed_from=NULL,updated=? WHERE id=?', (prev, time.time(), key))
        return {'id': key, 'status': prev}
    def purge(self, key, confirm=False):
        if confirm is not True: raise ValueError('Permanent delete requires confirmation')
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT status FROM drafts WHERE id=?', (key,)).fetchone()
            if not row: raise FileNotFoundError('Outbound message not found')
            if row[0] == 'submitting': raise ValueError('Submission is in progress; it cannot be deleted now')
            db.execute('DELETE FROM drafts WHERE id=?', (key,))
        return {'id': key, 'status': 'deleted', 'cancelled': row[0] in ('paused', 'rejected', 'draft'), 'already_submitted': row[0] in ('accepted', 'unknown')}
    def status(self, key, status, queue=None):
        with self.db() as db: db.execute('UPDATE drafts SET status=?,queue_id=?,updated=? WHERE id=?', (status, queue, time.time(), key))

def build_message(draft, identities, message_id=None, track_url=None):
    """read_receipt → Disposition-Notification-To; track_url → 1x1 image in the HTML part (HTML is created if needed)."""
    if draft['from'] not in identities: raise ValueError('From identity is not authorized')
    recipients = addresses(draft['to'])
    msg = EmailMessage(policy=email.policy.SMTP)
    for k,v in [('From',draft['from']),('To',draft['to']),('Subject',draft['subject'])]: msg[k] = header(v, 2000)
    if draft.get('in_reply_to'): msg['In-Reply-To'] = header(draft['in_reply_to'])
    msg['Date'] = formatdate(localtime=False); msg['Message-ID'] = message_id or make_msgid(domain='nullverse.cloud')
    if draft.get('read_receipt'): msg['Disposition-Notification-To'] = header(draft['from'], 254)
    pixel = '<img src="%s" width="1" height="1" alt="" style="display:block;width:1px;height:1px;border:0">' % track_url if track_url else ''
    if draft.get('body_html') or pixel:
        if draft.get('body_html'): safe, images = compose.sanitize(draft['body_html'])
        else:
            import html as _h
            safe, images = ''.join('<p>%s</p>' % (_h.escape(l) or '<br>') for l in draft['body'].split('\n')), []
        msg.set_content(compose.to_text(safe) if draft.get('body_html') else draft['body'])
        msg.add_alternative(compose.document(safe + pixel), subtype='html')
        part = msg.get_payload()[1]
        for img in images: part.add_related(img['data'], 'image', img['subtype'], cid='<%s>' % img['cid'], disposition='inline', filename=img['cid'].split('.')[0] + '.' + img['subtype'].replace('jpeg', 'jpg'))
    else: msg.set_content(draft['body'])
    raw = msg.as_bytes()
    if len(raw) > 250000: raise ValueError('Message is too large for Postfix')
    return recipients, raw
