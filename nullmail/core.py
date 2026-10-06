"""Bounded Maildir access and persistent drafts. No HTML rendering or deletion."""
import email.policy
from email.parser import BytesParser
from email.message import EmailMessage
from email.utils import getaddresses, make_msgid, formatdate
import hashlib, json, os, re, secrets, sqlite3, stat, time
from contextlib import contextmanager
from pathlib import Path

ALIASES = ('admin', 'support', 'billing', 'hello', 'storycast', 'postmaster', 'abuse')
FOLDERS = {'inbox': '', 'trash': '.Trash', 'sent': '.Sent'}
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
        return {'id': self.key(p), 'from': str(msg.get('From', '')), 'to': str(msg.get('To', '')),
                'recipient': recipient, 'subject': str(msg.get('Subject', '(No subject)')),
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
                      message_id=str(msg.get('Message-ID', '')))
        return result

    def attachment(self, folder, key, index):
        msg = self.read(self.locate(folder, key))
        allowed = {a['id']: a for a in self.message(folder, key)['attachments']}
        if index not in allowed: raise FileNotFoundError('Attachment not found')
        return allowed[index]['name'], list(msg.walk())[index].get_payload(decode=True) or b''

    def flag(self, folder, key, read):
        p = self.locate(folder, key)
        flags = set(p.name.partition(':2,')[2]); flags.discard('S')
        if read: flags.add('S')
        target = p.parent.parent / 'cur' / (p.name.split(':2,')[0] + ':2,' + ''.join(sorted(flags)))
        p.rename(target)

    def move(self, folder, key, target):
        if target not in ('inbox', 'trash') or folder not in ('inbox', 'trash') or target == folder:
            raise ValueError('Only trash and restore are supported')
        p = self.locate(folder, key)
        dest = self.root / FOLDERS[target] / p.parent.name / p.name
        if dest.exists(): raise ValueError('Destination already exists')
        p.rename(dest)

class Drafts:
    def __init__(self, path):
        self.path = str(path)
        with self.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS drafts (id TEXT PRIMARY KEY, data TEXT NOT NULL, status TEXT NOT NULL, updated REAL NOT NULL, queue_id TEXT)')
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
            return [dict(json.loads(data), id=key, status=status, updated=updated, queue_id=queue) for key,data,status,updated,queue in db.execute('SELECT * FROM drafts ORDER BY updated DESC')]
    def get(self, key):
        return next((d for d in self.list() if d['id'] == key), None)
    def save(self, data, identities):
        key = data.get('id') or secrets.token_hex(16)
        if not re.fullmatch('[a-f0-9]{32}', key): raise ValueError('Invalid draft ID')
        sender = header(data.get('from', ''), 254)
        if sender not in identities: raise ValueError('From identity is not authorized')
        clean = {'from': sender, 'to': header(data.get('to', ''), 2000), 'subject': header(data.get('subject', ''), 200),
                 'body': data.get('body', ''), 'in_reply_to': header(data.get('in_reply_to', ''), 998)}
        if not isinstance(clean['body'], str) or len(clean['body'].encode()) > 180000: raise ValueError('Draft is too large')
        with self.db() as db:
            current = db.execute('SELECT status FROM drafts WHERE id=?', (key,)).fetchone()
            if current and current[0] not in ('draft', 'paused'): raise ValueError('Submitted messages cannot be edited')
            db.execute('INSERT INTO drafts VALUES (?,?,?,?,NULL) ON CONFLICT(id) DO UPDATE SET data=excluded.data, status=excluded.status, updated=excluded.updated', (key, json.dumps(clean), 'draft', time.time()))
        return self.get(key)
    def status(self, key, status, queue=None):
        with self.db() as db: db.execute('UPDATE drafts SET status=?,queue_id=?,updated=? WHERE id=?', (status, queue, time.time(), key))

def build_message(draft, identities):
    if draft['from'] not in identities: raise ValueError('From identity is not authorized')
    recipients = addresses(draft['to'])
    msg = EmailMessage(policy=email.policy.SMTP)
    for k,v in [('From',draft['from']),('To',draft['to']),('Subject',draft['subject'])]: msg[k] = header(v, 2000)
    if draft.get('in_reply_to'): msg['In-Reply-To'] = header(draft['in_reply_to'])
    msg['Date'] = formatdate(localtime=False); msg['Message-ID'] = make_msgid(domain='nullverse.cloud')
    msg.set_content(draft['body'])
    raw = msg.as_bytes()
    if len(raw) > 250000: raise ValueError('Message is too large for Postfix')
    return recipients, raw
