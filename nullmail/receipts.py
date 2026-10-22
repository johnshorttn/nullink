"""Delivery confirmation (DSN / bounces), read receipts (MDN) and optional open tracking.

Everything here is observational. A DSN 'delivered' only means the receiving MTA said so;
a missing DSN proves nothing (many MTAs never return success DSNs). MDNs are voluntary and
the recipient's client may never send one. Open pixels are blocked or pre-fetched by many
clients (Gmail proxies images; Apple Mail Privacy Protection pre-loads them), so an 'open'
is a hint, not proof. Nullmail never sends an MDN automatically.
"""
import email.policy, re, secrets, time
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import formatdate, make_msgid, parseaddr

SCHEMA = [
    'CREATE TABLE IF NOT EXISTS outbound_meta(draft TEXT PRIMARY KEY, message_id TEXT, envid TEXT, dsn INTEGER NOT NULL DEFAULT 0, mdn INTEGER NOT NULL DEFAULT 0, track TEXT, recipients TEXT, provider TEXT, sent REAL)',
    'CREATE INDEX IF NOT EXISTS outbound_meta_msgid ON outbound_meta(message_id)',
    'CREATE UNIQUE INDEX IF NOT EXISTS outbound_meta_track ON outbound_meta(track)',
    'CREATE TABLE IF NOT EXISTS receipt_events(id INTEGER PRIMARY KEY, draft TEXT NOT NULL, kind TEXT NOT NULL, recipient TEXT, status TEXT NOT NULL, detail TEXT, at REAL NOT NULL, source TEXT)',
    'CREATE UNIQUE INDEX IF NOT EXISTS receipt_events_source ON receipt_events(source,recipient,kind) WHERE source IS NOT NULL',
    'CREATE TABLE IF NOT EXISTS receipt_scanned(key TEXT PRIMARY KEY, at REAL NOT NULL)',
    'CREATE TABLE IF NOT EXISTS mdn_responses(key TEXT PRIMARY KEY, action TEXT NOT NULL, status TEXT, at REAL NOT NULL)',
]
PIXEL = (b'GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00'
         b',\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;')
TRACK_RE = re.compile(r'[A-Za-z0-9_-]{24}')
MAX_OPENS = 500

def init(db):
    for s in SCHEMA: db.execute(s)

def new_track_token(): return secrets.token_urlsafe(18)

def record_outbound(db, draft, message_id, envid, dsn, mdn, track, recipients, provider):
    init(db)
    db.execute('INSERT OR REPLACE INTO outbound_meta VALUES (?,?,?,?,?,?,?,?,?)',
               (draft, message_id, envid, int(bool(dsn)), int(bool(mdn)), track, ','.join(recipients), provider, time.time()))

def record_open(db, token, now=None):
    """Unauthenticated pixel hit. Stores time only (no IP, no user agent). Rate-limited per token."""
    init(db); now = now or time.time()
    if not TRACK_RE.fullmatch(token or ''): return False
    row = db.execute('SELECT draft FROM outbound_meta WHERE track=?', (token,)).fetchone()
    if not row: return False
    last = db.execute("SELECT MAX(at),COUNT(*) FROM receipt_events WHERE draft=? AND kind='open'", (row[0],)).fetchone()
    if (last[0] and now - last[0] < 60) or last[1] >= MAX_OPENS: return False
    db.execute("INSERT INTO receipt_events(draft,kind,recipient,status,detail,at,source) VALUES (?,?,?,?,?,?,NULL)", (row[0], 'open', None, 'opened', None, now))
    return True

def _norm_id(v): 
    v = str(v or '').strip()
    m = re.search(r'<[^<>\s]+>', v)
    return m.group(0) if m else v

def _fields(part):
    """message/delivery-status and message/disposition-notification → list of header blocks."""
    payload = part.get_payload()
    if isinstance(payload, list): return [dict((k.lower(), str(v)) for k, v in p.items()) for p in payload]
    text = payload if isinstance(payload, str) else ''
    blocks = []
    for chunk in re.split(r'\r?\n\s*\r?\n', text):
        b = {}
        for line in re.split(r'\r?\n(?![ \t])', chunk.strip()):
            if ':' in line: k, v = line.split(':', 1); b[k.strip().lower()] = ' '.join(v.split())
        if b: blocks.append(b)
    return blocks

def _original_ids(msg):
    ids = []
    for part in msg.walk():
        ct = part.get_content_type()
        if ct == 'text/rfc822-headers':
            raw = part.get_payload(decode=True) or b''
            ids.append(_norm_id(BytesParser(policy=email.policy.default).parsebytes(raw).get('Message-ID')))
        elif ct == 'message/rfc822':
            inner = part.get_payload()
            inner = inner[0] if isinstance(inner, list) and inner else inner
            if hasattr(inner, 'get'): ids.append(_norm_id(inner.get('Message-ID')))
    for h in ('In-Reply-To', 'References'):
        ids += re.findall(r'<[^<>\s]+>', str(msg.get(h, '')))
    return [i for i in ids if i]

ACTIONS = {'delivered': 'delivered', 'relayed': 'relayed', 'expanded': 'delivered', 'delayed': 'delayed', 'failed': 'bounced'}

def parse(msg):
    """Return {'kind':'dsn'|'mdn', 'envid', 'message_ids', 'events':[{recipient,status,detail}]} or None."""
    ct = msg.get_content_type(); rtype = (msg.get_param('report-type') or '').lower()
    if ct == 'multipart/report' and rtype in ('delivery-status', 'disposition-notification'):
        want = 'message/delivery-status' if rtype == 'delivery-status' else 'message/disposition-notification'
        blocks = []
        for part in msg.walk():
            if part.get_content_type() == want: blocks = _fields(part); break
        if not blocks: return None
        head = blocks[0]; ids = _original_ids(msg)
        if rtype == 'disposition-notification':
            if head.get('original-message-id'): ids.insert(0, _norm_id(head['original-message-id']))
            disp = head.get('disposition', '').lower(); rcpt = head.get('final-recipient', '').split(';')[-1].strip()
            status = 'read' if 'displayed' in disp else ('deleted' if 'deleted' in disp else 'other')
            return {'kind': 'mdn', 'envid': None, 'message_ids': ids, 'events': [{'recipient': rcpt, 'status': status, 'detail': disp[:200]}]}
        events = []
        for b in blocks:
            if 'action' not in b: continue
            action = b['action'].lower().split()[0]
            rcpt = (b.get('final-recipient') or b.get('original-recipient') or '').split(';')[-1].strip()
            events.append({'recipient': rcpt, 'status': ACTIONS.get(action, 'other'),
                           'detail': ' '.join(x for x in (b.get('status', ''), b.get('diagnostic-code', '')) if x)[:300]})
        return {'kind': 'dsn', 'envid': head.get('original-envelope-id'), 'message_ids': ids, 'events': events} if events else None
    # Non-standard bounce (e.g. some Gmail/Google notices): mailer-daemon sender with failed-recipient header.
    sender = parseaddr(str(msg.get('From', '')))[1].lower()
    if re.match(r'(mailer-daemon|postmaster)@', sender) and (msg.get('X-Failed-Recipients') or re.search(r'(undeliver|delivery status notification|failure|returned mail)', str(msg.get('Subject', '')), re.I)):
        rcpts = [r.strip() for r in str(msg.get('X-Failed-Recipients', '')).split(',') if r.strip()] or [None]
        return {'kind': 'dsn', 'envid': None, 'message_ids': _original_ids(msg),
                'events': [{'recipient': r, 'status': 'bounced', 'detail': str(msg.get('Subject', ''))[:200]} for r in rcpts]}
    return None

def ingest(db, key, msg, now=None):
    """Match one report to an outbound message; returns the draft ID or None. Idempotent per message key."""
    init(db)
    if db.execute('SELECT 1 FROM receipt_scanned WHERE key=?', (key,)).fetchone(): return None
    db.execute('INSERT INTO receipt_scanned VALUES (?,?)', (key, time.time()))
    report = parse(msg)
    if not report: return None
    draft = None
    if report['envid']:
        row = db.execute('SELECT draft FROM outbound_meta WHERE envid=?', (report['envid'].strip(),)).fetchone(); draft = row and row[0]
    for mid in report['message_ids']:
        if draft: break
        row = db.execute('SELECT draft FROM outbound_meta WHERE message_id=?', (mid,)).fetchone(); draft = row and row[0]
    if not draft: return None
    at = now or time.time()
    for e in report['events']:
        db.execute('INSERT OR IGNORE INTO receipt_events(draft,kind,recipient,status,detail,at,source) VALUES (?,?,?,?,?,?,?)',
                   (draft, report['kind'], (e['recipient'] or '').lower() or None, e['status'], e['detail'], at, key))
    return draft

def scan(db, mail, folders=('inbox', 'spam'), limit=400):
    """Scan unseen messages for DSN/MDN/bounce reports. Only small, unseen files are parsed."""
    init(db); seen = {r[0] for r in db.execute('SELECT key FROM receipt_scanned')}; done = 0
    for folder in folders:
        for p in mail.files(folder):
            key = mail.key(p)
            if key in seen: continue
            if done >= limit: return done
            done += 1
            try: msg = mail.read(p)
            except Exception:
                db.execute('INSERT OR IGNORE INTO receipt_scanned VALUES (?,?)', (key, time.time())); continue
            ingest(db, key, msg)
    return done

def summary(db, draft):
    """Overall status: scheduled/sent → delivered | delayed | bounced (+ read / opens)."""
    init(db)
    meta = db.execute('SELECT message_id,dsn,mdn,track,recipients,provider,sent FROM outbound_meta WHERE draft=?', (draft,)).fetchone()
    if not meta: return None
    rows = db.execute('SELECT kind,recipient,status,detail,at FROM receipt_events WHERE draft=? ORDER BY at', (draft,)).fetchall()
    per = {}
    for kind, rcpt, status, detail, at in rows:
        if kind == 'dsn': per[rcpt or '*'] = {'status': status, 'detail': detail, 'at': at}
    states = [v['status'] for v in per.values()]
    if 'bounced' in states: overall = 'bounced'
    elif states and all(s in ('delivered', 'relayed') for s in states): overall = 'delivered'
    elif 'delayed' in states: overall = 'delayed'
    else: overall = 'sent'
    reads = [r for r in rows if r[0] == 'mdn' and r[2] == 'read']
    opens = [r[4] for r in rows if r[0] == 'open']
    return {'status': overall, 'recipients': per, 'relayed_only': bool(states) and all(s == 'relayed' for s in states),
            'dsn_requested': bool(meta[1]), 'read_receipt_requested': bool(meta[2]), 'tracking': bool(meta[3]),
            'read': [{'recipient': r[1], 'at': r[4]} for r in reads], 'read_at': reads[0][4] if reads else None,
            'opens': len(opens), 'first_open': opens[0] if opens else None, 'last_open': opens[-1] if opens else None,
            'provider': meta[5], 'message_id': meta[0]}

def by_message_id(db, message_id):
    init(db); row = db.execute('SELECT draft FROM outbound_meta WHERE message_id=?', (_norm_id(message_id),)).fetchone()
    return summary(db, row[0]) if row else None

# Incoming read-receipt requests. Never answered automatically.
def mdn_request(msg):
    dnt = str(msg.get('Disposition-Notification-To', '') or '').strip()
    if not dnt: return None
    addr = parseaddr(dnt)[1]
    if not re.fullmatch(r'[^\s<>@]{1,200}@[^\s<>@]{1,200}', addr or ''): return None
    rp = parseaddr(str(msg.get('Return-Path', '') or ''))[1]
    return {'to': addr, 'return_path_mismatch': bool(rp) and rp.lower() != addr.lower()}

def mdn_state(db, key):
    init(db); row = db.execute('SELECT action,status,at FROM mdn_responses WHERE key=?', (key,)).fetchone()
    return {'action': row[0], 'status': row[1], 'at': row[2]} if row else None

def mdn_claim(db, key, action):
    init(db)
    if db.execute('SELECT 1 FROM mdn_responses WHERE key=?', (key,)).fetchone(): raise ValueError('This read-receipt request was already answered')
    db.execute('INSERT INTO mdn_responses VALUES (?,?,?,?)', (key, action, 'pending' if action == 'send' else None, time.time()))

def mdn_done(db, key, status):
    db.execute('UPDATE mdn_responses SET status=? WHERE key=?', (status, key))

def build_mdn(original, sender, to):
    """RFC 8098 manual-action MDN for a message John chose to acknowledge."""
    msg = EmailMessage(policy=email.policy.SMTP)
    msg['From'] = sender; msg['To'] = to
    msg['Subject'] = 'Read: ' + str(original.get('Subject', ''))[:180]
    msg['Date'] = formatdate(localtime=False); msg['Message-ID'] = make_msgid(domain='nullverse.cloud')
    oid = _norm_id(original.get('Message-ID'))
    if oid: msg['In-Reply-To'] = oid; msg['References'] = oid
    msg.set_content('The message sent to %s was displayed. This is no guarantee that it was read or understood.\n' % sender)
    fields = 'Reporting-UA: nullmail.nullverse.cloud; Nullmail\r\nFinal-Recipient: rfc822;%s\r\n' % sender
    if oid: fields += 'Original-Message-ID: %s\r\n' % oid
    fields += 'Disposition: manual-action/MDN-sent-manually; displayed\r\n'
    msg.make_mixed()
    from email.mime.base import MIMEBase
    part = MIMEBase('message', 'disposition-notification'); part.set_payload(fields)
    msg.attach(part)
    msg.set_type('multipart/report'); msg.set_param('report-type', 'disposition-notification')
    return msg.as_bytes()
