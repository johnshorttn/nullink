"""Safe HTML rendering, header details and raw source for the Nullmail reader.

HTML is sanitized server-side (allowlist parser) and then shown client-side in an
iframe sandboxed WITHOUT allow-scripts / allow-same-origin, with a strict CSP meta.
cid: images become bounded data: URIs; remote images are stripped unless allowed.
"""
import base64, html, re
from html.parser import HTMLParser
from email.utils import getaddresses

ALLOWED = {'a','abbr','b','blockquote','br','caption','center','code','col','colgroup','dd','div','dl','dt','em','font','h1','h2','h3','h4','h5','h6',
           'hr','i','img','li','ol','p','pre','q','s','small','span','strike','strong','sub','sup','table','tbody','td','tfoot','th','thead','tr','tt','u','ul',
           'html','body','head','title','style','section','article','header','footer','main','nav','figure','figcaption','picture','big','address','wbr','label'}
DROP_CONTENT = {'script','iframe','object','embed','applet','frame','frameset','noscript','template','svg','math','form','textarea','select','button','input','audio','video','canvas','base','link','meta'}
VOID = {'br','hr','img','col','wbr'}
ATTRS = {'href','src','alt','title','width','height','align','valign','border','cellpadding','cellspacing','colspan','rowspan','bgcolor','color','face','size',
         'style','class','dir','lang','start','type','span','summary','id','name','role','aria-label','target'}
MAX_HTML = 3 * 1024 * 1024
MAX_INLINE = 8 * 1024 * 1024
SAFE_URL = re.compile(r'^(https?:|mailto:|tel:|#)', re.I)
CSS_BAD = re.compile(r'expression\s*\(|javascript:|vbscript:|-moz-binding|-o-link|behavior\s*:|@import|@namespace', re.I)
REMOTE_CSS = re.compile(r'url\(\s*([\'"]?)\s*(?:https?:)?//[^)]*\)', re.I)

class Sanitizer(HTMLParser):
    def __init__(self, cids, remote):
        super().__init__(convert_charrefs=True)
        self.out = []; self.cids = cids; self.remote = remote; self.skip = 0; self.stack = []; self.blocked = 0; self.in_style = False
    def css(self, value):
        # Decode CSS escapes and drop comments first so `exp\72 ession(` or `ex/**/pression(` cannot evade the checks.
        value = re.sub(r'/\*.*?(\*/|$)', '', value, flags=re.S)
        value = re.sub(r'\\([0-9a-fA-F]{1,6})\s?', lambda m: chr(int(m.group(1), 16)) if 0 < int(m.group(1), 16) < 0x110000 else '', value)
        value = re.sub(r'\\(.)', r'\1', value, flags=re.S).replace('\\', '')
        if CSS_BAD.search(value): return ''
        if not self.remote:
            new = REMOTE_CSS.sub('none', value)
            if new != value: self.blocked += 1
            value = new
        return value
    def handle_starttag(self, tag, attrs):
        if self.skip or tag in DROP_CONTENT:
            if tag not in VOID and tag not in ('base', 'link', 'meta', 'input'): self.skip += 1
            return
        if tag not in ALLOWED: return
        clean = []
        for k, v in attrs:
            k = k.lower(); v = v or ''
            if k not in ATTRS or k.startswith('on'): continue
            if k == 'style': v = self.css(v)
            if k == 'href':
                if not SAFE_URL.match(v.strip()): continue
            if k == 'src':
                s = v.strip()
                if tag != 'img': continue
                if s.lower().startswith('cid:'):
                    data = self.cids.get(s[4:].strip('<>'))
                    if not data: continue
                    v = data
                elif re.match(r'^https?:', s, re.I):
                    if not self.remote:
                        self.blocked += 1; clean.append(('data-blocked-src', '1')); continue
                elif s.lower().startswith('data:image/') and len(s) < 2_000_000: v = s
                else: continue
            if k == 'target': continue
            clean.append((k, v))
        if tag == 'a':
            clean += [('target', '_blank'), ('rel', 'noopener noreferrer nofollow')]
        if tag == 'style': self.in_style = True
        self.out.append('<' + tag + ''.join(' %s="%s"' % (k, html.escape(v, quote=True)) for k, v in clean) + '>')
        if tag not in VOID: self.stack.append(tag)
    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID and self.stack and self.stack[-1] == tag and not self.skip: self.handle_endtag(tag)
    def handle_endtag(self, tag):
        if self.skip:
            if tag in DROP_CONTENT: self.skip -= 1
            return
        if tag in self.stack:
            while self.stack:
                t = self.stack.pop(); self.out.append('</' + t + '>')
                if t == 'style': self.in_style = False
                if t == tag: break
    def handle_data(self, data):
        if self.skip: return
        self.out.append(self.css(data).replace('</', '<\\/') if self.in_style else html.escape(data, quote=False))
    def result(self):
        while self.stack: self.out.append('</' + self.stack.pop() + '>')
        return ''.join(self.out)

def csp(remote):
    return "default-src 'none'; img-src data: cid:%s; style-src 'unsafe-inline'; font-src data:; form-action 'none'; base-uri 'none'; frame-src 'none'; script-src 'none'" % (' https: http:' if remote else '')

def render(msg, remote=False):
    """Return {'html': full srcdoc, 'blocked_remote': n} or None when the message has no text/html."""
    part = None; cids = {}; total = 0
    for p in msg.walk():
        if p.is_multipart(): continue
        ctype = p.get_content_type()
        if ctype == 'text/html' and part is None and p.get_content_disposition() != 'attachment': part = p; continue
        cid = str(p.get('Content-ID', '')).strip().strip('<>')
        if cid and ctype.startswith('image/') and not p.get('X-Nullmail-Gmail-Attachment'):
            data = p.get_payload(decode=True) or b''
            if total + len(data) <= MAX_INLINE:
                total += len(data); cids[cid] = 'data:%s;base64,%s' % (ctype, base64.b64encode(data).decode())
    if part is None: return None
    raw = (part.get_payload(decode=True) or b'')[:MAX_HTML]
    try: text = raw.decode(part.get_content_charset() or 'utf-8', errors='replace')
    except LookupError: text = raw.decode('utf-8', errors='replace')
    s = Sanitizer(cids, remote); s.feed(text); s.close(); body = s.result()
    doc = ('<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="%s">'
           '<base target="_blank"><style>html{background:#fff;color-scheme:light;scrollbar-color:#22d3ee #e8eaed;scrollbar-width:auto}body{margin:0;padding:12px 16px;background:#fff;color:#202124;font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.4;overflow-x:auto;overflow-wrap:break-word}img{max-width:100%%;height:auto}table{max-width:none}pre{white-space:pre-wrap}::-webkit-scrollbar{height:12px;width:12px;background:#e8eaed}::-webkit-scrollbar-thumb{background:#22d3ee;border-radius:6px}</style></head><body>%s</body></html>') % (html.escape(csp(remote), quote=True), body)
    return {'html': doc, 'blocked_remote': s.blocked}

def addresses(value): return [a for _, a in getaddresses([str(value or '')]) if a]

def details(msg):
    """Expanded-header data: recipients, ids and authentication results."""
    auth = [str(v) for v in msg.get_all('Authentication-Results', [])][:10]
    text = ' '.join(auth + [str(v) for v in msg.get_all('ARC-Authentication-Results', [])][:5])
    verdict = {}
    for mech in ('spf', 'dkim', 'dmarc'):
        m = re.search(r'\b' + mech + r'\s*=\s*([a-z]+)', text, re.I)
        if m: verdict[mech] = m.group(1).lower()
    if 'spf' not in verdict:
        r = msg.get('Received-SPF')
        if r: verdict['spf'] = str(r).split()[0].lower()
    return {'cc': str(msg.get('Cc', '')), 'bcc': str(msg.get('Bcc', '')), 'reply_to_header': str(msg.get('Reply-To', '')),
            'list_id': str(msg.get('List-Id', '')), 'auth': verdict, 'authentication_results': auth,
            'dkim_domains': re.findall(r'\bd=([A-Za-z0-9.-]+)', ' '.join(str(v) for v in msg.get_all('DKIM-Signature', [])))[:5]}

# ---- Script-safety scan (detection only; scripts never run) ----
SCRIPT_PATTERNS = [
    ('script tag', re.compile(rb'<\s*script\b', re.I)),
    ('inline event handler', re.compile(rb'<[^>]{0,2000}\son[a-z]{3,20}\s*=', re.I)),
    ('javascript: URL', re.compile(rb'(?:href|src|action|formaction)\s*=\s*["\']?\s*(?:java|vb)script:', re.I)),
    ('iframe/frame', re.compile(rb'<\s*i?frame\b', re.I)),
    ('form', re.compile(rb'<\s*form\b', re.I)),
    ('embedded object', re.compile(rb'<\s*(?:object|embed|applet)\b', re.I)),
    ('obfuscated script', re.compile(rb'\beval\s*\(|\batob\s*\(|String\.fromCharCode|document\.write\s*\(|\bunescape\s*\(|(?:\\x[0-9a-f]{2}){12,}|(?:%u[0-9a-f]{4}){6,}', re.I)),
    ('meta refresh', re.compile(rb'<\s*meta[^>]+http-equiv\s*=\s*["\']?refresh', re.I)),
]
RISKY_EXT = {'.html': 'HTML attachment', '.htm': 'HTML attachment', '.xhtml': 'HTML attachment', '.svg': 'SVG (can contain script)', '.js': 'JavaScript',
             '.jse': 'JScript', '.vbs': 'VBScript', '.vbe': 'VBScript', '.hta': 'HTML application', '.ps1': 'PowerShell', '.psm1': 'PowerShell',
             '.bat': 'batch script', '.cmd': 'batch script', '.wsf': 'Windows script', '.wsh': 'Windows script', '.scr': 'screensaver executable',
             '.exe': 'executable', '.msi': 'installer', '.jar': 'Java archive', '.lnk': 'shortcut', '.iso': 'disk image', '.docm': 'macro-enabled Office',
             '.xlsm': 'macro-enabled Office', '.pptm': 'macro-enabled Office', '.dotm': 'macro-enabled Office', '.xlam': 'macro-enabled Office', '.sh': 'shell script'}
SCAN_LIMIT = 4 * 1024 * 1024

def scan(msg):
    """Return a list of {'kind','detail','where'} findings. Bounded; never executes anything."""
    found = []; seen = set(); budget = SCAN_LIMIT
    def add(kind, detail, where):
        k = (kind, where)
        if k not in seen and len(found) < 50: seen.add(k); found.append({'kind': kind, 'detail': detail, 'where': where})
    for i, p in enumerate(msg.walk()):
        if p.is_multipart(): continue
        name = str(p.get_filename() or '').lower(); ctype = p.get_content_type()
        where = name or ctype
        ext = '.' + name.rsplit('.', 1)[-1] if '.' in name else ''
        if ext in RISKY_EXT: add('risky attachment', RISKY_EXT[ext] + ': ' + name, where)
        if ctype in ('application/javascript', 'text/javascript', 'application/x-msdownload', 'application/hta', 'application/x-sh', 'application/vnd.ms-office.vbaproject'):
            add('risky attachment', ctype, where)
        if p.get('X-Nullmail-Gmail-Attachment'): continue          # stored separately; name/type checked above
        if budget <= 0: continue
        data = (p.get_payload(decode=True) or b'')[:budget]; budget -= len(data)
        if ctype in ('text/html', 'image/svg+xml', 'application/xhtml+xml') or ext in ('.html', '.htm', '.svg', '.xhtml', '.hta'):
            for kind, rx in SCRIPT_PATTERNS:
                if rx.search(data): add(kind, 'found in ' + ('HTML body' if not name else name), where)
        if b'vbaProject' in data or (data[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1' and (b'VBA' in data or b'Macros' in data)):
            add('Office macro', 'VBA macro project in ' + (name or ctype), where)
    return found
