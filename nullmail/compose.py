"""Outgoing rich-text (WYSIWYG) composer support.

The browser editor is Quill 2 (BSD-3-Clause, vendored in static/vendor). Its
HTML is never trusted: every save and send re-sanitizes it here with a strict
allowlist parser (stdlib only), converts Quill classes to inline email styles,
turns pasted/inserted data: images into cid: inline parts, and generates the
text/plain alternative.
"""
import base64, html, re, secrets
from html.parser import HTMLParser

TAGS = {'p','br','div','span','b','strong','i','em','u','s','strike','del','a','ol','ul','li','blockquote','pre','code','h1','h2','h3','img','sub','sup','hr','font'}
VOID = {'br','img','hr'}
DROP = {'script','style','iframe','object','embed','applet','frame','frameset','noscript','template','svg','math','form','textarea','select','button','input','audio','video','canvas','base','link','meta','head','title','xml'}
CSS_PROPS = {'color','background-color','font-size','font-family','font-weight','font-style','text-decoration','text-align','padding-left','margin-left','margin','border-left','padding'}
CSS_VALUE = re.compile(r'^[#(),.%\w\s\'"-]{1,120}$')
SAFE_URL = re.compile(r'^(https?:|mailto:|tel:)', re.I)
DATA_IMG = re.compile(r'^data:image/(png|jpeg|gif|webp);base64,([A-Za-z0-9+/=\s]+)$', re.I)
SIZES = {'small': '0.75em', 'large': '1.5em', 'huge': '2.5em'}
FONTS = {'serif': 'Georgia,"Times New Roman",serif', 'monospace': '"Courier New",monospace', 'sans-serif': 'Arial,Helvetica,sans-serif',
         'wide': '"Arial Black",Arial,sans-serif', 'narrow': '"Arial Narrow",Arial,sans-serif', 'comic': '"Comic Sans MS",cursive', 'garamond': 'Garamond,serif',
         'georgia': 'Georgia,serif', 'tahoma': 'Tahoma,sans-serif', 'trebuchet': '"Trebuchet MS",sans-serif', 'verdana': 'Verdana,sans-serif'}
QUOTE = 'margin:0 0 0 .8ex;border-left:1px solid #ccc;padding-left:1ex'
MAX_HTML = 240000
MAX_IMAGES = 10

def _css(value):
    out = []
    for decl in str(value or '').split(';'):
        k, _, v = decl.partition(':'); k = k.strip().lower(); v = v.strip()
        if k in CSS_PROPS and v and CSS_VALUE.match(v) and not re.search(r'url|expression|javascript|@import|\\', v, re.I):
            out.append('%s:%s' % (k, v))
    return out

def _classes(value):
    out = []
    for c in str(value or '').split():
        m = re.fullmatch(r'ql-(align|size|font|indent)-([a-z0-9-]+)', c)
        if not m: continue
        kind, v = m.groups()
        if kind == 'align' and v in ('center', 'right', 'justify'): out.append('text-align:' + v)
        elif kind == 'size' and v in SIZES: out.append('font-size:' + SIZES[v])
        elif kind == 'font' and v in FONTS: out.append('font-family:' + FONTS[v])
        elif kind == 'indent' and v.isdigit() and 1 <= int(v) <= 8: out.append('margin-left:%dem' % (3 * int(v)))
    return out

class _Clean(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out = []; self.stack = []; self.skip = 0; self.images = []; self.token = secrets.token_hex(6)
    def handle_starttag(self, tag, attrs):
        if self.skip or tag in DROP:
            if tag not in VOID and tag not in ('base', 'link', 'meta', 'input'): self.skip += 1
            return
        if tag not in TAGS: return
        a = dict((k.lower(), v or '') for k, v in attrs)
        style = _classes(a.get('class')) + _css(a.get('style'))
        if tag == 'font':  # legacy paste from Word/web → span
            if a.get('color') and re.fullmatch(r'#?[0-9A-Za-z]{3,20}', a['color']): style.append('color:' + a['color'])
            if a.get('face') and CSS_VALUE.match(a['face']): style.append('font-family:' + a['face'])
            tag = 'span'
        if tag == 'blockquote': style = [QUOTE] + style
        clean = []
        if tag == 'a':
            href = a.get('href', '').strip()
            if SAFE_URL.match(href): clean.append(('href', href))
        if tag == 'img':
            src = a.get('src', '').strip(); m = DATA_IMG.match(src)
            if not m or len(self.images) >= MAX_IMAGES: return
            try: data = base64.b64decode(re.sub(r'\s', '', m.group(2)), validate=True)
            except ValueError: return
            cid = 'img%d.%s@nullverse.cloud' % (len(self.images) + 1, self.token)
            self.images.append({'cid': cid, 'subtype': m.group(1).lower(), 'data': data})
            clean.append(('src', 'cid:' + cid)); style.append('max-width:100%')
            if a.get('alt'): clean.append(('alt', a['alt'][:200]))
        if tag == 'ol' and a.get('start', '').isdigit(): clean.append(('start', a['start'][:6]))
        if style: clean.append(('style', ';'.join(style)))
        self.out.append('<' + tag + ''.join(' %s="%s"' % (k, html.escape(v, quote=True)) for k, v in clean) + '>')
        if tag not in VOID: self.stack.append(tag)
    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID and not self.skip and self.stack and self.stack[-1] == tag: self.handle_endtag(tag)
    def handle_endtag(self, tag):
        if self.skip:
            if tag in DROP: self.skip -= 1
            return
        if tag == 'font': tag = 'span'
        if tag in self.stack:
            while self.stack:
                t = self.stack.pop(); self.out.append('</%s>' % t)
                if t == tag: break
    def handle_data(self, data):
        if not self.skip: self.out.append(html.escape(data, quote=False))
    def handle_comment(self, data): pass

def sanitize(value):
    """Return (clean_html_with_cid_images, images). Images are data:-decoded bytes."""
    if not isinstance(value, str): raise ValueError('Invalid HTML body')
    if len(value.encode()) > 4 * MAX_HTML: raise ValueError('Message is too large')
    p = _Clean(); p.feed(value); p.close()
    while p.stack: p.out.append('</%s>' % p.stack.pop())
    return ''.join(p.out), p.images

def restore_images(clean, images):
    """cid: → data: for re-editing a draft in the browser."""
    for img in images: clean = clean.replace('cid:' + img['cid'], 'data:image/%s;base64,%s' % (img['subtype'], base64.b64encode(img['data']).decode()))
    return clean

class _Text(HTMLParser):
    """Each block element (Quill emits one <p> per line) becomes one text line."""
    BLOCK = {'p','div','li','pre','h1','h2','h3','hr'}
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.lines = []; self.cur = None; self.quote = 0; self.lists = []; self.href = None; self.link = []
    def start(self, prefix=''):
        if self.cur is None: self.cur = ['> ' * self.quote + prefix]
    def flush(self):
        if self.cur is not None: self.lines.append(''.join(self.cur).rstrip())
        self.cur = None
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'br':
            self.start(); self.flush() if self.cur != ['> ' * self.quote] else None
            return
        if tag == 'blockquote': self.flush(); self.quote += 1
        elif tag in ('ol', 'ul'): self.flush(); self.lists.append([tag, int(a.get('start') or 1) if str(a.get('start') or '1').isdigit() else 1])
        elif tag == 'li':
            self.flush(); kind = self.lists[-1] if self.lists else ['ul', 1]
            m = re.search(r'margin-left:(\d+)em', a.get('style') or ''); depth = (int(m.group(1)) // 3 if m else 0) + max(len(self.lists) - 1, 0)
            self.start('  ' * depth + ('%d. ' % kind[1] if kind[0] == 'ol' else '- '))
            if kind[0] == 'ol': kind[1] += 1
        elif tag in self.BLOCK: self.flush()
        elif tag == 'img': self.start(); self.cur.append('[image]')
        elif tag == 'a': self.href = a.get('href'); self.link = []
    def handle_endtag(self, tag):
        if tag == 'blockquote': self.flush(); self.quote = max(0, self.quote - 1)
        elif tag in ('ol', 'ul'):
            self.flush()
            if self.lists: self.lists.pop()
        elif tag in self.BLOCK:
            if self.cur is None: self.start()
            self.flush()
        elif tag == 'a':
            text = ''.join(self.link).strip()
            if self.href and not self.href.startswith('mailto:') and self.href != text: self.start(); self.cur.append(' <%s>' % self.href)
            self.href = None
    def handle_data(self, data):
        data = re.sub(r'[ \t\r\n\xa0]+', ' ', data)
        if not data.strip() and self.cur is None: return
        if self.href is not None: self.link.append(data)
        self.start(); self.cur.append(data)

def to_text(clean):
    p = _Text(); p.feed(clean); p.close(); p.flush()
    text = '\n'.join(p.lines)
    return re.sub(r'\n{3,}', '\n\n', text).strip('\n') + '\n'

def document(clean):
    return ('<!doctype html><html><head><meta charset="utf-8"></head><body>'
            '<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px">%s</div></body></html>' % clean)
