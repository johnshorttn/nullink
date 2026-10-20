import email, email.policy, pathlib, sys, unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import reader
from test_nullmail import HttpTests as _Base

def mail(body):
    return email.message_from_bytes(b'From: News <n@shop.test>\r\nTo: john@nullverse.cloud\r\nSubject: s\r\nContent-Type: text/html\r\n\r\n' + body, policy=email.policy.default)
def body(r): return r['html'].split('<body>', 1)[1]

class ReaderCssTests(unittest.TestCase):
    def test_styles_preserved(self):
        b = body(reader.render(mail(b'<style>.hero{color:#ff6600;font-size:22px}td{padding:8px}</style><table style="width:600px;background-color:#f4f4f4"><tr><td class="hero" style="color:#123456;text-align:center">Sale</td></tr></table>')))
        for s in ('.hero{color:#ff6600;font-size:22px}', 'width:600px;background-color:#f4f4f4', 'color:#123456;text-align:center', 'class="hero"'):
            self.assertIn(s, b)
    def test_dangerous_css_stripped(self):
        for evil in (b'width:expression(alert(1))', b'behavior:url(x.htc)', b'-moz-binding:url(x.xml#a)', b'background:url(javascript:alert(1))',
                     b'width:exp\\72 ession(alert(1))', b'width:ex/**/pression(alert(1))', b'x:\\65 xpression(1)'):
            b = body(reader.render(mail(b'<div style="' + evil + b'">x</div>')))
            self.assertNotRegex(b.lower(), r'expression|behavior|binding|javascript', evil)
        b = body(reader.render(mail(b'<style>@import url(https://e.test/a.css);@\\69mport "https://e.test/b.css";p{color:red}</style><p>x</p>')))
        self.assertNotIn('@import', b); self.assertNotIn('e.test', b)
        b = body(reader.render(mail(b'<p onclick="x()" onmouseover=y>a<script>s()</script><a href="javascript:z()">j</a></p>')))
        for s in ('onclick', 'onmouseover', '<script', 'javascript:'): self.assertNotIn(s, b)
    def test_remote_url_blocked_unless_allowed(self):
        src = b'<style>.b{background:url("https://t.test/bg.png")}</style><div style="background-image:url(//t.test/x.png)">x</div><img src="https://t.test/p.gif">'
        r = reader.render(mail(src)); b = body(r)
        self.assertNotIn('t.test', b); self.assertEqual(r['blocked_remote'], 3); self.assertNotIn('https:', reader.csp(False))
        r = reader.render(mail(src), remote=True); b = body(r)
        self.assertIn('https://t.test/bg.png', b); self.assertNotIn('script', reader.csp(True).replace("script-src 'none'", ''))
    def test_frame_document_is_white_and_scrolls(self):
        h = reader.render(mail(b'<p>x</p>'))['html']
        self.assertIn('background:#fff', h); self.assertIn('overflow-x:auto', h); self.assertIn('#22d3ee', h); self.assertIn('max-width:100%', h)

class FrameHttpTests(_Base):
    def test_frame_endpoint_has_iframe_only_csp(self):
        mid = self.req('/api/v1/messages')[1]['messages'][0]['id']
        s, b, h = self.req('/api/v1/message/frame?folder=inbox&id=' + mid)
        self.assertEqual(s, 200); self.assertTrue(h['Content-Type'].startswith('text/html'))
        csp = h['Content-Security-Policy']
        self.assertIn("style-src 'unsafe-inline'", csp); self.assertIn("script-src 'none'", csp); self.assertIn('sandbox', csp)
        self.assertNotIn('allow-scripts', csp); self.assertNotIn('allow-same-origin', csp); self.assertIn("frame-ancestors 'self'", csp)
        self.assertNotIn(b'<script', b.split(b'<body>', 1)[1])
        self.assertEqual(self.req('/api/v1/message/frame?folder=inbox&id=' + mid, cookie='')[0], 401)
        s, _, h = self.req('/')
        self.assertIn("style-src 'self'", h['Content-Security-Policy']); self.assertNotIn('unsafe-inline', h['Content-Security-Policy']); self.assertIn("frame-src 'self'", h['Content-Security-Policy'])

if __name__ == '__main__': unittest.main()
