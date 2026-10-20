import email, email.policy, pathlib, sys, tempfile, unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import compose
from core import Drafts, build_message

PNG = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=='
IDS = ['john@nullverse.cloud']

class SanitizeTests(unittest.TestCase):
    def test_strips_scripts_handlers_and_bad_urls(self):
        h, imgs = compose.sanitize('<p onclick="x()">Hi<script>alert(1)</script><iframe src="https://e"></iframe>'
                                   '<a href="javascript:alert(1)">x</a><a href="https://ok.example">ok</a>'
                                   '<img src="https://track.example/p.gif"><span style="color:red;background:url(https://e)">c</span></p><style>p{}</style>')
        for bad in ('script', 'onclick', 'iframe', 'javascript:', 'track.example', 'url(', '<style'):
            self.assertNotIn(bad, h)
        self.assertIn('href="https://ok.example"', h); self.assertIn('color:red', h); self.assertEqual(imgs, [])
    def test_quill_classes_become_inline_styles(self):
        h, _ = compose.sanitize('<p class="ql-align-center ql-evil">a</p><p><span class="ql-size-large ql-font-serif">b</span></p><ol><li class="ql-indent-2">c</li></ol>')
        self.assertIn('text-align:center', h); self.assertIn('font-size:1.5em', h); self.assertIn('Georgia', h); self.assertIn('margin-left:6em', h)
        self.assertNotIn('class=', h)
    def test_word_paste_cleanup(self):
        h, _ = compose.sanitize('<!--[if gte mso 9]><xml><o:x/></xml><![endif]--><p class="MsoNormal" style="mso-line-height:1;color:#333"><font face="Calibri" color="#ff0000">Word</font><o:p></o:p></p>')
        self.assertNotIn('mso', h.lower()); self.assertNotIn('<font', h); self.assertNotIn('o:p', h); self.assertIn('Word', h); self.assertIn('color:#ff0000', h)
    def test_data_images_become_cid(self):
        h, imgs = compose.sanitize('<p><img src="data:image/png;base64,%s"><img src="data:image/svg+xml;base64,PHN2Zz4="></p>' % PNG)
        self.assertEqual(len(imgs), 1); self.assertIn('cid:' + imgs[0]['cid'], h); self.assertNotIn('svg', h)
        self.assertIn('data:image/png', compose.restore_images(h, imgs))
    def test_plain_text_generation(self):
        h, _ = compose.sanitize('<p><strong>Hello</strong></p><ol><li>one</li><li>two</li></ol><ul><li>dot</li></ul>'
                                '<blockquote>quoted line</blockquote><p><a href="https://x.example">site</a></p>')
        self.assertEqual(compose.to_text(h), 'Hello\n1. one\n2. two\n- dot\n> quoted line\nsite <https://x.example>\n')

class MessageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.drafts = Drafts(pathlib.Path(self.tmp.name) / 'd.db')
    def tearDown(self): self.tmp.cleanup()
    def test_draft_preserves_sanitized_html_and_regenerates_text(self):
        d = self.drafts.save({'from': IDS[0], 'to': 'john@nullverse.cloud', 'subject': 's', 'body': 'browser text ignored',
                              'body_html': '<p><em>Rich</em><img src=x onerror=alert(1)></p><p><img src="data:image/png;base64,%s"></p>' % PNG,
                              'body_delta': '{"ops":[{"insert":"Rich\\n"}]}'}, IDS)
        self.assertIn('<em>Rich</em>', d['body_html']); self.assertNotIn('onerror', d['body_html']); self.assertIn('data:image/png', d['body_html'])
        self.assertTrue(d['body'].startswith('Rich')); self.assertEqual(d['body_delta'], '{"ops":[{"insert":"Rich\\n"}]}')
    def test_multipart_alternative_with_inline_image(self):
        d = {'from': IDS[0], 'to': 'john@nullverse.cloud', 'subject': 'Rich', 'body': '', 'in_reply_to': '<a@b>',
             'body_html': '<p><strong>Bold</strong> <script>x</script></p><p><img src="data:image/png;base64,%s"></p>' % PNG}
        _, raw = build_message(d, IDS)
        msg = email.message_from_bytes(raw, policy=email.policy.default)
        self.assertEqual(msg.get_content_type(), 'multipart/alternative')
        self.assertEqual(msg.get_body(('plain',)).get_content().replace('\r\n', '\n').strip(), 'Bold\n[image]')
        html_part = msg.get_body(('html',)); body = html_part.get_content()
        self.assertIn('<strong>Bold</strong>', body); self.assertNotIn('script', body)
        img = [p for p in msg.walk() if p.get_content_type() == 'image/png'][0]
        self.assertIn('cid:' + str(img['Content-ID']).strip('<>'), body)
        self.assertEqual(msg['In-Reply-To'], '<a@b>')
    def test_plain_drafts_unchanged(self):
        _, raw = build_message({'from': IDS[0], 'to': 'john@nullverse.cloud', 'subject': 'p', 'body': 'Plain only'}, IDS)
        msg = email.message_from_bytes(raw, policy=email.policy.default)
        self.assertEqual(msg.get_content_type(), 'text/plain')

class StaticTests(unittest.TestCase):
    root = pathlib.Path(__file__).resolve().parents[1] / 'static'
    def test_vendored_editor_no_cdn(self):
        index = (self.root / 'index.html').read_text()
        self.assertIn('/vendor/quill.js', index); self.assertNotRegex(index, r'src="https?://')
        self.assertIn('Redistribution and use', (self.root / 'vendor' / 'QUILL-LICENSE.txt').read_text())
        self.assertIn('Quill Editor v2.0.3', (self.root / 'vendor' / 'quill.js.LICENSE.txt').read_text())
        self.assertNotRegex((self.root / 'vendor' / 'quill.js').read_text(), r'cdn\.|googleapis|unpkg')
    def test_toolbar_has_gmail_controls(self):
        js = (self.root / 'composer.js').read_text()
        for c in ('ql-undo', 'ql-redo', 'ql-font', 'ql-size', 'ql-bold', 'ql-italic', 'ql-underline', 'ql-color', 'ql-align', "'ordered'", "'bullet'",
                  'ql-indent', 'ql-blockquote', 'ql-strike', 'ql-clean', 'ql-link', 'ql-image', 'ql-emoji'):
            self.assertIn(c, js)

if __name__ == '__main__': unittest.main()
