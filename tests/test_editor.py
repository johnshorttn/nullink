"""Advanced editor (ed1): changed-since-open conflict check on save (409 unless force),
version info on open/save, vendored CodeMirror served, and the HTML sanitizer (run in headless
Chrome when available)."""
import hashlib
import json
import os
import shutil
import unittest
from pathlib import Path

import server
from tests.test_files_manager import FMBase, _put

ROOT = Path(__file__).resolve().parent.parent


class ConflictTests(FMBase):
    def open(self, fid="aaa111"):
        st, _, js, _ = self.j(f"/api/files/{fid}/content", method="GET")
        self.assertEqual(st, 200, js)
        return js

    def test_open_returns_version(self):
        js = self.open()
        self.assertEqual(js["sha256"], hashlib.sha256(b"alpha\n").hexdigest())
        self.assertIsInstance(js["mtime_ns"], int)

    def test_save_with_matching_base_ok_and_returns_new_version(self):
        base = self.open()["sha256"]
        st, _, js, _ = self.j("/api/files/save", {"id": "aaa111", "content": "beta\n", "base_sha256": base})
        self.assertEqual(st, 200, js)
        self.assertEqual(js["sha256"], hashlib.sha256(b"beta\n").hexdigest())
        # chained save with the new version also succeeds
        st, _, js2, _ = self.j("/api/files/save", {"id": "aaa111", "content": "gamma\n", "base_sha256": js["sha256"]})
        self.assertEqual(st, 200, js2)

    def test_changed_since_open_409_then_force(self):
        base = self.open()["sha256"]
        _put("data/files/a.txt", b"changed elsewhere\n")
        st, _, js, _ = self.j("/api/files/save", {"id": "aaa111", "content": "mine\n", "base_sha256": base})
        self.assertEqual((st, js["error"]), (409, "conflict"))
        self.assertEqual(js["sha256"], hashlib.sha256(b"changed elsewhere\n").hexdigest())
        self.assertEqual((server.BASE / "data/files/a.txt").read_bytes(), b"changed elsewhere\n")
        st, _, js, _ = self.j("/api/files/save", {"id": "aaa111", "content": "mine\n", "base_sha256": base, "force": True})
        self.assertEqual(st, 200, js)
        self.assertEqual((server.BASE / "data/files/a.txt").read_bytes(), b"mine\n")

    def test_mtime_only_base(self):
        js = self.open()
        st, *_ = self.j("/api/files/save", {"id": "aaa111", "content": "x\n", "base_mtime_ns": js["mtime_ns"]})
        self.assertEqual(st, 200)
        st, _, js2, _ = self.j("/api/files/save", {"id": "aaa111", "content": "y\n", "base_mtime_ns": 1})
        self.assertEqual((st, js2["error"]), (409, "conflict"))

    def test_legacy_save_without_base_still_works(self):
        st, *_ = self.j("/api/files/save", {"id": "aaa111", "content": "legacy\n"})
        self.assertEqual(st, 200)

    def test_fm_alias_content_has_version(self):
        st, _, js, _ = self.j("/api/fm/files/aaa111/content", method="GET")
        self.assertEqual(st, 200)
        self.assertIn("sha256", js)

    def test_vendored_assets_served(self):
        for path, ctype in (("/vendor/codemirror/codemirror.bundle.js", "application/javascript"),
                            ("/editor.js", "application/javascript"), ("/sanitize.js", "application/javascript"),
                            ("/vendor/codemirror/LICENSE.txt", "text/plain")):
            st, h, _, _ = self.req(path)
            self.assertEqual(st, 200, path)
            h = {k.lower(): v for k, v in h}
            self.assertTrue(h["content-type"].startswith(ctype), path)
        lic = (ROOT / "static/vendor/codemirror/LICENSE.txt").read_text()
        self.assertIn("MIT License", lic)
        self.assertIn("marked", lic)


CASES = [
    ("<p>ok <b>bold</b></p>", ["<p>ok <b>bold</b></p>"], []),
    ("<script>alert(1)</script><p>x</p>", ["<p>x</p>"], ["script", "alert"]),
    ('<img src=x onerror="alert(1)">', ['<img src="x">'], ["onerror", "alert"]),
    ('<a href="javascript:alert(1)">x</a>', ["<a>x</a>"], ["javascript"]),
    ('<a href=" JaVa\tScRiPt:alert(1)">x</a>', ["<a>x</a>"], ["alert"]),
    ('<a href="https://ok.example/" onclick="evil()" target="_top">x</a>',
     ['href="https://ok.example/"', 'rel="noopener noreferrer"', 'target="_blank"'], ["onclick", "evil", "_top"]),
    ('<iframe src="https://x"></iframe><object data=x></object><embed src=x>', [""], ["iframe", "object", "embed"]),
    ('<svg><script>alert(1)</script></svg><math><mi>x</mi></math>', [""], ["svg", "alert", "math"]),
    ('<style>body{display:none}</style><div style="background:url(javascript:x)">y</div>', ["<div>y</div>"], ["style", "javascript"]),
    ('<img src="data:image/png;base64,iVBORw0KGgo=">', ['src="data:image/png;base64,iVBORw0KGgo="'], []),
    ('<img src="data:text/html;base64,PHNjcmlwdD4=">', ["<img>"], ["data:"]),
    ('<a href="data:text/html,<script>x</script>">d</a>', ["<a>d</a>"], ["data:"]),
    ('<form action=x><input value=1><button formaction="javascript:x">b</button></form>', [""], ["form", "input", "button"]),
    ('<custom-el onmouseover="x()">kept text</custom-el>', ["kept text"], ["custom-el", "onmouseover"]),
    ('<table><tr><td colspan=2 onclick=x>c</td></tr></table>', ['colspan="2"'], ["onclick"]),
    ("<!-- c --><p>t</p>", ["<p>t</p>"], ["<!--"]),
    ('<a href="//evil.example/">p</a>', ["<a>p</a>"], ["evil"]),
    ('<a href="mailto:a@b.c">m</a>', ['href="mailto:a@b.c"'], []),
]


def _chrome():
    for p in ("/usr/bin/google-chrome", "/opt/google/chrome/chrome", shutil.which("chromium") or "", shutil.which("chromium-browser") or ""):
        if p and os.path.exists(p):
            return p
    return None


class SanitizerTests(unittest.TestCase):
    """Runs static/sanitize.js in a real browser DOM (the same parser it uses in production)."""

    @classmethod
    def setUpClass(cls):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise unittest.SkipTest("playwright not installed")
        exe = _chrome()
        if not exe:
            raise unittest.SkipTest("no Chrome/Chromium available")
        cls._pw = sync_playwright().start()
        cls._browser = cls._pw.chromium.launch(executable_path=exe, args=["--no-sandbox"])
        cls.page = cls._browser.new_page()
        cls.page.set_content("<!doctype html><html><body></body></html>")
        cls.page.add_script_tag(content=(ROOT / "static/sanitize.js").read_text())

    @classmethod
    def tearDownClass(cls):
        cls._browser.close()
        cls._pw.stop()

    def test_cases(self):
        results = self.page.evaluate("cases => cases.map(c => NLSanitize.sanitize(c))", [c[0] for c in CASES])
        for (src, must, mustnot), out in zip(CASES, results):
            low = out.lower()
            for m in must:
                self.assertIn(m, out, f"{src!r} -> {out!r}")
            for m in mustnot:
                self.assertNotIn(m.lower(), low, f"{src!r} -> {out!r}")

    def test_preview_doc_has_csp_and_no_scripts(self):
        doc = self.page.evaluate("() => NLSanitize.previewDoc(NLSanitize.sanitize('<p onclick=x>a</p><script>b</script>'), true)")
        self.assertIn("default-src 'none'", doc)
        self.assertNotIn("<script", doc)
        self.assertNotIn("onclick", doc)

    def test_safe_url(self):
        r = self.page.evaluate("""() => [NLSanitize.safeUrl('https://a'), NLSanitize.safeUrl('javascript:x'),
            NLSanitize.safeUrl('vbscript:x'), NLSanitize.safeUrl('/rel'), NLSanitize.safeUrl('#a'),
            NLSanitize.safeUrl('data:image/png;base64,AA==', true), NLSanitize.safeUrl('data:image/svg+xml;base64,AA==', true)]""")
        self.assertEqual(r, ["https://a", None, None, "/rel", "#a", "data:image/png;base64,AA==", None])


class EditorWiringTests(unittest.TestCase):
    def test_index_loads_editor_and_sanitizer(self):
        html = (ROOT / "static/index.html").read_text()
        self.assertIn('src="/sanitize.js', html)
        self.assertIn('type="module" src="/editor.js', html)
        self.assertLess(html.index("/sanitize.js"), html.index("/editor.js"))

    def test_preview_iframe_is_sandboxed_without_scripts(self):
        js = (ROOT / "static/editor.js").read_text()
        self.assertIn('prev.setAttribute("sandbox", "")', js)
        self.assertNotIn("allow-scripts", js)
        self.assertNotIn("allow-same-origin", js)
        # every srcdoc write goes through the sanitizer
        for line in js.splitlines():
            if "srcdoc" in line and "=" in line:
                self.assertIn("S.sanitize", line)
            if ".innerHTML =" in line:
                self.assertIn("S.sanitize", line)

    def test_save_sends_base_and_handles_409(self):
        js = (ROOT / "static/app.js").read_text()
        self.assertIn("base_sha256", js)
        self.assertIn("r.status === 409", js)
        self.assertIn("body.force = true", js)


if __name__ == "__main__":
    unittest.main()
