"""Files sort + "Latest of similar names" (static/fm-sort.js) — runs the node test harness."""
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")


@unittest.skipUnless(NODE, "node not installed")
class FmSortJsTests(unittest.TestCase):
    def test_js_sort_and_grouping(self):
        r = subprocess.run([NODE, str(ROOT / "tests" / "js" / "fm_sort_test.js")], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("OK 9", r.stdout)


class FmSortWiringTests(unittest.TestCase):
    def test_index_loads_sort_before_manager_and_has_control(self):
        html = (ROOT / "static" / "index.html").read_text()
        self.assertIn('id="fm-sort"', html)
        self.assertLess(html.index("/fm-sort.js"), html.index("/files-manager.js"))

    def test_manager_uses_sort_storage_and_upload_last_modified(self):
        js = (ROOT / "static" / "files-manager.js").read_text()
        self.assertIn('"nl.fm.sort"', js)
        self.assertIn("last_modified: f.lastModified", js)
        self.assertIn("similarGroups", js)
        self.assertIn("Newest of ${g.n} similar files", js)
        app = (ROOT / "static" / "app.js").read_text()
        self.assertIn('fd.append("last_modified"', app)
        self.assertIn("labelFilter: () =>", app)
