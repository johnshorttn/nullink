import unittest, pathlib, re
S = pathlib.Path(__file__).resolve().parents[1] / 'static'
class LayoutTree(unittest.TestCase):
    def test_desktop_main_pinned_and_independent_scroll(self):
        css = (S / 'style.css').read_text()
        block = css.split('/* Desktop layout:')[1]
        self.assertIn('main{margin:0 auto;align-self:start', block)
        self.assertIn('aside{overflow-y:auto', block)
        self.assertIn('height:100vh', block)
    def test_local_tree_grouped_and_collapsed_by_default(self):
        js = (S / 'workspace.js').read_text()
        self.assertIn("localAccountTree(accountConfig.accounts.filter(a=>a.provider==='local'))", js)
        self.assertIn("const open=k=>!!treeOpen[k]", js)
        self.assertIn("'ldom:'+d", js); self.assertIn("'luser:'+a.id", js)
        self.assertNotIn("group.open=provider==='local'", js)
if __name__ == '__main__': unittest.main()
