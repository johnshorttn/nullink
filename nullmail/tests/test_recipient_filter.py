import unittest, pathlib
S = pathlib.Path(__file__).resolve().parents[1] / 'static'
class RecipientFilter(unittest.TestCase):
    def test_lists_only_viewed_accounts_and_falls_back(self):
        app = (S / 'app.js').read_text(); ws = (S / 'workspace.js').read_text()
        self.assertIn("new Option('All viewed','')", app)
        self.assertIn("sel.has(a.id)", app)
        self.assertNotIn("for(const a of p.aliases)rec.add", app)
        self.assertIn("rec.value=keep?old:''", app)
        self.assertIn("refreshRecipients()", ws)
if __name__ == '__main__': unittest.main()
