import unittest, sqlite3, sys, pathlib, time
ROOT = pathlib.Path(__file__).resolve().parents[1]; sys.path.insert(0, str(ROOT))
import prefs
class Prefs(unittest.TestCase):
    def setUp(self): self.db = sqlite3.connect(':memory:')
    def put(self, actor, **kv): return prefs.put(self.db, actor, {'prefs': {k: {'value': v, 'updated': u} for k, (v, u) in kv.items()}})
    def test_lww_per_key_and_per_user(self):
        self.put('john', tree=({'a': True}, 1000), body_mode=('text', 1000))
        out = self.put('john', tree=({'a': False}, 500), body_mode=('html', 2000))
        self.assertEqual(out['tree']['value'], {'a': True})        # older write loses
        self.assertEqual(out['body_mode']['value'], 'html')        # newer wins
        self.assertEqual(prefs.get(self.db, 'other'), {})
    def test_future_timestamps_clamped(self):
        out = self.put('john', setup_tab=('status', time.time() * 1000 + 10 ** 9))
        self.assertLessEqual(out['setup_tab']['updated'], time.time() * 1000 + 1)
    def test_schema_rejects_bad_input(self):
        for bad in [{'prefs': {'nope': {'value': 1, 'updated': 1}}},
                    {'prefs': {'body_mode': {'value': 'rich', 'updated': 1}}},
                    {'prefs': {'tree': {'value': {'x': 'yes'}, 'updated': 1}}},
                    {'prefs': {'last_view': {'value': {'folder': 'inbox', 'evil': 'x'}, 'updated': 1}}},
                    {'prefs': {'setup_tab': {'value': 'local', 'updated': True}}},
                    {'other': {}}]:
            with self.assertRaises(ValueError): prefs.put(self.db, 'john', bad)
    def test_size_limit(self):
        big = {('k%04d' % i) + 'x' * 250: True for i in range(2900)}
        with self.assertRaises(ValueError): self.put('john', tree=(big, 1))
class Client(unittest.TestCase):
    def test_no_direct_localstorage_state_and_sync_hooks(self):
        app = (ROOT / 'static/app.js').read_text(); ws = (ROOT / 'static/workspace.js').read_text()
        self.assertNotIn('localStorage', app)
        self.assertNotIn("localStorage.setItem('nullmail-gmail-tree'", ws)
        for needle in ("method:'PUT'", "visibilitychange", "setInterval(()=>{if(document.visibilityState==='visible')prefsRemote();},60000)", "prefSet('body_mode'", "prefSet('last_view'", "localStorage.removeItem('nullmail-gmail-tree')"):
            self.assertIn(needle, ws)
        self.assertIn('await prefsInit()', app); self.assertIn("prefSet('setup_tab'", app)
if __name__ == '__main__': unittest.main()
