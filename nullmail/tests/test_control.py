import json, pathlib, sys, tempfile, unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import control

class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.tmp.name)
        self.patches=[patch.object(control,'ROOT',self.root),patch.object(control,'DOMAINS',self.root/'domains'),patch.object(control,'MAP',self.root/'aliases')]
        for p in self.patches:p.start()
        self.commands=[]
    def tearDown(self):
        for p in self.patches:p.stop()
        control.CACHE.clear();self.tmp.cleanup()
    def fake_run(self,*args):
        self.commands.append(args)
        if args[0]=='/usr/sbin/postmap':
            p=pathlib.Path(args[1].removeprefix('hash:'));pathlib.Path(str(p)+'.db').write_bytes(p.read_bytes())
        return ''
    def test_exact_project_maps_and_preserved_root(self):
        root_alias=self.root/'nullverse_aliases';root_alias.write_text('hello@nullverse.cloud john@nullverse.cloud\n')
        with patch.object(control,'run',self.fake_run):
            for label in ['nullink','axis','storycast']:control.update(label)
            control.update('axis')
        self.assertEqual(len(control.DOMAINS.read_text().splitlines()),3)
        lines=control.MAP.read_text().splitlines();self.assertEqual(len(lines),21)
        self.assertIn('support@axis.nullverse.cloud john@nullverse.cloud',lines)
        self.assertTrue(all(len(line.split())==2 and not line.startswith('@') for line in lines))
        self.assertEqual(root_alias.read_text(),'hello@nullverse.cloud john@nullverse.cloud\n')
        self.assertTrue(all(cmd[0] in ['/usr/sbin/postmap','/usr/sbin/postfix'] for cmd in self.commands))
        self.assertFalse(any('postconf' in str(cmd) or 'postsuper' in str(cmd) for cmd in self.commands))
    def test_failed_update_restores_all_map_bytes(self):
        with patch.object(control,'run',self.fake_run):control.update('axis')
        before={p:p.read_bytes() for p in self.root.iterdir()}
        def fail(*args):
            if args==('/usr/sbin/postfix','check'):raise RuntimeError('fixture failure')
            return self.fake_run(*args)
        with patch.object(control,'run',fail):
            with self.assertRaises(RuntimeError):control.update('fixture')
        self.assertEqual(before,{p:p.read_bytes() for p in self.root.iterdir()})
    def test_invalid_project_never_executes(self):
        with patch.object(control,'run') as run:
            for label in ['../main.cf','a;reboot','nullmail','foo.nullverse.cloud','x\n* OK']:
                with self.assertRaises(ValueError):control.update(label)
            run.assert_not_called()

if __name__=='__main__':unittest.main()
