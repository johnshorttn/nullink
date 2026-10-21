"""deploy_worker safe update (2026-10-21): ff-only, refusals + alert, backup, --keep rollback."""
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from deploy import deploy_worker as dw


def sh(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.origin, self.prod, self.dev = t / "origin.git", t / "prod", t / "dev"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(self.origin)], check=True)
        subprocess.run(["git", "clone", "-q", str(self.origin), str(self.dev)], check=True)
        for d in (self.dev,):
            sh(d, "config", "user.email", "t@t"); sh(d, "config", "user.name", "t")
        (self.dev / "a.txt").write_text("v1\n")
        sh(self.dev, "add", "."); sh(self.dev, "commit", "-qm", "v1"); sh(self.dev, "push", "-q", "origin", "HEAD:main")
        subprocess.run(["git", "clone", "-q", "-b", "main", str(self.origin), str(self.prod)], check=True)
        sh(self.prod, "config", "user.email", "t@t"); sh(self.prod, "config", "user.name", "t")
        self.state = t / "state"
        self.alerts = []
        cfg = {"path": str(self.prod), "branch": "main", "services": ["x.service"],
               "health_checks": [{"url": "http://127.0.0.1:1/health"}], "test_commands": [],
               "resolved_path": self.prod}
        self.health = [True]
        self.patches = [
            patch.object(dw, "STATE", self.state),
            patch.object(dw, "load_config", lambda repo: dict(cfg)),
            patch.object(dw, "restart", lambda services: None),
            patch.object(dw, "health_ok", lambda check: self.health.pop(0) if len(self.health) > 1 else self.health[0]),
            patch.object(dw, "alert", lambda repo, msg: self.alerts.append(msg)),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def push(self, content):
        (self.dev / "a.txt").write_text(content)
        sh(self.dev, "commit", "-qam", content.strip()); sh(self.dev, "push", "-q", "origin", "HEAD:main")
        return sh(self.dev, "rev-parse", "HEAD")

    def test_fast_forward_with_backup(self):
        c = self.push("v2\n")
        dw.deploy("o/r", c)
        self.assertEqual(sh(self.prod, "rev-parse", "HEAD"), c)
        self.assertEqual((self.prod / "a.txt").read_text(), "v2\n")
        self.assertEqual(sh(self.prod, "rev-parse", "--abbrev-ref", "HEAD"), "main")
        self.assertEqual(len(list((self.state / "backups").glob("*.tgz"))), 1)
        self.assertEqual(self.alerts, [])

    def test_untracked_files_survive(self):
        (self.prod / "runtime.env").write_text("keep")
        c = self.push("v2\n")
        dw.deploy("o/r", c)
        self.assertEqual((self.prod / "runtime.env").read_text(), "keep")

    def test_refuses_tracked_changes(self):
        (self.prod / "a.txt").write_text("local edit\n")
        c = self.push("v2\n")
        with self.assertRaises(dw.Refused):
            dw.deploy("o/r", c)
        self.assertEqual((self.prod / "a.txt").read_text(), "local edit\n")
        self.assertIn("tracked production changes", self.alerts[0])

    def test_refuses_non_fast_forward(self):
        (self.prod / "b.txt").write_text("local commit\n")
        sh(self.prod, "add", "."); sh(self.prod, "commit", "-qm", "local")
        c = self.push("v2\n")
        before = sh(self.prod, "rev-parse", "HEAD")
        with self.assertRaises(dw.Refused):
            dw.deploy("o/r", c)
        self.assertEqual(sh(self.prod, "rev-parse", "HEAD"), before)
        self.assertIn("not a fast-forward", self.alerts[0])

    def test_health_failure_rolls_back_without_hard_reset(self):
        prev = sh(self.prod, "rev-parse", "HEAD")
        c = self.push("v2\n")
        self.health = [False, True]
        calls = []
        real = dw.git
        with patch.object(dw, "git", lambda repo, *a, **k: (calls.append(a), real(repo, *a, **k))[1]):
            with self.assertRaises(RuntimeError):
                dw.deploy("o/r", c)
        self.assertEqual(sh(self.prod, "rev-parse", "HEAD"), prev)
        self.assertEqual((self.prod / "a.txt").read_text(), "v1\n")
        self.assertFalse(any("--hard" in a for a in calls))
        self.assertIn(("reset", "--keep", prev), calls)
        self.assertIn("rolled back", self.alerts[0])

    def test_no_hard_reset_in_source(self):
        src = Path(dw.__file__).read_text()
        self.assertNotIn('"--hard"', src)


if __name__ == "__main__":
    unittest.main()
