"""Vault -> Devices web section (static/vault-devices.js): node harness + wiring + served route."""
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")


@unittest.skipUnless(NODE, "node not installed")
class VaultDevicesJsTests(unittest.TestCase):
    def test_js_flows(self):
        r = subprocess.run([NODE, str(ROOT / "tests" / "js" / "vault_devices_test.js")], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("OK 11", r.stdout)


class VaultDevicesWiringTests(unittest.TestCase):
    html = (ROOT / "static" / "index.html").read_text()
    app = (ROOT / "static" / "app.js").read_text()

    def test_section_is_in_the_vault_panel_and_starts_hidden(self):
        panel = self.html[self.html.index('id="panel-vault"'):]
        panel = panel[:panel.index("</main>")]
        self.assertIn('id="vault-devices" class="vault-devices hidden"', panel)
        for i in ("vault-devices-list", "vault-devices-status", "vault-devices-confirm", "vault-devices-revoke-all",
                  "vault-devices-revoke-selected", "vault-devices-hint"):
            self.assertIn(f'id="{i}"', panel)
        self.assertIn(">Revoke all<", panel)

    def test_script_loaded_before_use_and_mounted_on_vault(self):
        self.assertIn('<script src="/vault-devices.js?v=vd1"></script>', self.html)
        self.assertIn("loadVaultDevices();", self.app)
        self.assertIn("window.NLVaultDevices.mount", self.app)

    def test_served_route(self):
        src = (ROOT / "server.py").read_text()
        self.assertTrue(re.search(r'path in \("/files-manager.js", "/fm-sort.js", "/vault-devices.js"\)', src))


from tests.test_auth import AuthBase  # noqa: E402


class VaultDevicesServeTests(AuthBase):
    def test_get_serves_js(self):
        st, _, _, data = self.req("/vault-devices.js")
        self.assertEqual(st, 200)
        self.assertIn(b"NLVaultDevices", data)
