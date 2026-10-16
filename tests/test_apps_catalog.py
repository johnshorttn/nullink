import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import server


class MessagesAppCatalogTests(unittest.TestCase):
    def load(self, apps):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "apps.json"
            path.write_text(json.dumps({"apps": apps}), encoding="utf-8")
            with patch.object(server, "APPS_FILE", path), patch.object(server, "ensure_dirs"):
                return server.load_apps_config()["apps"]

    def test_adds_messages_entry_when_desktop_is_configured(self):
        apps = self.load([{"id": "desktop", "url": "/desktop/", "enabled": True}])
        messages = next(app for app in apps if app["id"] == "messages")
        self.assertEqual(messages["url"], "/desktop/")
        self.assertTrue(messages["enabled"])

    def test_does_not_add_messages_entry_without_desktop(self):
        apps = self.load([{"id": "example", "url": "/example/", "enabled": True}])
        self.assertFalse(any(app["id"] == "messages" for app in apps))

    def test_does_not_duplicate_configured_messages_entry(self):
        configured = {"id": "messages", "url": "/desktop/", "enabled": True}
        apps = self.load([
            {"id": "desktop", "url": "/desktop/", "enabled": True},
            configured,
        ])
        self.assertEqual(sum(app["id"] == "messages" for app in apps), 1)


if __name__ == "__main__":
    unittest.main()
