import tempfile
import threading
import unittest
from pathlib import Path

from phone_bridge import PhoneBridge, PhoneBridgeError


class PhoneBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.bridge = PhoneBridge(root / "data", root / "staging")

    def tearDown(self):
        self.temp.cleanup()

    def pair_and_share(self):
        code = self.bridge.create_pairing_code()["code"]
        paired = self.bridge.pair(code, "Pixel 9")
        device = self.bridge.authenticate(paired["token"])
        self.assertIsNotNone(device)
        self.bridge.set_sharing(device["id"], True, [{"id": "photos", "name": "Photos"}, {"id": "docs", "name": "Documents"}])
        return paired, device

    def test_pairing_code_is_single_use_and_token_is_only_returned_once(self):
        code = self.bridge.create_pairing_code()["code"]
        paired = self.bridge.pair(code, "Pixel")
        self.assertTrue(paired["token"])
        self.assertNotIn("token", paired["device"])
        self.assertIsNotNone(self.bridge.authenticate(paired["token"]))
        with self.assertRaises(PhoneBridgeError):
            self.bridge.pair(code, "Second device")

    def test_listing_is_live_request_and_returns_phone_items(self):
        paired, device = self.pair_and_share()
        result_box = {}
        thread = threading.Thread(target=lambda: result_box.update(
            self.bridge.request_phone(device["id"], "list", "photos", "root", timeout=2)))
        thread.start()
        command = self.bridge.next_command(device["id"], timeout=1)
        self.assertEqual(command["operation"], "list")
        self.bridge.complete_command(device["id"], command["id"], {"items": [
            {"id": "folder_1", "name": "Camera", "directory": True},
            {"id": "photo_1", "name": "image.jpg", "mime": "image/jpeg", "size": 12},
        ]})
        thread.join(timeout=2)
        self.assertEqual([item["id"] for item in result_box["items"]], ["folder_1", "photo_1"])
        self.assertEqual(len(result_box["items"]), 2)

    def test_selected_file_is_staged_once_then_removed(self):
        _, device = self.pair_and_share()
        result_box = {}
        thread = threading.Thread(target=lambda: result_box.update(
            self.bridge.request_phone(device["id"], "read", "docs", "file_1", timeout=2)))
        thread.start()
        command = self.bridge.next_command(device["id"], timeout=1)
        staged = self.bridge.complete_file(device["id"], command["id"], "report.pdf", "application/pdf", b"PDF")
        thread.join(timeout=2)
        self.assertEqual(result_box["id"], staged["id"])
        self.assertEqual(self.bridge.list_staged()[0]["name"], "report.pdf")
        consumed = self.bridge.consume_staged(staged["id"])
        self.assertEqual(consumed["path"].read_bytes(), b"PDF")
        consumed["path"].unlink()
        self.assertIsNone(self.bridge.consume_staged(staged["id"]))

    def test_stopping_sharing_invalidates_folders_and_pending_reads(self):
        _, device = self.pair_and_share()
        outcome = {}
        thread = threading.Thread(target=lambda: self._request(outcome, device["id"]))
        thread.start()
        command = self.bridge.next_command(device["id"], timeout=1)
        self.bridge.set_sharing(device["id"], False, [])
        thread.join(timeout=2)
        self.assertEqual(outcome.get("error"), "sharing_stopped")
        self.assertEqual(self.bridge.list_devices()[0]["roots"], [])

    def _request(self, outcome, device_id):
        try:
            self.bridge.request_phone(device_id, "list", "photos", "root", timeout=2)
        except PhoneBridgeError as error:
            outcome["error"] = error.code

    def test_unselected_root_cannot_be_read(self):
        _, device = self.pair_and_share()
        with self.assertRaises(PhoneBridgeError) as caught:
            self.bridge.request_phone(device["id"], "read", "not_shared", "file_1", timeout=0.1)
        self.assertEqual(caught.exception.code, "folder_sharing_inactive")


if __name__ == "__main__":
    unittest.main()
