import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import server


class TotpTests(unittest.TestCase):
    def test_rfc6238_sha1_six_digit_value(self):
        config = {
            "secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "last_counter": -1,
        }
        self.assertTrue(server.verify_totp("287082", config, now=59, consume=False))
        self.assertFalse(server.verify_totp("287083", config, now=59, consume=False))

    def test_consumed_time_step_cannot_be_replayed(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "totp.json"
            config = {
                "enabled": True,
                "secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                "last_counter": -1,
            }
            with patch.object(server, "TOTP_FILE", config_path):
                self.assertTrue(server.verify_totp("287082", config, now=59, consume=True))
                saved = json.loads(config_path.read_text())
                self.assertEqual(saved["last_counter"], 1)
                self.assertFalse(server.verify_totp("287082", saved, now=59, consume=True))

    def test_recovery_code_is_single_use(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "totp.json"
            secret_path = Path(tmp) / "session_secret.txt"
            secret_path.write_text("test-session-secret")
            with patch.object(server, "TOTP_FILE", config_path), patch.object(
                server, "SESSION_SECRET_FILE", secret_path
            ):
                config = {
                    "enabled": True,
                    "secret": server.generate_totp_secret(),
                    "recovery_hashes": [server._recovery_hash("ABCDE-23456")],
                }
                self.assertTrue(server.consume_recovery_code("abcde-23456", config))
                self.assertFalse(server.consume_recovery_code("ABCDE-23456", config))

    def test_recovery_codes_have_at_least_fifty_bits_of_random_payload(self):
        codes = server.make_recovery_codes()
        self.assertEqual(len(codes), 8)
        self.assertEqual(len(set(codes)), 8)
        for code in codes:
            self.assertRegex(code, r"^[A-Z2-7]{5}-[A-Z2-7]{5}$")


if __name__ == "__main__":
    unittest.main()
