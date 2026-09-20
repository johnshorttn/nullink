import hashlib
import hmac
import json
import unittest

from deploy import deploy_webhook


class DeployWebhookTests(unittest.TestCase):
    def test_signature(self):
        body = b'{"ok":true}'
        secret = b"x" * 32
        signature = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
        self.assertTrue(deploy_webhook.valid_signature(body, signature, secret))
        self.assertFalse(deploy_webhook.valid_signature(body + b"x", signature, secret))

    def test_accepts_only_nullink_main_push(self):
        commit = "a" * 40
        body = json.dumps({
            "ref": "refs/heads/main",
            "after": commit,
            "repository": {"full_name": "johnshorttn/nullink"},
        }).encode()
        repos = {"johnshorttn/nullink": {"branch": "main"}}
        self.assertEqual(deploy_webhook.parse_deployment(body, "push", repos), ("johnshorttn/nullink", commit))
        self.assertIsNone(deploy_webhook.parse_deployment(body, "pull_request", repos))

    def test_rejects_other_repository_or_branch(self):
        commit = "b" * 40
        other_repo = json.dumps({
            "ref": "refs/heads/main", "after": commit,
            "repository": {"full_name": "someone/else"},
        }).encode()
        other_branch = json.dumps({
            "ref": "refs/heads/dev", "after": commit,
            "repository": {"full_name": "johnshorttn/nullink"},
        }).encode()
        repos = {"johnshorttn/nullink": {"branch": "main"}}
        self.assertIsNone(deploy_webhook.parse_deployment(other_repo, "push", repos))
        self.assertIsNone(deploy_webhook.parse_deployment(other_branch, "push", repos))


if __name__ == "__main__":
    unittest.main()
