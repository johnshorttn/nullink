"""Nullink -> MCP gateway approval forward (mcpgw_* Slack buttons). 2026-10-17."""
import json, os, sys, tempfile, threading, unittest
from unittest import mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import server  # noqa: E402


class _H(BaseHTTPRequestHandler):
    got = []
    def log_message(self, *a): pass
    def do_POST(self):
        _H.got.append((self.headers.get("X-Mcpgw-Forward"), json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
        b = b'{"ok": true, "status": "approved"}'
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)


class McpgwForwardTests(unittest.TestCase):
    def setUp(self):
        _H.got = []
        self.ga = mock.patch.object(server, "guest_audit"); self.ga.start()  # never touch real audit files
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.tmp = tempfile.NamedTemporaryFile("w", delete=False); self.tmp.write("sekret\n"); self.tmp.close()
        self.old = (server.MCPGW_FORWARD_URL, server.MCPGW_FORWARD_SECRET_FILE)
        server.MCPGW_FORWARD_URL = f"http://127.0.0.1:{self.srv.server_address[1]}/internal/slack-action"
        server.MCPGW_FORWARD_SECRET_FILE = self.tmp.name

    def tearDown(self):
        self.ga.stop(); self.srv.shutdown(); os.unlink(self.tmp.name)
        server.MCPGW_FORWARD_URL, server.MCPGW_FORWARD_SECRET_FILE = self.old

    def payload(self, user, aid="mcpgw_approve"):
        return {"type": "block_actions", "user": {"id": user}, "actions": [{"action_id": aid, "value": "MR-ABCDEFGH"}],
                "channel": {"id": "D1"}, "container": {"message_ts": "1.2"}}

    def test_owner_click_forwarded_with_secret(self):
        out = server.slack_handle_interaction(self.payload(server.SLACK_OWNER_UID))
        self.assertEqual(out["status"], "approved")
        self.assertEqual(_H.got[0][0], "sekret")
        self.assertEqual(_H.got[0][1]["value"], "MR-ABCDEFGH")

    def test_non_owner_mcpgw_click_forwarded_for_verification(self):
        # stage-1 (namespace admin) buttons: the approval service checks the clicker's mapped Slack id
        out = server.slack_handle_interaction(self.payload("UNADMIN1", "mcpgw_n_approve"))
        self.assertTrue(out["ok"]); self.assertEqual(_H.got[0][1]["user"], "UNADMIN1")

    def test_non_owner_other_actions_never_handled(self):
        for aid in ("share_approve", "guest_approve", "other"):
            out = server.slack_handle_interaction(self.payload("UNOTJOHN", aid))
            self.assertEqual(out["error"], "wrong_user")
        self.assertEqual(_H.got, [])

    def test_unreachable_is_safe(self):
        server.MCPGW_FORWARD_URL = "http://127.0.0.1:9/x"
        self.assertEqual(server.slack_handle_interaction(self.payload(server.SLACK_OWNER_UID))["error"], "mcpgw_unreachable")

    def test_guest_actions_unchanged(self):
        out = server.slack_handle_interaction(self.payload(server.SLACK_OWNER_UID, "something_else"))
        self.assertEqual(out["error"], "unknown_action"); self.assertEqual(_H.got, [])


if __name__ == "__main__":
    unittest.main()
