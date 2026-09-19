import json
import os
import threading
import unittest
import urllib.error
import urllib.request

os.environ["NULLINK_TOKEN"] = "nlk_test_token"

import mcp_http_server as gateway


class GatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = gateway.ThreadingHTTPServer(("127.0.0.1", 0), gateway.MCPHandler)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def request(self, payload, token="nlk_test_token", accept="application/json"):
        data = json.dumps(payload).encode()
        headers = {"Accept": accept, "Content-Type": "application/json"}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(self.base + "/mcp", data=data, headers=headers, method="POST")
        return urllib.request.urlopen(request)

    def test_requires_bearer(self):
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.request({"jsonrpc": "2.0", "id": 1, "method": "ping"}, token=None)
        self.assertEqual(caught.exception.code, 401)

    def test_initialize(self):
        payload = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}}
        with self.request(payload) as response:
            body = json.load(response)
        self.assertEqual(body["result"]["protocolVersion"], "2025-03-26")
        self.assertEqual(body["result"]["serverInfo"]["name"], "nullink")

    def test_tools_list(self):
        with self.request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}) as response:
            names = {tool["name"] for tool in json.load(response)["result"]["tools"]}
        self.assertIn("nullink_send_message", names)
        self.assertIn("nullink_pull_messages", names)

    def test_notification_returns_202(self):
        with self.request({"jsonrpc": "2.0", "method": "notifications/initialized"}) as response:
            self.assertEqual(response.status, 202)
            self.assertEqual(response.read(), b"")

    def test_sse_response(self):
        with self.request({"jsonrpc": "2.0", "id": 3, "method": "ping"}, accept="text/event-stream") as response:
            body = response.read().decode()
        self.assertTrue(body.startswith("event: message\ndata: "))
        self.assertIn('"id":3', body)


if __name__ == "__main__":
    unittest.main()
