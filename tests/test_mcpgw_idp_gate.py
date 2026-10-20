"""MCP gateway admin SSO relies on /api/auth/gate (Caddy forward_auth for /mcpgw-idp/authorize):
only the owner's human session passes; guests, API tokens and share-link cookies never do. 2026-10-18."""
import server
from tests.test_guest import GuestTests


class McpgwIdpGateTests(GuestTests):
    def test_gate_owner_only(self):
        self.assertEqual(self.req("/api/auth/gate", cookie=self.owner)[0], 204)
        ck, _ = self.guest("full")
        self.assertEqual(self.req("/api/auth/gate", cookie=ck)[0], 403)  # even a full-scope guest
        _rec, tok = server.create_api_token("idp-gate-test", ["health:read", "messages:read"], ["chatgpt"], 600)
        self.assertEqual(self.req("/api/auth/gate", headers={"Authorization": "Bearer " + tok})[0], 401)
        self.assertEqual(self.req("/api/auth/gate", cookie="nl_share_L1=dev.sig")[0], 401)
        self.assertEqual(self.req("/api/auth/gate", cookie=server.COOKIE_NAME + "=forged")[0], 401)
