# Nullink remote MCP gateway

The dependency-free gateway reuses `mcp_server.py`, binds to localhost on port
8767, and serves stateless Streamable HTTP at `/mcp`. The Nullink UI remains on
8766 and continues to use its OTP cookie.

## Deploy

1. Copy `mcp_http_server.py` beside `/opt/nullink/mcp_server.py`.
2. Keep the scoped ChatGPT token at
   `/opt/nullink/secrets/NULLINK_TOKEN_chatgpt.txt` with mode `0600`.
3. Install `deploy/nullink-mcp.service` as
   `/etc/systemd/system/nullink-mcp.service`.
4. Add the handler from `deploy/Caddyfile.mcp.example` before the existing
   Nullink catch-all proxy.
5. Run `systemctl daemon-reload && systemctl enable --now nullink-mcp` and
   reload Caddy after validating its configuration.

The public connector URL is:

```text
https://nullink.216.158.238.236.sslip.io/mcp
```

Configure the connector with the scoped `nlk_…` token as its Bearer token.

## Verify

```bash
python3 -m unittest -v tests.test_mcp_http_server

curl -i 'https://nullink.216.158.238.236.sslip.io/mcp' \
  -H "Authorization: Bearer $NULLINK_TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}'
```

The gateway compares the incoming token in constant time, accepts JSON or SSE
responses, enforces a 1 MiB request limit, and never stores MCP session state.
