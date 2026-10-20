# Owner-approved OAuth for Nullink Master MCP

This optional gateway adds a separate OAuth-only connection at `/connect/mcp`.
The verified static Bearer `/master/mcp` endpoint and legacy messaging `/mcp`
endpoint keep their current behavior. The new process reuses the deployed master
worker and messaging adapter; it never starts another worker.

## Authentication model

This is a single-owner authorization server. The owner authenticates through
an existing root VPS console (SSH or provider console), reviews a pending
request, and explicitly approves it. There is no public password form, shared
admin-token login page, email login, or third-party identity account.

The browser receives a Secure/HttpOnly/SameSite cookie and displays its pending
request ID. The owner checks that SAME ID on the VPS. Only the browser holding
the corresponding cookie can receive the authorization code after approval.
Do not send that request ID to an agent to approve: the human confirmation in
the root console is the authentication/consent step. The worker already has root
power, so this is not an isolation boundary against a compromised root agent.

The connection grants the complete `nullink:admin` scope: all sixteen tools,
including production administration with the worker's existing permissions.
There are no per-user or read-only OAuth roles in this version.

## Protocol

- RFC 9728 protected-resource metadata and WWW-Authenticate discovery challenge.
- RFC 8414 authorization-server metadata, code grant, mandatory S256 PKCE.
- RFC 9207 `iss` in successful and denied authorization redirects.
- Exact registered redirect URI and resource matching. No wildcard callbacks.
- Public OAuth clients (`token_endpoint_auth_method=none`) through restricted
  dynamic client registration. Only operator-allowlisted callbacks register.
- DCR is idempotent for the same callback; this does not establish client
  identity. Human owner approval is still mandatory for every new grant.
- State echoed unchanged; browser cookie bound to the pending approval.
- Pending approvals expire in ten minutes; codes in ninety seconds.
- Opaque access tokens expire in ten minutes. Every HTTP request checks the
  local token database. Only tokens issued for this gateway's fixed resource
  and scope are accepted. The database is pinned to the issuer/resource pair.
- Refresh tokens rotate and expire thirty days after issuance. Reuse revokes
  the entire family, including its access tokens. Authorization-code replay
  during its validity also revokes the resulting family.
- Token and code values are SHA-256 hashed at rest, not stored in plaintext.
- A revocation endpoint and console `revoke-all` command are provided.
- OAuth logs omit URLs, headers, query strings and tokens. The browser page
  disables framing and referrer disclosure. All OAuth responses use no-store.
- Single-process global limits: 30 authorizations/minute, 120 POST requests per
  OAuth endpoint/minute; at most 100 live approval requests. Public endpoints
  can still be denial-of-service targets; front-proxy protections may be needed.

This is a deliberately narrow first-party authorization implementation, not a
certified OAuth server or a replacement for an organization identity provider.
Review before exposing root-level production tools. No claim of a successful
ChatGPT handshake is made by unit or localhost HTTP tests.

## Deploy without replacing verified production files

Use a separate checkout of the reviewed commit. The VPS currently has local
fixes that may not be in GitHub; do NOT overwrite its existing master_gateway.py,
master_worker.py, mcp_http_server.py, or mcp_server.py.

1. Copy ONLY oauth_store.py and oauth_gateway.py into `/opt/nullink-master`
   root-owned 0644. They import the existing four master Python modules.
2. Copy `deploy/oauth-config.json.example` to `/etc/nullink-master/oauth.json`,
   root:nullink-master 0640. Confirm the issuer/resource public HTTPS URLs.
   Copy the EXACT callback URI shown by ChatGPT into `redirect_uris`. The stable
   callback example applies only if the connector actually selects it; an
   account-specific callback must be explicitly added if shown instead.
3. Install `deploy/nullink-oauth-gateway.service` into `/etc/systemd/system/`.
   Run `systemctl daemon-reload` and `systemctl enable --now nullink-oauth-gateway`.
   Start the service BEFORE using the console CLI so its database is created
   under the `nullink-master` account. Database/state mode is 0600/0700.
4. Add `deploy/Caddyfile.oauth.example` inside the existing site. These handlers
   preserve request paths. Keep the existing /master and /mcp handlers. Validate
   Caddy configuration, then reload Caddy only after validation succeeds.
5. Run the OAuth tests and existing gateway/worker tests on the VPS. Verify the
   public metadata and challenges; old admin/chat tokens MUST fail on the new
   endpoint. New OAuth tokens must not work on the old static-token endpoint.
6. Verify a disposable end-to-end OAuth flow and read-only MCP call. Revoke the
   disposable grant. Confirm the original master and messaging tests still pass.

State contains sensitive auth bindings and hashed credentials. Do not commit or
share the database. Back it up only as private authorization state. This version
cleans expired approval requests/codes during authorization; token-family history
has no automated retention purge. Stop the OAuth gateway before an intentional
state reset. Resetting state revokes every OAuth connection and requires re-linking.

## Add in ChatGPT

Use the custom MCP connection UI available to your account/workspace:

- MCP URL: `https://nullink.216.158.238.236.sslip.io/connect/mcp`
- Authentication: OAuth, using discovered endpoints and dynamic registration.
- No static admin token or client secret is supplied. If the UI requires a
  predefined client, register the exact displayed callback using the registration
  endpoint and use its returned public client ID (authentication method `none`).
- Check the exact redirect callback before connecting. If the client does not
  support public OAuth clients/DCR, report that incompatibility; never disable
  authentication to make a connection succeed.

When the approval page opens, on the ROOT VPS terminal (not inside Codex):

```bash
python3 /opt/nullink-master/oauth_store.py pending
python3 /opt/nullink-master/oauth_store.py approve REQUEST_ID_FROM_YOUR_BROWSER
```

Check the client, exact redirect and request ID. Type `APPROVE` only for the
connection you initiated. Return to the browser; it polls every three seconds
and redirects to ChatGPT. A rejected request can be denied with the `deny`
subcommand instead. Keep the browser cookie intact until completion.

Then enable the connector in a chat and call `master_capabilities`, followed by
a read-only repository check. That real connector/tool test is the completion
gate. Approval does not grant this pre-existing conversation tools automatically.
Refresh tokens normally avoid repeated owner approval until revoked or expired.

Emergency OAuth revocation (does not affect static Bearer tokens):

```bash
python3 /opt/nullink-master/oauth_store.py revoke-all
```

## Rollback

Stop/disable only `nullink-oauth-gateway`. Remove only its three Caddy handlers,
validate and reload Caddy. Keep the working master gateway and worker running.
Retain the private OAuth database if investigating; delete it only deliberately
when all grants should be invalidated. No application/repository reset is needed.

## References

- https://developers.openai.com/plugins/build/auth
- https://modelcontextprotocol.io/specification/latest/basic/authorization

Production gates: review this custom auth implementation, run the real browser
flow through HTTPS, confirm callback/resource behavior with the actual connector,
then verify a tool call. Automated tests do not substitute for those steps.
