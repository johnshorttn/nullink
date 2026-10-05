# Nullverse portal

`https://nullverse.cloud/` serves the existing Nullink login UI. After PIN,
TOTP, or recovery-code authorization through the existing verification endpoint,
it redirects to `/projects`. That route validates the real signed human session
on every request; absent, forged, or expired sessions redirect to login.

The small responsive dark page links to Nullink and StoryCast. Axis is explicitly
undeployed, has no active link, and retains its existing Caddy 503 response.
Logout uses the existing endpoint. Cookies remain host-only, HttpOnly,
SameSite=Lax and Secure on HTTPS; signing into the apex does not automatically
sign into sibling hosts. The existing stateless logout clears the browser cookie;
it does not revoke a copied session token before expiration.

The backend validates the actual Host header against apex, both existing Nullink
hosts, and localhost addresses. Forwarded host headers do not select the portal.
Apex routes are limited to login, auth/session, health, portal and shared assets.
The old and new Nullink hosts retain their workspace routes and UI.

## Deployment (2026-10-05)

Caddy's apex block now proxies to `127.0.0.1:8766` with automatic HTTPS. All
other site blocks and upstreams remain in place. See
`deploy/Caddyfile.nullverse.example` for the apex block.

Root-only backup: `/var/backups/nullverse-portal-20261005/`, including the original
server, app script, Caddyfile, pre-existing working diff, baseline responses,
test log, and Pixel 9 viewport screenshots. Unrelated working changes were
preserved and excluded from the portal commit.

Validated Caddy before reload; restarted only Nullink and reloaded Caddy.
Tests: `python3 -m unittest tests.test_portal tests.test_totp
 tests.test_mcp_http_server tests.test_deploy_webhook` (13 passing), Python
compilation and JavaScript syntax checks. The isolated HTTP test uses temporary
PIN/state files and exercises the actual verifier, cookie issuance, redirects,
expiry, logout, Host validation, asset paths and existing-host routing.
Live HTTPS checks use a short-lived locally signed session kept in memory,
without printing credentials. Both Nullink roots, health and OAuth metadata
match pre-deployment responses. Both StoryCast roots remain 200; their content
matches apart from dynamic numbers. `/health` and `/api/health` on StoryCast
returned 404 before and after this deployment.

Headless Chrome at a Pixel 9 viewport (412 × 915 CSS pixels) verified the
visible shared login, authenticated root redirect, project cards, absence of
horizontal overflow and JavaScript errors, and logout cookie removal. This
is browser emulation, not a test on a physical Pixel 9.

Rollback: restore `server.py` and `app.js` (the latter to `static/app.js`) from
the backup and restore its Caddyfile to `/etc/caddy/Caddyfile`; validate Caddy,
restart `nullink.service`, and reload Caddy. This restores the pre-existing
working changes as well as the original routing. New portal assets are inert
without the new routes.
