# Nullmail deployment — 2026-10-06

URL: **https://nullmail.nullverse.cloud**. Linked from the protected
https://nullverse.cloud/projects portal. Uses existing Nullink PIN/TOTP login
with a separate host-only, revocable session. Source and security/operations
notes: [nullmail/README.md](../nullmail/README.md).

## What is deployed

- Responsive dark inbox, original-recipient/project filters, subject/sender search,
  read/unread flags, plain-text reader, safe attachment downloads, reversible Trash.
- Compose/reply with exact original-recipient From default, durable drafts, paused
  Outbox, and an honest Sent view. Send is always paused in this release; saving
  or clicking Send never invokes SMTP or schedules later delivery.
- Project registration with exact aliases into John's unified mailbox; root aliases
  preserved; nullink/storycast/axis seeded. Catchall off; unknown addresses rejected.
- Setup page with observed MX/PTR/SPF/DMARC/milter state, mailbox size limit, shared
  filesystem capacity, historical held-queue count and current Postfix defer setting.
- Loopback-only unprivileged web service and separate constrained project-map helper.
  Dedicated Caddy TLS route; existing Caddy site/OAuth blocks preserved.

Current limitations: project-subdomain MX records are pending; root MX is verified.
PTR still resolves to the provider hostname, root SPF and DMARC are absent, and
no Postfix DKIM milter is configured as observed at verification. No DKIM key or
SPF policy was invented. Earlier outbound TCP 25 probes timed out; the owner is
independently investigating. This deployment ran **no new outbound probes**, changed
no firewall, relay, defer or HOLD settings, and sent no external mail. The app
stays paused even if the owner fixes Postfix. Direct Postfix activation and real
remote-delivery/Sent reconciliation require a later deliberate deployment.

## Validation

- 13 backend/integration tests pass with ResourceWarnings treated as errors.
  Covers real isolated Nullink single-use PIN and TOTP, per-client lockout,
  host-only cookie forwarding, session validation and logout revocation;
  API authentication/Origin/CSRF; Maildir path/symlink defense; attachment headers;
  header/From injection; read/trash/restore byte preservation; paused transport;
  project-label schema, exact maps and rollback on failed map update.
- Isolated real-browser checks pass at desktop 1440×1000 and Pixel 9 412×915:
  login, inbox/reader, hostile HTML displayed as text with no execution or remote
  requests, attachments present, original-recipient reply From, draft save,
  paused Outbox, Trash/restore, project registration/pending DNS, setup and logout.
  No horizontal overflow or JavaScript errors. These are viewport emulations,
  not testing on a physical Pixel 9. Screenshots contain synthetic mail only.
- Actual live TLS/browser/API verification passed: login page, temporary real
  authenticated session, inbox count 2/unread 2, projects/setup, portal link,
  invalid Origin/CSRF rejection, idempotent registration, and logout revocation.
  Neither real message was opened or marked read; no private bodies were logged.
- SMTP RCPT-only checks from 127.0.0.2 (outside mynetworks): all 29 configured
  addresses accepted; unknown addresses at root and all three projects rejected
  with 550; external relay denied. No SMTP DATA transmitted by these checks.
- Original two Maildir files and all five held messages retain identical paths
  and SHA256 bytes. No queue flush/release, mail deletion or recovery changes.
- Effective Postfix differences are only virtual_alias_domains and virtual_alias_maps,
  adding the dedicated project maps. All outbound settings remain unchanged.
- Caddy validation passed; services active; web listener is 127.0.0.1:8789.
  Nullmail cannot read Nullink secrets or write its code/Postfix config.
- Live site checks: apex, both Nullink hosts, both StoryCast hosts, Cockpit,
  recovery health, mail host, Nullmail health and OAuth metadata return 200.
  Axis retains expected 503; unauthenticated MCP retains expected 401.

## Backups and rollback

Root-only full backups (Postfix/Caddy configuration, Maildir, queue, original
working diff and preservation hashes):

- Initial: `/root/nullmail-build-backup/20261006T040021Z`
- Refreshed immediately before this resumed deployment:
  `/root/nullmail-build-backup/resume-20261006T095305Z`
- Pointer: `/root/nullmail-build-backup/deploy-latest`
- Fixture screenshots: `/root/nullmail-build-backup/fixture-*.png`

Prefer **app-only rollback**, preserving all incoming mail and project routing:

1. Stop/disable `nullmail.service` and `nullmail-control.service`.
2. Remove only the `nullmail.nullverse.cloud` Caddy block matching
   `nullmail/deploy/Caddyfile.fragment`; validate Caddy, then reload it.
   Preserve all other site blocks and any later edits.
3. Remove only the Nullmail card from `static/portal.html`. Static content needs
   no Nullink restart. Do not revert other portal/auth working changes.
4. Keep `/var/lib/nullmail` and all Postfix queues intact. Existing aliases keep
   delivering; no mailbox or draft data needs to be restored or deleted.

If project-map routing must also be reverted, remove only
`hash:/etc/postfix/nullmail_project_domains` from virtual_alias_domains and
`hash:/etc/postfix/nullmail_project_aliases` from virtual_alias_maps, preserving
all other values. Run postfix check and reload after reviewing current config.
This stops acceptance for project subdomain aliases; root mail remains intact.
Never restore an entire stale main.cf/Caddyfile/firewall snapshot over later owner
changes. Never restore old queue archives into a running queue or release held mail.
Backups are recovery copies, not an instruction to overwrite current mailbox data.

Runtime code is root-owned in `/usr/local/lib/nullmail`. To redeploy app-only
changes, copy the four Python modules and static files there with root ownership,
0644 files/0755 directories, then restart `nullmail`; restart the controller only
when its implementation changes. No secrets, mailbox data, queue files, browser
cookies or local auth state belong in git.
