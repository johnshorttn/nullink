# Nullmail

Small private mailbox for Nullverse. Production: https://nullmail.nullverse.cloud.
Source lives here; `/opt/nullink-mail/README.md` is historical transport documentation
and was preserved. Runtime code is copied to root-owned `/usr/local/lib/nullmail`.

## Architecture and authentication

Python standard-library HTTP service on **127.0.0.1:8789**, run as the existing
`nullmail` mailbox owner, behind Caddy TLS. There are no public IMAP or submission
listeners added by this app. Systemd denies non-loopback IP access and confines
writes to `/var/lib/nullmail`. App code and systemd units are root-owned; the web
process cannot read Nullink secrets, Postfix configuration, TLS keys or queues.

Nullmail delegates only `/api/auth/method`, `/api/auth/verify`, `/api/me`, and
`/api/auth/logout` to Nullink on loopback using its supported human HTTP API.
It stores no PIN/TOTP/session signing secrets. The current `__Host-nullink_session`
cookie is Secure, HttpOnly, SameSite=Lax, Path=/, and has no Domain attribute.
The login is separate for each host. Current Nullink PINs are single-use; TOTP
and enabled recovery codes use the same verifier and lockout logic. Caddy
**overwrites** `X-Nullmail-Client-IP`; the adapter forwards this normalized address
for Nullink's per-client lockout and preserves the global limiter. Only the
current host-prefixed cookie is accepted; legacy cookies and bearer credentials
cannot authenticate Nullmail. Every mail API call validates the real session
against Nullink, so server-side logout/revocation takes effect immediately.

Writes require the exact HTTPS Origin, same-origin Fetch Metadata when supplied,
and a session-bound HMAC CSRF token. Login requires the exact Origin too. CSRF
keys rotate on process restart; reload an existing browser tab after deployment.
No CORS permissions are granted. The CSP excludes inline script, third-party
resources, framing and HTML email execution. APIs return no-store/nosniff.

## Mail and drafts

Maildir: `/var/lib/nullmail/john/Maildir`. Messages are addressed by a SHA256 ID,
never a caller-provided path; lookup only enumerates fixed folders. Reads use
O_NOFOLLOW, a regular-file check, and a 2 MiB parser limit. Incoming Postfix size
limits remain independent and are shown from effective configuration. No email
HTML is rendered; HTML-only messages get an explicit explanation. Remote images
never load. Attachments use sanitized filenames, application/octet-stream and
Content-Disposition: attachment. Message bodies and subjects are inserted with
DOM textContent, not innerHTML. No mail content or cookie is written to app logs.

GET does not mark mail read. Opening a message in the UI makes a CSRF-protected
flag write. Inbox search covers sender, recipient and subject; filters cover
original recipient, project and unread state. Trash moves are reversible and
there is no delete endpoint or automatic retention purge. Drafts and paused
Outbox items persist in `/var/lib/nullmail/app/drafts.sqlite3`. Reply defaults to
an exact configured X-Original-To identity, otherwise John. From authorization
is checked again on save and Send; control characters/header injection are
rejected. Saving a draft allows an incomplete To field; Send validates it.

**Outbound is fixed paused in the app**, independently of the owner's ongoing
Postfix/network work. Clicking Send saves a paused Outbox item and transmits
nothing. There is no retry worker, scheduled send, or activation API. All five
historical recovery HOLD messages are outside this app and never released.
Sent remains empty unless actual Sent mail is present; paused mail is not Sent.
`transport.py` provides a direct Postfix SMTP adapter for future activation,
using a dedicated loopback endpoint (not deployed) and validated STARTTLS.
It distinguishes `accepted` from delivery and returns the Postfix queue ID;
absence from a queue must never be interpreted as delivery. Future activation
must add a delivery-status monitor and persist confirmed delivery/Sent records,
configure the dedicated loopback submission policy, and handle ambiguous SMTP
results without automatic duplicate retries. This is deliberately outside the
initial paused release. No SMTP relay subscription is required by the design.

## Project controller

`nullmail-control.service` is a separate root-owned Unix-socket helper. The socket
is root:nullmail 0660 in `/run/nullmail-control` (0750). Its only schemas are
`{"op":"status"}` and `{"op":"register","label":"safe-project"}`. It accepts
1–32 lowercase hostname-label characters, rejects reserved mail hostnames,
limits the total to 100 projects, and has no caller paths, shell commands,
config-edit operation, DNS-write operation, queue release or send operation.

The controller maintains ONLY these dedicated files and their postmap databases:

- `/etc/postfix/nullmail_project_domains`: virtual **alias** domains.
- `/etc/postfix/nullmail_project_aliases`: exact address → john@nullverse.cloud.

The pre-existing apex mailbox and alias maps are preserved. `nullverse.cloud`
remains the virtual **mailbox** domain. No catchall or plus-addressing is added.
Standard aliases are admin, support, billing, hello, storycast, postmaster and
abuse. Seed projects: nullink, storycast, axis. Web DNS and deployment state are
independent of mail registration: Axis remains an undeployed website.

Map writes use root-only staging, fixed postmap invocations and replacement;
failed checks restore prior map bytes. Postfix is checked/reloaded after map
updates; the helper never edits main.cf or any outbound setting. Status exposes
only queue IDs/states, not envelope addresses or message bodies. Queues are
observed, never modified. DNS checks are read-only and cached for 60 seconds.
A project is shown as MX verified only when an actual DNS lookup returns MX
records all targeting mail.nullverse.cloud. Registration alone stays pending.

Required project record: `PROJECT.nullverse.cloud. MX 25 mail.nullverse.cloud.`
Do not replace A/AAAA records used by existing websites. No public DNS writes
are performed. SPF/DMARC absence and observed PTR/milter settings are shown,
without inventing a DKIM selector/key or claiming all possible selectors were
queried. Provider PTR and DNS provisioning remain administrator tasks.

## Deployment and checks

See [deployment record](../docs/NULLMAIL.md) for exact backups, results and rollback.
Runtime dependencies are Python 3, Postfix, dig, systemd and Caddy already on
this VPS. There are no new runtime Python/npm packages or third-party assets.

Backend tests:

```sh
python3 -W error::ResourceWarning -m unittest discover -s nullmail/tests -v
node --check nullmail/static/app.js
```

`tests/browser_fixture.py` runs isolated Maildir/draft/auth state on 127.0.0.1:8798.
`tests/browser.cjs` exercises it through Playwright request routing at the real
HTTPS origin; all fixture traffic stays on loopback. It tests actual UI code,
HTTP handlers and real Nullink PIN verification, while only DNS/map operations
are fixtures. Set `PLAYWRIGHT_MODULE` to an installed Playwright package. Chrome
is `/opt/google/chrome/chrome`. Screenshots contain fixture mail only.

`tests/live_verify.py` is an explicit administrator test, run as `morc`, which
creates a temporary real session, reads inbox counts without opening messages,
checks auth/CSRF and idempotent Axis registration, and drives the actual live
HTTPS browser UI. It revokes the session afterward. Never print its token.
This test does not submit SMTP DATA, consume a live PIN, or send email.
