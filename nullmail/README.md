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
there is no delete endpoint or automatic retention purge. Drafts and
Outbox items persist in `/var/lib/nullmail/app/drafts.sqlite3`. Reply defaults to
an exact configured X-Original-To identity, otherwise John. From authorization
is checked again on save and Send; control characters/header injection are
rejected. Saving a draft allows an incomplete To field; Send validates it.

**Outbound submission is enabled in production** by root-owned
`/etc/nullmail/outbound.json` (`{"enabled": true}`). Missing configuration keeps
new installations paused. Changing this file requires a Nullmail service restart;
there is no web activation endpoint or automatic app retry worker. Existing paused
Outbox items remain paused until an explicit Send action.

Send requires a valid human session, same-origin request, CSRF token and authorized
From identity. It durably claims the draft before SMTP. Accepted, uncertain or
interrupted submissions cannot be edited or resent. A definite rejection permits
an explicit retry. A lost DATA response is **unknown**, never automatically retried.

`transport.py` validates the mail server's TLS certificate and presents the private
Nullmail client certificate to 127.0.0.1:2526. `nullmail-submission.service` runs a
separate Postfix instance configured in `/etc/postfix-nullmail`, with its own queue
at `/var/spool/postfix-nullmail`. Only its fingerprint allowlist can submit, even
from loopback. Local pickup is disabled. The instance shares existing exact virtual
alias/mailbox maps and server TLS certificate with the primary instance. Its SMTP
transport sends directly to destination MX hosts. No relay subscription is needed.

The primary Postfix configuration, global HOLD and SMTP deferral, and all five old
held recovery messages remain unchanged. No queue release/flush/delete is needed.
The dedicated instance has no HOLD/deferral and cannot see the old queue.

The app records SMTP **accepted** and the queue ID in Outbox. This is acceptance at
submission time, not a live assertion that the message remains queued. It does not
infer delivery from queue disappearance. There is currently no delivery-status
reconciliation or automatic Sent copy; delivery and inbox placement remain
unverified. Inspect the dedicated instance's logs/queue for administrator diagnosis.
Postfix can retry accepted messages normally; the app never retries submissions.

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
checks auth/CSRF and enabled outbound configuration, and drives the actual live
HTTPS browser UI. It revokes the session afterward. Never print its token.
This test does not submit SMTP DATA, consume a live PIN, or send email.

## Current core and Cases release (October 2026)

The live web client now uses `/api/v1` for account visibility, nested rule editing,
preview/explicit runs, local labels, submission audit and Cases. Cases are durable
work groups separate from labels, with provider/store/message membership, status,
notes and history. No external notification is sent when a case changes. See
[shared API and Android parity](../docs/NULLMAIL-API.md),
[Gmail implementation limits](../docs/NULLMAIL-GMAIL.md), and
[release evidence](../docs/NULLMAIL-CASES-RELEASE.md). Android remains future scope.

Run all fixture backend tests with the command above. Additional fixture browser
suites are `tests/browser_workspace.cjs` and `tests/browser_cases.cjs`; for Cases
start `tests/browser_fixture.py` with `NULLMAIL_FIXTURE_CASES=1` and matching
`NULLMAIL_FIXTURE_PORT` (Cases defaults to 8795). Never point fixture tests at
production mail. `tests/release_health.py` is an explicit read-only authenticated
release check: it opens no messages, groups no mail, checks prior active sessions
remain present, and revokes its own temporary session through the auth service.

Gmail integration (12 October 2026): the shared v1 API and web client now support
Google OAuth connection, encrypted server-held tokens, bounded import/history sync,
provider-routed send and cross-provider Cases. Production is **not connected** until
the owner supplies the OAuth client/consent, encryption key and approved HTTPS
egress. Gmail read flags/folders/labels/Cases are local-only. See
[setup and precise limitations](../docs/NULLMAIL-GMAIL.md) and
[release evidence](../docs/NULLMAIL-GMAIL-RELEASE.md). Android APK remains future work.
