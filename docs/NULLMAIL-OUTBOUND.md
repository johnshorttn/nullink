# Nullmail outbound activation — 6 October 2026

Production: https://nullmail.nullverse.cloud

The resumed initial deployment completed successfully (job
`9f8ec50c020f4aaf9d9de717b1286d20`, exit 0). It was not a usage-limit failure.
This follow-up enabled explicit user Send actions while preserving the owner's
repairs and the original mail queue.

## Isolation and configuration

Primary `/etc/postfix/main.cf` and `master.cf` are byte-identical to the pre-change
backup; effective postconf output is also unchanged. relayhost remains empty,
default_transport smtp, relay_transport relay, defer_transports smtp, and the
global hold_headers rule is retained. All five old queue entries remain held.

A separate Postfix instance listens only on 127.0.0.1:2526, managed by
`nullmail-submission.service`. It uses `/etc/postfix-nullmail`,
`/var/spool/postfix-nullmail` and `/var/lib/postfix-nullmail`. Its main/master
configuration snapshots are in `nullmail/deploy/submission-*.cf`. It has an empty
relayhost, direct SMTP transport, no deferral or HOLD rule, and no pickup service.
It shares existing TLS and exact mailbox/alias maps; it does not replace them.
Future primary routing changes need explicit review for this separate instance.

TLS validates mail.nullverse.cloud. A dedicated private client certificate,
readable only by root and the nullmail group, is stored under `/etc/nullmail`.
Only its SHA256 fingerprint is permitted in this instance's client, relay and
recipient restrictions. Loopback without that certificate is rejected. No SASL
password, public submission listener, unauthenticated relay or secret in git.
The self-signed client certificate expires in October 2036; renew it and update
the fingerprint allowlist together. The server certificate follows existing TLS
renewal. The web service cannot alter configuration or certificate files.

Root-owned `/etc/nullmail/outbound.json` contains `{"enabled": true}`. The web
service reads it at startup. Its systemd drop-in requires the submission service.
Only a human Send action invokes SMTP. Previously paused items are not replayed.

## Semantics and checks

SMTP acceptance is recorded as accepted with queue ID in Outbox. Delivery is
unverified; no automatic Sent entry or delivery monitor is claimed. Durable
submitting/unknown states prevent accidental retry after crashes or uncertain
DATA responses. Definite rejection permits explicit user retry.

- Fresh DNS MX lookups and bounded direct TCP25 greeting/QUIT probes succeeded
  to gmail-smtp-in.l.google.com, outlook-com.olc.protection.outlook.com and
  mail.protonmail.ch. No external SMTP envelope or DATA was submitted.
- Live local recipient checks: authenticated certificate 250; missing certificate
  554; primary port 25 untrusted relay 554. RSET/QUIT, no DATA.
- Runtime nullmail account can read activation configuration and authenticate.
- 16 backend/integration tests pass, including non-transmitting simulated SMTP
  acceptance, recipient refusal, uncertain response and duplicate/crash protection.
- Desktop/Pixel 9 fixture browser checks pass; enabled-send fixture verifies
  acceptance label, queue ID, read-only accepted message and blocked repeat Send.
- Live authenticated desktop/Pixel 9 browser checks pass: enabled outbound,
  inbox count, projects/setup, no JavaScript errors, logout revocation. No
  real message was opened or marked read.
- Maildir files and all five held recovery files retain their pre-change paths
  and SHA256 bytes. Primary queue: five held; dedicated submission queue: empty.
- No external test message, queue flush/release/delete, or production SMTP DATA.

## Backups and rollback

Pre-change root-only backup:
`/root/nullmail-build-backup/outbound-20261006T100641Z`.
Pointer: `/root/nullmail-build-backup/outbound-latest`.
Contains previous runtime/source, Postfix config, effective settings and preservation
hashes. Credentials remain outside source control.

To pause new submissions, set `enabled` to false in `/etc/nullmail/outbound.json`
and restart nullmail. This does not cancel already accepted messages; do not stop,
flush or delete queues blindly. There is no need to modify primary Postfix or
restore old Maildir/queue backups. Retain drafts, unknown/accepted records and both
queues. Application rollback must preserve duplicate-protection records.

The deployment corrected directory traversal permissions on `/etc/nullmail`
(root:nullmail 0750; configuration/client key files 0640) after the first startup
check caught a permission error. Final health and runtime authentication passed.
