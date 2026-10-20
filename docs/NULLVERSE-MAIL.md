# Nullverse mail configuration — 2026-10-06

Live VPS: 216.158.238.236. Identity: mail.nullverse.cloud. Postfix listens on
127.0.0.1:25 and 216.158.238.236:25 (IPv4 only). UFW permits inbound TCP25
on eth0 to that public address; nftables confirms the rule. No IMAP/submission
listeners were added. External incoming delivery has not been tested.

## Mailbox and acceptance

Only nullverse.cloud is a virtual mailbox domain. john@nullverse.cloud maps
to /var/lib/nullmail/john/Maildir/. Exact aliases hello, support, billing,
admin, storycast, postmaster and abuse at nullverse.cloud map to John.
No catch-all, plus addressing, project subdomains or unknown domains are accepted.
Maps: /etc/postfix/nullverse_mailboxes and /etc/postfix/nullverse_aliases,
compiled with postmap. No pre-existing mailbox was found.

The dedicated nullmail system account has a locked password and nologin shell;
Maildir directories are mode 0700. Postfix virtual delivery runs with its UID/GID.
A traverse-only ACL for postfix on the previously root-only /etc/postfix enables
map access without granting access to secrets. Local Unix-user delivery remains
disabled. enable_original_recipient=yes preserves X-Original-To; proven by
local delivery to hello with Delivered-To john. One synthetic validation message
remains in Maildir. No Nullmail UI was built; the HTTPS mail host only reports
that the UI is absent. Mail is accessible through administrator filesystem access.

mynetworks=127.0.0.1/32; smtpd_relay_restrictions=permit_mynetworks,
reject_unauth_destination. Recipient restrictions explicitly reject unlisted
recipients and unauthorized destinations, including on trusted connections.
SMTP AUTH is disabled. Existing 256 KiB message-size and rate limits remain.

## TLS and queue safety

Caddy manages the Let's Encrypt certificate for mail.nullverse.cloud (current
expiry 2027-01-04). SMTP offers STARTTLS with TLS >=1.2, opportunistically for
Internet MTA interoperability. Verified certificate/hostname handshake passed.
The root-only TLS sync helper validates hostname, expiry, key match and trust,
atomically copies a 0600 key+chain bundle, and reloads Postfix only on change.
An hourly systemd timer copies Caddy renewals. Helper and units are in deploy/;
private keys are not in the repository. Monitor timer/service failures.

relayhost is empty (the invalid placeholder was removed); outbound relay SASL
is disabled and SMTP TLS is opportunistic for direct MX routing. Actual outbound
sending remains paused by retained defer_transports=smtp and the existing HOLD
header checks for local pickup. Public SMTP uses a separate inbound-cleanup
service with header_checks empty, allowing incoming mail to reach Maildir.
Do not interpret relay removal as working outbound delivery or release old mail.

All five pre-existing held messages remain byte-for-byte unchanged (SHA256
verified). No existing queue was released/flushed. Only the newly created local
validation message was individually retried after fixing map directory access.
No external email DATA was transmitted.

## Validation and remaining gaps

Postfix check and effective main/master/map audits passed. SMTP tests from
127.0.0.2 and the public source address (both outside mynetworks) accepted John,
rejected unknown recipients with 550, and denied external relaying with 554.
All eight agreed addresses were RCPT-tested. Local alias delivery and original
recipient header were verified. Public-source tests ran on this host and do not
prove reachability from outside the VPS.

Eight-second TCP25 attempts to current MX records all timed out:
- Gmail: gmail-smtp-in.l.google.com / 142.251.163.27
- Outlook: outlook-com.olc.protection.outlook.com / 52.101.50.9
- Yahoo: mta5.am0.yahoodns.net / 67.195.204.72

These results do not establish a provider block. UFW outbound policy is allow.
Investigate upstream/network connectivity before enabling outbound delivery.

DNS observed (including authoritative checks): mail.nullverse.cloud A is
216.158.238.236; nullverse.cloud MX is 25 mail.nullverse.cloud. These are correct.
No mail AAAA is published and IPv6 SMTP is not enabled.
- PTR remains vps3612500.trouble-free.net; provider must change it to
  mail.nullverse.cloud for matching forward/reverse identity.
- No apex SPF TXT exists. For an exclusively this-VPS sender, the candidate
  record is v=spf1 ip4:216.158.238.236 -all; confirm all legitimate senders first.
- No DKIM signer/milter is configured and no key/selector was provisioned.
  Checks for default and mail selectors returned no TXT; arbitrary selectors
  cannot be exhaustively enumerated. A signer and its public DNS key are needed.
- No _dmarc.nullverse.cloud TXT exists. Publish a deliberate DMARC policy after
  aligning SPF/DKIM; monitoring-first is a reasonable initial deployment.

Portal, Nullink health, StoryCast root and recovery health all returned HTTP 200;
Postfix, Caddy, Nullink, StoryCast and both recovery services are active.
No existing application edits, passwords or recovery secrets were changed.

## Backup and rollback

Root-only backup: /root/mail-backup-20261006T034854Z contains original Postfix,
Caddy and UFW trees, firewall snapshots, effective config, queue metadata and held
message checksums. /root/nullverse-mail-backup-path records this location.

If rollback is needed: remove the exact new UFW TCP25 rule first, stop Postfix,
restore backed-up Postfix configuration with original directory permissions,
restore/validate/reload the backed-up Caddyfile, disable the TLS sync timer and
start Postfix via systemd. Preserve Maildir and all queues; do not delete or flush
them. Avoid restoring entire firewall snapshots over unrelated later changes.
No rollback was required after validation passed.
