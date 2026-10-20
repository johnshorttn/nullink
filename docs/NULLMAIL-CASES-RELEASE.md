# Nullmail core + Cases release — 12 October 2026

Deployed and authenticated verification passed:
[Nullmail](https://nullmail.nullverse.cloud) and
[alternate hostname](https://nullmail.216.158.238.236.sslip.io).
Source release commit: `1fbb27e3eae8053b96b11d62ba2b69e53e50e7b8`, preserved locally
on `refs/heads/nullmail-cases-20261012` in `/opt/nullink`. No push/publication.
The real Git index, main branch and unrelated dirty files were not reset or staged.

## Shipped

- Separate durable Cases with stable opaque IDs and CASE numbers, title,
  description, Open/In progress/Waiting/Closed status, timestamps, optimistic
  edits, append-only notes and actor audit.
- Multiple cases per message; cross-thread/account membership uses a distinct
  provider/store/message tuple that survives folder moves. Linking, closing and
  unlinking do not move/copy mail, change labels or send notifications.
- Desktop/mobile Cases navigation, search/status filters, create/edit, reader
  create/link/unlink, distinct clickable badges, chronological linked messages
  with account badges, notes and paginated activity history. Explicit Cases views
  include inbox-hidden **authorized** mail; visibility is not authorization.
- Creator-private case access checks on every route. A case is withheld completely
  if any current/former linked mail cannot be authorized/resolved, protecting
  titles, notes, counts and audit history. No multi-user availability is claimed.
- Explicit add-to-existing-case rule action, visual chooser, zero-write preview,
  case-version snapshot validation and idempotent linking with rule/actor audit.
  No automatic grouping of historical real mail.
- The October 10 core remains intact: local-first account visibility, authorized
  From selection, nested rules/exceptions/actions/order/stop, bounded explicit
  historical runs, rule versions/history, local labels, search/read/reply/drafts,
  durable send idempotency and audited submission status.
- Shared `/api/v1` contract, schemas/capabilities and Android parity mapping updated
  in [NULLMAIL-API.md](NULLMAIL-API.md) and
  [OpenAPI](../nullmail/openapi.json). CSRF, host/origin binding and existing auth
  audience are preserved.

## Evidence

- Current source/runtime were compared with October 10 deployment hashes before
  changes: all deployed files matched. The current mailbox had **four** files,
  rather than the earlier three, and was backed up afresh.
- Prior core authenticated release verification completed before Cases changes.
  Final deployment checks passed on both HTTPS hostnames: protected endpoints,
  authenticated capabilities/Cases reads, static assets, CSRF rejection, logout
  and revocation. Temporary verification sessions were removed; previously active
  sessions remained present. No PIN/TOTP was consumed by these release checks.
- **60 fixture backend tests passed**, including existing auth/transport regression,
  independent labels, cross-account/thread/multiple-case links, uniqueness,
  folder moves, close/reopen, notes/idempotency, version conflicts, pagination,
  provider validation, denied case metadata/notes/history/badges, former-member
  access guards, rule preview zero writes and case-only execution with unchanged
  Maildir bytes/paths.
- Desktop 1440×1000 and mobile 412×915 fixture Cases browser checks passed:
  create from reader, cross-account linking, badges, notes, hidden authorized mail,
  close/reopen, history, unlink, search/status filters, no overflow/JS errors or
  external requests. The existing desktop/mobile mail-client browser suite also
  passed. One earlier Chromium run closed unexpectedly; a fresh isolated rerun
  passed. Screenshots contain synthetic mail only, under the private backup root.
- Python compilation, JavaScript syntax, OpenAPI JSON parse and scoped whitespace
  checks passed. Deployment health passed on loopback and both public hosts.
- Final production SQLite integrity: `ok`; production case count: **0**. Existing
  rule-run count was preserved. All four original mail paths and SHA256 bytes
  matched the fresh backup. Primary/submission Postfix and `/etc/nullmail` config
  bytes remained unchanged. Mail transport, controller and app services are active.
  No real sends, production case creation, message opens, rule runs or email
  mutations were performed by the release tests.

## Migration, preservation and rollback

Fresh pre-change private checkpoint:
`/root/nullmail-build-backup/cases-20261012T141108Z` (pointer `cases-latest`).
It includes working source/runtime, dirty diff, mail/config snapshots and consistent
SQLite backups taken during a brief app-only stop. Transport kept running.

Deployment checkpoint:
`/root/nullmail-build-backup/cases-deploy-20261012T142608Z`
(pointer `/root/nullmail-build-backup/cases-deploy-latest`).
Previous runtime: `/usr/local/lib/nullmail-before-20261012T142608Z`.
The checkpoint's `release.json` records exact deployed hashes. The deployed app is
`/usr/local/lib/nullmail`; service `nullmail.service` remains loopback-only.

Migration is additive in `/var/lib/nullmail/app/workspace.sqlite3`: cases,
memberships, historical access references, notes, events, idempotency requests,
indexes and `cases_schema=1`. Existing preferences/rules/labels/send records and
`drafts.sqlite3` remain intact. No existing mail is grouped or reprocessed.

The deployment helper rolls back the runtime on failed public/authenticated health
checks, provided the installed hashes have not changed concurrently. For a later
manual rollback, compare current runtime hashes to the checkpoint first, stop only
`nullmail`, move the failed/current runtime aside, restore the previous runtime
path above to `/usr/local/lib/nullmail`, then start and health-check `nullmail`.
Keep current databases and Maildir: older core ignores the additive Cases tables.
Do not restore stale databases, mail, queues, transport config or auth sessions.
If runtime hashes differ, review/merge concurrent changes instead of overwriting.

## Remaining work / intentional limits

Gmail has only a fixture-tested dormant OAuth/read adapter; live sync, HTTP
callback/account integration, OAuth client/consent setup and Google egress are
**not complete**. See [exact Gmail blockers](NULLMAIL-GMAIL.md). Labels/Cases are
local metadata, never represented as Google-synchronized. No Android APK or native
bearer flow was built; native auth remains the documented future plan.

Cases are private to the existing single owner's principal; no shared-team inbox,
case delegation UI, assignments, SLA timers, external notifications, destructive
case deletion or note editing is shipped. Unresolvable historical members hide a
case conservatively and require administrator review. Future Gmail/multiple
physical stores must supply their own stable account references and resolvers.
The prior core's bounded references-based threading, non-atomic Maildir/SQLite
rule effects with explicit interrupted-run recovery, and unverified SMTP delivery
status remain accurately documented in the API contract.
