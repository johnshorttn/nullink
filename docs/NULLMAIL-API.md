# Nullmail API v1 and Android parity

Release: 2026-10-10. Base: `https://nullmail.nullverse.cloud/api/v1`.
The existing sslip hostname also serves the same API, with its own host-only session.
The web app uses this API. No Android APK has been built.

## Authentication and permissions

The existing Nullink single-owner human session remains authoritative. Login uses
`POST /auth/verify {"code":"…"}`; obtain a session-bound CSRF token from
`GET /session`. Cookies remain Secure, HttpOnly, SameSite=Lax, host-only. Every
request validates revocation through Nullink. Every POST requires the exact HTTPS
Origin for its host, same-origin Fetch Metadata when provided, JSON, and
`X-CSRF-Token` (login requires Origin but not a pre-login CSRF token).
No CORS, legacy cookies or bearer credentials have been added.

Nullink currently returns a session ID, not a multi-user identity. Its existing
human sessions map to the stable `local-owner` principal; preferences persist
across that owner's sessions. A future upstream `user_id` is never automatically
an owner: it receives no rights unless the server supplies explicit read/send
grants. The permission layer is exercised with delegated fixtures. Production
multi-user provisioning and a delegation management UI are **not implemented**.
Never map a browser-provided user ID, email, header or arbitrary bearer token to
owner rights. Rule/label administration and historical runs require owner rights.
Each message/attachment/flag/move/label operation checks mailbox read permissions;
each draft/send checks ownership and the current exact send identity allowlist.
Legacy `/api/*` aliases use the same permission checks.

The current mail installation contains one physical mailbox and 28 aliases. John
controls the controller-authorized identities. Alias virtual inboxes require the
trusted Postfix delivery prefix (`Return-Path`, `X-Original-To`, `Delivered-To`,
`Received`) with the expected physical Delivered-To. Only the first delivery-added
original recipient is authoritative. Visible To/Cc or sender-supplied headers
below the delivery prefix do not assign accounts. Historical mail without this
prefix remains in the physical mailbox with `routing_status: ambiguous`.
This trust model assumes Maildir is writable only by the existing delivery/app
account and administrators; arbitrary imports must not be treated as trusted
local deliveries. Additional physical mailboxes need an explicit server-side
store/routing registry; this release does not invent access to unconfigured stores.

## Endpoints and parity

Machine-readable schemas: [nullmail/openapi.json](../nullmail/openapi.json).
GET mail does not change read flags. POST actions do. Errors consistently include
`{"error":"human-readable message","code":"invalid_request"}`; codes also include
`unauthenticated`, `forbidden`, `not_found`, `unavailable`, and `request_error`.
The older human-readable `error` field remains compatible.

| Feature | Shared API | Web / future Android behavior |
|---|---|---|
| Discover support | GET `/capabilities` | Same feature flags, permissions, field/operator/action schema and limits |
| Account groups/counts | GET `/accounts` | Local first; aliases distinguished; independent authorized sending identities |
| Unified inbox visibility | POST `/accounts/selection` with `selection: []` or account IDs | Stored per principal; None means none, never delivery/sync disable |
| List/search | GET `/messages?folder=inbox&offset=0&limit=100` | `q` searches text body and metadata; `unread=1`, `recipient`, `label`; `account` explicitly selects one account independently of visibility |
| Read | GET `/message?folder=inbox&id=…` | Plain-text body, safe attachments, routing confidence, labels, priority, server-selected reply identity |
| Thread | GET `/thread?folder=inbox&id=…` | Message-ID/References/In-Reply-To matching, not subject guesses; 1,000-message scan / 100 results; `truncated` is explicit |
| Attachment | GET `/attachment?folder=inbox&id=…&part=N` | Same permissions; download-only octet stream |
| Read flag / move | POST `/message/read`, `/message/move` | `folder`, `id`, `read: boolean` or `target: inbox/archive/trash`; no permanent deletion |
| Drafts | GET/POST `/drafts` | Existing persistent drafts, server-side sender/ownership validation |
| Send | POST `/send` | `id` and required `request_id`; visible authorized From, no hidden-account filtering |
| Submission audit | GET `/sent?offset=0` | Actor, From identity, status/queue ID; accepted is not verified delivery |
| Labels | GET `/labels`; POST `/labels/save`, `/labels/delete` | Names, hex colors, parent IDs; local-only; cyclic nesting rejected |
| Apply labels | POST `/message/labels` | `folder`, `id`, complete `labels` list; same mailbox permission |
| Rules | GET `/rules`; POST `/rules/save` | Nested visual editor on web; Android renders same server schema |
| Versions | GET `/rules/versions?id=…`; POST `/rules/restore` | Restore creates a new version; optimistic current `version` required |
| Preview | POST `/rules/preview` | `folder`, explicit 1–50 `ids`, optional candidate `rule`; explanations, conflicts, zero writes |
| Explicit historical execution | POST `/rules/run` | Same IDs/folder, signed unexpired preview `token`, `confirm:true`; stale state/rules rejected |
| Run history | GET `/rules/history?offset=0` | Latest 100 per page; actor/source/status/actions/explanations |
| Project/mail setup | GET `/config`, `/projects`; POST `/projects` | Existing owner-only controller, routing/DNS unchanged |
| Logout | POST `/auth/logout` | Existing server revocation; independent of mail-controller availability |

Message pagination returns `total`, `offset`, `next_offset`, `messages`;
`limit` is 1–100. Run/submission history pages are at most 100. Rules, account and
label catalogs are bounded by service storage and should remain small. Drafts
retain the legacy list response; full draft/catalog cursor pagination is follow-up.

## Rules and processing

A condition is `{field, op, value}` or `{group: "ALL"|"ANY"|"NOT", children: […]}`.
NOT has exactly one child. Validation permits at most 64 nodes across condition
and exception, 6 nested levels, 16 children per group, 500-character values, and
16 actions. Regex, scripts, sends, scheduling, AI and tasks are unavailable.
Dates are YYYY-MM-DD UTC; age derives from the parsed message Date header and is
only evaluated on arrival or an explicit run, not periodically scheduled.
Malformed/missing dates do not match date/age leaves. Header/body predicates use
bounded parsed content; HTML is not executed or rendered. Recipient conditions
use trusted envelope identities. Labels are exact local label IDs.

Rule scope is a nonempty list of explicit authorized accounts. The physical
mailbox scope includes its alias deliveries. UI visibility never changes scope.
Ascending integer priority runs first, ties break by rule ID. Later rules see
simulated effects of earlier actions; stop ends the chain after a match. Actions:
add/remove local label, read/unread, priority low/normal/high, archive, or move to
inbox/archive. No rule can send, trash or delete mail. Conflicting assignments in
a preview are reported; later actions win.

The 15-second server worker seeds a persistent baseline before its first scan,
so all pre-existing mail is excluded. A stable Maildir key is claimed once before
any action; a label/flag/move cannot retrigger it. Editing rules does not reprocess
old messages. Each scan handles at most 50 new messages. An interrupted action
is logged and never automatically replayed; inspect history and use a fresh
explicit preview to recover. File flag/move steps and SQLite state are not one
transaction: interrupted runs can have partial effects, deliberately requiring
review. The system never claims exactly-once atomic filesystem/database effects.

Preview is pure (including no database writes). It hashes original message state,
planned results and rule revisions, signs the digest with a process-local key and
expires after ten minutes. Restart invalidates previews. Explicit run tokens are
claimed durably before effects and return their prior status on retries. No
automatic reprocessing of existing real mail is triggered by deployment.

Send request IDs are durable and bound to the actor, draft and payload fingerprint.
The exact session identifier is stored server-side for audit; no session cookie
is stored. A duplicate returns the recorded result; reusing a key with changed
content is rejected. Draft status is also durably claimed before SMTP. Unknown or
interrupted SMTP outcomes are never retried. Definite rejection or paused send
requires an explicit new request ID for a deliberate new attempt. Existing
accepted/outbox data remains intact; there is no fabricated delivery confirmation.

## Future Android authentication

Use an external system browser for owner login, never a JavaScript bridge that
extracts the web cookie. Before a native client ships, extend the existing auth
service with an audited authorization-code + PKCE flow, exact app-link redirects,
one-time codes, short-lived audience-restricted access tokens, rotating revocable
refresh tokens, and the same stable principal/permissions. Keep refresh material
in Android Keystore-backed encrypted storage, never localStorage, logs, URLs or
plain SharedPreferences. The current server deliberately rejects bearer auth;
this is a design plan, **not an enabled mobile token endpoint**. Auth changes must
preserve existing owner sessions and revocation. Every table row above is an
Android parity requirement; no rules or permission decisions belong exclusively
in the browser/native client.

## Cases (v1.1, 2026-10-12)

Cases are separate durable entities, not normal labels. The web client and future
Android use the same endpoints below. `capabilities.features.cases` is true;
`case_statuses` lists Open, In progress, Waiting, Closed; `case_sharing` is false.
The existing single-owner login is unchanged. No multi-user provisioning is claimed.

A case has an opaque stable `id`, a per-creator stable `number` and
`display_number` (for example CASE-000001), title (1–120 characters), description
(up to 4,000), status, created/updated timestamps, actor, and optimistic integer
`version`. A message can belong to multiple cases. A case may span threads and
all accounts its creator is authorized to read, including inbox-hidden accounts.
Membership keys are `(provider, account_id, message_id)`, never folder paths,
RFC Message-ID headers, UI alias selections or normal labels. The current local
store reference is `{"provider":"local","account_id":"primary","id":"<64 hex>"}`.
`primary` identifies the physical store; its aliases refer to the same message.
The schema distinguishes provider/account IDs. Gmail adapter support was added in v1.2 below; live availability depends on configuration and consent.

| Method / path | Request and result |
|---|---|
| GET `/cases` | `q`, `status`, `offset`, `limit`; returns `cases`, authorized `total`, `next_offset` |
| POST `/cases/create` | title, optional description/status, required request_id, optional `message` reference; atomic create/link; replay-safe |
| GET `/cases/detail` | `id`, offset/limit; case plus chronological `members`, total and next_offset; each member includes current folder, permitted account badges and message_ref |
| POST `/cases/save` | id, current version, title, description, status; stale versions return 409 `conflict` |
| POST `/cases/membership` | id (case), message reference, boolean linked; unique/idempotent; returns changed and current case |
| GET/POST `/cases/notes` | GET id + pagination; POST id, body, request_id; append-only, replay-safe notes |
| GET `/cases/history` | id + pagination; actor, kind, timestamp and changes, including link/unlink/rule source |

All writes require existing same-host Origin and CSRF protections. GET routes are
read-only. Collections accept offset 0–1,000,000 and limit 1–100. Caps: 2,000 cases
per creator, 500 current members per case, 20 cases per message, 1,000 notes per
case, and 4,000 characters per note. No delete/notification/external-recipient API
exists. Close/reopen/unlink do not move mail, change read flags, send mail or alter
normal labels. Normal reader opening retains its explicit mark-read behavior.
Message list/detail includes distinct case badges and `message_ref`.

**Access policy:** cases are creator-private. Every list/detail/member/note/history
and edit operation checks current mail access independently of visibility choices.
Because titles, descriptions and notes can mention any linked mail, a case is
withheld entirely (404, omitted from lists/badges/counts) if any current or former
member cannot be authorized/resolved. Former references are retained as access
guards after unlink to prevent history/free-text leakage following revocation.
No partial restricted counts or hidden subjects are returned. Missing/ambiguous
physical mail also fails closed; recovery requires administrator review. There is
no shared-case delegation UI or automatic cross-user sharing.

Rules support explicit `{"type":"add_to_case","value":"<existing case id>"}`.
The owner selects an existing case in the visual action builder. Preview reports
the proposed membership with zero writes and includes case versions in its signed
snapshot. Execution rechecks access, links idempotently, and records the rule ID
and actor in case audit history. A case-only rule action does not rename Maildir
files or rewrite normal labels. Existing-message grouping still requires the
explicit bounded preview/confirmation flow. No real mail was grouped in tests.

Android parity adds: Cases nav/search/status filter, create/edit/status/version
conflict handling, chronological members with account badges, append-only notes,
audit pagination, multiple clickable badges per mail, reader link/unlink/create,
and the add-to-existing-case rule action. All business rules and authorization
remain server-side; native auth and an APK remain future work.

## Gmail parity addition (v1.2, 12 October 2026)

All routes use the existing authenticated session. No new mobile bearer mechanism is introduced. Future Android must use the same server permissions, provider IDs, pagination and error envelope; Google credentials remain exclusively on the server. The future native auth plan remains a separately reviewed system-browser login with app-bound session exchange/secure OS credential storage; no embedded password collection, localStorage token, or Google refresh token in the APK. Google connect currently requires the existing browser session and returns to the HTTPS web callback. Native handoff is future work.

| Operation | Shared v1 API | Semantics |
| --- | --- | --- |
| Discover readiness | GET `gmail/status`, GET `capabilities` | `features.gmail` means adapter available, **not live/configured**. Check `gmail.configured`, `connected`, blockers and each account phase. No secrets. |
| Connect account | POST `gmail/connect` `{}` | Owner + CSRF; returns `authorization_url`. Open system browser/web navigation. |
| Complete OAuth | GET `gmail/callback?state=…&code=…` | Session-bound one-use state + PKCE; 303 same-origin redirect. No tokens returned. |
| Import historical mail | POST `gmail/import` `{account_id,confirm:true}` | Explicit opt-in, server polling continues; old mail does not run rules automatically. |
| Poll next bounded page | POST `gmail/sync` `{account_id}` | Account permission, CSRF, persisted retry/backoff and checkpoint. |
| Accounts/visibility | Existing `accounts`, `accounts/selection` | Local first, Gmail secondary; visibility is not permission or sync control. |
| Read/search/thread/attachment | Existing `messages`, `message`, `thread`, `attachment` | Same read authorization and pagination; Gmail cache IDs are globally namespaced hex IDs. |
| Compose/reply/send | Existing `drafts`, `send` with request_id, `sent` audit | Verified Google primary From routes to Gmail; local From routes to existing SMTP. Idempotency/unknown-send lock unchanged. |
| Labels/Cases/rules | Existing routes | Local-only effects, provider-aware membership and account scopes; previews still zero-write. |

Gmail account IDs are `gmail:<32 hex>` and remain stable if the verified address changes. Server-returned `message_ref` must be used for Cases, with provider `gmail`, matching account ID and global message ID. Native Google IDs are held server-side; do not infer account ownership from address or visible To headers. Current owners can only access their registered Gmail accounts; a hypothetical delegated principal cannot read another actor's cache through messages, attachments, Cases, notes or history. Connection remains owner-only; this does not introduce multiuser availability.

Gmail folders/read flags/labels/priority/Cases are local-only, while `provider_labels` reports observed Google label IDs. Provider changes do not undo local flag/folder choices. Historical imports are bounded at 20 list IDs/page; history page fanout capped at 100. Google history expiration sets `resync_required` until explicit import. API status exposes phase/error/retry; credentials never appear in responses. Full setup and exclusions: `NULLMAIL-GMAIL.md`. Machine contract: `nullmail/openapi.json` version 1.2.0.
