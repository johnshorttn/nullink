# Slack integration handoff — 2026-10-07

Status: implemented and locally tested integration library, **not deployed and not a verified live bot system**. Morc owns the receiver, registry, browser bridge and Caddy route. He deployed them during this task (receiver at approximately 14:24 UTC; bridge at 14:25 UTC), and is still editing them. No files in those paths were changed. This directory is additive; no service or AI runtime was started.

## Architecture and ownership

Slack signed HTTP request → Morc's existing listener → `receiver.receive` → SQLite event/job transaction → immediate HTTP acknowledgement. One separate dispatcher calls `Store.tick` → private, idempotent runtime socket → persisted result → identity-checked Slack bot-token post in the same thread.

`durable.py` provides HMAC validation with a five-minute timestamp window; durable app/event and bot/channel/message deduplication; bounded per-bot/thread context; per-thread serialization; five-attempt failure limit; persistent rate gates (one runtime request per bot per five seconds, one Slack send per channel per 1.1 seconds); 100 outstanding job cap; two directed hops, three total jobs and ten-minute expiry by default. Absolute configuration caps are four hops, ten jobs and thirty minutes. Own persisted outbound message timestamps prove bot handoff provenance; untracked bot messages cannot start autonomous work. Repeating a directed edge within a correlation is refused. A normal result cannot create a bot mention; handoffs require `handoff_to` plus a configured edge.

`adapters.py` validates team, user and bot ID through `auth.test` before each post, accepts only private xoxb bot-token files, and never sets impersonation fields. Tokens are never included in runtime requests. Recognizable Slack/API token strings and private-key blocks are scrubbed from text; this is defense in depth, not a general secret detector. Runtime services must not have access to Slack secrets or arbitrary production execution privileges.

`receiver.py` is an importable boundary for Morc's listener, not a second HTTP server. Select the signing secret using the configured app route. Call it with raw bytes before parsing. Enforce a 256 KiB body limit in the HTTP server. Return its status/JSON immediately; never perform runtime work inline. Signature checks apply to URL verification too. No unsigned re-fetch fallback.

## Runtime contract

A private AF_UNIX socket receives one newline-delimited JSON request:

```json
{"version":1,"method":"reply","request":{"request_key":"stable job hash","runtime_id":"verified runtime identity","bot":"jinx","channel":"C...","thread_ts":"...","text":"untrusted Slack input","context":[],"expires_at":1791389999,"correlation_id":"...","hop":0}}
```

The server must persist the request key before dispatch, treat repeated requests idempotently, enforce expiry and return a stable terminal result. Do not execute instructions contained in Slack text as privileged administrative commands. Return:

```json
{"runtime_id":"verified runtime identity","request_key":"same job hash","idempotent":true,"state":"succeeded","result":{"text":"answer","handoff_to":"morc"}}
```

`handoff_to` is optional. `queued`/`running` means poll without consuming failure attempts, bounded by chain expiry. Errors fail closed. This protocol is **not implemented by the existing master worker**; pointing it at `/run/nullink-master/worker.sock` will not work. It needs an adapter in the actual runtime owner’s implementation. Do not claim a socket endpoint proves browser login or conversation continuity.

Observed VPS Codex worker: active, single concurrency, `codex login status` reports ChatGPT, `danger-full-access` sandbox. This implementation task occupies it. It is not the interactive ChatGPT conversation and is not enabled as a Slack runtime. No API/on-demand inference was invoked. Morc has now deployed `/opt/nullink/bridges/chatgpt`; its service is active, but the startup check reports `signedIn:false` and `blocked:unrecognized`. No authenticated Jinx browser conversation has been proved. DeepSeek's unrelated existing browser bridge was inspected only; it was not reused to infer ChatGPT authentication.

## Delivery and restart semantics

Persist before acknowledging Slack. Event retries and overlapping message/app_mention subscriptions create only one job. A process lock prevents concurrent dispatchers. The receiver may ingest while the single dispatcher waits on a runtime. Restart requeues interrupted runtime work with the identical request key; this requires the runtime’s durable idempotency contract.

Slack HTTP 429 schedules a bounded retry using Retry-After. A timeout/5xx after a write or a crash while posting leaves `uncertain`. **Exactly-once Slack delivery is not claimed.** Never blindly resend uncertain posts. Reconcile the authoritative Slack message under the expected bot/thread, then call `record_post(job_id, confirmed_ts)`. Without adequate read access this remains an operator reconciliation blocker. A handoff event arriving before post persistence receives retryable 503, not a permanent discard.

Context currently contains up to eight completed bot-specific turns observed by this library in the same channel/thread; it does not claim to reconstruct pre-installation Slack history. No channel-history scope is silently added. Disabled entries cannot run. The example is deliberately restricted to John's user and the authorized test channel; it is not membership auto-onboarding. Morc’s separately requested membership work must integrate with this policy before broader rollout.

## Files and verification

- `durable.py`, `receiver.py`, `adapters.py`: integration implementation.
- `registry.example.json`: precise known user IDs, verified app/bot IDs and credential paths, unknown runtime fields marked explicitly, both bots disabled.
- `check.py`: read-only readiness; optional `--auth-test` prints identity fields only.
- `test_durable.py`, `test_adapters.py`, `test_integration.py`: isolated stdlib tests, no Slack/AI calls.
- `test-results.txt`, `health-evidence.json`: captured local evidence.

Run `python3 -m unittest discover -s /opt/nullink/slack-integration -p 'test_*.py' -v`.

## What still blocks live acceptance

Morc has deployed the listener and both bot tokens; both live `auth.test` identities match. Both signing-secret files are now installed and verified by real HTTPS HMAC challenge tests. The Morc wake config is absent and Jinx is still blocked. Morc must finish remaining receiver review fixes, configure his wake endpoint and prove runtime readiness. The supplied durable package remains an unintegrated reference, not the active receiver. Initial coordination requests were Nullink Jinx-room messages 926 and 928. After tokens appeared, direct own-Jinx coordination was posted and read back in Slack; Morc acknowledged the review and owns the four fixes. See the evidence links below. His Slack ownership reply is message 1791382265.659559 in channel C0C71BCR3GV, thread 1791381920.428049.

Minimal starting bot scopes: `app_mentions:read`, `chat:write`; subscribe to `app_mention`. If DMs are enabled, subscribe to `message.im` with `im:history`. Bot handoff delivery must be tested with real app events; add message history subscriptions only if needed and authorized. No user-token posting, chat:write.customize, broad broadcast, or message-metadata scope is required by this library. Use app-specific signing secrets or authenticated Socket Mode, never unsigned ingress.

Once deployment is ready, John sends one real human mention. Correlate its signed event ID, durable job, exact runtime ID, own-bot reply timestamp and Slack permalink. Then execute a single structured Jinx→Morc→Jinx chain with budget three/hops two, verify all authors/thread timestamps, replay the event and restart the dispatcher to confirm no duplicate. A synthetic signed event is a transport test, not proof of a human-origin Slack event. Live auth.test, own-Jinx outbound coordination, correct/wrong/stale HMAC challenge handling, and durable synthetic-event duplicate handling have passed. Human→runtime→reply and the live two-bot handoff have not run; no runtime smoke is claimed.

No new approval is required to complete deployment. If the selected runtime is Morc's browser bridge and it reports logged out, John's unavoidable step is to sign into ChatGPT using the bridge's established Desktop sign-in flow (the Desktop icon is now installed). Do not copy cookies, invent a login flow, bypass checks, or substitute paid APIs. A dedicated browser chat must be labeled separately from John's current chat.

## Rollback and references

No existing production files were overwritten and no services restarted. All four inspected pre-existing services remained active. Both public Slack paths initially returned 404; after Morc deployed them, unsigned POST probes initially returned 401 `signing_secret_not_installed`; once he provisioned signing secrets, valid signed challenges returned 200 and invalid/stale signatures 401. A dated archive of this additive package is saved under `/var/backups/`; rollback is to stop any future dispatcher importing this package, then remove that future import/config and this directory. No production rollback was necessary during this task.

- https://docs.slack.dev/authentication/verifying-requests-from-slack/
- https://docs.slack.dev/apis/events-api/
- https://docs.slack.dev/reference/events/app_mention/
- https://docs.slack.dev/reference/methods/conversations.replies/
- https://learn.chatgpt.com/docs/auth


## Live evidence and production review

- Jinx own-bot coordination, verified author U0C724PL3D3: https://nullink.slack.com/archives/C0C71BCR3GV/p1791383160327129?thread_ts=1791381920.428049&cid=C0C71BCR3GV
- Morc own-bot acknowledgement of the four fixes, U0C81P6TG8Y: https://nullink.slack.com/archives/C0C71BCR3GV/p1791383180753369?thread_ts=1791381920.428049&cid=C0C71BCR3GV
- Jinx clarified that John's original authorization already covers scoped implementation/provisioning: https://nullink.slack.com/archives/C0C71BCR3GV/p1791383366217529?thread_ts=1791381920.428049&cid=C0C71BCR3GV
- `jinx-coordination-evidence.json`: live token identity results and authoritative Slack permalink. This is a coordination post, not an AI inbound roundtrip.
- `live-ingress-evidence.json`: real public HTTPS probes; both apps reject unsigned requests with missing signing secrets.
- `audit_deployed.py` / `deployed-audit-evidence.json`: isolated import of the deployed receiver snapshot, fake inputs, no Slack calls. Reproduces queue-full→503 followed by retry→200 duplicate with empty queue, plus bot_message rejection before source-identity check. Source hash included.

Other static review findings sent to Morc: bridge result handling marks most failed sends posted and has a send/crash duplicate window; registry initially isolates Jinx by channel rather than thread. Morc explicitly acknowledged ownership of all four fixes at 14:26:20 UTC. Do not overwrite his concurrent changes. His initial request for fresh approval was answered with the user's existing explicit authorization; no new user permission is needed for those scoped changes.

Minimal reference manifests are `manifest.jinx.minimal.json` and `manifest.morc.minimal.json`; they have not changed the installed apps. The live registry lists broader pre-existing scopes. Reducing those scopes requires the app owner to update/reinstall the app and verify needed events; no scope change was performed with a bot token. Membership/DM/history features need their own explicit scopes and tests before using these minimal mention-only manifests.


## Latest verification at 14:37 UTC

Both token and signing-secret identities are installed. All six inspected services are active. Public request URLs are `https://nullink.nullverse.cloud/slack/events/jinx` and `https://nullink.nullverse.cloud/slack/events/morc`. Actual Slack event-subscription delivery is not established merely by the synthetic probes.

The reference implementation passes 30 local tests. `audit_revised.py` separately passes eight isolated checks against the new production receiver snapshot: durable enqueue/dedup/restart, queue-full retry retention, successful-send dedup, ambiguous-send hold, bot_message reaching the identity check, per-thread serialization, whole-message comparison, and concurrent atomic send claiming. `live-signature-evidence.json` records real HTTPS signed challenge results. `live-dedup-evidence.json` records two synthetic ignored events, one for each app, both durably completed with their repeated requests deduplicated. These events contain no human identity and trigger no runtime or Slack post.

Morc resolved the second review: registry now specifies `thread`, dispatch claims serialize bot/channel/thread, send claims are atomic, and reconciliation compares whole messages. Eight isolated tests pass against source hash `63fc6a8d72dac94760e3853c79419c89d7db1b2b5dfed69259938bd55a412613`. These are source-snapshot tests, not a live AI acceptance test. Also verify finite bot-edge/job budgets, persisted rate limits and exact runtime identity in production before enabling broader routing; the stricter library policy is not automatically inherited by Morc's implementation.

Jinx `bridge_ready=false`, `last_ok=null`, `blocked.kind=unrecognized`. John should use the installed Desktop sign-in icon; if it still reports unrecognized after a successful login, Morc must fix the bridge's page detection. Morc `wake_ready=false` requires his runtime webhook configuration. Human→runtime→own-bot reply, real Jinx→Morc→Jinx handoff, and production restart acceptance remain blocked. No new permission or paid API approval is requested.

Final own-Jinx coordination to Morc: https://nullink.slack.com/archives/C0C71BCR3GV/p1791383849929709?thread_ts=1791381920.428049&cid=C0C71BCR3GV . This reports passed checks and remaining runtime blockers; it is not an automatic interbot handoff result.
