# NullVault device endpoints (server side)

Design: NullVault DESIGN.md v0.3 (approved by John, 2026-11-12, vault room). Contract: [NULLVAULT-API.md](NULLVAULT-API.md).
Code: `nullvault.py` (+ 4 lines of routing in `server.py`), tests `tests/test_nullvault.py`.

**Off by default.** Every NullVault route answers `404` unless the service runs with `NULLVAULT_ENABLED=1`.
Merging this PR changes nothing in production until that flag is set.

## What it adds
- `POST /api/vault/device/register-challenge` — John's TOTP (consumed, same per-IP lockout as login/step-up) -> 120 s nonce.
- `POST /api/vault/device/register` — attestation chain to a pinned Google root, nonce as challenge, TEE/StrongBox,
  APK pins, device-key signature, 2-device cap -> device token (hash stored only) + Ed25519-signed 30-day lease.
- `POST /api/vault/sync-challenge`, `POST /api/vault/sync`, `POST /api/vault/device/write` — device token + K_dev
  signature + fresh attestation from the same hardware + APK report each time. No TOTP (John's decision 1).
- `GET /api/vault/devices`, `POST /api/vault/devices/<id>/revoke` — owner cookie only; revoke also needs Origin + TOTP.
- Registry `data/nullvault/devices.jsonl`: append-only, hash-chained, 0600 in a 0700 dir.
- Alerts: Slack DM to John (existing `slack_call` path) on register / refuse / flag / revoke; off while the flag is off.

v0.3 rules: root, unlocked bootloader, SelfSigned/Unverified boot, Developer options and ADB are **accepted and recorded**
(`assurance: reduced`). Refused: Failed boot, software-only attestation, imported keys, an unpinned or revoked
versionCode, wrong signing cert or APK hash (reported or attested), `debuggable`, and tamper findings
(debugger/tracer/Frida/Xposed in the app's process).

## Config
| Env | Default | Meaning |
| --- | --- | --- |
| `NULLVAULT_ENABLED` | `0` | `1` turns the routes on |
| `NULLVAULT_LINKS` | `0` | `1` adds links + projects (sync, signed writes, discovered-site and repo suggestions) |
| `NULLVAULT_FILES` | `0` | `1` adds device Files access (fingerprint files session, Range downloads, signed uploads/deletes) |
| `NULLVAULT_STATUS` | `0` | `1` adds the device server-status card (`GET /api/vault/status`, status-only `nvs_` tokens) and the down-alert monitor |
| `NULLVAULT_STATUS_SERVICES` | built-in list | comma list of systemd units to show (or `data/nullvault/status_services.json`) |
| `NULLVAULT_STATUS_MONITOR` | `1` | `0` turns off the 60 s Slack down-alert monitor (status card still works) |
| `NULLVAULT_NOTES` | `0` | `1` adds encrypted project notes (needs `NULLVAULT_LINKS=1`) |
| `NULLVAULT_CHAT` | `0` | `1` adds Nullink rooms on the phone (10-min fingerprint chat session, polling) |
| `NULLVAULT_APPROVALS` | `0` | `1` adds the approvals queue (GitHub PRs via `secrets/github_token.txt`; NullAxis placeholder) |
| `NULLVAULT_APPROVALS_GITHUB_REVIEW` | `1` | `0` records decisions only, never submits a GitHub APPROVE review |
| `NULLVAULT_APPROVALS_GITHUB_OWNER` | `johnshorttn` | account whose open PRs are listed |
| `NULLVAULT_ACTIONS` | `0` | `1` turns on quick actions (still nothing runs until the allowlist names an action) |
| `NULLVAULT_ACTIONS_ALLOW` | empty | comma list of `nullvault_actions.CATALOG` names; set only with John's OK |
| `NULLVAULT_SERVER_LABEL` | hostname | default server label for new links and discovered sites |
| `NULLVAULT_DISCOVERY_CADDY` | `1` | `0` skips the Caddy admin API probe (then Caddyfile, then seed file) |
| `NULLVAULT_DEVICE_CAP` | `2` | active (non-revoked) devices |
| `NULLVAULT_PATCH_FLOOR` | `202401` | minimum attested OS patch (YYYYMM) |
| `NULLVAULT_ALERTS` | `1` | `0` silences Slack alerts |
| `NULLVAULT_STATUS_FETCH` | `1` | fetch Google's attestation revocation list (24 h cache in `data/nullvault/attestation_status.json`) |
| credential `nullvault_lease_key` | — | Ed25519 seed (base64, 32 bytes) via systemd `LoadCredential`; `NULLVAULT_LEASE_KEY_FILE` for tests |

Release pins: `data/nullvault/release_pins.json` (example: `deploy/nullvault/release_pins.example.json`), managed with
`python3 nullvault.py pin-add --version-code N --cert-sha256 HEX --apk-sha256 HEX [--channel test]`.
Pinned Google roots: `nullvault_roots/google_roots.crt` (RSA root f92009e853b6b045 and "Key Attestation CA1"; matched by public key).

Library note: X.509 parsing, ECDSA and Ed25519 use `cryptography`, already a server dependency (vault AES-GCM).
The Android KeyDescription extension is parsed with a small stdlib DER reader in `nullvault.py`. No new dependency.

## Deploy (only after John's OK; not done by this PR)
1. Merge; let the normal deploy hook update `/opt/nullink`. Flag still off -> routes 404 (verify with `curl`).
2. Lease key (root): `install -d -m 700 /etc/nullink/nullvault && python3 /opt/nullink/nullvault.py gen-lease-key --out /etc/nullink/nullvault/lease.key`
   (prints nothing secret), then add to the nullink unit drop-in:
   `LoadCredential=nullvault_lease_key:/etc/nullink/nullvault/lease.key`.
3. Pins (as nullink): `python3 nullvault.py pin-add --version-code 1 --version-name 0.1.0-test --channel test --cert-sha256 <cert> --apk-sha256 <apk>`
   using the values in the app PR / `deploy/nullvault/release_pins.example.json`.
4. Turn on: `Environment=NULLVAULT_ENABLED=1` in the drop-in, `systemctl daemon-reload && systemctl restart nullink`.
   Check health, login and Files still work; `curl -s -o /dev/null -w '%{http_code}' -X POST https://…/api/vault/sync-challenge` -> 401.
5. **Append-only (John's decision 6, do at this step, not before):** after the first registration creates the file,
   `chattr +a /opt/nullink/data/nullvault/devices.jsonl` (root). The code only ever opens it with `O_APPEND`, so this
   is compatible. To rotate or repair it later, root must `chattr -a` first.

## Stage 1 deploy (Links, Projects, Files; app 0.2.0-test, versionCode 2)
1. Fast-forward `/opt/nullink` to the merge; restart Nullink. Sub-flags off -> the new routes 404, v1 app keeps working.
2. Pins (as nullink), **keep v1**: `python3 nullvault.py pin-add --version-code 2 --version-name 0.2.0-test --channel test --cert-sha256 69a9ba1d…6dcf --apk-sha256 3049cbb4…2c9d`.
   Without it the live server refuses 0.2.0-test with `apk_mismatch:version_not_pinned` (refused, not flagged or wiped).
3. Add `NULLVAULT_LINKS=1` and `NULLVAULT_FILES=1` next to `NULLVAULT_ENABLED=1`; daemon-reload; restart Nullink.
4. Optional seeds (only if neither the Caddy admin API nor the Caddyfile is readable by nullink):
   `data/nullvault/discovered_sites.json`, `data/nullvault/repo_catalog.json` (examples in `deploy/nullvault/`).
5. Rollback: drop the two sub-flags (routes 404, phones keep their local links) or revert the merge.

## Stage 2 deploy (Status, Notes; app 0.3.0-test, versionCode 3)
1. Fast-forward `/opt/nullink`; restart Nullink. New flags off -> `/api/vault/status*` 404, notes not in sync, v1/v2 apps unaffected.
2. Pins (as nullink), **keep v1 and v2**: `python3 nullvault.py pin-add --version-code 3 --version-name 0.3.0-test --channel test --cert-sha256 69a9ba1d…6dcf --apk-sha256 69e368c0…b053`.
3. Add `NULLVAULT_STATUS=1` and `NULLVAULT_NOTES=1` to the drop-in; daemon-reload; restart Nullink.
4. Optional: `data/nullvault/token_expiry.json` (example `deploy/nullvault/token_expiry.example.json`): names, kinds and expiry dates only, never values.
5. Rollback: drop the two flags (routes 404, monitor stops; phones keep local notes until next sync) or revert the merge.

Status reads only what the `nullink` user can already read: `/proc` (uptime, load, memory), `statvfs` of `/` and
the Nullink dir, unprivileged `systemctl show` (ActiveState/SubState only), the public TLS certificates served on
127.0.0.1:443, and the admin seed above. **Left out (would need extra privileges):** journal errors of other units
(adm/systemd-journal group), docker container state (docker socket), SMART/disk hardware health (root), other
users' processes and failed-login counts (root). They are listed in the response's `omitted` field.

Down alerts are **not true push**: no Firebase/FCM. The server sends a Slack DM through the existing alert path on a
down/up transition (watched unit not active, or disk >= 95%), at most one per unit and direction per 30 min, no alert
for the state found at start-up. The phone can opt in to a WorkManager check every 15 min (Android minimum, Doze may
delay it) that raises a local notification.

## Stage 3 deploy (Chat, Approvals, Quick-actions framework; app 0.4.0-test, versionCode 4)
1. Fast-forward `/opt/nullink`; restart Nullink. New flags off -> `/api/vault/chat/*`, `/api/vault/approvals*`, `/api/vault/actions*` 404.
2. Pins (as nullink), **keep v1-v3**: `python3 nullvault.py pin-add --version-code 4 --version-name 0.4.0-test --channel test --cert-sha256 69a9ba1d…6dcf --apk-sha256 4719348d…c6f6`.
3. Add `NULLVAULT_CHAT=1` and `NULLVAULT_APPROVALS=1` to the drop-in; daemon-reload; restart Nullink. Do **not** add `NULLVAULT_ACTIONS` or an allowlist without John's OK.
4. New append-only logs (created on first use): `data/nullvault/approvals.jsonl`, `data/nullvault/actions.jsonl`. Optional (root): `chattr +a` on them after they exist.
5. Rollback: drop the two flags (routes 404) or revert the merge. The logs can stay.

Chat: the existing `/api/messages` API only takes an owner cookie or `nl_` token, so device access is a separate,
flag-gated route over the same message store with the same send side effects. One fingerprint + device signature
opens a 10-minute `nvc_` session (memory only); the app asks for a tap-to-confirm on every send; polling only.

Approvals: GitHub access is whatever `secrets/github_token.txt` already allows (checked read-only 2026-11-12: it
exists, nullink can read it, it is a fine-grained token for johnshorttn). No token -> "unavailable", none listed.
A decision is fingerprint + device signed, bound to repo/number/head SHA, and appended with its signature to
`approvals.jsonl`. `approve` then submits a GitHub `APPROVE` review only if the token allows it; GitHub refuses
reviews on your own PRs, so those are recorded but not reviewed (`own_pr`). Nothing ever merges.
NullAxis: placeholder only (work on hold; no local endpoint exists on this server; nothing is contacted).

### Quick actions: proposed allowlist (needs John's OK; shipped empty, flag off)
Permission check (read-only, 2026-11-12): `sudo -l` as nullink allows `NOPASSWD: /usr/local/sbin/nulldo` (from a
login shell). But `nullink.service` runs with `NoNewPrivileges=yes` and an empty `CapabilityBoundingSet`, and sudo
refuses under no-new-privileges (verified with `setpriv --no-new-privs sudo -n -l` as nullink: "The 'no new
privileges' flag is set, which prevents sudo from running as root"). So nothing that goes through sudo can run
from inside the Nullink process today.

| Action (CATALOG name) | argv | Works with current permissions? |
| --- | --- | --- |
| `nullink-health` | `curl -sS -m 5 http://127.0.0.1:8766/health` | **Yes** (no privilege; same data as public `/health`) |
| `nullink-status` | `systemctl show nullink.service --property=…` | **Yes** (unprivileged `systemctl show`; same as the Status card) |
| `nulldo-status` | `sudo -n /usr/local/sbin/nulldo status` | **No**: sudoers allows it, but NoNewPrivileges blocks sudo from the service |
| `nulldo-health` | `sudo -n /usr/local/sbin/nulldo health` | **No** (same); `nullink-health` gives the same answer without sudo |
| `nulldo-journal` (lines 1-200) | `sudo -n /usr/local/sbin/nulldo journal N` | **No** (same). Without nulldo, nullink cannot read its unit's journal either (not in adm/systemd-journal) |
| `nulldo-restart` | `sudo -n /usr/local/sbin/nulldo restart` | **No** (same). Also note: it restarts the process serving the request, so the phone gets no answer; check health after |
| token renewal (chatgpt-mcp / mcpgw-upstream-readonly) | — | **Left out**: no renewal script exists on the server (only `mcpgw-approvals` / `mcpgw-tenants`, which require root) |

Ways to make the nulldo rows work (each is a permission change, so John's OK first; none done):
(a) drop `NoNewPrivileges=yes` from nullink.service (weakens the whole service's sandbox; not recommended), or
(b) a small root-owned helper unit (e.g. socket-activated `nulldo` bridge on a unix socket only nullink can open)
that accepts the same fixed action names, or (c) a systemd path/timer unit that runs one fixed nulldo action.
Recommended first allowlist if John agrees: `NULLVAULT_ACTIONS=1`, `NULLVAULT_ACTIONS_ALLOW=nullink-health,nullink-status`.

## Rollback
- Fast: remove `NULLVAULT_ENABLED=1` (or set `0`) and restart. All routes 404 again; devices wipe at their lease end.
- Full: revert the merge commit and redeploy. `data/nullvault/` can stay (inert) or be archived by root
  (`chattr -a` first if it was set).
- Revoke a single phone any time: Nullink owner session -> `POST /api/vault/devices/<id>/revoke` with a TOTP code.

## Honest limits
- Not end-to-end: the server decrypts entries for sync, same exposure as today's vault.
- On rooted phones the attested app id comes from the OS, which root controls; the reduced-assurance badge,
  revoke, 2-device cap and alerts are the backstop (DESIGN §7).
- Nonces live in memory; a restart invalidates outstanding ones (clients just ask again).
- Play Integrity skipped (decision 5).
