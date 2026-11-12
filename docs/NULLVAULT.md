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
