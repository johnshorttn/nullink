# NullVault ⇄ Nullink device API (contract v1)

Companion to DESIGN.md v0.3. Server code: `nullvault.py` in johnshorttn/nullink (branch
`feat/nullvault-devices`). Client code: `app/src/main/java/cloud/nullverse/nullvault/net/` in
johnshorttn/nullvault.

## 0. Ground rules
- **Feature flag.** Every route below returns `404 {"error":"not_found"}` unless the server runs with
  `NULLVAULT_ENABLED=1`. Default is OFF.
- **Transport.** HTTPS only, JSON bodies, `Cache-Control: no-store` on every response. The app pins the
  server's TLS SPKI per vault.
- **Encodings.** `b64` = standard base64 with padding. `b64url` = URL-safe, no padding. Times are Unix
  seconds (integers) unless suffixed `_iso`.
- **Package.** `cloud.nullverse.nullvault`.
- **Device token.** `nvd_` + 43 b64url chars (256-bit). Sent as `Authorization: Bearer nvd_…`. The server
  stores only its SHA-256. A device token alone is useless: every call that uses it also needs a fresh
  signature from the hardware key K_dev (fingerprint per use) over a server nonce.
- **Nonces.** 32 random bytes, b64url. Single use (deleted on first use, success or failure), bound to a
  purpose (`register`, `sync`, `write`) and to the install id or device id that asked for it.
  TTL: register 120 s, sync/write 60 s.
- **Signed envelope.** Device-signed requests send
  `{"payload": "<b64 of UTF-8 JSON bytes>", "signature": "<b64 DER ECDSA-P256-SHA256 over the exact payload bytes>"}`.
  The server parses the JSON from those bytes, so no canonical-JSON rules are needed.
  `payload.ts` must be within ±300 s of server time.
- **Errors.** `{"error": "<code>", "message": "<human text>"}`; plus `"wipe": true` when the app must wipe
  this vault now (revoked, flagged, unknown device).

## 1. Shared objects

### 1.1 `attestation_chain`
Array of b64 DER certificates, leaf first, as returned by `KeyStore.getCertificateChain(alias)`.
Server checks: each cert is signed by the next; the last cert's public key equals a pinned Google
hardware-attestation root key (`nullvault_roots/google_roots.crt`); no serial is on Google's
attestation status (revocation) list; the leaf carries the KeyDescription extension
`1.3.6.1.4.1.11129.2.1.17` and no other cert does; attestation and KeyMint security level are TEE (1)
or StrongBox (2); `origin` = GENERATED; `attestationChallenge` = the UTF-8 bytes of the nonce string;
`rootOfTrust.verifiedBootState` is Verified, SelfSigned or Unverified (Failed is refused);
`deviceLocked` true or false (recorded only).

### 1.2 `device` (reported by the app; supporting evidence only)
```json
{"manufacturer":"Google","brand":"google","model":"Pixel 8","device":"shiba","product":"shiba",
 "sdk_int":35,"release":"15","security_patch":"2026-10-05","fingerprint":"google/shiba/…",
 "strongbox":true,"install_id":"<uuid4>","name":"John's Pixel"}
```

### 1.3 `apk` (APK report, DESIGN §6a)
```json
{"package":"cloud.nullverse.nullvault","version_code":1,"version_name":"0.1.0-test",
 "signing_cert_sha256":["<64 hex>"],"signing_lineage_sha256":["<64 hex>"],
 "base_apk_sha256":"<64 hex>","split_apk_sha256":[],
 "installer":{"installing":"com.google.android.packageinstaller","initiating":null,"originating":null},
 "debuggable":false}
```

### 1.4 `state` (device state, information only, never blocks; DESIGN §7)
```json
{"root_indicators":["su_binary","magisk","test_keys"],"dev_options":true,"adb_enabled":false,
 "tamper":{"debugger":false,"tracer_pid":0,"frida":false,"xposed":false}}
```
`tamper.*` true values are app-aimed findings: the app wipes itself, and the server refuses + flags.

### 1.5 `lease`
`{"payload":"<b64 JSON>","sig":"<b64 Ed25519 signature over the payload bytes>"}` with payload
`{"v":1,"device_id":"…","vault_id":"nullink","synced_at":1763000000,"offline_until":1765592000,"server_time":1763000000}`.
`offline_until = synced_at + 30 days`. The Ed25519 public key (`lease_public_key`, raw 32 bytes b64) is
returned at registration and pinned in the app.

### 1.6 `pins` (signed release manifest)
`{"payload":"<b64 JSON>","sig":"<b64 Ed25519>"}`, payload =
`{"package":"…","version_code":1,"signing_cert_sha256":["…"],"apk_sha256":["…"],"channel":"test"}`
for the caller's versionCode. The app compares its own measured hashes against it (and against the
cert digest built into the app).

### 1.7 `entry`
`{"id":"a1b2c3","title":"…","tags":["…"],"body":"<plaintext>","created_at":"…Z","updated_at":"…Z"}`

## 2. Registration (the only step that uses John's code)

### 2.1 `POST /api/vault/device/register-challenge`
Request: `{"code":"123456","install_id":"<uuid4>"}`
- `code` is John's TOTP. Verified with `consume=True` (no replay) under the existing per-IP lockout
  (`rate_locked` / `rate_record_failure`), so failures count toward the same lockout as login/step-up.
- Refused early with `409 device_cap` when the active-device cap (default 2) is already reached.

`200 {"nonce":"<b64url>","expires_in":120,"purpose":"register"}`
Errors: `401 wrong_code` (+`attempts_left`), `429 locked`, `409 totp_not_enabled`, `409 device_cap`.

### 2.2 `POST /api/vault/device/register`
Signed envelope. Payload:
```json
{"purpose":"register","nonce":"<from 2.1>","ts":1763000000,"install_id":"<uuid4>",
 "attestation_chain":[…],"device":{…},"apk":{…},"state":{…},"play_integrity":null}
```
The signature is by K_dev, whose certificate is `attestation_chain[0]` and whose attestation
challenge is the nonce. Server checks §1.1, the signature, the APK pins (§4), the patch floor, and the cap.

`201`:
```json
{"device_id":"nvd-<16 hex>","device_token":"nvd_…","lease_public_key":"<b64 raw Ed25519>",
 "assurance":"full|reduced","lease":{…},"pins":{…},"server_time":1763000000}
```
`assurance` is `reduced` when `deviceLocked=false` or the boot state is not Verified, or root
indicators were reported.
Errors: `400 bad_request`, `403 attestation_invalid` (+`reason`), `403 apk_mismatch` (+`reason`),
`403 tamper_detected`, `403 bad_signature`, `403 nonce_invalid`, `409 device_cap`.
Every refusal is appended to the registry and alerts John.

## 3. Sync and writes (fingerprint + device signature, no code)

### 3.1 `POST /api/vault/sync-challenge`
Headers: `Authorization: Bearer nvd_…`. Request: `{"purpose":"sync"}` or `{"purpose":"write"}`.
`200 {"nonce":"…","expires_in":60,"purpose":"sync"}`.
Errors: `401 unauthorized` (+`wipe:true`), `403 revoked` (+`wipe:true`), `403 flagged` (+`wipe:true`).

### 3.2 `POST /api/vault/sync`
Bearer + signed envelope. Payload:
```json
{"purpose":"sync","nonce":"…","ts":1763000000,"device_id":"nvd-…",
 "attestation_chain":[…],"apk":{…},"state":{…},"device":{…}}
```
`attestation_chain` is for a **throwaway** attested key created with challenge = nonce (a hardware
key's challenge is fixed at creation). It must come from the same hardware: same `verifiedBootKey`,
same security level as at registration. The signature is by **K_dev** (the registered key).
Additional checks: device active and not flagged; `install_id`, manufacturer and model unchanged;
`osPatchLevel` ≥ the last accepted one (newer is accepted and logged, older is refused); APK pins (§4).
Every sync appends a `sync_report` row to the registry.

`200`:
```json
{"entries":[entry,…],"count":12,"lease":{…},"pins":{…},"server_time":1763000000}
```
On any check failure: `403 <reason>` with `"wipe":true`, and the device becomes `flagged`
(model/key change ⇒ `reregister_required`).

### 3.3 `POST /api/vault/device/write`
Bearer + signed envelope; nonce from 3.1 with `purpose:"write"`. Payload is the sync payload plus:
```json
{"purpose":"write","op":"create|update|delete",
 "entry":{"id":"…","title":"…","tags":[…],"body":"…"},"base_updated_at":"…Z"}
```
- `create` ignores any client id (server picks it).
- `update`/`delete` need `id`. When `base_updated_at` is given and differs from the server copy the
  server answers `409 conflict` with the current metadata (no body), and the app keeps its outbox item.

`200 {"ok":true,"op":"update","entry":{id,title,tags,created_at,updated_at},"lease":{…}}`.
Audit: `device_write` with id and op only, never the body.

## 4. Release pins (`data/nullvault/release_pins.json`, admin-only, mode 600)
```json
{"package":"cloud.nullverse.nullvault",
 "releases":{"1":{"version_name":"0.1.0-test","channel":"test",
   "signing_cert_sha256":["<hex>"],"apk_sha256":["<hex>"],"revoked":false}}}
```
Server rule: the versionCode must be pinned and not revoked; the reported signing certs and
`attestationApplicationId.signature_digests` must equal the pinned cert set; `base_apk_sha256`
(and every split) must be in `apk_sha256`; package names match; `debuggable` false; and the
attestation's package version equals `version_code`. Managed with `python3 nullvault.py pin-add …`
(no HTTP route; root/nullink on the box only).

## 5. Admin (owner cookie session; never a Bearer token)

### 5.1 `GET /api/vault/devices`
`200 {"cap":2,"devices":[{"device_id","name","status":"active|flagged|revoked","assurance","model",
"manufacturer","security_level","patch_level","version_code","registered_at","last_seen_at",
"last_ip","flags":[…]}]}`. Never returns token hashes, attestation keys, or entries.

### 5.2 `POST /api/vault/devices/<device_id>/revoke`
Owner cookie + `Origin` in the allowed list + `{"code":"<TOTP>"}` (same lockout). Immediate: the next
contact from that device gets `403 revoked` + `wipe:true`.
`200 {"ok":true,"device_id":"…","status":"revoked"}`.

## 6. Registry (`data/nullvault/devices.jsonl`)
Append-only JSONL, mode 600, dir 700, hash-chained: every row has `prev` (SHA-256 of the previous
raw line, `"0"*64` for the first) and `h` (SHA-256 of the row without `h`). Row kinds: `register`,
`refused`, `sync_report`, `write`, `flag`, `revoke`. Device state is rebuilt by replaying the file.
At deploy time (John's decision 6) the file is made `chattr +a`; not done by the PR.

## 7. Alerts
Slack DM to John via the existing `slack_call` path on `register`, `refused`, `flag` and `revoke`,
including `reduced assurance` when it applies. Never includes tokens, codes or entry data. Sent only
when `NULLVAULT_ENABLED=1` and `NULLVAULT_ALERTS` is not `0`.
