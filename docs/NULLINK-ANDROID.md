# Nullink Android (Redroid) — build brief

John locked 2026-09-17:
- Android instance reachable from Nullink (Apps) for APK-only apps / Aurora Store
- Shared filesystem to host (Nullink files)
- **Snapshot** current instance state
- **Clone** snapshot → new instance

## Architecture (preferred)
- Host: VPS (`216.158.238.236`), Docker
- Runtime: **Redroid** (Android in Docker, privileged / binderfs as required)
- UI in browser: **ws-scrcpy** or similar WebRTC/scrcpy web client, reverse-proxied under Nullink HTTPS same-origin path e.g. `/android/` and `/android-scrcpy/`
- Nullink Apps entry: iframe or new-tab to `/android/` (same-origin preferred for corp)
- Data: named Docker volume `nullink-android-data` bind or volume; also mount `/opt/nullink/android-share` ↔ `/sdcard/Nullink` (or `/storage/emulated/0/Nullink`)
- ADB exposed only on localhost on VPS

## Snapshot
- API or CLI: `POST /api/android/snapshot` (Nullink-auth) or script `android-snapshot.sh`
- Implementation: stop or freeze container → `docker commit` **or** tar the data volume → store under `/opt/nullink/android-snapshots/<id>-<ts>.tar.zst` + metadata JSON (name, created, size, android_version)
- List/delete snapshots via API or Apps UI later; v1 CLI + simple JSON list is fine

## Clone
- `POST /api/android/clone` { snapshot_id, new_name }
- New volume from snapshot tar, new Redroid container + scrcpy route `/android-<name>/` or port map
- v1: support **one live instance + N offline snapshots**; clone creates second instance if resources allow (document RAM: Redroid is heavy — warn if <8GB free)

## Aurora / APKs
- Preinstall or document Aurora Store sideload via adb
- Shared folder for dropping APKs from Nullink Files into Android

## Nullink wiring
- `apps.json` entry `android` → embed `/android/` (path)
- Optional admin endpoints under existing Nullink session auth
- Do not break Desktop/Guacamole, multi-upload, Apps allowlist

## Success criteria
1. From Nullink Apps → Android opens usable UI in browser
2. Can install an APK (Aurora or sideload via share folder)
3. Snapshot creates a listed restore point
4. Clone boots a second instance from snapshot (or clear documented single-instance limit with restore-from-snapshot)

## Non-goals (v1)
- Full Google Play certified device
- Play Integrity / banking apps
- Multi-user fancy UI beyond basic list snapshots / clone / open

Ship on VPS under `/opt/nullink-android/` compose + scripts; wire Nullink Apps.

## Aurora Store + APKMirror (John 2026-09-17)
- **Preinstall or easy-sideload Aurora Store** into the Redroid image (preferred F-Droid / official Aurora APK).
- Add Nullink Apps (or Android home bookmarks) links:
  - Aurora Store: https://auroraoss.com/ (download) / F-Droid: https://f-droid.org/en/packages/com.aurora.store/
  - APKMirror: https://www.apkmirror.com/
- Shared folder `/opt/nullink/android-share` also used to drop APKs downloaded via APKMirror on Desktop/browser into Android for install.
- Document: prefer Aurora for Play-sourced APKs; APKMirror for specific versioned APKs when Aurora/Play is awkward.
