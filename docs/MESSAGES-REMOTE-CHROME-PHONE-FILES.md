# Nullink Remote Chrome: Google Messages and Phone Files

**Status:** Approved design direction  
**Date:** 2026-10-16  
**Scope:** Nullink VPS browser surface for Google Messages for Web, with temporary access to selected folders on the user's Pixel.

## Goal

Use Google Messages for Web, including the user's existing RCS conversations, from a work PC by opening a contained Chrome surface inside Nullink. Allow attachments to come from Nullink Files, the work desktop, or selected folders on the phone.

The phone remains the Google Messages device and stays online. It does not need to run a screen mirror, and no SMS-default-app switch is required.

## Architecture

1. **VPS Chrome session:** Run Chrome in the existing isolated XFCE/Guacamole remote desktop environment. Give it a persistent, dedicated browser profile for Google Messages for Web pairing.
2. **Nullink surface:** Present that remote Chrome session as a dockable, resizable Nullink panel. The work PC browser connects only to Nullink over HTTPS; Chrome and its profile stay on the VPS.
3. **Google Messages:** Pair the Pixel with Messages for Web once. Keep Google Messages as the phone's default SMS/RCS app. RCS, SMS, and Google Messages' own conversation state remain managed by Google Messages.
4. **Phone companion:** Add an Android companion connection to Nullink. The phone initiates an authenticated outbound TLS connection to the VPS; do not expose an inbound service or public file share on the phone.
5. **Phone file source:** In the companion app, let the user add multiple folders using Android's system folder picker. The user can toggle each folder's availability for the current Nullink session. Expose enabled roots as a read-only virtual `Phone` drive to the VPS Chrome environment.

## File access behavior

- **Phone:** Browse enabled folder names and contents from the remote Chrome file chooser. This is live, on-demand access, not synchronization. Do not bulk-copy or continuously mirror phone folders.
- **VPS/Nullink:** Nullink Files already available on the VPS can be selected directly in Chrome.
- **Work desktop:** Upload local desktop files through Nullink Files first; those files then appear to the VPS Chrome session.
- When Chrome needs an attachment from the phone, stream only that selected file through the authenticated phone connection. A temporary VPS staging file may be used to satisfy Chrome's file picker. Remove it after the upload completes, or on cancel/session end. Clean up abandoned staging files when the session closes.
- Do not allow the remote browser to modify or delete the phone's originals. Phone folder access is read-only for this feature.

## User flow

1. Open **Nullink → Remote Apps → Messages**.
2. If needed, pair the persistent VPS Chrome profile with Google Messages on the Pixel.
3. In the Pixel companion app, choose **Share folders**, add one or more directories, and enable the desired folders for this session.
4. In Messages for Web, choose an attachment. The file picker offers **Phone**, **Nullink Files**, and files uploaded from the work desktop.
5. The selected phone file is streamed/staged temporarily and attached through Google Messages Web.
6. Stop folder sharing or close the session. The phone drive becomes unavailable and temporary staging data is cleared.

## Security and privacy

- Bind every phone connection and file request to the authenticated Nullink user, device, and active remote-browser session.
- Use short-lived session credentials and encrypted transport. Store no phone account credentials on the VPS.
- Show a persistent phone-side sharing indicator with the active folder names and a one-tap **Stop sharing** control.
- Keep folder listing and file reads read-only. Do not expose unselected folders, the whole device filesystem, or an unauthenticated WebDAV/SMB port.
- Keep the Chrome profile isolated from other Nullink users and services. Provide an explicit unpair/sign-out action and session shutdown cleanup.

## Constraints

- The phone needs internet access for pairing and live phone-file reads. The screen may remain locked; this feature does not depend on screen capture.
- Android grants folder access only for directories the user selects through the system picker. The companion may retain those URI grants, but it only exposes folders while the sharing/session toggle is active.
- Google Messages Web controls which attachment formats it accepts. Verify image, video, audio, and document behavior in the actual web client. For unsupported file types, Nullink can offer a controlled file-share link instead of an attachment.
- Google Messages Web pairing/session persistence is controlled by Google; handle re-pairing if its session expires or is unpaired.

## Implementation phases

### Phase 1: Remote Messages surface
- Reuse the existing Guacamole/XFCE path and persistent browser profile.
- Add a Nullink dockable panel and first-time pairing instructions.
- Verify RCS/SMS display, sending, session persistence, reconnect, and sign-out from the work-PC browser.

### Phase 2: Shared work/VPS files
- Make Nullink Files and work-desktop uploads visible to the remote Chrome file picker.
- Confirm attachment flow and supported file formats.

### Phase 3: Temporary phone folder drive
- Build the Android companion's folder grants and session sharing controls.
- Add the authenticated outbound device connection, virtual read-only file view, and on-demand file streaming/staging.
- Add upload completion/cancel cleanup plus session-end cleanup.
- Test with multiple selected directories, phone locked, reconnects, and revoked folder grants.

## Acceptance criteria

- The user can open Google Messages for Web inside Nullink without navigating away to a separate work-PC browser tab.
- The persistent Chrome profile can pair with the Pixel and reach its Google Messages session while the phone is online.
- The user can browse at least two independently selected phone folders in the remote Chrome attachment picker.
- Only the selected attachment is transferred from the phone; no background sync or bulk folder mirroring occurs.
- Work-desktop uploads and Nullink Files can also be selected from the VPS Chrome session.
- Phone originals remain unchanged; temporary staged attachment bytes are deleted after completion or session end.
- Stopping phone sharing immediately disables the virtual Phone drive and rejects later reads for that session.
