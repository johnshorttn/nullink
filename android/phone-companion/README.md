# Nullink Phone companion

This Android companion lets the signed-in Nullink browser browse folders that
you explicitly select on the phone. The phone makes an outbound HTTPS
connection to Nullink; no inbound port or VPN is required.

## What it does

- Pair with a one-time code from **Nullink → Phone Drive**.
- Choose one or more folders using Android's system folder picker.
- Turn sharing on only while you need it. Android shows a persistent
  notification with a Stop control while the service is active.
- Browse names and folder structure live. File contents are transferred only
  after you choose a file in Nullink Phone Drive, and each staged copy expires
  after 15 minutes or after one download.
- Download the selected file into the VPS Chrome session's Downloads folder,
  where a page such as Google Messages for Web can attach it.
- Start a separate screen session from the phone app. Android shows
  its system capture approval each time, and a persistent notification provides
  a Stop control. Frames are downscaled, held in server memory only, and expire
  within seconds; they are not recorded.

Folder access is read-only. This is an on-demand file handoff, not a sync
service or a native Windows mapped drive. The current transfer limit is 25 MB.

## Build

Open this directory in Android Studio with JDK 17 and Android SDK 35, or run:

```sh
gradle :app:assembleDebug
```

The debug APK is written to `app/build/outputs/apk/debug/app-debug.apk`.
GitHub Actions also builds the debug APK on pushes and pull requests that touch
this directory.

The CI build uses a separate `Nullink Phone Awake` package so it can be
installed beside an older debug build. Pair the new install and reselect its
shared folders; Android keeps the old app's data separate.

## Android behavior

Sharing uses a user-started `specialUse` foreground service because it must
remain available while the screen is locked. Android displays the ongoing
notification, and the user can stop sharing from either the app or the
notification. Android battery and network policies can still defer background
network activity; for reliable use, allow Nullink Phone to run unrestricted
by the phone's battery manager. Selecting a folder grants the app persistent
read access through Android's Storage Access Framework. Removing that folder
releases the grant.

The device token is encrypted with an Android Keystore key. The server stores
only a hash of that token. Six-digit pairing codes expire after two minutes
and can be used once. Pair attempts are limited to eight per client address in
a five-minute window.

Screen mirroring is independent of folder sharing. Tap **Start screen
mirroring** in the phone app and accept Android's screen-capture prompt, then
choose **View screen** for that phone in Nullink. While mirroring is active, the
phone app holds a dim screen wake lock to prevent automatic timeout. This uses
extra battery; pressing the power button still turns the display off and may
blank the captured picture. Stop mirroring in the phone app or from its
persistent notification to release the wake lock.

## Optional remote control (0.3)

1. In the phone app, open Accessibility Settings and manually enable **Nullink
   Phone Control**. The app cannot enable this permission itself.
2. Start screen mirroring and accept the separate Android capture prompt.
3. Tap **Allow remote control for this session** on the phone. Control is off
   by default and is never restored across app process restart or reboot.
4. In Phone Drive, choose **View screen** on this paired phone. Click/tap to
   tap, drag to swipe, or use Back, Home, and Recents. Status reports whether
   Accessibility and session permission are enabled.
5. Tap **Stop remote control** in the app, or **Stop mirroring** in the app or
   ongoing notification. Stopping browser viewing does not stop phone capture.

Control requires an unlocked phone and a fresh live frame. Protected Android
screens/dialogs may refuse input or appear blank. Rotate only after stopping
mirroring, then restart capture: input is refused if display dimensions change.
No text insertion, window-content retrieval, shell commands, or code execution
is supported. Accessibility permission may naturally persist, but session control
permission lives only in memory. The notification displays REMOTE CONTROL ACTIVE.

The server requires a signed-in human browser session to submit control; a phone
bearer token can only poll/ack its own commands and report its own state. Separate
control and folder lanes use the existing authenticated long-poll route. Commands
expire in three seconds, are limited to five per second and four queued per phone,
and include a fresh phone-generated session identifier. Coordinates must be finite
normalized values; swipes last 100–1000 ms. Both Android and the server validate.

The package remains `cloud.nullverse.nullinkphone.awake`, beside the original
`cloud.nullverse.nullinkphone` app. This repository currently has one debug app
variant. CI debug signing keys are ephemeral: if Android reports an incompatible
update signature, uninstall only the previous Awake build, install the new APK,
and pair/reselect folders again. The original side-by-side app remains installed.
Future updates need a retained signing key to preserve the Awake app's data.

API basis: https://developer.android.com/guide/topics/ui/accessibility/service
