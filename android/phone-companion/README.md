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
- Start a separate view-only screen session from the phone app. Android shows
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
