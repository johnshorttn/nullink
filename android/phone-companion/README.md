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
only a hash of that token. Pairing codes expire after two minutes and can be
used once.
