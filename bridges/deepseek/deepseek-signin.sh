#!/usr/bin/env bash
# Run by the Desktop user (desk) from the "Sign in to DeepSeek" desktop icon.
# Lets the Nullink DeepSeek bridge (runs as morc) show its browser window on THIS
# desktop, then asks it to open DeepSeek so John can sign in himself.
# The bridge never sees the password; it only keeps the browser profile/cookies.
set -u
REQ_DIR="${DS_LOGIN_REQ_DIR:-/opt/nullink/bridges/deepseek/login-req}"
BRIDGE_USER=morc
note() {
  notify-send -a "DeepSeek bridge" -i dialog-information "DeepSeek bridge" "$1" 2>/dev/null \
    || (xmessage -center -timeout 15 "$1" >/dev/null 2>&1 &)
}
if [[ -z "${DISPLAY:-}" ]]; then echo "No DISPLAY" >&2; exit 1; fi
if ! xhost "+SI:localuser:${BRIDGE_USER}" >/dev/null 2>&1; then
  note "Could not allow the bridge to open a window on this desktop."; exit 1
fi
rm -f "$REQ_DIR/status.json" 2>/dev/null
umask 022
printf '{"display":"%s","ts":%s}\n' "$DISPLAY" "$(date +%s)" > "$REQ_DIR/.request.tmp" \
  && mv -f "$REQ_DIR/.request.tmp" "$REQ_DIR/request.json" \
  || { note "Could not reach the DeepSeek bridge (request dir not writable)."; exit 1; }
note "Opening the DeepSeek window… (about 10 seconds)"
for _ in $(seq 1 90); do
  sleep 1
  if [[ -f "$REQ_DIR/status.json" ]]; then
    st=$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print(d.get("status",""));print(d.get("message",""))' "$REQ_DIR/status.json" 2>/dev/null)
    s1=$(printf '%s\n' "$st" | sed -n 1p); s2=$(printf '%s\n' "$st" | sed -n 2p)
    case "$s1" in
      open) note "Sign in to DeepSeek in the window that just opened. It closes by itself a few seconds after you're signed in."; exit 0 ;;
      error) note "DeepSeek bridge: $s2"; exit 1 ;;
    esac
  fi
done
note "The DeepSeek bridge is busy finishing a message or not running. The window will appear when it's free (service: nullink-deepseek-bridge)."
