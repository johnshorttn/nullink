#!/usr/bin/env bash
# Runs ON the VPS. Installs staged router (+ optional bridge) files with a backup and automatic health rollback.
#   remote-deploy.sh <staging_dir> [--bridge]
# Touches only nullink-slack-events (and nullink-chatgpt-bridge with --bridge). Never nullink.service,
# the deepseek bridge or Caddy.
set -uo pipefail
STAGE=$1; BRIDGE=${2:-}
H=/opt/nullink/slack-events; B=/opt/nullink/bridges/chatgpt
TS=$(date +%Y%m%d-%H%M%S); BK=$H/backups/deploy-$TS
mkdir -p "$BK/bridge"
for f in slack_events.py registry.json; do [ -f $H/$f ] && cp -a $H/$f "$BK/"; done
# consistent DB snapshot (schema migrations are additive, but rollback restores the pre-deploy DB)
[ -f $H/state/router.db ] && python3 -c "import sqlite3,sys;s=sqlite3.connect(sys.argv[1]);d=sqlite3.connect(sys.argv[2]);s.backup(d);d.close()" \
  $H/state/router.db "$BK/router.db"
BFILES="worker.py cg_selectors.py page_js.py persona.md"
if [ "$BRIDGE" = --bridge ]; then for f in $BFILES; do [ -f $B/$f ] && cp -a $B/$f "$BK/bridge/"; done; fi
echo "backup: $BK"

health() {
  local out
  systemctl is-active --quiet nullink-slack-events || { echo "unhealthy: service not active"; return 1; }
  out=$(curl -s -m 5 localhost:8772/slack/health) || { echo "unhealthy: no local health"; return 1; }
  python3 - "$out" <<'PY' || return 1
import json, sys
h = json.loads(sys.argv[1])
assert h.get("ok") is True, "ok"
bots = {b["id"]: b for b in h["bots"]}
for bid in ("morc", "jinx"):
    assert bots[bid]["token"] and bots[bid]["signing_secret"], bid + " credentials"
assert "jobs" in h and "rate_hits" in h and h["handoff"]["hop_budget"] == 2, "new schema"
if any((b.get("brain") == "slack_wake") for b in h["bots"]):
    assert "wakes" in h, "wake schema"
    assert all(b["wake_ready"] is True for b in h["bots"] if b.get("brain") == "slack_wake"), "wake_ready"
PY
  [ "$(curl -s -o /dev/null -w '%{http_code}' -m 5 -X POST -d '{"type":"url_verification","challenge":"x"}' localhost:8772/slack/events/morc)" = 401 ] \
    || { echo "unhealthy: unsigned request not refused"; return 1; }
  curl -s -m 8 https://nullink.nullverse.cloud/slack/health | grep -Eq '^\{"ok": ?true\}$' || { echo "unhealthy: public route"; return 1; }
  grep -q "Traceback" <(journalctl -u nullink-slack-events --since "-20s" --no-pager 2>/dev/null) && { echo "unhealthy: traceback in journal"; return 1; }
  if [ "$BRIDGE" = --bridge ]; then
    systemctl is-active --quiet nullink-chatgpt-bridge || { echo "unhealthy: bridge not active"; return 1; }
    local age=$(( $(date +%s) - $(stat -c %Y $B/state/heartbeat 2>/dev/null || echo 0) ))
    [ $age -lt 90 ] || { echo "unhealthy: bridge heartbeat ${age}s"; return 1; }
  fi
  echo healthy
}

install() {
  for f in slack_events.py registry.json; do
    [ -s "$STAGE/$f" ] || { echo "missing staged $f"; return 1; }
  done
  python3 -c "import ast,sys;ast.parse(open(sys.argv[1]).read())" "$STAGE/slack_events.py" || return 1
  python3 -c "import json,sys;json.load(open(sys.argv[1]))" "$STAGE/registry.json" || return 1
  cp "$STAGE/slack_events.py" $H/slack_events.py.new && mv $H/slack_events.py.new $H/slack_events.py
  cp "$STAGE/registry.json" $H/registry.json.new && mv $H/registry.json.new $H/registry.json
  if [ "$BRIDGE" = --bridge ]; then
    for f in $BFILES; do [ -s "$STAGE/bridge/$f" ] && cp "$STAGE/bridge/$f" $B/$f; done
    [ -d "$STAGE/bridge/tests" ] && cp "$STAGE/bridge/tests/"* $B/tests/
    grep -q '^CG_RUNTIME_ID=' $B/bridge.env || echo 'CG_RUNTIME_ID=chatgpt-bridge:jinx' >> $B/bridge.env
  fi
}

rollback() {
  echo "ROLLBACK to $BK"
  sudo systemctl stop nullink-slack-events
  for f in slack_events.py registry.json; do [ -f "$BK/$f" ] && cp -a "$BK/$f" $H/$f; done
  [ -f "$BK/router.db" ] && { rm -f $H/state/router.db-wal $H/state/router.db-shm; cp -a "$BK/router.db" $H/state/router.db; }
  sudo systemctl start nullink-slack-events
  if [ "$BRIDGE" = --bridge ]; then
    for f in $BFILES; do [ -f "$BK/bridge/$f" ] && cp -a "$BK/bridge/$f" $B/$f; done
    sudo systemctl restart nullink-chatgpt-bridge
  fi
  sleep 3; health; return 1
}

install || { echo "install precheck failed; nothing changed"; exit 2; }
sudo systemctl restart nullink-slack-events
[ "$BRIDGE" = --bridge ] && sudo systemctl restart nullink-chatgpt-bridge
for i in 1 2 3 4 5 6; do sleep 5; health >/tmp/slack-deploy-health.txt 2>&1 && break; done
cat /tmp/slack-deploy-health.txt
grep -q '^healthy' /tmp/slack-deploy-health.txt || { rollback; exit 1; }
echo "DEPLOYED OK (backup $BK)"
