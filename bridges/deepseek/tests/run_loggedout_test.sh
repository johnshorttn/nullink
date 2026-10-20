#!/usr/bin/env bash
# Logged-out detection against the REAL chat.deepseek.com with an EMPTY profile, isolated temp Nullink copy.
set -u
T=/tmp/dstest-lo; rm -rf $T; mkdir -p $T/data $T/login-req
cp /opt/nullink/reply.py $T/reply.py
: > $T/data/messages.jsonl
D=/opt/nullink/bridges/deepseek
export NL_ROOT=$T NL_SESSION=deepseek-test NL_LAST_HANDLED=$T/data/.last-handled NL_BRIDGE_SESSIONS=deepseek,deepseek-test \
  DS_STATE_DIR=$T/state DS_PROFILE=$T/profile DS_LOG_DIR=$T/logs DS_LOGIN_REQ_DIR=$T/login-req DS_MIN_GAP_SEC=1 \
  PLAYWRIGHT_BROWSERS_PATH=$D/ms-playwright
echo "2026-10-06T00:00:00+00:00" > $T/data/.last-handled
add() { python3 - "$@" <<'PY'
import json,sys,datetime
ts=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
open("/tmp/dstest-lo/data/messages.jsonl","a").write(json.dumps({"role":"user","text":sys.argv[2],"ts":ts,"session_id":sys.argv[1]})+"\n")
PY
}
notices() { grep -c 'DeepSeek bridge' $T/data/messages.jsonl; }
start() { $D/venv/bin/python $D/worker.py run > $T/run$1.out 2>&1 & echo $! > $T/pid; }
start 1
for i in $(seq 1 45); do sleep 2; [[ $(notices) -ge 1 ]] && break; done
echo "notices after startup: $(notices)"
add deepseek-test "TEST-LO-1 queued while logged out"
add deepseek-test "TEST-LO-2 another"
sleep 15
echo "notices after 2 queued msgs (expect 1): $(notices)"
echo ".last-handled (expect advanced to TEST-LO-1 ts): $(cat $T/data/.last-handled)"
kill -TERM $(cat $T/pid); sleep 6
start 2; sleep 45
echo "notices after restart (expect 1): $(notices)"
kill -TERM $(cat $T/pid); sleep 5
echo "--- messages ---"; cat $T/data/messages.jsonl
echo "--- state ---"; DS_STATE_DIR=$T/state $D/venv/bin/python $D/worker.py status
echo "--- log ---"; cat $T/logs/worker.log
