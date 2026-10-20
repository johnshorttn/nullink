#!/usr/bin/env bash
# Pipeline test against a MOCKED chat.deepseek.com in an isolated temp Nullink copy.
set -u
T=/tmp/dstest-mock; rm -rf $T; mkdir -p $T/data $T/login-req
cp /opt/nullink/reply.py $T/reply.py
printf '%s\n' '{"role": "user", "text": "old history msg", "ts": "2026-10-01T00:00:00+00:00", "session_id": "deepseek-test"}' > $T/data/messages.jsonl
echo "2026-10-06T00:00:00+00:00" > $T/data/.last-handled
D=/opt/nullink/bridges/deepseek
export NL_ROOT=$T NL_SESSION=deepseek-test NL_LAST_HANDLED=$T/data/.last-handled NL_BRIDGE_SESSIONS=deepseek,deepseek-test \
  DS_STATE_DIR=$T/state DS_PROFILE=$T/profile DS_LOG_DIR=$T/logs DS_LOGIN_REQ_DIR=$T/login-req \
  DS_TEST_MOCK_HTML=$D/tests/mock_deepseek.html DS_MIN_GAP_SEC=1 DS_STARTUP_CHECK=1 \
  PLAYWRIGHT_BROWSERS_PATH=$D/ms-playwright
add() { python3 - "$@" <<'PY'
import json,sys,datetime
ts=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
open("/tmp/dstest-mock/data/messages.jsonl","a").write(json.dumps({"role":"user","text":sys.argv[2],"ts":ts,"session_id":sys.argv[1]})+"\n")
PY
}
start() { $D/venv/bin/python $D/worker.py run > $T/run$1.out 2>&1 & echo $! > $T/pid; }
count() { python3 -c "import json;L=[json.loads(l) for l in open('$T/data/messages.jsonl')];print(sum(1 for d in L if d['role']=='assistant' and d['session_id']=='deepseek-test'))"; }
start 1; sleep 14
echo "after start (expect 0 replies, history ignored): $(count)"
add deepseek-test "TEST-1 hello bridge"
add morc "TEST other room msg (must not be answered)"
add deepseek-test "TEST-2 second question"
for i in $(seq 1 40); do sleep 2; [[ $(count) -ge 2 ]] && break; done
echo "replies after 2 msgs: $(count)"
echo ".last-handled now: $(cat $T/data/.last-handled)  (should NOT pass the morc msg)"
kill -TERM $(cat $T/pid); sleep 6
start 2; sleep 16
echo "after restart (expect still 2): $(count)"
add deepseek-test "TEST-3 noreact converter path"
for i in $(seq 1 40); do sleep 2; [[ $(count) -ge 3 ]] && break; done
echo "replies after 3rd: $(count)"
kill -TERM $(cat $T/pid); sleep 5
echo "--- messages ---"; cat $T/data/messages.jsonl
echo "--- state ---"; DS_STATE_DIR=$T/state $D/venv/bin/python $D/worker.py status
echo "--- log ---"; cat $T/logs/worker.log
