#!/usr/bin/env bash
# Bridge pipeline test against a MOCKED chatgpt.com in an isolated temp dir (no real ChatGPT, no Slack).
set -u
T=/tmp/cgtest-mock; rm -rf $T; mkdir -p $T/jobs/pending $T/login-req
D=/opt/nullink/bridges/chatgpt
export CG_JOBS_DIR=$T/jobs CG_STATE_DIR=$T/state CG_PROFILE=$T/profile CG_LOG_DIR=$T/logs CG_LOGIN_REQ_DIR=$T/login-req \
  CG_TEST_MOCK_HTML=$D/tests/mock_chatgpt.html CG_MIN_GAP_SEC=1 CG_STARTUP_CHECK=1 \
  PLAYWRIGHT_BROWSERS_PATH=/opt/nullink/bridges/deepseek/ms-playwright
job() { python3 -c "import json,sys,time;json.dump({'version':1,'method':'reply','request':{'request_key':sys.argv[1],'runtime_id':sys.argv[4] if len(sys.argv)>4 else 'chatgpt-bridge:jinx','bot':'jinx','channel':sys.argv[2],'thread_ts':'1.0','text':sys.argv[3],'context':[],'expires_at':int(time.time())+600,'correlation_id':'hT','hop':0},'meta':{'id':sys.argv[1],'created':time.time(),'conversation_key':sys.argv[2],'handoff_targets':['morc'],'prompt':sys.argv[3]}},open('$T/jobs/pending/'+str(int(time.time()*1000))+'-'+sys.argv[1]+'.json','w'))" "$@"; }
/opt/nullink/bridges/deepseek/venv/bin/python $D/worker.py run > $T/run.out 2>&1 & PID=$!
sleep 12
job sAAA001 C1 "[Slack message for Jinx - #test] New message from John: TEST-1 hello"
job sAAA002 C2 "[Slack message for Jinx - #other] New message from John: TEST-2 other channel"
job sAAA003 C3 "TEST-3 wrong runtime" "chatgpt-bridge:someone-else"
for i in $(seq 1 60); do sleep 2; [[ $(ls $T/jobs/results 2>/dev/null | wc -l) -ge 3 ]] && break; done
kill -TERM $PID; sleep 4
echo "--- results ---"; for f in $T/jobs/results/*.json; do python3 -c "import json,sys;d=json.load(open(sys.argv[1]));print(d['runtime_id'],d['request_key'],d['state'],d['idempotent'],d['meta']['conversation_key'],repr(d['result']))" $f; done
echo "--- state ---"; python3 -c "import json;d=json.load(open('$T/state/state.json'));print('blocked',d.get('blocked'),'last_ok',bool(d.get('last_ok')),'convs',d.get('conversations'))"
echo "--- heartbeat age ---"; echo $(( $(date +%s) - $(stat -c %Y $T/state/heartbeat) ))s
echo "--- pending left ---"; ls $T/jobs/pending
echo "--- log tail ---"; tail -15 $T/logs/worker.log
