#!/usr/bin/env bash
# Sign-in hand-off chain on a THROWAWAY Xvfb display (not John's desktop):
# desk runs the launcher -> request file -> worker opens visible window there -> status 'open'
# -> nobody signs in -> times out -> re-check -> still logged out -> NO second notice.
set -u
T=/tmp/dstest-login; sudo rm -rf $T; mkdir -p $T/data; : > $T/data/messages.jsonl
sudo install -d -o desk -g morc -m 2770 $T/login-req
chmod 755 $T
cp /opt/nullink/reply.py $T/reply.py
D=/opt/nullink/bridges/deepseek
Xvfb :77 -screen 0 1280x900x24 -nolisten tcp -ac >/dev/null 2>&1 & XP=$!
sleep 2
export NL_ROOT=$T NL_SESSION=deepseek-test NL_ADVANCE_LAST_HANDLED=0 DS_STATE_DIR=$T/state DS_PROFILE=$T/profile \
  DS_LOG_DIR=$T/logs DS_LOGIN_REQ_DIR=$T/login-req DS_LOGIN_TIMEOUT=25 PLAYWRIGHT_BROWSERS_PATH=$D/ms-playwright
$D/venv/bin/python $D/worker.py run > $T/run.out 2>&1 & WP=$!
for i in $(seq 1 40); do sleep 2; grep -q 'DeepSeek bridge' $T/data/messages.jsonl && break; done
echo "notice count before sign-in attempt: $(grep -c 'DeepSeek bridge' $T/data/messages.jsonl)"
sudo -u desk env DISPLAY=:77 DS_LOGIN_REQ_DIR=$T/login-req timeout 100 bash $D/deepseek-signin.sh; echo "launcher exit: $?"
cat $T/login-req/status.json 2>/dev/null; echo
DISPLAY=:77 xwininfo -root -tree 2>/dev/null | grep -i -E 'deepseek|chrom' | head -3
sleep 50
echo "status after timeout: $(cat $T/login-req/status.json 2>/dev/null)"
echo "notice count after (expect 1): $(grep -c 'DeepSeek bridge' $T/data/messages.jsonl)"
kill -TERM $WP; sleep 6; kill $XP 2>/dev/null
echo "--- log ---"; cat $T/logs/worker.log
