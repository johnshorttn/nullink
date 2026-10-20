#!/usr/bin/env python3
"""Isolated regression probes of deployed receiver. No live events, tokens, or posts."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import queue
import tempfile
from unittest.mock import patch

source=Path('/opt/nullink/slack-events/slack_events.py').read_bytes()
report={'source_sha256':hashlib.sha256(source).hexdigest(),'probe_kind':'local isolated regression; not live Slack'}
with tempfile.TemporaryDirectory() as td:
    snapshot=Path(td)/'receiver_snapshot.py';snapshot.write_bytes(source)
    with patch.dict(os.environ,{'SLACK_EVENTS_HOME':td,'SLACK_EVENTS_STATE':td+'/state','SLACK_EVENTS_SECRETS':td+'/absent'}):
        spec=importlib.util.spec_from_file_location('deployed_probe',snapshot)
        m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    m.db_init()
    bot={'id':'jinx','app_id':'A','bot_user_id':'Ujinx','bot_id':'Bjinx'}
    payload={'type':'event_callback','team_id':'T','api_app_id':'A','event_id':'probe-queue-full','event':{'type':'app_mention'}}
    body=json.dumps(payload).encode()
    h=m.Handler.__new__(m.Handler)
    h.path='/slack/events/jinx';h.headers={'Content-Length':str(len(body))}
    responses=[];h._send=lambda status,value,*a:responses.append({'status':status,'body':value})
    q=queue.Queue(maxsize=1);q.put(('occupied',{}))
    with patch.object(m,'get_bot',return_value=bot),patch.object(m,'registry',return_value={'team_id':'T'}),patch.object(m,'signing_secret',return_value='test'),patch.object(m,'verify_signature',return_value=True),patch.object(m,'_work',q):
        h.rfile=io.BytesIO(body);h.do_POST()
        q.get()
        h.rfile=io.BytesIO(body);h.do_POST()
    report['queue_full_responses']=responses
    report['lost_after_queue_full_retry']=responses[-1]['body'].get('dup') is True and q.empty()
    event={'type':'app_mention','subtype':'bot_message','channel':'C','ts':'1.0','user':'Umorc','bot_id':'Bmorc','text':'<@Ujinx> directed probe'}
    with patch.object(m,'bot_token',return_value='test-not-used'),patch.object(m,'registered_bot_for',return_value={'id':'morc'}) as source_check:
        m.handle_event(bot,{'event':event})
        report['bot_message_rejected_before_identity_check']=source_check.call_count==0
    for handler in m.log.handlers:handler.close()
print(json.dumps(report,indent=2))
