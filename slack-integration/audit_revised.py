#!/usr/bin/env python3
"""Test revised deployed receiver in a temporary directory with mocked Slack."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
from unittest.mock import patch

source=Path('/opt/nullink/slack-events/slack_events.py').read_bytes()
r={'source_sha256':hashlib.sha256(source).hexdigest(),'kind':'isolated revised receiver tests; no live posts'}
with tempfile.TemporaryDirectory() as td:
    path=Path(td)/'snapshot.py';path.write_bytes(source)
    with patch.dict(os.environ,{'SLACK_EVENTS_HOME':td,'SLACK_EVENTS_STATE':td+'/state','SLACK_EVENTS_SECRETS':td+'/absent'}):
        spec=importlib.util.spec_from_file_location('revised_probe',path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    m.db_init()
    assert m.inbox_put('e1','jinx',b'{}')=='queued'
    assert m.inbox_put('e1','jinx',b'{}')=='dup'
    assert m.inbox_claim()[0]=='e1'
    m.db_init()
    if hasattr(m,'_busy_threads'): m._busy_threads.clear() # process-restart simulation
    assert m.inbox_claim()[0]=='e1'
    m.inbox_set('e1',phase='dispatching');m.db_init()
    con=m.db();state=con.execute("SELECT state FROM inbox WHERE event_key='e1'").fetchone()[0];con.close()
    assert state=='uncertain'
    r['durable_ingress_dedup_and_restart']=True
    con=m.db()
    con.executemany("INSERT INTO inbox VALUES (?,?,?,'queued',NULL,0,0,NULL)",[(f'fill-{n}','jinx','{}') for n in range(1000)])
    con.close()
    assert m.inbox_put('retryable','jinx',b'{}')=='busy'
    con=m.db();con.execute("DELETE FROM inbox WHERE event_key LIKE 'fill-%'");con.close()
    assert m.inbox_put('retryable','jinx',b'{}')=='queued'
    r['queue_full_retry_preserved']=True
    con=m.db();con.execute('DELETE FROM inbox');con.close()
    if hasattr(m,'_busy_threads'): m._busy_threads.clear()
    payload=json.dumps({'event':{'channel':'C','thread_ts':'1.0'}}).encode()
    m.inbox_put('thread-1','jinx',payload);m.inbox_put('thread-2','jinx',payload)
    first=m.inbox_claim();assert first[0]=='thread-1'
    assert m.inbox_claim() is None
    m.inbox_set('thread-1',state='done');m.inbox_release(first[3])
    second=m.inbox_claim();assert second[0]=='thread-2';m.inbox_release(second[3])
    r['per_thread_dispatch_serialized']=True
    assert m._norm_text('a'*301+'x') != m._norm_text('a'*301+'y')
    r['full_text_reconciliation_not_prefix']=True
    claims=[]
    def claim(): claims.append(m._send_claim('concurrent','jinx','C','1.0'))
    threads=[threading.Thread(target=claim) for _ in range(8)]
    for thread in threads:thread.start()
    for thread in threads:thread.join()
    assert claims.count(None)==1 and claims.count('posting')==7
    r['concurrent_send_claim_exactly_one_owner']=True
    bot={'id':'jinx','bot_user_id':'Ujinx','bot_id':'Bjinx'}
    with patch.object(m,'bot_token',return_value='fake'),patch.object(m,'outbound_allowed',return_value=True),patch.object(m,'slack',return_value={'ok':True,'ts':'2.0'}) as slack:
        assert m.send_once(bot,'s1','C','1.0','text')=='ok'
        assert m.send_once(bot,'s1','C','1.0','text')=='dup'
        assert slack.call_count==1
    r['send_success_dedup']=True
    with patch.object(m,'bot_token',return_value='fake'),patch.object(m,'outbound_allowed',return_value=True),patch.object(m,'reconcile_send',return_value=None),patch.object(m,'slack',return_value={'ok':False,'error':'request_failed:TimeoutError'}) as slack:
        assert m.send_once(bot,'s2','C','1.0','text')=='uncertain'
        assert m.send_once(bot,'s2','C','1.0','text')=='uncertain'
        assert slack.call_count==1
    r['ambiguous_send_not_reposted']=True
    ev={'type':'app_mention','subtype':'bot_message','channel':'C','ts':'3.0','user':'Umorc','bot_id':'Bmorc','text':'<@Ujinx> test'}
    with patch.object(m,'bot_token',return_value='fake'),patch.object(m,'registered_bot_for',return_value={'id':'morc'}) as identity,patch.object(m,'handoff_step',return_value=(None,2)):
        m.handle_event(bot,{'event':ev})
        assert identity.call_count==1
    r['bot_message_reaches_handoff_identity_check']=True
    for handler in m.log.handlers:handler.close()
Path('/opt/nullink/slack-integration/revised-audit-evidence.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps(r,indent=2))
