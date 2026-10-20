import hashlib
import hmac
import json
import threading
import unittest
from durable import Pending, Retry, Store, Rejected
from receiver import receive
import test_durable
from test_durable import Runtime


class IntegrationTests(unittest.TestCase):
    setUp = test_durable.Tests.setUp
    tearDown = test_durable.Tests.tearDown
    open = test_durable.Tests.open
    event = test_durable.Tests.event
    finish = test_durable.Tests.finish
    def signed(self, value):
        raw=json.dumps(value).encode()
        stamp=str(self.now)
        signature='v0='+hmac.new(b'secret', b'v0:'+stamp.encode()+b':'+raw,hashlib.sha256).hexdigest()
        return {'X-Slack-Signature':signature,'X-Slack-Request-Timestamp':stamp},raw
    def test_ingress_signed_then_durable(self):
        headers,raw=self.signed(self.event())
        self.assertEqual(receive(self.s,'jinx','secret',headers,raw),(200,{'ok':True,'queued':True}))
        self.s.close(); self.open()
        self.assertEqual(receive(self.s,'jinx','secret',headers,raw),(200,{'ok':True,'queued':False}))
        self.assertEqual(receive(self.s,'jinx','',headers,raw)[0],401)
        self.assertEqual(receive(self.s,'jinx','secret',{},raw)[0],401)
    def test_signed_challenge_only(self):
        headers,raw=self.signed({'type':'url_verification','challenge':'test'})
        self.assertEqual(receive(self.s,'jinx','secret',headers,raw),(200,{'challenge':'test'}))
        self.assertEqual(receive(self.s,'jinx','secret',{},raw)[0],401)
    def test_receiver_does_not_wait_for_runtime(self):
        key=self.s.ingest('jinx',self.event())
        entered,release=threading.Event(),threading.Event()
        class Blocking(Runtime):
            def run(self, request):
                entered.set()
                release.wait(5)
                return {'text':'done'}
        worker=threading.Thread(target=self.s.tick,args=(Blocking(),self.slack))
        worker.start()
        try:
            self.assertTrue(entered.wait(2))
            headers,raw=self.signed(self.event(ts='2.0'))
            self.assertEqual(receive(self.s,'jinx','secret',headers,raw)[0],200)
            self.assertTrue(worker.is_alive())
        finally:
            release.set(); worker.join(5)
    def test_inflight_handoff_event_retried_not_lost(self):
        key=self.s.ingest('jinx',self.event())
        self.s.tick(Runtime('morc'),self.slack)
        with self.s.db: self.s.db.execute("UPDATE jobs SET state='posting' WHERE id=?",(key,))
        event=self.event('morc','88.0','Ujinx',thread_ts='1.0',bot_id='Bjinx')
        with self.assertRaises(Retry): self.s.ingest('morc',event)
        self.s.record_post(key,'88.0')
        self.assertIsNotNone(self.s.ingest('morc',event))
    def test_wrong_thread_bot_handoff_rejected(self):
        key=self.s.ingest('jinx',self.event())
        self.finish(Runtime('morc'))
        self.assertIsNone(self.s.ingest('morc',self.event('morc',self.s.get(key)['reply_ts'],'Ujinx',thread_ts='other')))
    def test_runtime_pending_until_ttl_without_retry_exhaustion(self):
        class Slow(Runtime):
            def run(self, req): raise Pending(10)
        key=self.s.ingest('jinx',self.event())
        for _ in range(6):
            self.s.tick(Slow(),self.slack); self.now+=11
        self.assertEqual(self.s.get(key)['attempts'],0)
        self.assertEqual(self.s.get(key)['state'],'queued')
    def test_unstructured_mentions_cannot_wake_bots(self):
        class Mention(Runtime):
            def run(self, req): return {'text':'<@Umorc> <!channel> hello'}
        self.s.ingest('jinx',self.event())
        self.finish(Mention())
        self.assertNotIn('<@',self.slack.calls[0][3])
        self.assertNotIn('<!',self.slack.calls[0][3])
    def test_retry_exhausted(self):
        class Failing(Runtime):
            def run(self, req): raise Retry(1)
        key=self.s.ingest('jinx',self.event())
        for _ in range(5):
            self.s.tick(Failing(),self.slack);self.now+=6
        self.assertEqual(self.s.get(key)['state'],'failed')
    def test_runtime_rate_persists_restart(self):
        self.s.ingest('jinx',self.event())
        self.s.tick(Runtime(),self.slack)
        second=self.s.ingest('jinx',self.event(ts='2.0'))
        self.s.close();self.open()
        self.s.tick(Runtime(),self.slack) # first result may post; second may not run yet
        self.assertEqual(self.s.get(second)['attempts'],0)

    def test_duplicate_identity_rejected(self):
        self.cfg['bots']['morc']['user_id']='Ujinx'
        with self.assertRaises(Rejected): Store(self.path,self.cfg)
    def test_unbounded_limits_rejected(self):
        self.cfg['max_hops']=999999
        with self.assertRaises(Rejected): Store(self.path,self.cfg)
