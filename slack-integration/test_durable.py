import hashlib
import hmac
import json
import tempfile
import unittest
from pathlib import Path
from durable import Store, verify, Rejected, Retry, Ambiguous


class Runtime:
    def __init__(self, target=None):
        self.calls = []
        self.target = target
    def run(self, request):
        self.calls.append(request)
        return {'text': 'ack ' + request['bot'], 'handoff_to': self.target}


class Slack:
    def __init__(self):
        self.calls = []
    def post(self, *args):
        self.calls.append(args)
        return f'{100 + len(self.calls)}.000001'


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'queue.sqlite'
        self.now = 1000
        self.cfg = {'team_id': 'T', 'channels': ['C'], 'human_users': ['H'], 'handoffs': [['jinx', 'morc'], ['morc', 'jinx']], 'max_hops': 2, 'job_budget': 3, 'ttl_seconds': 600,
                    'bots': {b: {'app_id': 'A' + b, 'user_id': 'U' + b, 'bot_id': 'B' + b, 'runtime_id': b + '-test', 'enabled': True, 'label': b + ' mock runtime'} for b in ('jinx', 'morc')}}
        self.open()
        self.slack = Slack()
    def open(self):
        self.s = Store(self.path, self.cfg, lambda: self.now)
    def tearDown(self):
        self.s.close()
        self.tmp.cleanup()
    def event(self, bot='jinx', ts='1.0', sender='H', **fields):
        event = {'type': 'app_mention', 'channel': 'C', 'ts': ts, 'user': sender, 'text': '<@U' + bot + '> smoke', **fields}
        return {'type': 'event_callback', 'team_id': 'T', 'api_app_id': 'A' + bot, 'event_id': bot + ts, 'event': event}
    def finish(self, runtime):
        self.s.tick(runtime, self.slack)
        self.now += 6
        self.s.tick(runtime, self.slack)
        self.now += 6

    def test_signatures(self):
        raw = b'{"type":"url_verification"}'
        sig = 'v0=' + hmac.new(b'secret', b'v0:1000:' + raw, hashlib.sha256).hexdigest()
        headers = {'X-Slack-Request-Timestamp': '1000', 'X-Slack-Signature': sig}
        self.assertEqual(verify('secret', headers, raw, 1000)['type'], 'url_verification')
        for secret, body, now in [('', raw, 1000), ('bad', raw, 1000), ('secret', raw+b' ', 1000), ('secret', raw, 1400)]:
            with self.assertRaises(Rejected): verify(secret, headers, body, now)

    def test_human_runtime_own_thread_reply(self):
        key = self.s.ingest('jinx', self.event(thread_ts='0.0'))
        runtime = Runtime()
        self.finish(runtime)
        self.assertEqual(self.s.get(key)['state'], 'done')
        self.assertEqual(runtime.calls[0]['runtime_id'], 'jinx-test')
        self.assertEqual(self.slack.calls[0][:3], ('jinx', 'C', '0.0'))

    def test_event_and_cross_subscription_dedup_after_restart(self):
        e = self.event()
        key = self.s.ingest('jinx', e)
        self.s.close(); self.open()
        self.assertIsNone(self.s.ingest('jinx', e))
        e['event_id'] = 'different-app-mention-event-id'
        self.assertIsNone(self.s.ingest('jinx', e))
        self.finish(Runtime())
        self.assertEqual(len(self.slack.calls), 1)
        self.assertEqual(self.s.get(key)['state'], 'done')

    def test_directed_roundtrip_and_hop_stop(self):
        first = self.s.ingest('jinx', self.event())
        self.finish(Runtime('morc'))
        ts = self.s.get(first)['reply_ts']
        second = self.s.ingest('morc', self.event('morc', ts, 'Ujinx', thread_ts='1.0', bot_id='Bjinx'))
        self.finish(Runtime('jinx'))
        ts2 = self.s.get(second)['reply_ts']
        third = self.s.ingest('jinx', self.event('jinx', ts2, 'Umorc', thread_ts='1.0', bot_id='Bmorc'))
        self.finish(Runtime())
        self.assertEqual(self.s.get(third)['hop'], 2)
        self.assertEqual(self.s.get(first)['chain'], self.s.get(third)['chain'])
        self.assertEqual([x[0] for x in self.slack.calls], ['jinx', 'morc', 'jinx'])
        self.assertIsNone(self.s.ingest('morc', self.event('morc', self.s.get(third)['reply_ts'], 'Ujinx', thread_ts='1.0')))

    def test_unknown_bots_and_human_denied(self):
        for sender, fields in [('stranger', {}), ('unknownbot', {'bot_id':'Bunknown'}), ('H', {'subtype':'bot_message'})]:
            self.assertIsNone(self.s.ingest('jinx', self.event(ts=sender, sender=sender, **fields)))

    def test_identity_team_and_app(self):
        for field in ('team_id', 'api_app_id'):
            e=self.event(); e[field]='wrong'
            with self.assertRaises(Rejected): self.s.ingest('jinx', e)

    def test_ttl(self):
        key = self.s.ingest('jinx', self.event())
        self.now += 601
        self.s.tick(Runtime(), self.slack)
        self.assertEqual(self.s.get(key)['state'], 'expired')
        self.assertFalse(self.slack.calls)

    def test_runtime_retry_same_key_and_thread_serialization(self):
        first = self.s.ingest('jinx', self.event())
        second = self.s.ingest('jinx', self.event(ts='2.0', thread_ts='1.0'))
        class Busy(Runtime):
            def run(self, request):
                self.calls.append(request)
                raise Retry(10)
        runtime=Busy()
        self.s.tick(runtime, self.slack)
        self.now += 6
        self.assertIsNone(self.s.tick(runtime, self.slack))
        self.now += 6
        self.s.close(); self.open()
        self.s.tick(runtime, self.slack)
        self.assertEqual([r['request_key'] for r in runtime.calls], [first, first])
        self.assertEqual(self.s.get(second)['attempts'], 0)

    def test_post_crash_reconciliation_no_duplicate(self):
        key = self.s.ingest('jinx', self.event())
        self.s.tick(Runtime(), self.slack)
        with self.s.db:
            self.s.db.execute("UPDATE jobs SET state='posting' WHERE id=?", (key,))
        self.s.close(); self.open()
        self.assertEqual(self.s.get(key)['state'], 'uncertain')
        self.s.tick(Runtime(), self.slack)
        self.assertFalse(self.slack.calls)
        self.s.record_post(key, '999.0001')
        self.assertEqual(self.s.get(key)['state'], 'done')

    def test_ambiguous_network_not_reposted(self):
        class Timeout(Slack):
            def post(self, *args): raise Ambiguous()
        key=self.s.ingest('jinx', self.event())
        self.s.tick(Runtime(), self.slack)
        self.now += 6
        self.s.tick(Runtime(), Timeout())
        self.assertEqual(self.s.get(key)['state'], 'uncertain')
        self.now += 10
        self.assertIsNone(self.s.tick(Runtime(), self.slack))

    def test_context_isolation_and_redaction(self):
        e=self.event(text='<@Ujinx> xoxb-sensitive-secret')
        self.s.ingest('jinx', e)
        self.finish(Runtime())
        key=self.s.ingest('jinx', self.event(ts='2.0', thread_ts='1.0'))
        c=self.s.context(self.s.get(key))
        self.assertEqual(len(c), 1)
        self.assertNotIn('xoxb-', c[0]['message'])
        other=self.s.ingest('jinx', self.event(ts='3.0'))
        self.assertEqual(self.s.context(self.s.get(other)), [])

    def test_single_process_lock(self):
        with self.assertRaises(OSError): Store(self.path, self.cfg)

    def test_disabled_runtime(self):
        self.cfg['bots']['jinx']['enabled']=False
        key=self.s.ingest('jinx', self.event())
        self.assertIsNone(self.s.tick(Runtime(), self.slack))
        self.assertEqual(self.s.get(key)['state'], 'queued')

if __name__ == '__main__': unittest.main(verbosity=2)
