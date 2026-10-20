import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from adapters import Slack
from durable import Rejected, Ambiguous, Retry
from urllib.error import HTTPError


class Response:
    def __init__(self, value): self.value=value
    def __enter__(self): return self
    def __exit__(self, *a): pass
    def read(self, *a): return json.dumps(self.value).encode()


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.token=Path(self.tmp.name)/'token'
        self.token.write_text('xoxb-test-only')
        self.token.chmod(0o600)
        self.client=Slack({'team_id':'T','bots':{'jinx':{'user_id':'U','bot_id':'B','token_file':str(self.token)}}})
    def tearDown(self): self.tmp.cleanup()
    def test_identity_mismatch_prevents_post(self):
        with patch('urllib.request.urlopen', return_value=Response({'ok':True,'team_id':'T','user_id':'John','bot_id':'B'})) as p:
            with self.assertRaises(Rejected): self.client.post('jinx','C','1.0','smoke','id')
            self.assertEqual(p.call_count,1)
    def test_own_identity_exact_thread_and_no_broadcast(self):
        with patch('urllib.request.urlopen', side_effect=[Response({'ok':True,'team_id':'T','user_id':'U','bot_id':'B'}), Response({'ok':True,'ts':'2.0'})]) as p:
            self.assertEqual(self.client.post('jinx','C','1.0','smoke','id'),'2.0')
            req=p.call_args_list[1].args[0]
            body=json.loads(req.data)
            self.assertEqual(body['thread_ts'],'1.0')
            self.assertFalse(body['reply_broadcast'])
            self.assertNotIn('username', body)
            self.assertNotIn('icon_url', body)
    def test_user_token_refused(self):
        self.token.write_text('xoxp-test-only')
        with self.assertRaises(Rejected): self.client.identity('jinx')
    def test_world_readable_token_refused(self):
        self.token.chmod(0o644)
        with self.assertRaises(Rejected): self.client.identity('jinx')
    def test_write_timeout_is_ambiguous(self):
        with patch('urllib.request.urlopen', side_effect=TimeoutError):
            with self.assertRaises(Ambiguous): self.client.call('jinx','chat.postMessage',{},write=True)
    def test_rate_limit_preserves_retry_after(self):
        error=HTTPError('https://slack.com',429,'rate',{'Retry-After':'42'},None)
        with patch('urllib.request.urlopen', side_effect=error):
            with self.assertRaises(Retry) as caught: self.client.call('jinx','chat.postMessage',{},write=True)
            self.assertEqual(caught.exception.seconds,42)
