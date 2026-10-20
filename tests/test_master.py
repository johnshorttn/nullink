import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
import socketserver
from unittest.mock import patch
from master_worker import Handler
from master_worker import Worker
import master_gateway as gateway

class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.fake = self.root / 'codex'
        self.fake.write_text('''#!/usr/bin/env python3
import json, sys, time
prompt = sys.stdin.read()
print(json.dumps({'type':'thread.started','thread_id':'11111111-1111-4111-8111-111111111111'}), flush=True)
if prompt == 'slow': time.sleep(30)
if prompt == 'flood': print('x' * 100000, flush=True)
print(json.dumps({'type':'item.completed','item':{'text':'done'}}), flush=True)
''')
        self.fake.chmod(0o700)
        self.config = {'state_dir': str(self.root/'state'), 'projects': {'test': str(self.root)},
                       'codex_bin': str(self.fake), 'timeout_seconds': 2, 'max_output_bytes': 65536}
        self.worker = Worker(self.config)
    def tearDown(self):
        self.worker.close()
        self.tmp.cleanup()
    def submit(self, prompt='hello', key='request1'):
        return self.worker.call('agent_start_task', {'project':'test', 'prompt':prompt, 'request_key':key})
    def test_gateway_worker_socket_roundtrip(self):
        path = str(self.root / 'worker.sock')
        try:
            server = socketserver.ThreadingUnixStreamServer(path, Handler)
        except PermissionError:
            self.skipTest('Runtime prohibits Unix sockets; run this integration test on the VPS')
        with server:
            server.worker = self.worker
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                with patch.dict(os.environ, {'MASTER_SOCKET': path}):
                    caps = gateway.call_worker('master_capabilities', {})
                    self.assertEqual(caps['projects'], ['test'])
                    job = gateway.call_worker('agent_start_task', {'project':'test', 'prompt':'hello', 'request_key':'socket1'})
                    self.worker.run_one()
                    result = gateway.call_worker('agent_task_status', {'job_id':job['id']})
                    self.assertEqual(result['state'], 'succeeded')
            finally:
                server.shutdown()
                thread.join()

    def test_run_and_resume(self):
        job = self.submit()
        self.assertTrue(self.worker.run_one())
        result = self.worker.call('agent_task_status', {'job_id':job['id']})
        self.assertEqual(result['state'], 'succeeded')
        self.assertIn('done', result['output'])
        self.assertNotIn('prompt', result)
        follow = self.worker.call('agent_reply', {'job_id':job['id'], 'prompt':'continue', 'request_key':'reply1'})
        argv = self.worker.argv(self.worker.get(follow['id']))
        self.assertIn('resume', argv)
        self.assertIn(result['session'], argv)
        self.worker.run_one()
        self.assertEqual(self.worker.get(follow['id'])['state'], 'succeeded')
    def test_idempotency_and_conflict(self):
        self.assertEqual(self.submit()['id'], self.submit()['id'])
        with self.assertRaises(ValueError): self.submit('different')
    def test_project_allowlist(self):
        with self.assertRaises(ValueError): self.worker.call('repo_status', {'project':'../../etc'})
        with self.assertRaises(ValueError): self.worker.call('service_status', {'service':'--all'})
    def test_cancel_queued(self):
        job = self.submit()
        self.worker.call('agent_cancel_task', {'job_id':job['id']})
        self.assertFalse(self.worker.run_one())
        self.assertEqual(self.worker.get(job['id'])['state'], 'cancelled')
    def test_cancel_running(self):
        job = self.submit('slow')
        thread = threading.Thread(target=self.worker.run_one)
        thread.start()
        deadline = time.monotonic() + 2
        while self.worker.call('agent_task_status', {'job_id':job['id']})['state'] == 'queued':
            if time.monotonic() > deadline: self.fail('worker did not start')
            time.sleep(.01)
        self.worker.call('agent_cancel_task', {'job_id':job['id']})
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(self.worker.get(job['id'])['state'], 'cancelled')
    def test_timeout(self):
        self.worker.config['timeout_seconds'] = .15
        job = self.submit('slow')
        self.worker.run_one()
        self.assertEqual(self.worker.get(job['id'])['state'], 'timed_out')
    def test_output_limit(self):
        job = self.submit('flood')
        self.worker.run_one()
        result = self.worker.get(job['id'])
        self.assertEqual(result['state'], 'failed')
        self.assertIn('output limit', result['output'])
        self.assertLessEqual(len(result['output']), 32768)
    def test_restart_recovery(self):
        job = self.submit()
        self.worker.update(job['id'], state='running')
        self.worker.close()
        self.worker = Worker(self.config)
        self.assertEqual(self.worker.get(job['id'])['state'], 'interrupted')
    def test_single_worker_lock(self):
        with self.assertRaises(BlockingIOError): Worker(self.config)
    def test_live_reply_rejected(self):
        job = self.submit()
        with self.assertRaises(ValueError):
            self.worker.call('agent_reply', {'job_id':job['id'], 'prompt':'continue', 'request_key':'reply1'})
    def test_gateway_schema_rejects_before_socket(self):
        with self.assertRaises(ValueError): gateway.call_worker('agent_start_task', {'shell':'id'})
        with self.assertRaises(ValueError): gateway.call_worker('not_a_tool', {})
    def test_audit_records_lifecycle_without_prompt(self):
        self.submit('private prompt')
        self.worker.run_one()
        audit = self.worker.call('master_audit', {})
        self.assertEqual([r['action'] for r in audit], ['succeeded', 'start', 'submit'])
        self.assertNotIn('private prompt', json.dumps(audit))

class AuthTests(unittest.TestCase):
    def test_separate_admin_token(self):
        handler = object.__new__(gateway.MasterHandler)
        handler.server = type('Server', (), {'admin_token':'admin-test-token'})()
        for token, accepted in [('legacy-chat-token', False), ('admin-test-token', True), ('', False)]:
            handler.headers = {'Authorization': 'Bearer ' + token}
            self.assertEqual(handler._authorized(), accepted)

if __name__ == '__main__': unittest.main()
