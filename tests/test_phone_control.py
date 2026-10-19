import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from phone_bridge import PhoneBridge, PhoneBridgeError


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.bridge = PhoneBridge(Path(self.temp.name)/'data', Path(self.temp.name)/'stage')
        self.device = self.pair()
        self.ready(self.device)

    def pair(self):
        return self.bridge.pair(self.bridge.create_pairing_code()['code'], 'Test')['device']['id']

    def ready(self, device):
        self.bridge.set_screen_active(device, True)
        self.bridge.publish_screen_frame(device, b'\xff\xd8\xfftest')
        self.bridge.set_control_state(device, {'enabled': True, 'accessibility': True, 'session': 'a'*32})

    def request(self, device=None):
        result = {}
        def run():
            try: result.update(self.bridge.request_control(device or self.device, {'action': 'tap', 'x': .5, 'y': .2}, timeout=1))
            except PhoneBridgeError as e: result['error'] = e.code
        thread = threading.Thread(target=run)
        thread.start()
        with self.bridge._changed:
            self.bridge._changed.wait_for(lambda: bool(self.bridge._pending) or bool(result), timeout=1)
        return thread, result

    def test_strict_schema(self):
        invalid = [None, [], {}, {'action': []}, {'action': 'shell'}, {'action': 'text', 'text': 'x'},
                   {'action': 'home', 'extra': 1}, {'action': 'tap', 'x': True, 'y': 0},
                   {'action': 'tap', 'x': float('nan'), 'y': 0}, {'action': 'tap', 'x': -1, 'y': 0},
                   {'action': 'tap', 'x': 0, 'y': 1.01}, {'action': 'tap', 'x': '0', 'y': 0},
                   {'action': 'swipe', 'x': 0, 'y': 0, 'end_x': 1, 'end_y': 1, 'duration_ms': 1001}]
        for command in invalid:
            with self.subTest(command=command), self.assertRaises(PhoneBridgeError):
                self.bridge.validate_control(command)
        for action in ('back', 'home', 'recents'):
            self.assertEqual(self.bridge.validate_control({'action': action}), {'action': action})

    def test_delivery_ack_and_device_isolation_without_folder_sharing(self):
        other = self.pair(); self.ready(other)
        thread, result = self.request()
        self.assertIsNone(self.bridge.next_control(other, 0))
        command = self.bridge.next_control(self.device, 1)
        self.assertEqual(command['command']['x'], .5)
        with self.assertRaises(PhoneBridgeError):
            self.bridge.complete_command(other, command['id'], {'ok': True})
        self.bridge.complete_command(self.device, command['id'], {'ok': True})
        thread.join(); self.assertEqual(result, {'ok': True})
        self.assertFalse(self.bridge._pending)

    def test_android_failure_visible(self):
        thread, result = self.request()
        command = self.bridge.next_control(self.device, 1)
        self.bridge.complete_command(self.device, command['id'], {'ok': False})
        thread.join(); self.assertEqual(result['error'], 'phone_control_rejected')

    def test_stop_cancels_pending_and_restart_does_not_reenable(self):
        thread, result = self.request()
        self.bridge.set_screen_active(self.device, False)
        thread.join(); self.assertEqual(result['error'], 'control_stopped')
        self.bridge.set_screen_active(self.device, True)
        self.assertIsNone(self.bridge.next_control(self.device, 0))
        restarted = PhoneBridge(self.bridge.data_dir, self.bridge.staging_dir)
        self.assertFalse(restarted.public_device(self.device)['control_enabled'])

    def test_permission_off_stale_state_stale_frame_and_unknown_device(self):
        for field in ('enabled', 'accessibility'):
            state = {'enabled': True, 'accessibility': True, 'session': 'a'*32}
            state[field] = False
            self.bridge.set_control_state(self.device, state)
            with self.assertRaises(PhoneBridgeError): self.bridge.request_control(self.device, {'action': 'home'})
        self.ready(self.device)
        self.bridge._control[self.device]['seen'] -= 11
        with self.assertRaises(PhoneBridgeError): self.bridge.request_control(self.device, {'action': 'home'})
        self.ready(self.device)
        self.bridge._screen_frames[self.device]['created'] -= 9
        with self.assertRaises(PhoneBridgeError): self.bridge.request_control(self.device, {'action': 'home'})
        with self.assertRaises(PhoneBridgeError): self.bridge.request_control('unknown', {'action': 'home'})

    def test_rate_queue_and_expired_delivery(self):
        self.bridge._control_rates[self.device] = [time.time()] * 5
        with self.assertRaises(PhoneBridgeError) as e: self.bridge.request_control(self.device, {'action': 'home'})
        self.assertEqual(e.exception.status, 429)
        self.bridge._control_rates.clear()
        thread, result = self.request()
        q = self.bridge._control_queues[self.device]
        q.queue[0]['expires_at'] = 0
        self.assertIsNone(self.bridge.next_control(self.device, 0))
        thread.join(); self.assertEqual(result['error'], 'control_timeout')
        import queue
        q = queue.Queue(maxsize=4)
        for i in range(4): q.put({})
        self.bridge._control_queues[self.device] = q
        with self.assertRaises(PhoneBridgeError) as e: self.bridge.request_control(self.device, {'action': 'home'})
        self.assertEqual(e.exception.code, 'control_queue_full')

    def test_revoke_cancels_control(self):
        thread, result = self.request()
        self.bridge.revoke(self.device)
        thread.join(); self.assertEqual(result['error'], 'device_revoked')
        self.assertIsNone(self.bridge.next_control(self.device, 0))


class ControlHTTPTests(unittest.TestCase):
    def test_routes_require_browser_session_and_bind_status_to_device_token(self):
        import http.client
        import json
        from http.server import ThreadingHTTPServer
        import server
        with tempfile.TemporaryDirectory() as tmp:
            bridge = PhoneBridge(Path(tmp)/'data', Path(tmp)/'stage')
            pair = bridge.pair(bridge.create_pairing_code()['code'], 'Test')
            httpd = ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
            thread = threading.Thread(target=httpd.serve_forever, daemon=True); thread.start()
            def request(path, body, headers=None):
                conn = http.client.HTTPConnection('127.0.0.1', httpd.server_port)
                conn.request('POST', path, json.dumps(body), {'Content-Type':'application/json', **(headers or {})})
                response = conn.getresponse(); payload = response.read(); conn.close()
                return response.status, payload
            try:
                with patch.object(server, 'get_bridge', return_value=bridge):
                    payload = {'device_id':pair['device']['id'], 'command':{'action':'home'}}
                    with patch.object(server.Handler, '_resolve_auth', return_value=None):
                        self.assertEqual(request('/api/phone/control', payload)[0], 401)
                        self.assertEqual(request('/api/phone/control', payload, {'Authorization':'Bearer '+pair['token']})[0], 401)
                    with patch.object(server.Handler, '_resolve_auth', return_value={'type':'bearer'}):
                        self.assertEqual(request('/api/phone/control', payload)[0], 403)
                    with patch.object(server.Handler, '_resolve_auth', return_value={'type':'session'}):
                        self.assertEqual(request('/api/phone/control', payload)[0], 409)
                        payload['device_id'] = 'unknown'
                        self.assertEqual(request('/api/phone/control', payload)[0], 404)
                    state = {'session':'a'*32, 'enabled':True, 'accessibility':True}
                    self.assertEqual(request('/api/phone/control/status', state)[0], 401)
                    self.assertEqual(request('/api/phone/control/status', state, {'Authorization':'Bearer '+pair['token']})[0], 200)
                    state['device_id'] = 'another-device'
                    self.assertEqual(request('/api/phone/control/status', state, {'Authorization':'Bearer '+pair['token']})[0], 400)
            finally:
                httpd.shutdown(); httpd.server_close(); thread.join()
