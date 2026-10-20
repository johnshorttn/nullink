"""Socket.IO realtime push tests (2026-10-14): handshake auth via /api/rt/whoami, guest scope,
live emit on new message (any writer), catch-up after reconnect.
The rt_server part needs python-socketio: run with /opt/nullink/rtvenv/bin/python -m unittest tests.test_realtime"""
import asyncio
import json
import os
import socket
import threading
import time
import unittest

import server
from tests.test_auth import AuthBase, totp_code
import tests.test_guest as _tg
GuestTests = None  # avoid re-collecting the guest suite here

try:
    import socketio  # noqa: F401
    import uvicorn
    HAVE_SIO = True
except ImportError:
    HAVE_SIO = False


class WhoamiTests(AuthBase):
    request = _tg.GuestTests.request
    approve = _tg.GuestTests.approve
    redeem = _tg.GuestTests.redeem
    guest = _tg.GuestTests.guest

    def setUp(self):
        super().setUp()
        for f in (server.GUEST_FILE, server.GUEST_AUDIT_FILE):
            try:
                f.unlink()
            except FileNotFoundError:
                pass
        self.enable_totp()
        st, _, self.owner = self.login(totp_code())
        self.assertEqual(st, 200)

    def test_unauthenticated_rejected(self):
        st, _, _, _ = self.req("/api/rt/whoami")
        self.assertEqual(st, 401)
        st, _, _, _ = self.req("/api/rt/whoami", headers={"Authorization": "Bearer nope"})
        self.assertEqual(st, 401)

    def test_owner(self):
        st, _, js, _ = self.req("/api/rt/whoami", cookie=self.owner)
        self.assertEqual(st, 200)
        self.assertFalse(js["guest"])
        self.assertEqual(js["sessions"], "*")

    def test_guest_scope(self):
        ck, _ = self.guest()
        st, _, js, _ = self.req("/api/rt/whoami", cookie=ck)
        self.assertEqual(st, 200)
        self.assertTrue(js["guest"])
        self.assertTrue(js["hide_history"])
        self.assertIn("replit", js["owner_only"])


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@unittest.skipUnless(HAVE_SIO, "python-socketio not installed (use rtvenv)")
class RealtimeTests(WhoamiTests):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        os.environ["NL_API"] = f"http://127.0.0.1:{cls.httpd.server_port}"
        os.environ["NL_MESSAGES"] = str(server.MESSAGES_FILE)
        os.environ["NL_RT_TAIL_SEC"] = "0.05"
        os.environ["NL_REPLIT_STATUS"] = "http://127.0.0.1:9/none"
        import importlib
        import rt_server
        cls.rt = importlib.reload(rt_server)
        cls.rt_port = _free_port()
        cfg = uvicorn.Config(cls.rt.app, host="127.0.0.1", port=cls.rt_port, log_level="error", lifespan="on")
        cls.uv = uvicorn.Server(cfg)
        cls.uv_thread = threading.Thread(target=cls.uv.run, daemon=True)
        cls.uv_thread.start()
        for _ in range(100):
            if cls.uv.started:
                break
            time.sleep(0.05)
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        cls.uv.should_exit = True
        cls.uv_thread.join(5)
        super().tearDownClass()

    def run_async(self, coro):
        return asyncio.run(asyncio.wait_for(coro, 20))

    async def client(self, cookie=None, auth=None):
        c = socketio.AsyncClient(reconnection=False)
        got = []
        c.on("message", lambda d: got.append(d))
        headers = {"Cookie": cookie} if cookie else {}
        await c.connect(f"http://127.0.0.1:{self.rt_port}", headers=headers, auth=auth,
                        transports=["websocket"], wait_timeout=5)
        return c, got

    def post(self, text, sid="morc"):
        st, _, js, _ = self.req("/api/messages", "POST", {"text": text, "session_id": sid}, cookie=self.owner)
        self.assertEqual(st, 200, js)
        return js["message"]

    def test_socket_unauthenticated_rejected(self):
        async def go():
            with self.assertRaises(socketio.exceptions.ConnectionError):
                await self.client()
            with self.assertRaises(socketio.exceptions.ConnectionError):
                await self.client(cookie="nullink_session=forged.value")
            with self.assertRaises(socketio.exceptions.ConnectionError):
                await self.client(auth={"token": "bogus"})
        self.run_async(go())

    def test_emit_on_new_message_and_direct_file_writer(self):
        async def go():
            c, got = await self.client(self.owner)
            ack = await c.call("join", {"session": "morc", "after": 0}, timeout=5)
            self.assertTrue(ack["ok"])
            m = await asyncio.to_thread(self.post, "hello realtime")
            # direct append like the Replit room worker does
            with server.MESSAGES_FILE.open("a") as f:
                f.write(json.dumps({"role": "assistant", "text": "from bridge", "session_id": "morc"}) + "\n")
            for _ in range(60):
                if len(got) >= 2:
                    break
                await asyncio.sleep(0.05)
            ids = [x["id"] for d in got for x in d["messages"]]
            self.assertIn(m["id"], ids)
            self.assertEqual(got[-1]["messages"][0]["text"], "from bridge")
            await asyncio.to_thread(self.post, "other room", "chatgpt")
            await asyncio.sleep(0.4)
            self.assertFalse(any(x["session_id"] == "chatgpt" for d in got for x in d["messages"]))
            await c.disconnect()
        self.run_async(go())

    def test_catchup_after_reconnect(self):
        async def go():
            c, got = await self.client(self.owner)
            await c.call("join", {"session": "morc", "after": 0}, timeout=5)
            first = await asyncio.to_thread(self.post, "before drop")
            await asyncio.sleep(0.3)
            await c.disconnect()
            missed = [await asyncio.to_thread(self.post, f"missed {i}") for i in range(3)]
            c2, got2 = await self.client(self.owner)
            ack = await c2.call("join", {"session": "morc", "after": first["id"]}, timeout=5)
            self.assertEqual([x["id"] for x in ack["messages"]], [m["id"] for m in missed])
            await c2.disconnect()
        self.run_async(go())

    def test_guest_scope_on_socket(self):
        ck, _ = self.guest()
        async def go():
            c, got = await self.client(ck)
            ack = await c.call("join", {"session": "replit", "after": 0}, timeout=5)
            self.assertFalse(ack["ok"])
            ack = await c.call("join", {"session": "morc", "after": 1}, timeout=5)
            self.assertTrue(ack["ok"])
            self.assertTrue(ack["history_hidden"])
            self.assertEqual(ack["messages"], [])
            await asyncio.to_thread(self.post, "secret owner message")
            await asyncio.sleep(0.4)
            self.assertEqual(got, [])
            await c.disconnect()
        self.run_async(go())
