"""slack-events: a peer (Caddy) that hung up before the response is one quiet log line, not a traceback flood."""
import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_TMP = tempfile.mkdtemp(prefix="slack-events-test-")
os.environ.setdefault("SLACK_EVENTS_HOME", _TMP)
os.environ.setdefault("SLACK_EVENTS_STATE", _TMP)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "slack-events"))
se = importlib.import_module("slack_events")


class _Gone:
    def __init__(self, exc):
        self.exc = exc

    def write(self, data):
        raise self.exc

    def flush(self):
        pass


def _handler(exc):
    h = se.Handler.__new__(se.Handler)
    h.send_response = mock.Mock(); h.send_header = mock.Mock(); h.end_headers = mock.Mock()
    h.wfile = _Gone(exc)
    return h


class SendTests(unittest.TestCase):
    def test_send_swallows_broken_pipe_and_reset(self):
        for exc in (BrokenPipeError(32, "Broken pipe"), ConnectionResetError(104, "reset")):
            with mock.patch.object(se.log, "info") as info:
                _handler(exc)._send(200, {"ok": True})  # must not raise
            info.assert_called_once()
            self.assertIn(type(exc).__name__, info.call_args.args)

    def test_send_other_errors_still_raise(self):
        with self.assertRaises(ValueError):
            _handler(ValueError("x"))._send(200, {"ok": True})

    def test_server_handle_error_quiet_only_for_hangups(self):
        srv = se.QuietServer.__new__(se.QuietServer)
        with mock.patch("socketserver.BaseServer.handle_error") as base, mock.patch.object(se.log, "info") as info:
            try:
                raise BrokenPipeError(32, "Broken pipe")
            except BrokenPipeError:
                srv.handle_error(None, ("127.0.0.1", 1))
            base.assert_not_called(); info.assert_called_once()
            try:
                raise RuntimeError("real bug")
            except RuntimeError:
                srv.handle_error(None, ("127.0.0.1", 1))
            base.assert_called_once()


if __name__ == "__main__":
    unittest.main()
