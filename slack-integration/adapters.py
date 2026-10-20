"""Credential-isolated Slack transport and local runtime contract."""
import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from durable import Ambiguous, Rejected, Retry, Pending


class Slack:
    def __init__(self, registry):
        self.registry = registry
        self.verified = set()

    def call(self, bot, method, payload, write=False):
        cfg = self.registry['bots'][bot]
        path = Path(cfg['token_file'])
        if path.stat().st_mode & 0o077:
            raise Rejected('token file must be private')
        token = path.read_text().strip()
        if not token.startswith('xoxb-'):
            raise Rejected('only bot tokens permitted')
        form = method in ('chat.getPermalink', 'conversations.replies', 'conversations.history')
        data = urllib.parse.urlencode(payload).encode() if form else json.dumps(payload).encode()
        content_type = 'application/x-www-form-urlencoded' if form else 'application/json; charset=utf-8'
        req = urllib.request.Request('https://slack.com/api/' + method, data=data, headers={'Authorization': 'Bearer ' + token, 'Content-Type': content_type})
        try:
            with urllib.request.urlopen(req, timeout=15) as response:
                result = json.loads(response.read(262144))
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                raise Retry(exc.headers.get('Retry-After', 30)) from None
            if write and exc.code >= 500:
                raise Ambiguous() from None
            raise Rejected('Slack HTTP failure') from None
        except Exception:
            if write:
                raise Ambiguous() from None
            raise Retry(10) from None
        if not result.get('ok'):
            if result.get('error') == 'ratelimited':
                raise Retry(30)
            if write and result.get('error') in ('internal_error', 'fatal_error', 'request_timeout', 'service_unavailable'):
                raise Ambiguous()
            raise Rejected('Slack rejected request')
        return result

    def identity(self, bot):
        cfg = self.registry['bots'][bot]
        r = self.call(bot, 'auth.test', {})
        if r.get('user_id') != cfg['user_id'] or r.get('team_id') != self.registry['team_id'] or r.get('bot_id') != cfg['bot_id']:
            raise Rejected('token identity mismatch')
        self.verified.add(bot)
        return {k: r[k] for k in ('user_id', 'team_id', 'bot_id', 'url') if k in r}

    def post(self, bot, channel, thread, text, client_id):
        # Verify immediately before each post; rotating a token cannot silently switch identity.
        self.identity(bot)
        result = self.call(bot, 'chat.postMessage', {'channel': channel, 'thread_ts': thread, 'text': text, 'client_msg_id': client_id, 'unfurl_links': False, 'unfurl_media': False, 'parse': 'none', 'reply_broadcast': False}, write=True)
        return result.get('ts')


class RuntimeSocket:
    """Private AF_UNIX interface, NOT the privileged master worker protocol.

    Server must persist request_key before dispatch, retain terminal results, and
    return identical results on retries. It must expose no arbitrary tool/exec API.
    Neither a ChatGPT browser session nor a Codex worker is inferred by this client.
    """
    def __init__(self, paths):
        self.paths = paths

    def run(self, request):
        path = self.paths[request['runtime_id']]
        if not Path(path).is_absolute():
            raise Rejected('runtime socket must be absolute')
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(20)
                client.connect(path)
                client.sendall(json.dumps({'version': 1, 'method': 'reply', 'request': request}).encode() + b'\n')
                with client.makefile('rb') as f:
                    raw = f.readline(65537)
            if len(raw) > 65536 or not raw.endswith(b'\n'):
                raise Rejected('invalid runtime framing')
            result = json.loads(raw)
        except (OSError, json.JSONDecodeError):
            # Retrying is safe only under the documented runtime idempotency contract.
            raise Retry(10) from None
        if result.get('runtime_id') != request['runtime_id'] or result.get('request_key') != request['request_key'] or result.get('idempotent') is not True:
            raise Rejected('runtime identity/idempotency mismatch')
        if result.get('state') in ('queued', 'running'):
            raise Pending(10)
        if result.get('state') != 'succeeded':
            raise Rejected('runtime blocked or failed')
        return result['result']
