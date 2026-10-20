"""Import into Morc's existing HTTP listener; deliberately no competing server."""
import json
from durable import verify, Rejected, Retry


def receive(store, bot, secret, headers, raw):
    """Returns (status, JSON object). Do not run AI or Slack calls in this path.

    HTTP adapter must enforce Content-Length <=262144 before reading request body,
    return this response immediately, and run ONE Store.tick dispatcher separately.
    """
    try:
        body = verify(secret, headers, raw, now=store.clock())
        if not isinstance(body, dict):
            raise Rejected('invalid body')
        if body.get('type') == 'url_verification':
            challenge = body.get('challenge')
            if not isinstance(challenge, str) or len(challenge) > 256:
                raise Rejected('invalid challenge')
            return 200, {'challenge': challenge}
        key = store.ingest(bot, body)
        return 200, {'ok': True, 'queued': bool(key)}
    except (Rejected, KeyError, TypeError, ValueError):
        return 401, {'ok': False}
    except Retry:
        return 503, {'ok': False}
