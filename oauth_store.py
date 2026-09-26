"""Single-owner OAuth authorization state. Tokens are opaque and hashed at rest."""
from contextlib import contextmanager
import base64
import hashlib
import json
import re
import secrets
import sqlite3
import time
from pathlib import Path
from urllib.parse import urlsplit, urlencode

SCOPE = 'nullink:admin'


def digest(value):
    return hashlib.sha256(value.encode('ascii')).hexdigest()


def challenge(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode('ascii')).digest()).rstrip(b'=').decode()


class OAuthError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class Store:
    def __init__(self, config):
        self.config = config
        self.issuer = config['issuer']
        self.resource = config['resource']
        for value in (self.issuer, self.resource, *config['redirect_uris']):
            if not isinstance(value, str) or any(ord(c) <= 32 or ord(c) == 127 for c in value) or '*' in value or '\\' in value:
                raise ValueError('OAuth URLs must be exact, printable URLs')
            url = urlsplit(value)
            if url.scheme != 'https' or not url.hostname or url.username or url.password or url.fragment:
                raise ValueError('OAuth URLs must use HTTPS without credentials or fragments')
        if urlsplit(self.issuer).query or urlsplit(self.resource).query:
            raise ValueError('Issuer/resource must not have a query')
        if self.issuer.endswith('/') or self.resource.endswith('/'):
            raise ValueError('Issuer/resource must not end in a slash')
        if urlsplit(self.issuer).netloc != urlsplit(self.resource).netloc:
            raise ValueError('Issuer and resource must use the same public origin')
        self.path = Path(config['database'])
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.db() as db:
            db.executescript('''
              CREATE TABLE IF NOT EXISTS binding(issuer TEXT, resource TEXT);
              CREATE TABLE IF NOT EXISTS clients(id TEXT PRIMARY KEY, redirect TEXT, created REAL);
              CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY, client TEXT, redirect TEXT,
                state TEXT, challenge TEXT, browser TEXT, expires REAL, decision TEXT, created REAL);
              CREATE TABLE IF NOT EXISTS codes(hash TEXT PRIMARY KEY, client TEXT, redirect TEXT,
                challenge TEXT, expires REAL, family TEXT);
              CREATE TABLE IF NOT EXISTS families(id TEXT PRIMARY KEY, client TEXT, revoked INTEGER DEFAULT 0);
              CREATE TABLE IF NOT EXISTS tokens(hash TEXT PRIMARY KEY, family TEXT, kind TEXT,
                expires REAL, used INTEGER DEFAULT 0);
            ''')
            bound = db.execute("SELECT * FROM binding").fetchone()
            if bound and (bound["issuer"], bound["resource"]) != (self.issuer, self.resource):
                raise ValueError("Database is bound to a different issuer/resource")
            if not bound: db.execute("INSERT INTO binding VALUES(?,?)", (self.issuer, self.resource))
        self.path.chmod(0o600)

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def metadata(self):
        return {'issuer': self.issuer, 'authorization_endpoint': self.issuer + '/authorize',
                'token_endpoint': self.issuer + '/token', 'registration_endpoint': self.issuer + '/register',
                'revocation_endpoint': self.issuer + '/revoke',
                'response_types_supported': ['code'], 'grant_types_supported': ['authorization_code', 'refresh_token'],
                'code_challenge_methods_supported': ['S256'], 'token_endpoint_auth_methods_supported': ['none'],
                'scopes_supported': [SCOPE], 'authorization_response_iss_parameter_supported': True}

    def protected(self):
        return {'resource': self.resource, 'authorization_servers': [self.issuer],
                'scopes_supported': [SCOPE], 'bearer_methods_supported': ['header']}

    def register(self, args):
        redirects = args.get('redirect_uris')
        if not isinstance(redirects, list) or len(redirects) != 1 or redirects[0] not in self.config['redirect_uris']:
            raise OAuthError('invalid_redirect_uri')
        if args.get('token_endpoint_auth_method', 'none') != 'none':
            raise OAuthError('invalid_client_metadata')
        if args.get('response_types', ['code']) != ['code']:
            raise OAuthError('invalid_client_metadata')
        if not set(args.get('grant_types', ['authorization_code', 'refresh_token'])) <= {'authorization_code', 'refresh_token'}:
            raise OAuthError('invalid_client_metadata')
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            existing = db.execute('SELECT id FROM clients WHERE redirect=?', (redirects[0],)).fetchone()
            if not existing and db.execute('SELECT count(*) FROM clients').fetchone()[0] >= 200:
                raise OAuthError('temporarily_unavailable')
            client = existing['id'] if existing else secrets.token_urlsafe(24)
            db.execute('INSERT OR IGNORE INTO clients VALUES(?,?,?)', (client, redirects[0], time.time()))
        return {'client_id': client, 'client_id_issued_at': int(time.time()), 'redirect_uris': redirects,
                'token_endpoint_auth_method': 'none', 'grant_types': ['authorization_code', 'refresh_token'],
                'response_types': ['code']}

    def authorize(self, args):
        required = ['client_id', 'redirect_uri', 'state', 'code_challenge', 'resource', 'response_type', 'scope']
        if any(not isinstance(args.get(k), str) or not args[k] for k in required):
            raise OAuthError('invalid_request')
        if args['resource'] != self.resource: raise OAuthError('invalid_target')
        if args['scope'] != SCOPE: raise OAuthError('invalid_scope')
        if args['response_type'] != 'code': raise OAuthError('unsupported_response_type')
        if args.get('code_challenge_method') != 'S256' or not re.fullmatch(r'[A-Za-z0-9_-]{43}', args['code_challenge']):
            raise OAuthError('invalid_request')
        if len(args['state']) > 2048: raise OAuthError('invalid_request')
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            client = db.execute('SELECT * FROM clients WHERE id=?', (args['client_id'],)).fetchone()
            if not client or client['redirect'] != args['redirect_uri']: raise OAuthError('invalid_client')
            db.execute('DELETE FROM requests WHERE expires<?', (time.time(),))
            db.execute('DELETE FROM codes WHERE expires<?', (time.time(),))
            if db.execute('SELECT count(*) FROM requests').fetchone()[0] >= 100:
                raise OAuthError('temporarily_unavailable')
            request, browser = secrets.token_hex(16), secrets.token_urlsafe(32)
            db.execute('INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?)',
                       (request, args['client_id'], args['redirect_uri'], args['state'], args['code_challenge'],
                        digest(browser), time.time() + 600, 'pending', time.time()))
        return request, browser

    def pending(self):
        with self.db() as db:
            return [dict(r) for r in db.execute('SELECT id,client,redirect,expires,decision FROM requests WHERE expires>? AND decision=?', (time.time(), 'pending'))]

    def decide(self, request, approve):
        with self.db() as db:
            result = db.execute("UPDATE requests SET decision=? WHERE id=? AND decision='pending' AND expires>?",
                                ('approved' if approve else 'denied', request, time.time()))
            if result.rowcount != 1: raise OAuthError('invalid_request')

    def poll(self, request, browser):
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM requests WHERE id=? AND browser=? AND expires>?',
                             (request, digest(browser), time.time())).fetchone()
            if not row or row['decision'] == 'consumed': raise OAuthError('invalid_request')
            if row['decision'] == 'pending': return None
            params = {'state': row['state'], 'iss': self.issuer}
            if row['decision'] == 'denied': params['error'] = 'access_denied'
            else:
                code = secrets.token_urlsafe(32)
                db.execute('INSERT INTO codes VALUES(?,?,?,?,?,NULL)',
                           (digest(code), row['client'], row['redirect'], row['challenge'], time.time() + 90))
                params['code'] = code
            db.execute("UPDATE requests SET decision='consumed' WHERE id=?", (request,))
            return row['redirect'] + ('&' if '?' in row['redirect'] else '?') + urlencode(params)

    def issue(self, db, client, family=None):
        if family is None:
            family = secrets.token_hex(16)
            db.execute('INSERT INTO families VALUES(?,?,0)', (family, client))
        access, refresh = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
        db.execute('INSERT INTO tokens VALUES(?,?,?,?,0)', (digest(access), family, 'access', time.time() + 600))
        db.execute('INSERT INTO tokens VALUES(?,?,?,?,0)', (digest(refresh), family, 'refresh', time.time() + 30*86400))
        return {'access_token': access, 'token_type': 'Bearer', 'expires_in': 600,
                'refresh_token': refresh, 'scope': SCOPE}

    def token(self, args):
        if args.get('resource') != self.resource: raise OAuthError('invalid_target')
        if args.get('scope', SCOPE) != SCOPE: raise OAuthError('invalid_scope')
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            if args.get('grant_type') == 'authorization_code':
                verifier = args.get('code_verifier', '')
                if not re.fullmatch(r'[A-Za-z0-9._~-]{43,128}', verifier): raise OAuthError('invalid_grant')
                code = db.execute('SELECT * FROM codes WHERE hash=?', (digest(args.get('code', '')),)).fetchone()
                if not code or code['expires'] <= time.time() or code['client'] != args.get('client_id') or code['redirect'] != args.get('redirect_uri') or code['challenge'] != challenge(verifier):
                    raise OAuthError('invalid_grant')
                if code['family']:
                    db.execute('UPDATE families SET revoked=1 WHERE id=?', (code['family'],))
                    db.commit()
                    raise OAuthError('invalid_grant')
                family = secrets.token_hex(16)
                db.execute('INSERT INTO families VALUES(?,?,0)', (family, code['client']))
                db.execute('UPDATE codes SET family=? WHERE hash=?', (family, digest(args['code'])))
                return self.issue(db, code['client'], family)
            if args.get('grant_type') == 'refresh_token':
                row = db.execute('SELECT t.*,f.client,f.revoked FROM tokens t JOIN families f ON f.id=t.family WHERE t.hash=? AND t.kind=?',
                                 (digest(args.get('refresh_token', '')), 'refresh')).fetchone()
                if not row or row['client'] != args.get('client_id') or row['expires'] <= time.time() or row['revoked']:
                    raise OAuthError('invalid_grant')
                if row['used']:
                    db.execute('UPDATE families SET revoked=1 WHERE id=?', (row['family'],))
                    db.commit()  # Preserve replay revocation even though the request fails.
                    raise OAuthError('invalid_grant')
                db.execute('UPDATE tokens SET used=1 WHERE hash=?', (row['hash'],))
                return self.issue(db, row['client'], row['family'])
            raise OAuthError('unsupported_grant_type')

    def valid(self, token):
        try:
            with self.db() as db:
                row = db.execute("SELECT 1 FROM tokens t JOIN families f ON f.id=t.family WHERE t.hash=? AND t.kind='access' AND t.expires>? AND f.revoked=0", (digest(token), time.time())).fetchone()
                return bool(row)
        except (UnicodeError, ValueError): return False

    def revoke(self, token, client=None):
        with self.db() as db:
            row = db.execute('SELECT f.id,f.client FROM tokens t JOIN families f ON f.id=t.family WHERE t.hash=?', (digest(token),)).fetchone()
            if row and (client is None or row['client'] == client):
                db.execute('UPDATE families SET revoked=1 WHERE id=?', (row['id'],))

    def revoke_all(self):
        with self.db() as db:
            db.execute('UPDATE families SET revoked=1')


def load_config():
    import os
    with open(os.environ.get('MASTER_OAUTH_CONFIG', '/etc/nullink-master/oauth.json')) as f:
        return json.load(f)


def main():
    import argparse
    import os
    parser = argparse.ArgumentParser(description='Owner console for Nullink OAuth. Never share approval requests or credentials in AI chat.')
    parser.add_argument('action', choices=['pending', 'approve', 'deny', 'revoke-all'])
    parser.add_argument('request', nargs='?')
    args = parser.parse_args()
    if os.geteuid() != 0: parser.error('Owner approval requires the root VPS console')
    os.umask(0o077)
    store = Store(load_config())
    if args.action == 'pending': print(json.dumps(store.pending(), indent=2))
    elif args.action == 'revoke-all': store.revoke_all(); print('All OAuth grants revoked.')
    else:
        if not args.request: parser.error('request ID required')
        rows = [r for r in store.pending() if r['id'] == args.request]
        if not rows: parser.error('Pending request not found')
        print(json.dumps(rows[0], indent=2))
        if args.action == 'approve':
            print('This grants FULL ADMIN tools for the displayed client and redirect.')
            if input('Type APPROVE to authorize your own connection: ') != 'APPROVE':
                parser.error('Approval cancelled')
        store.decide(args.request, args.action == 'approve')
        print('Decision saved; return to your browser.')


if __name__ == '__main__': main()
