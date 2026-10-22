"""Provider-agnostic write-back of Nullmail organisation (labels, Cases, folders, read state).

A ProviderAdapter translates neutral operations into one provider's API. Gmail is
implemented now; an Outlook adapter (categories + folders via Graph) can register later
with the same interface. Nothing here ever deletes provider labels or messages.
"""
import json, re, secrets, time

CASE_PREFIX = 'Cases/'
MAX_ATTEMPTS = 8

class ProviderAdapter:
    """Interface every provider implements."""
    provider = 'abstract'
    def enabled(self, account): raise NotImplementedError          # -> (bool, reason)
    def find_label(self, account, name): raise NotImplementedError # -> provider label id or None
    def create_label(self, account, name): raise NotImplementedError
    def modify(self, account, native, add_ids, remove_ids): raise NotImplementedError
    def case_label(self, title): return CASE_PREFIX + title        # Outlook: category name
    # Neutral folder/flag semantics -> provider label ids (system labels for Gmail).
    def folder_change(self, source, target): raise NotImplementedError
    def read_change(self, read): raise NotImplementedError

class GmailAdapter(ProviderAdapter):
    provider = 'gmail'
    def __init__(self, gmail): self.g = gmail
    def enabled(self, account):
        try: scopes = self.g.granted_scopes(account)
        except Exception: return False, 'Gmail credentials unavailable; reconnect'
        from gmail import missing_scopes
        if missing_scopes(scopes): return False, 'Reconnect Gmail to allow label sync'
        return True, 'Label sync enabled'
    def find_label(self, account, name):
        with self.g.state.db() as db:
            for lid, lname in db.execute('SELECT id,name FROM gmail_labels WHERE account=?', (account,)):
                if lname.casefold() == name.casefold(): return lid
        return None
    def create_label(self, account, name):
        actor = self.g.actor_of(account)
        result = self.g.post(actor, account, 'labels', {'name': name, 'labelListVisibility': 'labelShow', 'messageListVisibility': 'show'})
        lid = result.get('id')
        if not isinstance(lid, str) or not re.fullmatch('[A-Za-z0-9_-]{1,200}', lid): raise ValueError('Gmail did not return a label ID')
        with self.g.state.db() as db: db.execute('INSERT OR REPLACE INTO gmail_labels VALUES (?,?,?,?)', (account, lid, name, 'user'))
        return lid
    def modify(self, account, native, add_ids, remove_ids):
        actor = self.g.actor_of(account)
        result = self.g.post(actor, account, 'messages/' + native + '/modify', {'addLabelIds': add_ids, 'removeLabelIds': remove_ids})
        labels = result.get('labelIds')
        if isinstance(labels, list):
            with self.g.state.db() as db: db.execute('UPDATE gmail_messages SET labels=?,labels_checked=? WHERE account=? AND native=?', (json.dumps(labels), time.time(), account, native))
    def folder_change(self, source, target):
        add, remove = [], []
        if target == 'spam': add, remove = ['SPAM'], ['INBOX']
        elif source == 'spam' and target == 'inbox': add, remove = ['INBOX'], ['SPAM']
        elif target == 'archive': remove = ['INBOX']
        elif target == 'inbox' and source == 'archive': add = ['INBOX']
        # Trash is mirrored only for outbound (Sent) deletes, which the UI confirms first because
        # Gmail empties its Trash after 30 days. Inbox/Archive/Spam -> Trash stays local-only.
        elif target == 'trash' and source == 'sent': add = ['TRASH']
        if source == 'trash' and target != 'trash': remove = remove + ['TRASH']
        return add, remove
    def read_change(self, read): return ([], ['UNREAD']) if read else (['UNREAD'], [])

SCHEMA = '''CREATE TABLE IF NOT EXISTS provider_ops(id TEXT PRIMARY KEY, provider TEXT NOT NULL, account TEXT NOT NULL, native TEXT NOT NULL,
 add_names TEXT NOT NULL, remove_names TEXT NOT NULL, add_ids TEXT NOT NULL, remove_ids TEXT NOT NULL, status TEXT NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0, retry REAL NOT NULL DEFAULT 0, error TEXT, created REAL NOT NULL)'''

class ProviderSync:
    def __init__(self, state, adapters):
        self.state, self.adapters = state, adapters
        with state.db() as db: db.execute(SCHEMA)
    def adapter(self, provider): return self.adapters.get(provider)
    def status(self, provider, account):
        a = self.adapter(provider)
        enabled, reason = a.enabled(account) if a else (False, 'Provider not supported')
        with self.state.db() as db:
            counts = dict(db.execute('SELECT status,count(*) FROM provider_ops WHERE account=? GROUP BY status', (account,)).fetchall())
        return {'enabled': enabled, 'reason': reason, 'queue': counts}
    def missing(self, provider, account, names):
        a = self.adapter(provider)
        return [n for n in names if a.find_label(account, n) is None]
    def enqueue(self, provider, account, native, add_names=(), remove_names=(), add_ids=(), remove_ids=()):
        """Queue one change. Silently ignored (local-only) while the grant lacks write scope."""
        a = self.adapter(provider)
        if not a or not a.enabled(account)[0]: return None
        if not (add_names or remove_names or add_ids or remove_ids): return None
        key = secrets.token_hex(12)
        with self.state.db() as db:
            db.execute('INSERT INTO provider_ops VALUES (?,?,?,?,?,?,?,?,?,0,0,NULL,?)', (key, provider, account, native,
                json.dumps(list(add_names)), json.dumps(list(remove_names)), json.dumps(list(add_ids)), json.dumps(list(remove_ids)), 'pending', time.time()))
        return key
    def create_label(self, provider, account, name):
        a = self.adapter(provider)
        if not a.enabled(account)[0]: raise PermissionError('Reconnect Gmail to allow label sync')
        existing = a.find_label(account, name)
        if existing: return existing
        lid = a.create_label(account, name)
        with self.state.db() as db: db.execute("UPDATE provider_ops SET status='pending',retry=0 WHERE account=? AND status='needs_label'", (account,))
        return lid
    def process(self, limit=10, retry_exc=()):
        with self.state.db() as db:
            rows = db.execute("SELECT id,provider,account,native,add_names,remove_names,add_ids,remove_ids,attempts FROM provider_ops WHERE status='pending' AND retry<=? ORDER BY created LIMIT ?", (time.time(), limit)).fetchall()
        done = 0
        for key, provider, account, native, an, rn, ai, ri, attempts in rows:
            a = self.adapter(provider)
            if not a.enabled(account)[0]:
                with self.state.db() as db: db.execute("UPDATE provider_ops SET status='disabled',error=? WHERE id=?", ('Write scope not granted', key))
                continue
            add = json.loads(ai); remove = json.loads(ri); missing = []
            for n in json.loads(an):
                lid = a.find_label(account, n)
                if lid: add.append(lid)
                else: missing.append(n)
            if missing:
                with self.state.db() as db: db.execute("UPDATE provider_ops SET status='needs_label',error=? WHERE id=?", ('Label not in provider: ' + ', '.join(missing)[:150], key))
                continue
            remove += [lid for lid in (a.find_label(account, n) for n in json.loads(rn)) if lid]   # removing an absent label is a no-op
            try:
                if add or remove: a.modify(account, native, add, remove)
                with self.state.db() as db: db.execute("UPDATE provider_ops SET status='done',error=NULL WHERE id=?", (key,))
                done += 1
            except Exception as e:
                n = attempts + 1
                final = n >= MAX_ATTEMPTS and not isinstance(e, retry_exc)
                with self.state.db() as db: db.execute('UPDATE provider_ops SET status=?,attempts=?,retry=?,error=? WHERE id=?', ('failed' if final else 'pending', n, time.time() + min(3600, 30 * 2 ** min(n, 7)), str(e)[:180], key))
        with self.state.db() as db: db.execute("DELETE FROM provider_ops WHERE status='done' AND created<?", (time.time() - 7 * 86400,))
        return done
