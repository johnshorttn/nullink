"""Shared server-side accounts, local labels, rules, audit and processing state."""
import hashlib, json, re, secrets, sqlite3, time
from pathlib import Path
from core import Drafts, FOLDERS
import rules
import cases

OWNER='local-owner'
MAILBOX='john@nullverse.cloud'

def principal(auth):
    # Existing Nullink human sessions authenticate its single owner. Never use a
    # caller header, cookie payload or browser storage to select a principal.
    subject=auth.get('user_id')
    return OWNER if subject is None else str(subject)

def permissions(actor, identities, grants=None):
    if actor==OWNER: return {'read':list(identities),'send':list(identities),'admin':True}
    grant=(grants or {}).get(actor,{})
    return {'read':[x for x in grant.get('read',[]) if x in identities],
            'send':[x for x in grant.get('send',[]) if x in identities],'admin':False}

def accounts(identities):
    return [{'id':a,'address':a,'provider':'local','kind':'mailbox' if a==MAILBOX else 'alias',
             'mailbox':MAILBOX,'capabilities':{'read':True,'send':True,'labels':'local-only'}} for a in dict.fromkeys(identities) if not a.startswith("gmail:")]

def routing(message, identities):
    if message.get('gmail_account'):
        account=message['gmail_account']
        return dict(message,accounts=[account] if account in identities else [],routing_recipients=[],routing_status='provider-account')
    original=message.get('envelope_recipient')
    recipients=[original] if original in identities else []
    # The physical mailbox includes all deliveries; virtual inboxes require a
    # trusted envelope identity. Visible To/Cc is never routing evidence.
    account_ids=([MAILBOX] if MAILBOX in identities else [])+([original] if original in identities and original!=MAILBOX else [])
    return dict(message,accounts=account_ids,routing_recipients=recipients,
                routing_status='trusted' if recipients else 'ambiguous')

def require_read(message,perm):
    if not set(message['accounts']).intersection(perm['read']): raise PermissionError('Mailbox read permission required')

def reply_identity(message,perm):
    recipients=[a for a in message['routing_recipients'] if a in perm['send']]
    if len(recipients)==1: return {'from':recipients[0],'fallback':False,'reason':'Trusted receiving identity'}
    fallback=MAILBOX if MAILBOX in perm['send'] else next(iter(perm['send']),None)
    return {'from':fallback,'fallback':True,'reason':'Receiving identity is ambiguous or not authorized. Review the visible From before sending.'}

class Workspace(Drafts):
    def __init__(self,path):
        self.path=str(path)
        with self.db() as db:
            db.executescript('''
CREATE TABLE IF NOT EXISTS preferences(actor TEXT PRIMARY KEY, selection TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS labels(id TEXT PRIMARY KEY, name TEXT NOT NULL, color TEXT NOT NULL, parent TEXT);
CREATE TABLE IF NOT EXISTS message_state(id TEXT PRIMARY KEY, labels TEXT NOT NULL DEFAULT '[]', priority TEXT NOT NULL DEFAULT 'normal');
CREATE TABLE IF NOT EXISTS rules(id TEXT PRIMARY KEY, data TEXT NOT NULL, version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS rule_versions(id TEXT NOT NULL, version INTEGER NOT NULL, data TEXT NOT NULL, actor TEXT NOT NULL, created REAL NOT NULL, PRIMARY KEY(id,version));
CREATE TABLE IF NOT EXISTS seen(id TEXT PRIMARY KEY, status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, message TEXT NOT NULL, actor TEXT NOT NULL, source TEXT NOT NULL, created REAL NOT NULL, status TEXT NOT NULL, details TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS send_requests(key TEXT PRIMARY KEY, draft TEXT NOT NULL, actor TEXT NOT NULL, identity TEXT NOT NULL, created REAL NOT NULL, result TEXT);
CREATE TABLE IF NOT EXISTS send_payloads(key TEXT PRIMARY KEY, hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS draft_owners(id TEXT PRIMARY KEY, actor TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
''')
            db.execute("INSERT OR IGNORE INTO meta VALUES ('schema','1')")
            cases.migrate(db)
    def selection(self,actor,allowed):
        with self.db() as db: row=db.execute('SELECT selection FROM preferences WHERE actor=?',(actor,)).fetchone()
        return [x for x in json.loads(row[0]) if x in allowed] if row else list(allowed)
    def select(self,actor,selected,allowed):
        if not isinstance(selected,list) or any(not isinstance(x,str) or x not in allowed for x in selected): raise ValueError('Unknown account selection')
        with self.db() as db: db.execute('INSERT OR REPLACE INTO preferences VALUES (?,?)',(actor,json.dumps(list(dict.fromkeys(selected)))))
        return selected
    def labels(self):
        with self.db() as db: return [dict(id=i,name=n,color=c,parent=p,semantics='local-only') for i,n,c,p in db.execute('SELECT * FROM labels ORDER BY name,id')]
    def label_save(self,data):
        key=data.get('id') or secrets.token_hex(12);name=data.get('name');color=data.get('color','#b2a2ff');parent=data.get('parent') or None
        if not isinstance(key,str) or not re.fullmatch('[a-f0-9]{24}',key): raise ValueError('Invalid label ID')
        if not isinstance(name,str) or not 1<=len(name.strip())<=80: raise ValueError('Label name required, maximum 80 characters')
        if not isinstance(color,str) or not re.fullmatch('#[a-fA-F0-9]{6}',color): raise ValueError('Use a hex color')
        known={l['id']:l for l in self.labels()};cursor=parent;depth=0
        while cursor:
            if cursor==key or cursor not in known or depth>=6: raise ValueError('Invalid parent, cycle or nesting beyond 6')
            cursor=known[cursor]['parent'];depth+=1
        with self.db() as db: db.execute('INSERT OR REPLACE INTO labels VALUES (?,?,?,?)',(key,name.strip(),color,parent))
        return key
    def label_delete(self,key):
        # Avoid invalidating persisted rules or losing child hierarchy.
        if any(l['parent']==key for l in self.labels()): raise ValueError('Move child labels first')
        if any(key in json.dumps(r) for r in self.rules()): raise ValueError('Remove label references from rules first')
        with self.db() as db:
            db.execute('DELETE FROM labels WHERE id=?',(key,))
            for mid,labels in db.execute('SELECT id,labels FROM message_state').fetchall():
                db.execute('UPDATE message_state SET labels=? WHERE id=?',(json.dumps([x for x in json.loads(labels) if x!=key]),mid))
    def enrich(self,message,identities):
        m=routing(message,identities)
        with self.db() as db: row=db.execute('SELECT labels,priority FROM message_state WHERE id=?',(m['id'],)).fetchone()
        m.update(labels=json.loads(row[0]) if row else [],priority=row[1] if row else 'normal')
        return m
    def set_state(self,key,labels,priority):
        with self.db() as db: db.execute('INSERT OR REPLACE INTO message_state VALUES (?,?,?)',(key,json.dumps(labels),priority))
    def rules(self):
        with self.db() as db: rows=db.execute('SELECT id,data,version FROM rules').fetchall()
        return sorted([dict(json.loads(data),id=i,version=v) for i,data,v in rows],key=lambda r:(r['priority'],r['id']))
    def case_ids(self):
        with self.db() as db:return [r[0] for r in db.execute('SELECT id FROM cases WHERE actor=?',(OWNER,))]
    def save_rule(self,data,actor,allowed):
        rules.validate_rule(data,allowed,[l['id'] for l in self.labels()],self.case_ids())
        key=data.get('id') or secrets.token_hex(12)
        if not isinstance(key,str) or not re.fullmatch('[a-f0-9]{24}',key): raise ValueError('Invalid rule ID')
        clean={k:v for k,v in data.items() if k not in ('id','version')}
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            old=db.execute('SELECT version FROM rules WHERE id=?',(key,)).fetchone()
            if old and data.get('version')!=old[0]: raise ValueError('Rule changed; reload before saving')
            version=old[0]+1 if old else 1;raw=json.dumps(clean)
            db.execute('INSERT OR REPLACE INTO rules VALUES (?,?,?)',(key,raw,version))
            db.execute('INSERT INTO rule_versions VALUES (?,?,?,?,?)',(key,version,raw,actor,time.time()))
        return dict(clean,id=key,version=version)
    def versions(self,key):
        with self.db() as db: return [dict(id=key,version=v,data=json.loads(d),actor=a,created=t) for v,d,a,t in db.execute('SELECT version,data,actor,created FROM rule_versions WHERE id=? ORDER BY version DESC LIMIT 100',(key,))]
    def initialize_baseline(self,mail):
        with self.db() as db:
            if db.execute("SELECT 1 FROM meta WHERE key='baseline'").fetchone(): return
            # Seed ALL existing folders, never mass-process historic real messages.
            for folder in FOLDERS:
                for p in mail.files(folder): db.execute('INSERT OR IGNORE INTO seen VALUES (?,?)',(mail.key(p),'historic'))
            db.execute("INSERT INTO meta VALUES ('baseline',?)",(str(time.time()),))
    def preview(self,mail,identities,ids,folder='inbox',candidate=None):
        if folder not in ('inbox','archive','trash'): raise ValueError('Preview supports inbox, archive and trash only')
        if not isinstance(ids,list) or not 1<=len(ids)<=50 or len(set(ids))!=len(ids): raise ValueError('Preview requires 1–50 unique message IDs')
        selected=self.rules() if candidate is None else [rules.validate_rule(candidate,identities,[l['id'] for l in self.labels()],self.case_ids())]
        if candidate is not None: selected=[dict(candidate,id=candidate.get('id','unsaved'))]
        case_service=cases.Cases(self,mail,identities,OWNER,permissions(OWNER,identities))
        destinations={}
        for rule in selected:
            for action in rule['actions']:
                if action['type']=='add_to_case':
                    destinations[action['value']]=case_service.accessible(action['value'])[0]['version']
        plans=[];snapshots=[]
        for key in ids:
            message=self.enrich(mail.message(folder,key),identities);message['folder']=folder
            message['case_ids']=[c['id'] for c in case_service.badges((mail.reference(key) if hasattr(mail,'reference') else cases.reference(key)))]
            snapshots.append(message)
            planned=rules.plan(selected,message);planned['identities']=list(identities)
            plans.append(planned)
        digest=hashlib.sha256(json.dumps({'rules':selected,'plans':plans,'snapshots':snapshots,'case_versions':destinations},sort_keys=True).encode()).hexdigest()
        return {'plans':plans,'digest':digest,'count':len(plans),'writes':0}
    def execute_plan(self,mail,plan,actor,source):
        key=plan['id'];run=secrets.token_hex(16)
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            if source=='new':
                if db.execute('SELECT 1 FROM seen WHERE id=?',(key,)).fetchone(): return False
                db.execute('INSERT INTO seen VALUES (?,?)',(key,'claimed'))
            # Claim precedes filesystem changes. Interruptions are logged for
            # explicit inspection; never automatically replay unknown outcomes.
            db.execute('INSERT INTO runs VALUES (?,?,?,?,?,?,?)',(run,key,actor,source,time.time(),'claimed',json.dumps({'actions':plan['actions'],'explanations':plan['explanations'],'warnings':plan['warnings']})))
        try:
            if plan['actions']:
                m=plan['result'];folder=plan['folder']
                kinds={a['type'] for a in plan['actions']}
                if kinds.intersection(('read','unread')):mail.flag(folder,key,not m['unread'])
                if m.get('folder',folder)!=folder:mail.move(folder,key,m['folder'])
                if kinds.intersection(('add_label','remove_label','priority')):self.set_state(key,m['labels'],m.get('priority','normal'))
                for action in plan['actions']:
                    if action['type']=='add_to_case':
                        identities=list(dict.fromkeys(m['accounts']+m.get('routing_recipients',[])))
                        # Current rule actor is the single owner; resolve every
                        # destination/member using the full configured allowlist.
                        identities=plan.get('identities',identities)
                        service=cases.Cases(self,mail,identities,OWNER,permissions(OWNER,identities))
                        service.membership({'id':action['value'],'message':(mail.reference(key) if hasattr(mail,'reference') else cases.reference(key)),'linked':True},audit_actor=actor,source='rule:'+action['rule_id'])
            status='completed'
        except Exception:
            status='interrupted'
            raise
        finally:
            with self.db() as db:
                db.execute('UPDATE runs SET status=? WHERE id=?',(status,run))
                if source=='new': db.execute('UPDATE seen SET status=? WHERE id=?',(status,key))
        return True
    def process_new(self,mail,identities):
        self.initialize_baseline(mail);count=0
        for row in mail.listing('inbox'):
            with self.db() as db: seen=db.execute('SELECT 1 FROM seen WHERE id=?',(row['id'],)).fetchone()
            if seen: continue
            preview=self.preview(mail,identities,[row['id']])
            self.execute_plan(mail,preview['plans'][0],'server-worker','new');count+=1
            if count>=50: break
        return count
    def history(self,offset=0):
        with self.db() as db: return [dict(id=i,message=m,actor=a,source=s,created=t,status=st,details=json.loads(d)) for i,m,a,s,t,st,d in db.execute('SELECT * FROM runs ORDER BY created DESC LIMIT 100 OFFSET ?',(offset,))]
    def own_draft(self,key,actor):
        with self.db() as db:
            row=db.execute('SELECT actor FROM draft_owners WHERE id=?',(key,)).fetchone()
        # Existing drafts are the original single owner's drafts.
        if (row[0] if row else OWNER)!=actor: raise PermissionError('Draft permission required')
    def register_draft(self,key,actor):
        with self.db() as db: db.execute('INSERT OR IGNORE INTO draft_owners VALUES (?,?)',(key,actor))
    def send_claim(self,key,draft,actor,session):
        if not isinstance(key,str) or not re.fullmatch('[A-Za-z0-9_-]{16,100}',key): raise ValueError('Idempotency key requires 16–100 safe characters')
        payload=hashlib.sha256(json.dumps({k:draft.get(k,'') for k in ('from','to','subject','body','in_reply_to')},sort_keys=True).encode()).hexdigest()
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT draft,actor,result FROM send_requests WHERE key=?',(key,)).fetchone()
            if row:
                if row[:2]!=(draft['id'],actor): raise ValueError('Idempotency key already used')
                stored=db.execute('SELECT hash FROM send_payloads WHERE key=?',(key,)).fetchone()
                if stored and stored[0]!=payload: raise ValueError('Idempotency key payload changed; explicit new submission required')
                return json.loads(row[2]) if row[2] else {'status':'submitting','message':'Submission already claimed; do not resend.'}
            if draft['status'] not in ('draft','paused','rejected'): raise ValueError('Already submitted; duplicate send blocked')
            db.execute('INSERT INTO send_payloads VALUES (?,?)',(key,payload))
            db.execute('INSERT INTO send_requests VALUES (?,?,?,?,?,NULL)',(key,draft['id'],actor+'',draft['from'],time.time()))
            db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',('send-session:'+key,session))
        return None
    def send_result(self,key,result):
        with self.db() as db: db.execute('UPDATE send_requests SET result=? WHERE key=?',(json.dumps(result),key))
    def sent(self,actor,offset=0):
        with self.db() as db: return [dict(request_id=k,draft=d,actor=a,identity=i,created=t,result=json.loads(r) if r else {'status':'submitting'}) for k,d,a,i,t,r in db.execute('SELECT * FROM send_requests WHERE actor=? ORDER BY created DESC LIMIT 100 OFFSET ?',(actor,offset))]
