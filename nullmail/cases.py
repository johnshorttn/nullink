"""Separate local Cases. Membership identifies a provider/store/message, never a folder or label.

Cases are private to their creator. Every read and mutation revalidates all current
member permissions, including notes/history. Fail closed on missing or inaccessible
members: free text may refer to any member, so filtering just a message count is unsafe.
"""
import hashlib, json, re, secrets, time
from core import FOLDERS

STATUSES=('Open','In progress','Waiting','Closed')
LOCAL_ACCOUNT='primary'

class Conflict(ValueError): pass

def migrate(db):
    db.executescript('''
CREATE TABLE IF NOT EXISTS cases (
 id TEXT PRIMARY KEY, number INTEGER NOT NULL, actor TEXT NOT NULL,
 title TEXT NOT NULL, description TEXT NOT NULL, status TEXT NOT NULL,
 created REAL NOT NULL, updated REAL NOT NULL, version INTEGER NOT NULL,
 UNIQUE(actor,number));
CREATE TABLE IF NOT EXISTS case_members (
 case_id TEXT NOT NULL, provider TEXT NOT NULL, account_id TEXT NOT NULL,
 message_id TEXT NOT NULL, linked REAL NOT NULL, actor TEXT NOT NULL,
 PRIMARY KEY(case_id,provider,account_id,message_id));
CREATE TABLE IF NOT EXISTS case_access_refs (
 case_id TEXT NOT NULL, provider TEXT NOT NULL, account_id TEXT NOT NULL,
 message_id TEXT NOT NULL, PRIMARY KEY(case_id,provider,account_id,message_id));
CREATE INDEX IF NOT EXISTS case_member_message ON case_members(provider,account_id,message_id);
CREATE TABLE IF NOT EXISTS case_notes (
 id TEXT PRIMARY KEY, case_id TEXT NOT NULL, actor TEXT NOT NULL,
 body TEXT NOT NULL, created REAL NOT NULL, request_id TEXT NOT NULL,
 UNIQUE(case_id,actor,request_id));
CREATE TABLE IF NOT EXISTS case_events (
 id TEXT PRIMARY KEY, case_id TEXT NOT NULL, actor TEXT NOT NULL,
 kind TEXT NOT NULL, data TEXT NOT NULL, created REAL NOT NULL);
CREATE INDEX IF NOT EXISTS case_events_case ON case_events(case_id,created);
CREATE TABLE IF NOT EXISTS case_requests (
 actor TEXT NOT NULL, request_id TEXT NOT NULL, case_id TEXT NOT NULL,
 fingerprint TEXT NOT NULL, PRIMARY KEY(actor,request_id));
''')
    db.execute('INSERT OR IGNORE INTO case_access_refs SELECT case_id,provider,account_id,message_id FROM case_members')
    db.execute("INSERT OR IGNORE INTO meta VALUES ('cases_schema','1')")

def identifier(value):
    if not isinstance(value,str) or not re.fullmatch('[a-f0-9]{24}',value): raise ValueError('Invalid case ID')
    return value

def request_id(value):
    if not isinstance(value,str) or not re.fullmatch('[A-Za-z0-9_-]{16,100}',value): raise ValueError('request_id requires 16–100 safe characters')
    return value

def text(value,name,limit,empty=False):
    if not isinstance(value,str) or len(value)>limit or '\x00' in value or (not empty and not value.strip()): raise ValueError(name+' is invalid or exceeds '+str(limit)+' characters')
    return value.strip()

def reference(message_id):
    return {'provider':'local','account_id':LOCAL_ACCOUNT,'id':message_id}

def validate_ref(ref):
    if not isinstance(ref,dict) or set(ref)!={'provider','account_id','id'}: raise ValueError('message requires provider, account_id and id')
    if not ((ref['provider']=='local' and ref['account_id']==LOCAL_ACCOUNT) or (ref['provider']=='gmail' and isinstance(ref['account_id'],str) and re.fullmatch('gmail:[a-f0-9]{32}',ref['account_id']))):raise ValueError('Provider/account is not available')
    if not isinstance(ref['id'],str) or not re.fullmatch('[a-f0-9]{64}',ref['id']): raise ValueError('Invalid message ID')
    return ref

def page(rows,offset,limit,key):
    return {key:rows[offset:offset+limit],'total':len(rows),'offset':offset,'next_offset':offset+limit if offset+limit<len(rows) else None}

class Cases:
    def __init__(self,store,mail,identities,actor,permissions):
        self.store,self.mail,self.identities,self.actor,self.permissions=store,mail,identities,actor,permissions
    def resolve(self,ref):
        from workspace import require_read
        validate_ref(ref)
        expected=self.mail.reference(ref['id']) if hasattr(self.mail,'reference') else reference(ref['id'])
        if expected!=ref:raise FileNotFoundError()
        found=[]
        for folder in FOLDERS:
            try:
                path=self.mail.locate(folder,ref['id'])
                m=self.store.enrich(self.mail.metadata(path,self.mail.read(path)),self.identities)
                require_read(m,self.permissions)
                # Return only account identifiers this actor may read.
                m['accounts']=[a for a in m['accounts'] if a in self.permissions['read']]
                m.update(folder=folder,message_ref=ref);found.append(m)
            except FileNotFoundError:continue
        if len(found)!=1:raise FileNotFoundError('Message unavailable or ambiguous')
        return found[0]
    def row(self,key):
        identifier(key)
        with self.store.db() as db:
            db.row_factory=__import__('sqlite3').Row
            row=db.execute('SELECT * FROM cases WHERE id=? AND actor=?',(key,self.actor)).fetchone()
        if not row:raise FileNotFoundError()
        return dict(row)
    def members(self,key):
        with self.store.db() as db:
            refs=[{'provider':p,'account_id':a,'id':i} for p,a,i in db.execute('SELECT provider,account_id,message_id FROM case_members WHERE case_id=?',(key,))]
        return [self.resolve(ref) for ref in refs]
    def accessible(self,key):
        row=self.row(key)
        try:
            with self.store.db() as db:
                guards=[{'provider':p,'account_id':a,'id':i} for p,a,i in db.execute('SELECT provider,account_id,message_id FROM case_access_refs WHERE case_id=?',(key,))]
            for ref in guards:self.resolve(ref)
            members=self.members(key)
        except (PermissionError,FileNotFoundError,ValueError):raise FileNotFoundError() from None
        # Even an empty case is unavailable to a principal with no mail rights.
        if not self.permissions['read']:raise FileNotFoundError()
        row['display_number']='CASE-'+str(row['number']).zfill(6)
        row['member_count']=len(members)
        return row,members
    def listing(self,query='',status='',offset=0,limit=50):
        if not isinstance(query,str) or len(query)>200:raise ValueError('Case search is limited to 200 characters')
        if status and status not in STATUSES:raise ValueError('Invalid case status')
        with self.store.db() as db:keys=[r[0] for r in db.execute('SELECT id FROM cases WHERE actor=? ORDER BY updated DESC,id',(self.actor,))]
        rows=[]
        for key in keys:
            try:row,_=self.accessible(key)
            except FileNotFoundError:continue
            if status and row['status']!=status:continue
            if query.casefold() not in (row['title']+' '+row['description']+' '+row['display_number']).casefold():continue
            rows.append(row)
        return page(rows,offset,limit,'cases')
    def detail(self,key,offset=0,limit=50):
        row,members=self.accessible(key)
        members.sort(key=lambda m:(m['timestamp'],m['id']))
        return {'case':row,**page(members,offset,limit,'members')}
    def badges(self,ref):
        self.resolve(ref)
        with self.store.db() as db:keys=[r[0] for r in db.execute('SELECT case_id FROM case_members WHERE provider=? AND account_id=? AND message_id=?',(ref['provider'],ref['account_id'],ref['id']))]
        rows=[]
        for key in keys:
            try:row,_=self.accessible(key)
            except FileNotFoundError:continue
            rows.append({k:row[k] for k in ('id','display_number','title','status')})
        return sorted(rows,key=lambda r:r['display_number'])
    def event(self,db,key,kind,data,actor=None):
        db.execute('INSERT INTO case_events VALUES (?,?,?,?,?,?)',(secrets.token_hex(12),key,actor or self.actor,kind,json.dumps(data),time.time()))
    def create(self,data):
        if set(data)-{'title','description','status','request_id','message'}:raise ValueError('Unknown case fields')
        if not self.permissions['read']:raise PermissionError('Mailbox read permission required')
        title=text(data.get('title'),'Title',120);description=text(data.get('description',''),'Description',4000,True)
        status=data.get('status','Open')
        if status not in STATUSES:raise ValueError('Invalid case status')
        req=request_id(data.get('request_id'));ref=data.get('message')
        if ref is not None:self.resolve(ref)
        digest=hashlib.sha256(json.dumps({'title':title,'description':description,'status':status,'message':ref},sort_keys=True).encode()).hexdigest()
        with self.store.db() as db:
            db.execute('BEGIN IMMEDIATE')
            old=db.execute('SELECT case_id,fingerprint FROM case_requests WHERE actor=? AND request_id=?',(self.actor,req)).fetchone()
            if old:
                if old[1]!=digest:raise Conflict('Case request ID was reused with different content')
                key=old[0]
            else:
                count,number=db.execute('SELECT count(*),coalesce(max(number),0)+1 FROM cases WHERE actor=?',(self.actor,)).fetchone()
                if count>=2000:raise ValueError('Case limit reached (2000 per principal)')
                key=secrets.token_hex(12);now=time.time()
                db.execute('INSERT INTO cases VALUES (?,?,?,?,?,?,?,?,?)',(key,number,self.actor,title,description,status,now,now,1))
                self.event(db,key,'created',{'title':title,'status':status})
                if ref is not None:self._link(db,key,ref,True)
                db.execute('INSERT INTO case_requests VALUES (?,?,?,?)',(self.actor,req,key,digest))
        return self.detail(key)
    def save(self,data):
        if set(data)!={'id','version','title','description','status'}:raise ValueError('Case update requires id, version, title, description and status')
        old,_=self.accessible(data['id']);title=text(data['title'],'Title',120);description=text(data['description'],'Description',4000,True)
        if data['status'] not in STATUSES:raise ValueError('Invalid case status')
        if type(data['version']) is not int:raise ValueError('Integer case version required')
        with self.store.db() as db:
            changed=db.execute('UPDATE cases SET title=?,description=?,status=?,updated=?,version=version+1 WHERE id=? AND version=?',(title,description,data['status'],time.time(),data['id'],data['version'])).rowcount
            if changed!=1:raise Conflict('Case changed; reload before editing')
            changes={k:{'before':old[k],'after':v} for k,v in [('title',title),('description',description),('status',data['status'])] if old[k]!=v}
            self.event(db,data['id'],'updated',changes)
        return self.detail(data['id'])
    def _link(self,db,key,ref,linked,actor=None,source='manual'):
        values=(key,ref['provider'],ref['account_id'],ref['id'])
        exists=db.execute('SELECT 1 FROM case_members WHERE case_id=? AND provider=? AND account_id=? AND message_id=?',values).fetchone()
        if bool(exists)==linked:return False
        if linked:
            if db.execute('SELECT count(*) FROM case_members WHERE case_id=?',(key,)).fetchone()[0]>=500:raise ValueError('Case membership limit is 500')
            if db.execute('SELECT count(*) FROM case_members WHERE provider=? AND account_id=? AND message_id=?',values[1:]).fetchone()[0]>=20:raise ValueError('Message case limit is 20')
            db.execute('INSERT OR IGNORE INTO case_access_refs VALUES (?,?,?,?)',values)
            db.execute('INSERT INTO case_members VALUES (?,?,?,?,?,?)',(*values,time.time(),actor or self.actor))
        else:db.execute('DELETE FROM case_members WHERE case_id=? AND provider=? AND account_id=? AND message_id=?',values)
        db.execute('UPDATE cases SET updated=?,version=version+1 WHERE id=?',(time.time(),key))
        self.event(db,key,'linked' if linked else 'unlinked',{'message':ref,'source':source},actor)
        return True
    def membership(self,data,audit_actor=None,source='manual'):
        if set(data)!={'id','message','linked'} or type(data.get('linked')) is not bool:raise ValueError('Membership requires id, message and boolean linked')
        self.accessible(data['id']);self.resolve(data['message'])
        with self.store.db() as db:
            db.execute('BEGIN IMMEDIATE');changed=self._link(db,data['id'],data['message'],data['linked'],audit_actor,source)
        return {'ok':True,'changed':changed,'case':self.accessible(data['id'])[0]}
    def notes(self,key,offset=0,limit=50):
        self.accessible(key)
        with self.store.db() as db:
            count=db.execute('SELECT count(*) FROM case_notes WHERE case_id=?',(key,)).fetchone()[0]
            rows=[dict(id=i,actor=a,body=b,created=t) for i,a,b,t in db.execute('SELECT id,actor,body,created FROM case_notes WHERE case_id=? ORDER BY created,id LIMIT ? OFFSET ?',(key,limit,offset))]
        return {'notes':rows,'total':count,'offset':offset,'next_offset':offset+limit if offset+limit<count else None}
    def add_note(self,data):
        if set(data)!={'id','body','request_id'}:raise ValueError('Note requires id, body and request_id')
        self.accessible(data['id']);body=text(data['body'],'Note',4000);req=request_id(data['request_id'])
        with self.store.db() as db:
            db.execute('BEGIN IMMEDIATE')
            old=db.execute('SELECT id,body FROM case_notes WHERE case_id=? AND actor=? AND request_id=?',(data['id'],self.actor,req)).fetchone()
            if old:
                if old[1]!=body:raise Conflict('Note request ID was reused with different content')
                return {'id':old[0],'duplicate':True}
            if db.execute('SELECT count(*) FROM case_notes WHERE case_id=?',(data['id'],)).fetchone()[0]>=1000:raise ValueError('Note limit is 1000 per case')
            key=secrets.token_hex(12)
            db.execute('INSERT INTO case_notes VALUES (?,?,?,?,?,?)',(key,data['id'],self.actor,body,time.time(),req))
            db.execute('UPDATE cases SET updated=?,version=version+1 WHERE id=?',(time.time(),data['id']))
            self.event(db,data['id'],'note_added',{'note_id':key})
        return {'id':key,'duplicate':False}
    def history(self,key,offset=0,limit=50):
        self.accessible(key)
        with self.store.db() as db:
            total=db.execute('SELECT count(*) FROM case_events WHERE case_id=?',(key,)).fetchone()[0]
            rows=[dict(id=i,actor=a,kind=k,data=json.loads(d),created=t) for i,a,k,d,t in db.execute('SELECT id,actor,kind,data,created FROM case_events WHERE case_id=? ORDER BY created DESC,id LIMIT ? OFFSET ?',(key,limit,offset))]
        return {'events':rows,'total':total,'offset':offset,'next_offset':offset+limit if offset+limit<total else None}
