"""Server-held Google OAuth and bounded Gmail cache. HTTP is injectable in tests.

Google is read-only except explicit send. Folders/read flags/labels/Cases are local.
No credentials are returned through the API. No automatic retry of sends.
"""
import base64, hashlib, json, os, re, secrets, time, stat, shutil
import email.message, email.policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError
from cryptography.fernet import Fernet, InvalidToken
from core import MailStore, MAX_MAIL, FOLDERS, SPAM_DAYS, addresses

READ='https://www.googleapis.com/auth/gmail.readonly'
SEND='https://www.googleapis.com/auth/gmail.send'
MODIFY='https://www.googleapis.com/auth/gmail.modify'
LABELS='https://www.googleapis.com/auth/gmail.labels'
FULL='https://mail.google.com/'
COMPOSE='https://www.googleapis.com/auth/gmail.compose'
SETTINGS_BASIC='https://www.googleapis.com/auth/gmail.settings.basic'
SETTINGS_SHARING='https://www.googleapis.com/auth/gmail.settings.sharing'
REQUESTED=[FULL,MODIFY,LABELS,COMPOSE,SETTINGS_BASIC,SETTINGS_SHARING]
SCOPE='openid email '+' '.join(REQUESTED)
def can_read(scopes):return bool({READ,MODIFY,FULL}&scopes)
def can_send(scopes):return bool({SEND,COMPOSE,MODIFY,FULL}&scopes)
def missing_scopes(scopes):return [s for s in REQUESTED if s not in scopes]
CONFIG=Path('/etc/nullmail/google-oauth.json')
KEY=Path('/etc/nullmail/google-token.key')
class ProviderError(ValueError): pass
class FullSyncRequired(ProviderError): pass
class RetryLater(ProviderError): pass
class MessageGone(ProviderError): pass
class TooLarge(ProviderError): pass
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise ProviderError('Google redirect rejected')

def request_json(url,data=None,token=None,limit=4*1024*1024):
    parts=urlsplit(url)
    if parts.scheme!='https' or parts.netloc not in ('oauth2.googleapis.com','gmail.googleapis.com','openidconnect.googleapis.com'):raise ProviderError('Unapproved provider endpoint')
    headers={'Accept':'application/json'}
    if token:headers['Authorization']='Bearer '+token
    raw=None
    if data is not None:
        is_send=parts.path.endswith(('/messages/send','/modify','/me/labels'))
        headers['Content-Type']='application/json' if is_send else 'application/x-www-form-urlencoded'
        raw=(json.dumps(data) if is_send else urlencode(data)).encode()
    try:
        with build_opener(NoRedirect).open(Request(url,data=raw,headers=headers),timeout=20) as response:
            raw=response.read(limit+1)
            if len(raw)>limit:raise TooLarge('Provider response exceeds limit')
            return json.loads(raw)
    except HTTPError as e:
        if e.code==404 and '/history?' in url:raise FullSyncRequired('History expired; explicit reimport required') from None
        if e.code==404 and '/messages/' in url:raise MessageGone('Google message no longer available') from None
        if e.code==429 or e.code>=500:raise RetryLater('Google temporarily unavailable; sync backed off') from None
        raise ProviderError('Google request rejected (HTTP '+str(e.code)+'); reconnect if authorization expired') from None
    except (OSError,ValueError) as e:
        if isinstance(e,ProviderError):raise
        raise RetryLater('Google unavailable; sync backed off') from None

MAX_FULL=8*1024*1024            # format=full JSON (MIME tree + inline bodies)
MAX_PART=40*1024*1024           # one attachments.get JSON response (25 MB Gmail max + base64 overhead)
MAX_LARGE=60*1024*1024          # total decoded attachment bytes per message
CHUNK=256*1024
CATEGORY_NAMES={'CATEGORY_PERSONAL':'Primary','CATEGORY_SOCIAL':'Social','CATEGORY_PROMOTIONS':'Promotions','CATEGORY_UPDATES':'Updates','CATEGORY_FORUMS':'Forums'}
RECENT_QUERY='newer_than:30d'
OLDER_QUERY='older_than:30d'

def request_stream(url,token,dest,limit):
    """GET JSON to a file in bounded chunks; same host allowlist and no redirects."""
    parts=urlsplit(url)
    if parts.scheme!='https' or parts.netloc!='gmail.googleapis.com':raise ProviderError('Unapproved provider endpoint')
    total=0
    try:
        with build_opener(NoRedirect).open(Request(url,headers={'Accept':'application/json','Authorization':'Bearer '+token}),timeout=120) as response, open(dest,'wb') as out:
            while True:
                chunk=response.read(CHUNK)
                if not chunk:break
                total+=len(chunk)
                if total>limit:raise TooLarge('Gmail attachment response exceeds limit')
                out.write(chunk)
    except HTTPError as e:
        if e.code==404:raise MessageGone('Google attachment no longer available') from None
        if e.code==429 or e.code>=500:raise RetryLater('Google temporarily unavailable; sync backed off') from None
        raise ProviderError('Google request rejected (HTTP '+str(e.code)+')') from None
    except (OSError,ValueError) as e:
        if isinstance(e,ProviderError):raise
        raise RetryLater('Google unavailable; sync backed off') from None

def decode_attachment_json(src,dest,limit=MAX_LARGE):
    """Stream-decode the base64url "data" string of an attachments.get JSON file into dest."""
    with open(src,'rb') as f, open(dest,'wb') as out:
        buf=b'';pos=-1
        while pos<0:
            chunk=f.read(CHUNK)
            if not chunk:raise ProviderError('Gmail attachment missing data')
            buf+=chunk;m=re.search(rb'"data"\s*:\s*"',buf)
            if m:pos=m.end()
            elif len(buf)>65536:buf=buf[-64:]
        rest=buf[pos:];total=0;done=False
        while True:
            end=rest.find(b'"')
            if end>=0:rest,done=rest[:end],True
            rest=re.sub(rb'\\.|\s','',rest) if (b'\\' in rest or b'\n' in rest) else rest
            cut=len(rest) if done else len(rest)-len(rest)%4
            piece,rest=rest[:cut],rest[cut:]
            if piece:
                data=base64.b64decode(piece+b'='*(-len(piece)%4),altchars=b'-_')
                total+=len(data)
                if total>limit:raise TooLarge('Gmail message exceeds large-message limit')
                out.write(data)
            if done:break
            chunk=f.read(CHUNK)
            if not chunk:raise ProviderError('Truncated Gmail attachment')
            rest+=chunk
    return total

def clean(value):return re.sub(r'[\r\n]+',' ',str(value))[:20000]

def restricted(path):
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o137:raise ProviderError('Google configuration must be root-owned, regular and mode 0640 or stricter')
    return path.read_bytes()

class Gmail:
    def __init__(self,state,config=None,http=request_json,key=None,cache=None):
        self.state,self.http=state,http;self.stream=request_stream
        self.config={};self.cipher=None;self.problem=None
        try:
            self.config=json.loads(restricted(CONFIG)) if config is None and CONFIG.exists() else (config or {})
            if not isinstance(self.config,dict):raise ValueError('Invalid config')
            secret=key if key is not None else (restricted(KEY).strip() if KEY.exists() else None)
            if secret:self.cipher=Fernet(secret)
        except (OSError,ValueError) as e:self.config={};self.problem='Google configuration/key permissions or format are invalid'
        self.cache=MailStore(cache or Path(state.path).parent/'gmail-cache')
        with state.db() as db:
            db.executescript('''
CREATE TABLE IF NOT EXISTS google_states(state TEXT PRIMARY KEY, actor TEXT NOT NULL, session TEXT NOT NULL, verifier TEXT NOT NULL, redirect TEXT NOT NULL, expires REAL NOT NULL);
CREATE TABLE IF NOT EXISTS gmail_accounts(id TEXT PRIMARY KEY,actor TEXT NOT NULL,subject TEXT NOT NULL,address TEXT NOT NULL,token TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'connected',history TEXT,page TEXT,phase TEXT NOT NULL DEFAULT 'idle',retry REAL NOT NULL DEFAULT 0,failures INTEGER NOT NULL DEFAULT 0,error TEXT,updated REAL NOT NULL, UNIQUE(actor,subject));
CREATE TABLE IF NOT EXISTS gmail_skipped(account TEXT NOT NULL,native TEXT NOT NULL,reason TEXT NOT NULL,PRIMARY KEY(account,native));
CREATE TABLE IF NOT EXISTS gmail_messages(id TEXT PRIMARY KEY,account TEXT NOT NULL,native TEXT NOT NULL,thread TEXT,labels TEXT NOT NULL,deleted INTEGER NOT NULL DEFAULT 0, UNIQUE(account,native));
''')
            cols=[r[1] for r in db.execute('PRAGMA table_info(gmail_accounts)')]
            if 'backfill_paused' not in cols:db.execute('ALTER TABLE gmail_accounts ADD COLUMN backfill_paused INTEGER NOT NULL DEFAULT 1')
            if 'stage' not in cols:
                db.execute('ALTER TABLE gmail_accounts ADD COLUMN stage TEXT')
                # Migrate an in-flight unfiltered import to recent-first ordering (dedupe makes this safe).
                db.execute("UPDATE gmail_accounts SET stage='recent',page=NULL WHERE phase='import'")
            scols=[r[1] for r in db.execute('PRAGMA table_info(gmail_skipped)')]
            if 'attempts' not in scols:db.execute('ALTER TABLE gmail_skipped ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0')
            if 'retry' not in scols:db.execute('ALTER TABLE gmail_skipped ADD COLUMN retry REAL NOT NULL DEFAULT 0')
            db.execute("UPDATE gmail_skipped SET retry=0 WHERE reason LIKE '%2 MiB reader limit%'")
            db.execute('CREATE TABLE IF NOT EXISTS gmail_purged(account TEXT NOT NULL,native TEXT NOT NULL,purged REAL NOT NULL,PRIMARY KEY(account,native))')
            db.execute('CREATE TABLE IF NOT EXISTS gmail_meta(k TEXT PRIMARY KEY,v TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS gmail_labels(account TEXT NOT NULL,id TEXT NOT NULL,name TEXT NOT NULL,type TEXT NOT NULL,PRIMARY KEY(account,id))')
            db.execute('CREATE TABLE IF NOT EXISTS gmail_label_maps(account TEXT NOT NULL,provider_label TEXT NOT NULL,label TEXT NOT NULL,created REAL NOT NULL,PRIMARY KEY(account,provider_label,label))')
            mcols=[r[1] for r in db.execute('PRAGMA table_info(gmail_messages)')]
            if 'labels_checked' not in mcols:db.execute('ALTER TABLE gmail_messages ADD COLUMN labels_checked REAL NOT NULL DEFAULT 0')
        self.migrate_spam()
        from provider_sync import ProviderSync, GmailAdapter
        self.sync=ProviderSync(state,{'gmail':GmailAdapter(self)})
    def blockers(self):
        result=[]
        if self.problem:result.append(self.problem)
        if not (self.config.get('client_id') and self.config.get('client_secret') and self.config.get('redirect_uris')):result.append('Missing /etc/nullmail/google-oauth.json with Google web client ID, secret and exact HTTPS redirect_uris')
        if not self.cipher:result.append('Missing restricted /etc/nullmail/google-token.key (Fernet key)')
        if self.config.get('egress_ready') is not True:result.append('Google HTTPS egress is not enabled: retain service isolation and configure an administrator-reviewed allowlisted HTTPS proxy before setting egress_ready')
        return result
    def ready(self):
        if self.blockers():raise ProviderError('; '.join(self.blockers()))
    def accounts(self,actor=None):
        with self.state.db() as db:
            db.row_factory=__import__('sqlite3').Row
            rows=db.execute('SELECT id,actor,address,status,phase,stage,backfill_paused,retry,error,updated,(SELECT COUNT(*) FROM gmail_skipped WHERE account=gmail_accounts.id) AS skipped,(SELECT COUNT(*) FROM gmail_messages WHERE account=gmail_accounts.id) AS imported FROM gmail_accounts'+(' WHERE actor=?' if actor is not None else ''),(actor,) if actor is not None else ()).fetchall()
        return [dict(r) for r in rows]
    def account(self,actor,key):
        with self.state.db() as db:
            db.row_factory=__import__('sqlite3').Row
            row=db.execute('SELECT * FROM gmail_accounts WHERE id=? AND actor=?',(key,actor)).fetchone()
        if not row:raise PermissionError('Gmail account permission required')
        return dict(row)
    def begin(self,actor,session,redirect):
        self.ready()
        if redirect not in self.config['redirect_uris'] or not redirect.startswith('https://'):raise ProviderError('Redirect URI not registered')
        nonce=secrets.token_urlsafe(32);verifier=secrets.token_urlsafe(48)
        challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
        with self.state.db() as db:
            db.execute('DELETE FROM google_states WHERE expires<?',(time.time(),))
            db.execute('INSERT INTO google_states VALUES (?,?,?,?,?,?)',(hashlib.sha256(nonce.encode()).hexdigest(),actor,hashlib.sha256(session.encode()).hexdigest(),verifier,redirect,time.time()+600))
        return 'https://accounts.google.com/o/oauth2/v2/auth?'+urlencode({'client_id':self.config['client_id'],'redirect_uri':redirect,'response_type':'code','scope':SCOPE,'access_type':'offline','prompt':'consent','state':nonce,'code_challenge':challenge,'code_challenge_method':'S256'})
    def complete(self,actor,session,nonce,code,local_identities=()):
        self.ready()
        if not isinstance(nonce,str) or len(nonce)>200 or not isinstance(code,str) or not 1<=len(code)<=4096:raise ProviderError('Invalid authorization callback')
        with self.state.db() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT actor,session,verifier,redirect,expires FROM google_states WHERE state=?',(hashlib.sha256(nonce.encode()).hexdigest(),)).fetchone()
            if not row or row[0]!=actor or row[1]!=hashlib.sha256(session.encode()).hexdigest() or row[4]<time.time():raise ProviderError('OAuth state expired or session mismatch')
            db.execute('DELETE FROM google_states WHERE state=?',(hashlib.sha256(nonce.encode()).hexdigest(),))
        data=self.http('https://oauth2.googleapis.com/token',{'client_id':self.config['client_id'],'client_secret':self.config['client_secret'],'code':code,'code_verifier':row[2],'redirect_uri':row[3],'grant_type':'authorization_code'})
        if not (can_read(set(data.get('scope','').split())) and can_send(set(data.get('scope','').split()))) or not data.get('access_token') or not data.get('refresh_token'):raise ProviderError('Offline Gmail read and send consent required; reconnect')
        user=self.http('https://openidconnect.googleapis.com/v1/userinfo',token=data['access_token'])
        profile=self.http('https://gmail.googleapis.com/gmail/v1/users/me/profile',token=data['access_token'])
        address=user.get('email','').lower();subject=user.get('sub','')
        if user.get('email_verified') is not True or not isinstance(subject,str) or not 1<=len(subject)<=255 or address!=profile.get('emailAddress','').lower():raise ProviderError('Google account identity could not be verified')
        addresses(address)
        if address in local_identities:raise ProviderError('This address is already a local sending identity; ambiguous transport is not supported')
        key='gmail:'+hashlib.sha256((actor+'\0'+subject).encode()).hexdigest()[:32]
        data['expires_at']=time.time()+min(86400,int(data.get('expires_in',3600)))
        encrypted=self.cipher.encrypt(json.dumps(data).encode()).decode()
        with self.state.db() as db:
            db.execute("INSERT INTO gmail_accounts(id,actor,subject,address,token,updated) VALUES (?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET address=excluded.address,token=excluded.token,status='connected',retry=0,error=NULL,updated=excluded.updated",(key,actor,subject,address,encrypted,time.time()))
        return {'authorized':True,'account_id':key,'import_required':True}
    def access_token(self,actor,key):
        self.ready();account=self.account(actor,key)
        try:data=json.loads(self.cipher.decrypt(account['token'].encode()))
        except (InvalidToken,ValueError):raise ProviderError('Stored Google credentials cannot be decrypted; reconnect') from None
        if data.get('expires_at',0)<time.time()+60:
            refreshed=self.http('https://oauth2.googleapis.com/token',{'client_id':self.config['client_id'],'client_secret':self.config['client_secret'],'refresh_token':data['refresh_token'],'grant_type':'refresh_token'})
            if not refreshed.get('access_token'):raise ProviderError('Refresh failed; reconnect Gmail')
            if 'scope' in refreshed and not (can_read(set(refreshed['scope'].split())) and can_send(set(refreshed['scope'].split()))):raise ProviderError('Google permissions were reduced; reconnect')
            data.update(refreshed);data['expires_at']=time.time()+min(86400,int(refreshed.get('expires_in',3600)))
            with self.state.db() as db:db.execute('UPDATE gmail_accounts SET token=? WHERE id=?',(self.cipher.encrypt(json.dumps(data).encode()).decode(),key))
        return data['access_token']
    def get(self,actor,key,path,params=None):
        return self.http('https://gmail.googleapis.com/gmail/v1/users/me/'+path+('?' +urlencode(params) if params else ''),token=self.access_token(actor,key))
    def start_import(self,actor,key,confirm):
        self.account(actor,key)
        if confirm is not True:raise ValueError('Explicit import confirmation required; imported history never runs rules automatically')
        profile=self.get(actor,key,'profile');history=str(profile.get('historyId',''))
        if not history.isdigit():raise ProviderError('Google history checkpoint missing')
        with self.state.db() as db:db.execute("UPDATE gmail_accounts SET phase='import',stage='recent',history=?,page=NULL,status='connected',retry=0,error=NULL WHERE id=?",(history,key))
        return {'status':'import','stage':'recent','page_size':20,'historical_rules':False}
    def reference(self,key):
        with self.state.db() as db:row=db.execute('SELECT account FROM gmail_messages WHERE id=?',(key,)).fetchone()
        return {'provider':'gmail','account_id':row[0],'id':key} if row else None
    def ingest(self,actor,account,native,historic):
        if not isinstance(native,str) or not re.fullmatch('[A-Za-z0-9_-]{1,100}',native):raise ProviderError('Invalid Google message ID')
        name='gmail-'+account.split(':')[1]+'-'+native;key=hashlib.sha256(name.encode()).hexdigest()
        if self.purged(account,native):return None
        meta=self.get(actor,account,'messages/'+native,{'format':'minimal'})
        with self.state.db() as db:known=db.execute('SELECT 1 FROM gmail_messages WHERE id=?',(key,)).fetchone()
        if known:
            self.update_labels(account,key,meta.get('labelIds',[]))
            with self.state.db() as db:db.execute('DELETE FROM gmail_skipped WHERE account=? AND native=?',(account,native))
            return key
        size=meta.get('sizeEstimate',0)
        raw=None
        if isinstance(size,int) and size<=MAX_MAIL:
            try:
                result=self.get(actor,account,'messages/'+native,{'format':'raw'})
                encoded=result.get('raw','')
                if isinstance(encoded,str) and len(encoded)<=2800000:
                    try:raw=base64.b64decode(encoded+'='*(-len(encoded)%4),altchars=b'-_',validate=True)
                    except ValueError:raise ProviderError('Invalid Gmail encoding') from None
                    if len(raw)>MAX_MAIL:raw=None
            except TooLarge:raw=None
        if raw is None:result,raw=self.segmented(actor,account,native,key)
        labels=result.get('labelIds',[])
        if not isinstance(labels,list) or len(labels)>1000 or any(not isinstance(x,str) or len(x)>200 for x in labels):raise ProviderError('Invalid Gmail labels')
        with self.state.db() as db:
            exists=db.execute('SELECT 1 FROM gmail_messages WHERE id=?',(key,)).fetchone()
            if not exists:
                folder='trash' if 'TRASH' in labels else 'spam' if 'SPAM' in labels else 'inbox' if 'INBOX' in labels else 'sent' if 'SENT' in labels else 'archive'
                dest=self.cache.root/FOLDERS[folder]/'cur'/(name+':2,'+('' if 'UNREAD' in labels else 'S'))
                temp=self.cache.root/'tmp'/secrets.token_hex(16)
                temp.write_bytes(raw);os.chmod(temp,0o600)
                stamp=min(time.time(),max(0,int(result.get('internalDate',str(int(time.time()*1000))))/1000))
                os.utime(temp,(stamp,stamp));os.replace(temp,dest)
            db.execute('INSERT INTO gmail_messages(id,account,native,thread,labels,deleted,labels_checked) VALUES (?,?,?,?,?,0,?) ON CONFLICT(id) DO UPDATE SET labels=excluded.labels,deleted=0,labels_checked=excluded.labels_checked',(key,account,native,str(result.get('threadId',''))[:100],json.dumps(labels),time.time()))
            db.execute('DELETE FROM gmail_skipped WHERE account=? AND native=?',(account,native))
            if historic:db.execute("INSERT OR IGNORE INTO seen VALUES (?,'gmail-historical')",(key,))
        self.apply_maps(account,key,labels)
        return key
    # ---- Gmail provider labels (read-only toward Google; separate from Nullmail labels) ----
    def update_labels(self,account,key,labels):
        if not isinstance(labels,list) or len(labels)>1000 or any(not isinstance(x,str) or len(x)>200 for x in labels):raise ProviderError('Invalid Gmail labels')
        with self.state.db() as db:db.execute('UPDATE gmail_messages SET labels=?,labels_checked=? WHERE id=?',(json.dumps(labels),time.time(),key))
        self.apply_maps(account,key,labels)
    def refresh_labels(self,actor,key,force=False,every=6*3600):
        with self.state.db() as db:row=db.execute('SELECT v FROM gmail_meta WHERE k=?',('labels:'+key,)).fetchone()
        if not force and row and float(row[0])>time.time()-every:return False
        result=self.get(actor,key,'labels')
        items=result.get('labels',[])
        if not isinstance(items,list) or len(items)>10000:raise ProviderError('Invalid Gmail label list')
        with self.state.db() as db:
            db.execute('DELETE FROM gmail_labels WHERE account=?',(key,))
            for l in items:
                if not isinstance(l,dict) or not isinstance(l.get('id'),str) or len(l['id'])>200:continue
                db.execute('INSERT OR REPLACE INTO gmail_labels VALUES (?,?,?,?)',(key,l['id'],clean(l.get('name',l['id']))[:300],'system' if l.get('type')=='system' else 'user'))
            db.execute('INSERT OR REPLACE INTO gmail_meta VALUES (?,?)',('labels:'+key,str(time.time())))
        return True
    def label_backfill(self,actor,key,limit=20):
        """Fetch labelIds (format=minimal, no body) for messages imported before label tracking."""
        with self.state.db() as db:rows=db.execute('SELECT id,native FROM gmail_messages WHERE account=? AND labels_checked=0 LIMIT ?',(key,limit)).fetchall()
        for mid,native in rows:
            try:self.update_labels(key,mid,self.get(actor,key,'messages/'+native,{'format':'minimal'}).get('labelIds',[]))
            except MessageGone:
                with self.state.db() as db:db.execute('UPDATE gmail_messages SET labels_checked=? WHERE id=?',(time.time(),mid))
        return len(rows)
    def label_names(self,account):
        with self.state.db() as db:return {i:(n,t) for i,n,t in db.execute('SELECT id,name,type FROM gmail_labels WHERE account=?',(account,))}
    @staticmethod
    def label_kind(lid,ltype):
        return 'category' if lid.startswith('CATEGORY_') else 'system' if ltype=='system' or lid.isupper() else 'user'
    def describe(self,account,ids,names=None):
        names=self.label_names(account) if names is None else names
        out=[]
        for lid in ids:
            name,ltype=names.get(lid,(CATEGORY_NAMES.get(lid,lid.title() if lid.isupper() else lid),'system' if lid.isupper() else 'user'))
            if lid in CATEGORY_NAMES:name=CATEGORY_NAMES[lid]
            out.append({'id':lid,'name':name,'kind':self.label_kind(lid,ltype),'provider':'gmail'})
        return out
    def label_catalog(self,actor):
        result=[]
        for a in self.accounts(actor):
            names=self.label_names(a['id']);counts={};unread={}
            with self.state.db() as db:rows=db.execute('SELECT labels FROM gmail_messages WHERE account=? AND deleted=0',(a['id'],)).fetchall()
            for (raw,) in rows:
                ls=json.loads(raw)
                for l in ls:
                    counts[l]=counts.get(l,0)+1
                    if 'UNREAD' in ls:unread[l]=unread.get(l,0)+1
            views={'inbox_unread':0,'archived':0,'archived_unread':0,'all_unread':0}
            for (raw,) in rows:
                ls=set(json.loads(raw))
                if ls&{'SPAM','TRASH'}:continue
                u='UNREAD' in ls
                if u:views['all_unread']+=1
                if u and 'INBOX' in ls:views['inbox_unread']+=1
                if 'INBOX' not in ls and 'SENT' not in ls:views['archived']+=1;views['archived_unread']+=u
            labels=[]
            for lid in sorted(set(names)|set(counts)):
                d=self.describe(a['id'],[lid],names)[0];d.update(count=counts.get(lid,0),unread=unread.get(lid,0));labels.append(d)
            with self.state.db() as db:maps=[dict(provider_label=p,label=l) for p,l in db.execute('SELECT provider_label,label FROM gmail_label_maps WHERE account=? ORDER BY created',(a['id'],))]
            result.append({'account_id':a['id'],'address':a['address'],'labels':labels,'views':views,'maps':maps,'messages':len(rows),'labels_pending':self.pending_labels(a['id'])})
        return result
    def pending_labels(self,account):
        with self.state.db() as db:return db.execute('SELECT count(*) FROM gmail_messages WHERE account=? AND labels_checked=0',(account,)).fetchone()[0]
    def add_local_label(self,key,label):
        with self.state.db() as db:
            row=db.execute('SELECT labels,priority FROM message_state WHERE id=?',(key,)).fetchone()
            labels=json.loads(row[0]) if row else []
            if label in labels:return False
            db.execute('INSERT OR REPLACE INTO message_state VALUES (?,?,?)',(key,json.dumps(labels+[label]),row[1] if row else 'normal'))
        return True
    def apply_maps(self,account,key,labels):
        with self.state.db() as db:maps=db.execute('SELECT provider_label,label FROM gmail_label_maps WHERE account=?',(account,)).fetchall()
        known={l['id'] for l in self.state.labels()}
        for p,l in maps:
            if p in labels and l in known:self.add_local_label(key,l)
    def map_label(self,actor,key,provider_label,label,mode):
        self.account(actor,key)
        if mode not in ('once','auto'):raise ValueError('mode must be once or auto')
        if not isinstance(provider_label,str) or not 1<=len(provider_label)<=200:raise ValueError('Invalid Gmail label')
        if label not in {l['id'] for l in self.state.labels()}:raise ValueError('Unknown Nullmail label')
        with self.state.db() as db:
            rows=db.execute('SELECT id,labels FROM gmail_messages WHERE account=? AND deleted=0',(key,)).fetchall()
            if mode=='auto':db.execute('INSERT OR IGNORE INTO gmail_label_maps VALUES (?,?,?,?)',(key,provider_label,label,time.time()))
        applied=sum(self.add_local_label(mid,label) for mid,raw in rows if provider_label in json.loads(raw))
        return {'applied':applied,'mode':mode}
    def unmap_label(self,actor,key,provider_label,label):
        self.account(actor,key)
        with self.state.db() as db:n=db.execute('DELETE FROM gmail_label_maps WHERE account=? AND provider_label=? AND label=?',(key,provider_label,label)).rowcount
        return {'removed':n}
    def granted_scopes(self,key):
        with self.state.db() as db:row=db.execute('SELECT token FROM gmail_accounts WHERE id=?',(key,)).fetchone()
        if not row or not self.cipher:return set()
        try:return set(str(json.loads(self.cipher.decrypt(row[0].encode())).get('scope','')).split())
        except (InvalidToken,ValueError):return set()
    def actor_of(self,key):
        with self.state.db() as db:row=db.execute('SELECT actor FROM gmail_accounts WHERE id=?',(key,)).fetchone()
        if not row:raise PermissionError('Gmail account permission required')
        return row[0]
    def post(self,actor,key,path,data):
        return self.http('https://gmail.googleapis.com/gmail/v1/users/me/'+path,data,self.access_token(actor,key))
    def native(self,key):
        with self.state.db() as db:return db.execute('SELECT account,native FROM gmail_messages WHERE id=?',(key,)).fetchone()
    def note_sync(self,key,status,items,error=None):
        with self.state.db() as db:
            row=db.execute('SELECT v FROM gmail_meta WHERE k=?',('sync:'+key,)).fetchone()
            prev=json.loads(row[0]) if row else {}
            data={'at':time.time(),'status':status,'items':items,'error':error,'total_items':prev.get('total_items',0)+items,'last_ok':time.time() if status=='ok' else prev.get('last_ok')}
            db.execute('INSERT OR REPLACE INTO gmail_meta VALUES (?,?)',('sync:'+key,json.dumps(data)))
    def sync_now(self,actor,key):
        self.account(actor,key)
        with self.state.db() as db:db.execute('UPDATE gmail_accounts SET retry=0 WHERE id=?',(key,))
        return self.sync_page(actor,key)
    def retry_failed_now(self,actor,key):
        self.account(actor,key)
        with self.state.db() as db:
            a=db.execute('UPDATE gmail_skipped SET retry=0 WHERE account=?',(key,)).rowcount
            b=db.execute("UPDATE provider_ops SET status='pending',attempts=0,retry=0 WHERE account=? AND status IN ('failed','pending')",(key,)).rowcount
        return {'messages_requeued':a,'writeback_requeued':b}
    def details(self,actor):
        """Status-screen view. Never includes tokens: only booleans and expiry times."""
        out=[]
        for a in self.accounts(actor):
            with self.state.db() as db:
                row=db.execute('SELECT token,history,failures,retry FROM gmail_accounts WHERE id=?',(a['id'],)).fetchone()
                sync=db.execute('SELECT v FROM gmail_meta WHERE k=?',('sync:'+a['id'],)).fetchone()
                lrow=db.execute('SELECT v FROM gmail_meta WHERE k=?',('labels:'+a['id'],)).fetchone()
                skipped=[dict(reason=r,attempts=n,retry=t) for r,n,t in db.execute('SELECT reason,attempts,retry FROM gmail_skipped WHERE account=? LIMIT 20',(a['id'],))]
            health={'decryptable':False,'refresh_token':False,'access_expires':None}
            try:
                data=json.loads(self.cipher.decrypt(row[0].encode()))
                health={'decryptable':True,'refresh_token':bool(data.get('refresh_token')),'access_expires':data.get('expires_at')}
            except Exception:pass
            scopes=self.granted_scopes(a['id'])
            cat=[l for l in self.label_catalog(actor) if l['account_id']==a['id']]
            labels=cat[0]['labels'] if cat else []
            out.append({'account_id':a['id'],'provider':'gmail','address':a['address'],'status':a['status'],'phase':a['phase'],'stage':a['stage'],
              'backfill_paused':bool(a['backfill_paused']),'error':a['error'],'failures':row[2],'backoff_until':row[3] if row[3]>time.time() else None,
              'imported':a['imported'],'pending_retry':a['skipped'],'skipped_detail':skipped,'labels_pending':cat[0]['labels_pending'] if cat else 0,
              'granted_scopes':sorted(scopes),'missing_scopes':missing_scopes(scopes),'token':health,
              'last_sync':json.loads(sync[0]) if sync else None,'labels_refreshed':float(lrow[0]) if lrow else None,
              'label_counts':{'user':sum(l['kind']=='user' for l in labels),'category':sum(l['kind']=='category' for l in labels),'system':sum(l['kind']=='system' for l in labels)},
              'categories':{l['name']:l['count'] for l in labels if l['kind']=='category'},
              'writeback':self.sync.status('gmail',a['id']),'auto_maps':len(cat[0]['maps']) if cat else 0})
        return out
    def set_backfill(self,actor,key,paused):
        a=self.account(actor,key)
        if not isinstance(paused,bool):raise ValueError('paused must be true or false')
        with self.state.db() as db:
            db.execute('UPDATE gmail_accounts SET backfill_paused=? WHERE id=?',(int(paused),key))
            if paused and a['phase']=='import' and a['stage']=='older':db.execute("UPDATE gmail_accounts SET phase='history',stage='older_paused',page=NULL WHERE id=?",(key,))
            if not paused and a['stage']=='older_paused':db.execute("UPDATE gmail_accounts SET phase='import',stage='older',page=NULL,retry=0 WHERE id=?",(key,))
        a=self.account(actor,key);return {'backfill_paused':bool(a['backfill_paused']),'phase':a['phase'],'stage':a['stage']}
    def purged(self,account,native):
        with self.state.db() as db:return db.execute('SELECT 1 FROM gmail_purged WHERE account=? AND native=?',(account,native)).fetchone() is not None
    def migrate_spam(self):
        """One-time: Gmail SPAM messages previously filed in Trash move to Spam. Real trash is untouched."""
        with self.state.db() as db:
            if db.execute("SELECT 1 FROM gmail_meta WHERE k='spam_folder_v1'").fetchone():return 0
            rows=db.execute('SELECT id,labels FROM gmail_messages').fetchall()
        moved=0
        spam={k for k,l in rows if 'SPAM' in json.loads(l) and 'TRASH' not in json.loads(l)}
        for p in list(self.cache.files('trash')):
            if MailStore.key(p) in spam:
                os.replace(p,self.cache.root/FOLDERS['spam']/p.parent.name/p.name);moved+=1
        with self.state.db() as db:db.execute("INSERT OR REPLACE INTO gmail_meta VALUES ('spam_folder_v1',?)",(str(moved),))
        return moved
    def forget(self,key):
        """Remove one purged Gmail cache message, its side files and keep a tombstone so it is never re-imported."""
        with self.state.db() as db:
            row=db.execute('SELECT account,native FROM gmail_messages WHERE id=?',(key,)).fetchone()
            if row:
                db.execute('INSERT OR REPLACE INTO gmail_purged VALUES (?,?,?)',(row[0],row[1],time.time()))
                db.execute('DELETE FROM gmail_messages WHERE id=?',(key,))
                db.execute('DELETE FROM gmail_skipped WHERE account=? AND native=?',(row[0],row[1]))
        d=self.attachment_dir(key)
        if d.exists():shutil.rmtree(d)
    def attachment_dir(self,key):
        if not re.fullmatch('[a-f0-9]{64}',key):raise ValueError('Invalid message ID')
        return self.cache.root/'gmail-attachments'/key
    def segmented(self,actor,account,native,key):
        """Large message: MIME tree via format=full, each attachment via attachments.get to disk.
        Stored message is a reader-sized MIME skeleton; attachment parts point to side files."""
        result=self.http('https://gmail.googleapis.com/gmail/v1/users/me/messages/'+native+'?format=full',token=self.access_token(actor,account),limit=MAX_FULL)
        payload=result.get('payload')
        if not isinstance(payload,dict):raise ProviderError('Gmail message structure missing')
        base=self.attachment_dir(key);work=self.cache.root/'tmp'/('seg-'+secrets.token_hex(8))
        work.mkdir(mode=0o700);counter=[0];total=[0]
        def headers(part,drop=()):
            out=[]
            for h in part.get('headers') or []:
                n=clean(h.get('name',''))
                if not re.fullmatch(r'[!-9;-~]{1,100}',n) or n.lower() in drop:continue
                out.append(n+': '+clean(h.get('value','')))
            return out
        def ctype(part):
            m=email.message.Message()
            for h in part.get('headers') or []:
                if str(h.get('name','')).lower()=='content-type':m['Content-Type']=clean(h.get('value',''))
            if not m['Content-Type']:m['Content-Type']=clean(part.get('mimeType') or 'text/plain')
            return m
        def render(part,depth=0):
            if depth>30:raise ProviderError('Gmail MIME nesting too deep')
            mime=str(part.get('mimeType',''))
            if mime.startswith('multipart/') and part.get('parts'):
                m=ctype(part);boundary=m.get_boundary() or ('nm-'+secrets.token_hex(12))
                hs=headers(part,('content-type','content-transfer-encoding','content-length'))
                hs.append('Content-Type: '+mime+'; boundary="'+boundary.replace('"','')+'"')
                body=b''.join(b'--'+boundary.encode()+b'\r\n'+render(p,depth+1)+b'\r\n' for p in part['parts'])+b'--'+boundary.encode()+b'--\r\n'
                return ('\r\n'.join(hs)+'\r\n\r\n').encode('utf-8','replace')+body
            b=part.get('body') or {}
            hs=headers(part,('content-transfer-encoding','content-length'))
            if b.get('attachmentId'):
                aid=str(b['attachmentId'])
                if not re.fullmatch('[A-Za-z0-9_-]{1,2000}',aid):raise ProviderError('Invalid Gmail attachment ID')
                counter[0]+=1;n=counter[0];tmpjson=work/('a%d.json'%n)
                self.stream('https://gmail.googleapis.com/gmail/v1/users/me/messages/'+native+'/attachments/'+aid,self.access_token(actor,account),tmpjson,MAX_PART)
                got=decode_attachment_json(tmpjson,work/('%d.bin'%n),MAX_LARGE-total[0]);total[0]+=got;tmpjson.unlink()
                hs=[h for h in hs if not h.lower().startswith('content-disposition:')]
                d=email.message.Message();d.add_header('Content-Disposition','attachment',filename=str(part.get('filename') or 'attachment-%d'%n)[:200])
                hs+=['Content-Disposition: '+d['Content-Disposition'],'X-Nullmail-Gmail-Attachment: %d; size=%d'%(n,got)]
                return ('\r\n'.join(hs)+'\r\n\r\n').encode('utf-8','replace')
            data=b.get('data') or ''
            try:raw=base64.b64decode(data+'='*(-len(data)%4),altchars=b'-_') if data else b''
            except ValueError:raise ProviderError('Invalid Gmail encoding') from None
            hs.append('Content-Transfer-Encoding: base64')
            return ('\r\n'.join(hs)+'\r\n\r\n').encode('utf-8','replace')+base64.encodebytes(raw).replace(b'\n',b'\r\n')
        try:
            top=headers(payload) if payload.get('headers') else []
            raw=render(payload)
            if len(raw)>MAX_MAIL:raise TooLarge('Gmail inline bodies exceed reader limit')
            if not top:raise ProviderError('Gmail message headers missing')
            if base.exists():shutil.rmtree(base)
            base.parent.mkdir(mode=0o700,exist_ok=True);os.replace(work,base)
        finally:
            if work.exists():shutil.rmtree(work,ignore_errors=True)
        return result,raw
    def external(self,key,part):
        v=str(part.get('X-Nullmail-Gmail-Attachment',''))
        m=re.fullmatch(r'(\d{1,4}); size=(\d{1,12})',v)
        if not m:return None
        p=self.attachment_dir(key)/(m.group(1)+'.bin')
        return p,int(m.group(2))
    def record_failure(self,key,native,e):
        with self.state.db() as db:
            row=db.execute('SELECT attempts FROM gmail_skipped WHERE account=? AND native=?',(key,native)).fetchone()
            n=(row[0] if row else 0)+1
            db.execute('INSERT OR REPLACE INTO gmail_skipped(account,native,reason,attempts,retry) VALUES (?,?,?,?,?)',(key,native,str(e)[:180],n,time.time()+min(86400,60*2**min(n,10))))
    def retry_failed(self,actor,key,limit=2):
        with self.state.db() as db:rows=db.execute('SELECT native FROM gmail_skipped WHERE account=? AND retry<=? ORDER BY retry LIMIT ?',(key,time.time(),limit)).fetchall()
        for (native,) in rows:
            try:self.ingest(actor,key,native,True)
            except MessageGone:
                with self.state.db() as db:db.execute('DELETE FROM gmail_skipped WHERE account=? AND native=?',(key,native))
            except RetryLater:raise
            except ProviderError as e:self.record_failure(key,native,e)
    def sync_page(self,actor,key):
        a=self.account(actor,key)
        if a['phase'] not in ('import','history') or a['retry']>time.time():return {'status':a['phase'],'backoff_until':a['retry']}
        try:
            self.retry_failed(actor,key)
            self.refresh_labels(actor,key);self.label_backfill(actor,key)
            self.sync.process(retry_exc=(RetryLater,))
            params={'maxResults':20}
            if a['page']:params['pageToken']=a['page']
            stage=a.get('stage') or 'recent'
            if a['phase']=='import':
                params.update(includeSpamTrash='true',q=RECENT_QUERY if stage=='recent' else OLDER_QUERY)
                result=self.get(actor,key,'messages',params);items=[m['id'] for m in result.get('messages',[])]
            else:
                params['startHistoryId']=a['history'];result=self.get(actor,key,'history',params)
                items=list(dict.fromkeys(m['message']['id'] for h in result.get('history',[]) for m in h.get('messagesAdded',[])))
                # Existing provider label changes are observed; local state never overwrites Google.
                items=list(dict.fromkeys(items+[m['message']['id'] for h in result.get('history',[]) for event in ('labelsAdded','labelsRemoved') for m in h.get(event,[])]))
            if len(items)>100:raise ProviderError('History page exceeds bounded import limit; explicit reimport required')
            for native in items:
                try:self.ingest(actor,key,native,a['phase']=='import')
                except MessageGone:pass
                except RetryLater:raise
                except ProviderError as e:self.record_failure(key,native,e)
            page=result.get('nextPageToken')
            if page is not None and (not isinstance(page,str) or len(page)>4096):raise ProviderError('Invalid Google page token')
            history=a['history'] if page or a['phase']=='import' else str(result.get('historyId',a['history']))
            if not history.isdigit():raise ProviderError('Invalid Google history checkpoint')
            with self.state.db() as db:
                for h in result.get('history',[]):
                    for deleted in h.get('messagesDeleted',[]):db.execute('UPDATE gmail_messages SET deleted=1 WHERE account=? AND native=?',(key,deleted['message']['id']))
                if a['phase']=='import' and not page and stage=='recent':phase,stage=('history','older_paused') if a.get('backfill_paused',1) else ('import','older')
                elif a['phase']=='import' and stage=='older' and a.get('backfill_paused',1):phase,stage,page='history','older_paused',None
                elif a['phase']=='import' and page:phase='import'
                elif a['phase']=='history' and stage=='older_paused' and not a.get('backfill_paused',1):phase,stage,page='import','older',None
                else:phase,stage='history',(stage if a['phase']=='history' else 'complete')
                delay=15 if phase=='history' or stage=='recent' else 45
                db.execute("UPDATE gmail_accounts SET page=?,history=?,phase=?,stage=?,retry=?,failures=0,error=NULL,updated=? WHERE id=?",(page,history,phase,stage,time.time()+delay,time.time(),key))
            self.note_sync(key,'ok',len(items))
            return {'status':phase,'stage':stage,'imported':len(items),'has_more':phase=='import'}
        except FullSyncRequired:
            with self.state.db() as db:db.execute("UPDATE gmail_accounts SET phase='resync_required',error='History expired; explicitly reimport' WHERE id=?",(key,))
            return {'status':'resync_required'}
        except ProviderError as e:
            failures=a['failures']+1
            with self.state.db() as db:db.execute('UPDATE gmail_accounts SET retry=?,failures=?,error=? WHERE id=?',(time.time()+min(3600,30*2**min(failures,7))+secrets.randbelow(20),failures,str(e)[:180],key))
            self.note_sync(key,'backoff',0,str(e)[:180])
            return {'status':'backoff'}
    def submit(self,actor,key,sender,raw):
        a=self.account(actor,key)
        if a['address']!=sender:raise PermissionError('Only the verified Google primary identity may send')
        token=self.access_token(actor,key)
        try:
            result=self.http('https://gmail.googleapis.com/gmail/v1/users/me/messages/send',{'raw':base64.urlsafe_b64encode(raw).decode()},token)
            if not re.fullmatch('[A-Za-z0-9_-]{1,100}',str(result.get('id',''))):raise ProviderError('Missing send receipt')
            return {'status':'accepted','queue_id':'gmail:'+result['id']}
        except Exception:return {'status':'unknown','queue_id':None}

class CombinedMail:
    """One global ID namespace; local delivery files are never copied or modified by sync."""
    def __init__(self,local,gmail):self.local,self.gmail=local,gmail
    key=staticmethod(MailStore.key)
    def files(self,folder):
        yield from self.local.files(folder)
        for path in self.gmail.cache.files(folder):
            if self.gmail.reference(self.key(path)):yield path
    def reference(self,key):
        from cases import reference
        return self.gmail.reference(key) or reference(key)
    def locate(self,folder,key):
        return (self.gmail.cache if self.gmail.reference(key) else self.local).locate(folder,key)
    def read(self,path):return self.local.read(path)
    def source(self,folder,key):
        """Raw stored RFC822 bytes plus any segmented attachment parts (never reads side files)."""
        store=self.gmail.cache if self.gmail.reference(key) else self.local
        p=store.locate(folder,key);raw=p.read_bytes()[:MAX_MAIL+1]
        parts=[]
        if store is self.gmail.cache:
            for i,part in enumerate(self.read(p).walk()):
                ext=self.gmail.external(key,part)
                if ext:parts.append({'part':i,'name':str(part.get_filename() or 'attachment'),'content_type':part.get_content_type(),'size':ext[1]})
        return raw,parts
    def eml(self,folder,key,limit=25*1024*1024):
        """Download form. Segmented Gmail messages are reassembled when they fit the bound."""
        raw,parts=self.source(folder,key)
        if not parts:return raw,False
        if sum(x['size'] for x in parts)>limit:return raw,False
        msg=BytesParser(policy=email.policy.compat32).parsebytes(raw);walk=list(msg.walk())
        for x in parts:
            part=walk[x['part']];ext=self.gmail.external(key,part)
            del part['X-Nullmail-Gmail-Attachment'];del part['Content-Transfer-Encoding']
            part['Content-Transfer-Encoding']='base64'
            part.set_payload(base64.encodebytes(ext[0].read_bytes()).decode())
        return msg.as_bytes(),True
    def metadata(self,path,msg):
        m=self.local.metadata(path,msg);ref=self.gmail.reference(m['id'])
        if ref:
            with self.gmail.state.db() as db:r=db.execute('SELECT labels,deleted FROM gmail_messages WHERE id=?',(m['id'],)).fetchone()
            m.update(gmail_account=ref['account_id'],provider='gmail',provider_labels=json.loads(r[0]),provider_deleted=bool(r[1]),envelope_recipient=None)
            m['provider_label_details']=self.gmail.describe(ref['account_id'],m['provider_labels'])
        return m
    def listing(self,folder='inbox',query='',recipient='',unread=False):
        rows=self.local.listing(folder,query,recipient,unread)
        for p in self.gmail.cache.files(folder):
            m=self.metadata(p,self.read(p))
            if not m.get('gmail_account'):continue
            if unread and not m['unread']:continue
            if recipient.lower() not in m['recipient'].lower():continue
            if query.lower() not in ' '.join(str(m[k]) for k in ('subject','from','to','recipient')).lower():continue
            rows.append(m)
        return sorted(rows,key=lambda m:m['timestamp'],reverse=True)
    def message(self,folder,key):
        store=self.gmail.cache if self.gmail.reference(key) else self.local
        result=store.message(folder,key);msg=store.read(store.locate(folder,key));result.update(self.metadata(store.locate(folder,key),msg))
        if store is self.gmail.cache:
            parts=list(msg.walk())
            for a in result.get('attachments',[]):
                ext=self.gmail.external(key,parts[a['id']])
                if ext:a['size']=ext[1]
        return result
    def purge_spam(self,now=None,days=SPAM_DAYS):
        """Delete Spam messages whose received time (file mtime = delivery / Gmail internalDate) is older than `days`."""
        cutoff=(now or time.time())-days*86400;count=0
        for p in list(self.gmail.cache.files('spam')):
            if p.stat().st_mtime<cutoff:
                key=self.key(p)
                if self.gmail.reference(key):self.gmail.forget(key)
                p.unlink(missing_ok=True);count+=1
        for p in list(self.local.files('spam')):
            if p.stat().st_mtime<cutoff:p.unlink(missing_ok=True);count+=1
        return count
    def attachment(self,folder,key,index):
        if not self.gmail.reference(key):return self.local.attachment(folder,key,index)
        store=self.gmail.cache;msg=store.read(store.locate(folder,key))
        allowed={a['id']:a for a in self.message(folder,key)['attachments']}
        if index not in allowed:raise FileNotFoundError('Attachment not found')
        ext=self.gmail.external(key,list(msg.walk())[index])
        if ext is None:return store.attachment(folder,key,index)
        return allowed[index]['name'],ext[0].read_bytes()
    def flag(self,folder,key,read):
        if not self.gmail.reference(key):return self.local.flag(folder,key,read)
        result=self.gmail.cache.flag(folder,key,read)
        account,native=self.gmail.native(key);add,remove=self.gmail.sync.adapter('gmail').read_change(read)
        self.gmail.sync.enqueue('gmail',account,native,add_ids=add,remove_ids=remove)
        return result
    def delete(self,folder,key,confirm=False):
        """Permanent local delete from Trash. A Gmail message is tombstoned so sync never re-imports it;
        the Gmail copy itself stays in Gmail Trash (Gmail empties it after 30 days). Nothing is deleted at Google."""
        if not self.gmail.reference(key):return self.local.delete(folder,key,confirm)
        if confirm is not True:raise ValueError('Permanent delete requires confirmation')
        if folder!='trash':raise ValueError('Move the message to Trash before deleting it permanently')
        p=self.gmail.cache.locate(folder,key);self.gmail.forget(key);p.unlink(missing_ok=True)
    def move(self,folder,key,target):
        if not self.gmail.reference(key):return self.local.move(folder,key,target)
        result=self.gmail.cache.move(folder,key,target)
        account,native=self.gmail.native(key);add,remove=self.gmail.sync.adapter('gmail').folder_change(folder,target)
        self.gmail.sync.enqueue('gmail',account,native,add_ids=add,remove_ids=remove)
        return result
