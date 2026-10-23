"""Nullmail HTTP service, loopback only. Auth delegated to Nullink's human API."""
import reader
import hashlib, hmac, http.client, ipaddress, json, os, secrets, socket, threading, time
import api_v1
from gmail import Gmail, CombinedMail
from cases import Conflict
from workspace import require_read
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs
from core import MailStore, Drafts, build_message
from transport import DirectPostfix, outbound_enabled

STATIC=Path(__file__).parent/'static'
ORIGIN='https://nullmail.nullverse.cloud'
# Dual address (2026-10-07): same instance on both hosts. Each host only accepts writes
# from its own exact HTTPS origin; sessions stay host-only per host.
PUBLIC_HOSTS=('nullmail.nullverse.cloud','nullmail.216.158.238.236.sslip.io')
ORIGINS=frozenset('https://'+h for h in PUBLIC_HOSTS)
COOKIE_NAME='__Host-nullink_session'
AUTH_PORT=8766
CSRF_KEY=secrets.token_bytes(32)
MUTATION=threading.Lock()

def control(request):
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(120);s.connect('/run/nullmail-control/control.sock')
        s.sendall(json.dumps(request).encode()+b'\n')
        with s.makefile('rb') as stream:
            raw=stream.readline(262145)
    response=json.loads(raw)
    if not response.get('ok'): raise ValueError(response.get('error','Controller unavailable'))
    return response['result']

def nullink(path, cookie='', body=None, client_ip='127.0.0.1', user_agent='Nullmail'):
    conn=http.client.HTTPConnection('127.0.0.1',AUTH_PORT,timeout=8)
    headers={'Host':'nullverse.cloud','X-Forwarded-Proto':'https','Cookie':cookie,
             'X-Forwarded-For':client_ip, 'User-Agent':user_agent}
    if body is not None: headers['Content-Type']='application/json'
    try:
        conn.request('POST' if body is not None else 'GET',path,body,headers)
        res=conn.getresponse()
        cookie=next((v for k,v in res.getheaders() if k.lower()=='set-cookie' and v.startswith(COOKIE_NAME+'=')),None)
        return res.status,res.read(65536),cookie
    finally: conn.close()

def owner_session_live(cookie):
    """Read-only check for the open pixel: is this a live, unexpired, non-guest Nullink session?
    Uses Nullink's loopback-only session lookup (signature + expiry, get_session without touch), so
    it never extends the session, sets a cookie, needs CSRF or redirects. Any error counts as 'no'."""
    value=cookie.split('=',1)[1] if cookie and '=' in cookie else ''
    if not value: return False
    conn=http.client.HTTPConnection('127.0.0.1',AUTH_PORT,timeout=3)
    try:
        conn.request('POST','/api/admin/ssh-session',json.dumps({'token':value}),{'Host':'127.0.0.1','Content-Type':'application/json'})
        res=conn.getresponse();data=json.loads(res.read(4096))
        return res.status==200 and isinstance(data,dict) and data.get('ok') is True
    except Exception: return False
    finally: conn.close()

class Handler(BaseHTTPRequestHandler):
    server_version='Nullmail'
    def setup(self):
        super().setup()
        self.connection.settimeout(20)
    def log_message(self,*args): pass # Never log message IDs, recipients, cookies or bodies.
    def reply(self,status,data,kind='application/json; charset=utf-8',extra=None):
        if isinstance(data,dict) and status>=400 and 'error' in data: data=dict(data,code={400:'invalid_request',401:'unauthenticated',403:'forbidden',404:'not_found',409:'conflict',503:'unavailable'}.get(status,'request_error'))
        if not isinstance(data,bytes): data=json.dumps(data).encode()
        self.send_response(status)
        for k,v in {'Content-Type':kind,'Content-Length':str(len(data)),'Cache-Control':'no-store',
                    'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer',
                    'Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors https://nullink.nullverse.cloud https://nullink.216.158.238.236.sslip.io",**(extra or {})}.items(): self.send_header(k,v)
        self.end_headers();self.wfile.write(data)
    def cookie(self):
        c=SimpleCookie()
        try: c.load(self.headers.get('Cookie',''))
        except Exception: return ''
        token=c.get(COOKIE_NAME)
        return COOKIE_NAME+'='+token.value if token and len(token.value)<512 else ''
    def csrf(self):
        return hmac.new(CSRF_KEY,self.cookie().encode(),hashlib.sha256).hexdigest()
    def authenticated(self):
        if not self.cookie(): return False
        status,raw,_=nullink('/api/me',self.cookie())
        if status!=200: return False
        data=json.loads(raw)
        self.auth_data=data
        return data.get('authenticated') is True and data.get('auth_type')=='session'
    def valid_host(self):
        hosts=self.headers.get_all('Host',[])
        return len(hosts)==1 and hosts[0] in PUBLIC_HOSTS+('127.0.0.1:8789',)
    def expected_origin(self):
        host=self.headers.get('Host','')
        return 'https://'+host if host in PUBLIC_HOSTS else ORIGIN
    def body(self):
        if self.headers.get('Transfer-Encoding'): raise ValueError('Transfer encoding not supported')
        length=int(self.headers.get('Content-Length','0'))
        if not 0<length<=220000: raise ValueError('Request too large or empty')
        if self.headers.get_content_type()!='application/json': raise ValueError('JSON required')
        result=json.loads(self.rfile.read(length))
        if not isinstance(result,dict): raise ValueError('JSON object required')
        return result
    def do_GET(self): self.dispatch(False)
    def do_POST(self): self.dispatch(True)
    def do_PUT(self): self.dispatch(True)
    def dispatch(self,write):
        try:
            if not self.valid_host(): return self.reply(421,{'error':'Untrusted host'})
            path=urlsplit(self.path).path
            self.versioned=path.startswith('/api/v1/')
            if self.versioned: path='/api/'+path[len('/api/v1/'):]
            self.api_path=path
            origin=self.headers.get('Origin')
            if write and (origin not in ORIGINS or origin!=self.expected_origin() or self.headers.get('Sec-Fetch-Site') not in (None,'same-origin')):
                return self.reply(403,{'error':'Origin rejected'})
            if not write and path in ('/','/app.js','/workspace.js','/cases.js','/outbound.js','/receipts.js','/composer.js','/vendor/quill.js','/vendor/quill.snow.css','/style.css'):
                f={'/':'index.html','/app.js':'app.js','/workspace.js':'workspace.js','/cases.js':'cases.js','/outbound.js':'outbound.js','/receipts.js':'receipts.js','/composer.js':'composer.js','/vendor/quill.js':'vendor/quill.js','/vendor/quill.snow.css':'vendor/quill.snow.css','/style.css':'style.css'}[path]
                return self.reply(200,(STATIC/f).read_bytes(),{'/':'text/html; charset=utf-8','/composer.js':'text/javascript; charset=utf-8','/vendor/quill.js':'text/javascript; charset=utf-8','/vendor/quill.snow.css':'text/css; charset=utf-8','/app.js':'text/javascript; charset=utf-8','/workspace.js':'text/javascript; charset=utf-8','/cases.js':'text/javascript; charset=utf-8','/outbound.js':'text/javascript; charset=utf-8','/receipts.js':'text/javascript; charset=utf-8','/style.css':'text/css; charset=utf-8'}[path])
            if not write and path.startswith('/t/') and path.endswith('.gif'):
                # Open-tracking pixel (opt-in per message). Unauthenticated; stores time only. John's own
                # signed-in views (a valid, unexpired session; read-only lookup) are not counted.
                import receipts
                if not owner_session_live(self.cookie()):
                    with MUTATION, api_v1.state(self.server).db() as db:receipts.record_open(db,path[3:-4])
                return self.reply(200,receipts.PIXEL,'image/gif',{'Cache-Control':'no-store, private','Cross-Origin-Resource-Policy':'cross-origin'})
            if not write and path=='/health': return self.reply(200,{'ok':True,'service':'nullmail'})
            if path=='/api/auth/method' and not write:
                status,body,_=nullink('/api/auth/method');return self.reply(status,body)
            if path=='/api/auth/verify' and write:
                data=self.body()
                code=data.get('code','')
                if not isinstance(code,str) or len(code)>80: raise ValueError('Invalid code')
                try: client_ip=str(ipaddress.ip_address(self.headers.get('X-Nullmail-Client-IP','127.0.0.1')))
                except ValueError: client_ip='127.0.0.1'
                status,body,cookie=nullink(path,body=json.dumps({'code':code}).encode(),client_ip=client_ip,user_agent=self.headers.get('User-Agent','Nullmail')[:250])
                return self.reply(status,body,extra={'Set-Cookie':cookie} if cookie else None)
            if not self.authenticated(): return self.reply(401,{'error':'Sign in with Nullink'})
            if write and not hmac.compare_digest(self.headers.get('X-CSRF-Token',''),self.csrf()):
                return self.reply(403,{'error':'CSRF token rejected; reload the page'})
            if write:
                data=self.body()
                with MUTATION: return self.write_api(path,data)
            return self.read_api(path,parse_qs(urlsplit(self.path).query))
        except Conflict as e: self.reply(409,{'error':str(e)})
        except PermissionError as e: self.reply(403,{'error':str(e)[:180]})
        except FileNotFoundError: self.reply(404,{'error':'Not found'})
        except (ValueError,TypeError,KeyError) as e: self.reply(400,{'error':str(e)[:180]})
        except Exception: self.reply(503,{'error':'Service unavailable. Try again shortly.'})
    def read_api(self,path,q):
        folder=q.get('folder',['inbox'])[0]
        extended={'capabilities','accounts','labels','rules','rules/history','rules/versions','thread','sent'}
        endpoint=path.removeprefix('/api/')
        if endpoint=='prefs':
            import prefs
            store,_,actor,_=api_v1.context(self)
            with store.db() as db: return self.reply(200,{'prefs':prefs.get(db,actor),'server_time':time.time()*1000})
        if endpoint=='gmail/callback':
            store,ids,actor,perm=api_v1.context(self);api_v1.admin(perm)
            with MUTATION:self.server.gmail.complete(actor,self.cookie(),q.get('state',[''])[0],q.get('code',[''])[0],self.identities())
            return self.reply(303,b'',extra={'Location':'/?gmail=connected#setup/external'})
        if endpoint=='message/frame':
            # HTML email is served as its own sandboxed document (not srcdoc) so it gets an iframe-only CSP that
            # permits the email's inline styles while scripts, forms, plugins and (unless allowed) remote loads stay blocked.
            out=api_v1.read(self,'message/html',q)
            if not out.get('html'): return self.reply(404,{'error':'No HTML body'})
            return self.reply(200,out['html'].encode(),'text/html; charset=utf-8',{'Content-Security-Policy':reader.csp(out['remote'])+"; sandbox allow-popups allow-popups-to-escape-sandbox; frame-ancestors 'self'",'X-Frame-Options':'SAMEORIGIN','Cross-Origin-Resource-Policy':'same-origin'})
        if endpoint in extended or endpoint in ('messages','message','cases','gmail/status','gmail/labels','gmail/details','message/html','message/source') or endpoint.startswith('cases/'):
            return self.reply(200,api_v1.read(self,endpoint,q))
        if path=='/api/session': return self.reply(200,{'authenticated':True,'csrf':self.csrf()})
        if path=='/api/config' or path=='/api/projects':
            _,_,_,perm=api_v1.context(self);api_v1.admin(perm)
            result=control({'op':'status'})
            enabled=getattr(self.server,'outbound_enabled',False)
            result['outbound'].update(paused=not enabled, reason=('Send submits to the authenticated local queue. Accepted means queued; delivery is unverified. No automatic app retries.' if enabled else 'Sending is paused. Nothing is transmitted.'))
            return self.reply(200,result)
        if path=='/api/message/eml':
            m=api_v1.message(self,folder,q.get('id',[''])[0])
            body,_=self.server.mail.eml(folder,m['id'])
            return self.reply(200,body,'message/rfc822',{'Content-Disposition':'attachment; filename="message-'+m['id'][:12]+'.eml"'})
        if path=='/api/attachment':
            api_v1.message(self,folder,q.get('id',[''])[0])
            name,body=self.server.mail.attachment(folder,q.get('id',[''])[0],int(q.get('part',['-1'])[0]))
            return self.reply(200,body,'application/octet-stream',{'Content-Disposition':f'attachment; filename="{name}"'})
        if path=='/api/drafts':
            store,_,actor,_=api_v1.context(self);drafts=[]
            for d in self.server.drafts.list():
                try: store.own_draft(d['id'],actor)
                except PermissionError: continue
                drafts.append(d)
            return self.reply(200,{'drafts':drafts})
        return self.reply(404,{'error':'Not found'})
    def identities(self):
        return [a for p in control({'op':'status'})['projects'] for a in p['aliases']]
    def provider_trash_check(self,folder,key,target,confirmed):
        # Deleting a Gmail Sent message also moves it to Gmail Trash, which Gmail empties after 30 days.
        gmail=getattr(self.server,'gmail',None)
        if folder=='sent' and target=='trash' and gmail and gmail.reference(key) and confirmed is not True:
            raise ValueError('Confirm moving this Gmail message to Gmail Trash')
    def outbound(self,op,data,store,actor):
        """Bulk outbound delete/restore. drafts: Outbox/Drafts/Sent-audit IDs; messages: Sent folder {folder,id}."""
        drafts=data.get('drafts') or [];messages=data.get('messages') or []
        if not isinstance(drafts,list) or not isinstance(messages,list) or len(drafts)+len(messages)>200: raise ValueError('Select up to 200 messages')
        if not drafts and not messages: raise ValueError('Nothing selected')
        permanent=data.get('permanent') is True
        if permanent and data.get('confirm') is not True: raise ValueError('Permanent delete requires confirmation')
        for key in drafts:
            if not isinstance(key,str): raise ValueError('Invalid draft ID')
            store.own_draft(key,actor)
        for m in messages:
            if not isinstance(m,dict) or not isinstance(m.get('id'),str) or m.get('folder') not in ('sent','trash'): raise ValueError('Only Sent or Trash messages can be deleted here')
            api_v1.message(self,m['folder'],m['id'])
        results=[]
        for key in drafts:
            try:
                if op=='restore': r=self.server.drafts.restore(key)
                elif permanent: r=self.server.drafts.purge(key,True)
                else: r=self.server.drafts.trash(key)
            except (ValueError,FileNotFoundError) as e: r={'id':key,'error':str(e)}
            results.append(r)
        if op=='restore' and messages: raise ValueError('Restore Sent messages from Trash with Restore')
        for m in messages:
            try:
                if permanent and m['folder']=='trash': self.server.mail.delete('trash',m['id'],True)
                elif permanent: raise ValueError('Move the message to Trash before deleting it permanently')
                else:
                    self.provider_trash_check(m['folder'],m['id'],'trash',data.get('confirm_provider'))
                    self.server.mail.move(m['folder'],m['id'],'trash')
                results.append({'id':m['id'],'status':'deleted' if permanent else 'trashed'})
            except (ValueError,FileNotFoundError) as e: results.append({'id':m['id'],'error':str(e)})
        return {'results':results,'ok':sum('error' not in r for r in results),'failed':sum('error' in r for r in results)}
    def mdn_respond(self,data,store,actor,perm):
        """John explicitly answers a read-receipt request: 'send' or 'ignore'. Never automatic."""
        import receipts
        if data.get('action') not in ('send','ignore'):raise ValueError('action must be send or ignore')
        if data['action']=='send' and data.get('confirm') is not True:raise ValueError('Confirm sending the read receipt')
        m=api_v1.message(self,data.get('folder'),data.get('id'))
        original=self.server.mail.read(self.server.mail.locate(data['folder'],m['id']))
        req=receipts.mdn_request(original)
        if not req:raise ValueError('This message did not request a read receipt')
        with store.db() as db:receipts.mdn_claim(db,m['id'],data['action'])
        if data['action']=='ignore':return {'status':'ignored','message':'No receipt will be sent.'}
        import email.utils
        addressed=[a.lower() for h in (original.get('To'),original.get('Cc'),m.get('envelope_recipient')) if h for _,a in email.utils.getaddresses([str(h)]) if a]
        gmail_account=m.get('gmail_account')
        if gmail_account:
            acct=next((a for a in self.server.gmail.accounts(actor) if a['id']==gmail_account),None)
            sender=acct and acct['address']
        else:sender=next((a for a in addressed+[x.lower() for x in m.get('routing_recipients') or []] if a in [x.lower() for x in perm['send']]),None)
        if not sender:
            with store.db() as db:receipts.mdn_done(db,m['id'],'failed')
            raise PermissionError('No authorized identity received this message')
        raw=receipts.build_mdn(original,sender,req['to'])
        if gmail_account:
            try:result=self.server.gmail.submit(actor,gmail_account,sender,raw)
            except Exception:result={'status':'unknown'}
        else:result=DirectPostfix(enabled=getattr(self.server,'outbound_enabled',False)).submit(sender,[req['to']],raw)
        with store.db() as db:receipts.mdn_done(db,m['id'],result['status'])
        return {'status':result['status'],'message':{'paused':'Outbound is paused; the receipt was not sent.','accepted':'Read receipt handed to the mail server.'}.get(result['status'],'Read receipt was not confirmed as sent.')}
    def write_api(self,path,data):
        if path=='/api/auth/logout':
            status,body,cookie=nullink(path,self.cookie(),b'{}');return self.reply(status,body,extra={'Set-Cookie':cookie} if cookie else None)
        store,ids,actor,perm=api_v1.context(self)
        endpoint=path.removeprefix('/api/')
        if endpoint.startswith(('rules/','labels/','cases/','gmail/')) or endpoint in ('accounts/selection','message/labels','messages/bulk-label','message/remote-images','message/review'):
            return self.reply(200,api_v1.write(self,endpoint,data))
        if path=='/api/prefs':
            if self.command!='PUT': raise ValueError('Use PUT for preferences')
            import prefs
            with store.db() as db: return self.reply(200,{'prefs':prefs.put(db,actor,data),'server_time':time.time()*1000})
        if path=='/api/message/read':
            api_v1.message(self,data['folder'],data['id'])
            if not isinstance(data.get('read'),bool): raise ValueError('read must be boolean')
            self.server.mail.flag(data['folder'],data['id'],data['read']);return self.reply(200,{'ok':True})
        if path=='/api/message/move':
            api_v1.message(self,data['folder'],data['id'])
            self.provider_trash_check(data['folder'],data['id'],data['target'],data.get('confirm_provider'))
            self.server.mail.move(data['folder'],data['id'],data['target']);return self.reply(200,{'ok':True})
        if path=='/api/message/delete':
            api_v1.message(self,data['folder'],data['id'])
            self.server.mail.delete(data['folder'],data['id'],data.get('confirm'));return self.reply(200,{'ok':True})
        if path in ('/api/outbound/delete','/api/outbound/restore'):
            return self.reply(200,self.outbound(path.rsplit('/',1)[1],data,store,actor))
        if path=='/api/projects':
            api_v1.admin(perm)
            if set(data)!={'label'}: raise ValueError('Only a project label is accepted')
            return self.reply(200,control({'op':'register','label':data['label']}))
        if path=='/api/drafts':
            if data.get('id'): store.own_draft(data['id'],actor)
            draft=self.server.drafts.save(data,perm['send']);store.register_draft(draft['id'],actor)
            return self.reply(200,draft)
        if path=='/api/send':
            draft=self.server.drafts.get(data.get('id'))
            if not draft: raise FileNotFoundError()
            store.own_draft(draft['id'],actor)
            if draft['from'] not in perm['send']: raise PermissionError('From identity is not authorized')
            external=next((a for a in self.server.gmail.accounts(actor) if a['address']==draft['from']),None) if hasattr(self.server,'gmail') else None
            if external and draft['from'] in self.identities():raise PermissionError('Ambiguous sending transport; administrator review required')
            if external:self.server.gmail.ready()
            recipients,raw=build_message(draft,perm['send'])
            request_key=data.get('request_id')
            if self.versioned and not request_key: raise ValueError('request_id is required for sending')
            if request_key:
                replay=store.send_claim(request_key,draft,actor,str(getattr(self,'auth_data',{}).get('session',{}).get('id') or hashlib.sha256(self.cookie().encode()).hexdigest()))
                if replay is not None: return self.reply(200,replay)
            if draft['status'] not in ('draft','paused','rejected'): raise ValueError('Already submitted; duplicate send blocked')
            if not request_key:
                request_key=secrets.token_hex(16)
                store.send_claim(request_key,draft,actor,str(getattr(self,'auth_data',{}).get('session',{}).get('id','legacy-session')))
            delay=send_delay(store,actor,getattr(self.server,'undo_default',0))
            if delay>0:
                send_at=time.time()+delay
                self.server.drafts.schedule(draft['id'],send_at,request_key,actor)
                response={'id':draft['id'],'status':'scheduled','send_at':send_at,'delay':delay,'queue_id':None,'provider':'gmail' if external else 'local',
                          'message':'Sending in %ds. Undo or Retract from the Outbox until then; after hand-off it cannot be recalled.'%delay}
                store.send_result(request_key,response)
                return self.reply(200,response)
            self.server.drafts.claim(draft['id'])
            return self.reply(200,deliver(self.server,draft['id'],actor,request_key))
        if path=='/api/retract':
            store.own_draft(data.get('id'),actor)
            r=self.server.drafts.retract(data['id'])
            if r.get('request_id'):store.send_result(r['request_id'],{'id':data['id'],'status':'retracted','queue_id':None,'message':'Retracted before sending. Nothing was transmitted.'})
            return self.reply(200,{'id':data['id'],'status':'draft','message':'Retracted. Back in Drafts; nothing was sent.'})
        if path=='/api/mdn/respond':
            return self.reply(200,self.mdn_respond(data,store,actor,perm))
        return self.reply(404,{'error':'Not found'})

UNDO_DEFAULT=30
def send_delay(store,actor,default=UNDO_DEFAULT):
    """Per-user undo window; servers without an explicit default (tests) send immediately."""
    import prefs
    with store.db() as db:v=prefs.get(db,actor).get('undo_send_seconds',{}).get('value',default)
    return int(v) if isinstance(v,int) and 0<=v<=120 else default

def deliver(server,draft_id,actor,request_key):
    """Hand a claimed ('submitting') draft to Postfix or Gmail. Records DSN/MDN/tracking metadata."""
    import receipts
    from email.utils import make_msgid
    store=api_v1.state(server);draft=server.drafts.get(draft_id)
    external=next((a for a in server.gmail.accounts(actor) if a['address']==draft['from']),None) if hasattr(server,'gmail') else None
    enabled=bool(external) or getattr(server,'outbound_enabled',False)
    message_id=make_msgid(idstring='nm'+draft_id[:12],domain='nullverse.cloud')
    track=None
    if draft.get('track_opens'):track=receipts.new_track_token()
    try:
        recipients,raw=build_message(draft,[draft['from']],message_id=message_id,track_url=(TRACK_ORIGIN+'/t/'+track+'.gif') if track else None)
    except Exception as e:
        server.drafts.status(draft_id,'rejected');result={'status':'rejected','queue_id':None}
    else:
        if not enabled:result={'status':'paused','queue_id':None}
        elif external:
            try:result=server.gmail.submit(actor,external['id'],draft['from'],raw)
            except Exception:result={'status':'unknown','queue_id':None}
        else:result=DirectPostfix(enabled=getattr(server,'outbound_enabled',False)).submit(draft['from'],recipients,raw,envid=draft_id)
        server.drafts.status(draft_id,result['status'],result['queue_id'])
        if result['status'] in ('accepted','unknown'):
            with store.db() as db:receipts.record_outbound(db,draft_id,message_id,draft_id,result.get('dsn'),draft.get('read_receipt'),track,recipients,'gmail' if external else 'local')
    messages={'paused':'Saved in paused Outbox. Nothing was sent.',
              'accepted':'Accepted by Postfix and queued.'+(' Delivery receipt requested.' if result.get('dsn') else ' Delivery is not confirmed.'),
              'rejected':'Submission failed before acceptance. No automatic retry; review before trying again.',
              'unknown':'Submission outcome is uncertain. Do not resend: delivery may have occurred. Administrator review required.'}
    if external:messages['accepted']='Accepted by Gmail. Delivery is not confirmed; bounces are shown if Gmail returns one.'
    response={'id':draft_id,**{k:v for k,v in result.items() if k!='dsn'},'dsn_requested':bool(result.get('dsn')),'provider':'gmail' if external else 'local','message':messages[result['status']]}
    if request_key:store.send_result(request_key,response)
    return response

def send_due(server,now=None):
    """Undo window elapsed: claim and send. A retract that won the race leaves nothing to claim."""
    sent=0
    for item in server.drafts.due(now):
        with MUTATION:
            try:server.drafts.claim_scheduled(item['id'])
            except ValueError:continue
            try:deliver(server,item['id'],item['actor'],item['request_id'])
            except Exception:server.drafts.status(item['id'],'unknown');print('Nullmail scheduled send failed; outcome uncertain',flush=True)
            sent+=1
    return sent

TRACK_ORIGIN=ORIGIN

def serve(mailroot='/var/lib/nullmail/john/Maildir',state='/var/lib/nullmail/app',port=8789):
    os.umask(0o077);Path(state).mkdir(parents=True,exist_ok=True,mode=0o700)
    server=ThreadingHTTPServer(('127.0.0.1',port),Handler)
    server.outbound_enabled=outbound_enabled();server.undo_default=UNDO_DEFAULT
    server.mail=MailStore(mailroot);server.drafts=Drafts(Path(state)/'drafts.sqlite3')
    server.preview_key=secrets.token_bytes(32)
    workspace=api_v1.state(server);workspace.initialize_baseline(server.mail)
    server.gmail=Gmail(workspace);server.mail=CombinedMail(server.mail,server.gmail)
    def worker():
        last_purge=0
        while True:
            time.sleep(15)
            if time.time()-last_purge>3600:
                last_purge=time.time()
                try:
                    with MUTATION:
                        n=server.mail.purge_spam()
                    if n:print('Nullmail spam retention purged %d message(s)'%n,flush=True)
                except Exception:print('Nullmail spam retention purge failed',flush=True)
            try:
                with MUTATION:
                    identities=[a for p in control({'op':'status'})['projects'] for a in p['aliases']]
                    for account in server.gmail.accounts():
                        server.gmail.sync_page(account['actor'],account['id'])
                    identities += [a['id'] for a in server.gmail.accounts('local-owner')]
                    workspace.process_new(server.mail,identities)
                    api_v1.reviews(server).collect()
                    import receipts
                    with workspace.db() as db:receipts.scan(db,server.mail)
            except Exception:
                # No message content or credentials in logs. A claimed run is
                # never retried automatically after an uncertain filesystem step.
                print('Nullmail rule scan failed; inspect run history',flush=True)
    def scheduler():
        while True:
            time.sleep(1)
            try:send_due(server)
            except Exception:print('Nullmail scheduler error',flush=True)
    threading.Thread(target=worker,daemon=True).start()
    threading.Thread(target=scheduler,daemon=True).start()
    server.serve_forever()

if __name__=='__main__': serve()
