"""Nullmail HTTP service, loopback only. Auth delegated to Nullink's human API."""
import hashlib, hmac, http.client, ipaddress, json, os, secrets, socket, threading
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs
from core import MailStore, Drafts, build_message
from transport import DirectPostfix

STATIC=Path(__file__).parent/'static'
ORIGIN='https://nullmail.nullverse.cloud'
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

class Handler(BaseHTTPRequestHandler):
    server_version='Nullmail'
    def setup(self):
        super().setup()
        self.connection.settimeout(20)
    def log_message(self,*args): pass # Never log message IDs, recipients, cookies or bodies.
    def reply(self,status,data,kind='application/json; charset=utf-8',extra=None):
        if not isinstance(data,bytes): data=json.dumps(data).encode()
        self.send_response(status)
        for k,v in {'Content-Type':kind,'Content-Length':str(len(data)),'Cache-Control':'no-store',
                    'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer',
                    'Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",**(extra or {})}.items(): self.send_header(k,v)
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
        return data.get('authenticated') is True and data.get('auth_type')=='session'
    def valid_host(self):
        hosts=self.headers.get_all('Host',[])
        return len(hosts)==1 and hosts[0] in ('nullmail.nullverse.cloud','127.0.0.1:8789')
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
    def dispatch(self,write):
        try:
            if not self.valid_host(): return self.reply(421,{'error':'Untrusted host'})
            path=urlsplit(self.path).path
            if write and (self.headers.get('Origin')!=ORIGIN or self.headers.get('Sec-Fetch-Site') not in (None,'same-origin')):
                return self.reply(403,{'error':'Origin rejected'})
            if not write and path in ('/','/app.js','/style.css'):
                f={'/':'index.html','/app.js':'app.js','/style.css':'style.css'}[path]
                return self.reply(200,(STATIC/f).read_bytes(),{'/':'text/html; charset=utf-8','/app.js':'text/javascript; charset=utf-8','/style.css':'text/css; charset=utf-8'}[path])
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
        except FileNotFoundError: self.reply(404,{'error':'Not found'})
        except (ValueError,TypeError,KeyError) as e: self.reply(400,{'error':str(e)[:180]})
        except Exception: self.reply(503,{'error':'Service unavailable. Try again shortly.'})
    def read_api(self,path,q):
        folder=q.get('folder',['inbox'])[0]
        if path=='/api/session': return self.reply(200,{'authenticated':True,'csrf':self.csrf()})
        if path=='/api/config' or path=='/api/projects':
            return self.reply(200,control({'op':'status'}))
        if path=='/api/messages':
            rows=self.server.mail.listing(folder,q.get('q',[''])[0][:200],q.get('recipient',[''])[0][:254],q.get('unread',[''])[0]=='1')
            offset=max(0,int(q.get('offset',['0'])[0]));return self.reply(200,{'total':len(rows),'messages':rows[offset:offset+100]})
        if path=='/api/message': return self.reply(200,self.server.mail.message(folder,q.get('id',[''])[0]))
        if path=='/api/attachment':
            name,body=self.server.mail.attachment(folder,q.get('id',[''])[0],int(q.get('part',['-1'])[0]))
            return self.reply(200,body,'application/octet-stream',{'Content-Disposition':f'attachment; filename="{name}"'})
        if path=='/api/drafts': return self.reply(200,{'drafts':self.server.drafts.list()})
        return self.reply(404,{'error':'Not found'})
    def identities(self):
        return [a for p in control({'op':'status'})['projects'] for a in p['aliases']]
    def write_api(self,path,data):
        if path=='/api/auth/logout':
            status,body,cookie=nullink(path,self.cookie(),b'{}');return self.reply(status,body,extra={'Set-Cookie':cookie} if cookie else None)
        if path=='/api/message/read':
            if not isinstance(data.get('read'),bool): raise ValueError('read must be boolean')
            self.server.mail.flag(data['folder'],data['id'],data['read']);return self.reply(200,{'ok':True})
        if path=='/api/message/move':
            self.server.mail.move(data['folder'],data['id'],data['target']);return self.reply(200,{'ok':True})
        if path=='/api/projects':
            if set(data)!={'label'}: raise ValueError('Only a project label is accepted')
            return self.reply(200,control({'op':'register','label':data['label']}))
        if path=='/api/drafts': return self.reply(200,self.server.drafts.save(data,self.identities()))
        if path=='/api/send':
            draft=self.server.drafts.get(data.get('id'))
            if not draft: raise FileNotFoundError()
            if draft['status'] not in ('draft','paused'): raise ValueError('Already submitted; duplicate send blocked')
            recipients,raw=build_message(draft,self.identities())
            # Fixed paused transport. Activation is deliberately outside this web API.
            result=DirectPostfix(enabled=False).submit(draft['from'],recipients,raw)
            self.server.drafts.status(draft['id'],result['status'],result['queue_id'])
            return self.reply(200,{'id':draft['id'],**result,'message':'Saved in paused Outbox. Nothing was sent. Open and click Send again after an administrator enables delivery.'})
        return self.reply(404,{'error':'Not found'})

def serve(mailroot='/var/lib/nullmail/john/Maildir',state='/var/lib/nullmail/app',port=8789):
    os.umask(0o077);Path(state).mkdir(parents=True,exist_ok=True,mode=0o700)
    server=ThreadingHTTPServer(('127.0.0.1',port),Handler)
    server.mail=MailStore(mailroot);server.drafts=Drafts(Path(state)/'drafts.sqlite3')
    server.serve_forever()

if __name__=='__main__': serve()
