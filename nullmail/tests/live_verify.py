"""Explicit local admin check: temporary real session; no inbox bodies or credentials logged.
Run as the Nullink service user. Requires installed local Playwright/Chrome.
"""
import hashlib,json,os,pathlib,subprocess,sys,time,urllib.request,urllib.error
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[2]))
import server

def request(url,cookie=None,body=None,origin=None,csrf=None):
 headers={}
 if cookie:headers['Cookie']='__Host-nullink_session='+cookie
 if origin:headers['Origin']=origin
 if csrf:headers['X-CSRF-Token']=csrf
 if body is not None:headers['Content-Type']='application/json'
 req=urllib.request.Request(url,headers=headers,data=json.dumps(body).encode() if body is not None else None)
 try:
  with urllib.request.urlopen(req,timeout=30) as r:return r.status,r.headers,r.read()
 except urllib.error.HTTPError as e:
  with e:return e.code,e.headers,e.read()

assert len(server.load_sessions())<45,'Avoid pruning any existing sessions'
token,_=server.create_session('127.0.0.1','Nullmail deployment validation (temporary)','deployment-check')
base='https://nullmail.nullverse.cloud'
try:
 status,_,raw=request(base+'/api/session',token);assert status==200
 csrf=json.loads(raw)['csrf']
 status,_,raw=request(base+'/api/messages',token);assert status==200
 result=json.loads(raw);print('Live inbox count:',result['total'],'unread:',sum(m['unread'] for m in result['messages']))
 for p in ['/api/config','/api/projects','/api/drafts','/api/messages','/api/message?id=../etc/passwd','/api/attachment']:
  assert request(base+p)[0]==401
 assert request(base+'/api/projects',token,{'label':'must-not-register'},origin='https://evil.invalid',csrf=csrf)[0]==403
 assert request(base+'/api/projects',token,{'label':'must-not-register'},origin=base,csrf='bad')[0]==403
 status,_,html=request('https://nullverse.cloud/projects',token);assert status==200 and b'https://nullmail.nullverse.cloud' in html
 # Authenticated project helper write is idempotent: re-register an existing real seed.
 status,_,raw=request(base+'/api/projects',token,{'label':'axis'},origin=base,csrf=csrf);assert status==200,(status,raw[:100])
 print('PASS live API authentication, Origin/CSRF rejection, protected portal link, idempotent project registration')
 subprocess.run(['node',str(pathlib.Path(__file__).with_name('live_browser.cjs'))],input=json.dumps({'token':token}),text=True,check=True,env=os.environ)
 assert request(base+'/api/session',token)[0]==401
 print('PASS real session revocation after browser logout')
finally:
 server.revoke_session(token)
