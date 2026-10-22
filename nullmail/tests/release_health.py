"""Read-only release health: temporary owner session, no message opens or sends.
Run explicitly as the existing Nullink service user. Never discover as unittest.
"""
import json,pathlib,sys,time,urllib.request,urllib.error
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[2]))
import server

def request(base,path,token=None,body=None,csrf=None):
    headers={}
    if token:headers['Cookie']='__Host-nullink_session='+token
    if body is not None:headers.update({'Origin':base,'Content-Type':'application/json','X-CSRF-Token':csrf or ''})
    req=urllib.request.Request(base+path,headers=headers,data=json.dumps(body).encode() if body is not None else None)
    try:
        with urllib.request.urlopen(req,timeout=30) as r:return r.status,r.read()
    except urllib.error.HTTPError as e:
        with e:return e.code,e.read()

before=server.load_sessions()
active_before={key for key,record in before.items() if float(record.get('expires_at',0))>time.time()}
assert len(before)<45,'Do not prune existing owner sessions'
# Keep all existing records when adding our temporary session. The running
# auth service remains the authority for logout and expiry.
server._prune_sessions=lambda sessions,now:sessions
token,_=server.create_session('127.0.0.1','Nullmail core release health (temporary)','deployment-check')
try:
    for base in ['https://nullmail.nullverse.cloud','https://nullmail.216.158.238.236.sslip.io']:
        for path in ['/api/v1/capabilities','/api/v1/gmail/status','/api/v1/accounts','/api/v1/rules','/api/v1/labels','/api/v1/sent','/api/v1/cases','/api/v1/cases/detail?id='+'a'*24,'/api/v1/cases/notes?id='+'a'*24,'/api/v1/cases/history?id='+'a'*24]:
            assert request(base,path)[0]==401
        assert request(base,'/health')[0]==200
        status,raw=request(base,'/api/v1/capabilities',token);assert status==200
        caps=json.loads(raw);assert caps['version']=='1' and caps['features']['rules'] and caps['features']['gmail'] and caps['gmail']['connected'] and caps['gmail']['configured'] and caps['gmail']['blockers']==[]
        status,raw=request(base,'/api/v1/gmail/status',token);assert status==200
        gmail=json.loads(raw);addresses=sorted(a['address'] for a in gmail['accounts'])
        assert gmail['connected'] and gmail['configured'] and gmail['blockers']==[] and 'ibbofez@gmail.com' in addresses and addresses==sorted(a['address'] for a in caps['gmail']['accounts'])
        assert request(base,'/api/v1/gmail/connect',token,{},csrf='invalid')[0]==403
        assert request(base,'/api/v1/accounts',token)[0]==200
        assert request(base,'/api/v1/rules',token)[0]==200
        assert request(base,'/api/v1/labels',token)[0]==200
        if caps['features'].get('cases'):
            assert request(base,'/api/v1/cases',token)[0]==200
            assert request(base,'/api/v1/cases/notes',token,{},csrf='invalid')[0]==403
        assert request(base,'/api/v1/rules/save',token,{},csrf='invalid')[0]==403
        for path in ['/app.js','/workspace.js','/style.css']+(['/cases.js'] if caps['features'].get('cases') else []):assert request(base,path)[0]==200
        print('PASS protected v1 endpoints, static assets, CSRF rejection and health:',base)
    status,raw=request('https://nullmail.nullverse.cloud','/api/v1/session',token);assert status==200
    csrf=json.loads(raw)['csrf']
    assert request('https://nullmail.nullverse.cloud','/api/v1/auth/logout',token,{},csrf)[0]==200
    assert request('https://nullmail.nullverse.cloud','/api/v1/session',token)[0]==401
    print('PASS session revocation; no mail opened, flags changed, rules run or SMTP sent')
finally:
    # Revocation through the running authority avoids a second independent
    # session-file write on the normal path. Never restore a stale snapshot.
    status,raw=request('https://nullmail.nullverse.cloud','/api/v1/session',token)
    if status==200:
        request('https://nullmail.nullverse.cloud','/api/v1/auth/logout',token,{},json.loads(raw)['csrf'])
    after=server.load_sessions()
    assert active_before.issubset(after),'Existing session set changed during verification; inspect without restoring stale state'
    assert server._session_key_from_cookie(token) not in after,'Temporary session was not revoked'
    print('PASS existing active sessions preserved')
