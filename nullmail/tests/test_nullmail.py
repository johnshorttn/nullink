import concurrent.futures, email.message, http.client, json, os, pathlib, socket, sys, tempfile, threading, unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import app, control
from core import MailStore, Drafts, build_message, safe_name
from transport import DirectPostfix

FIXTURE={'projects':[{'name':'nullverse','domain':'nullverse.cloud','dns_status':'verified','mx_required':'nullverse.cloud. MX 25 mail.nullverse.cloud.','aliases':['john@nullverse.cloud','hello@nullverse.cloud']}],
'outbound':{'paused':True,'reason':'Fixture: TCP 25 unavailable; no transmission.','transport':'Direct Postfix','queued':[]},
'inbound':{'address':'john@nullverse.cloud'},'capacity':{'free':10**10,'total':20**10},
'dns':{'mail_a':['216.158.238.236'],'ptr':['provider.invalid.'],'ptr_required':'mail.nullverse.cloud','spf':[],'dmarc':[],'dkim':'Not provisioned','spf_guidance':'Confirm legitimate senders','dmarc_guidance':'Align first'},'checked_at':0}

def fake_nullink(path,cookie='',body=None,**kwargs):
    if path=='/api/auth/verify': return (200,b'{"ok":true}','__Host-nullink_session=fixture; Path=/; HttpOnly; Secure; SameSite=Lax') if json.loads(body).get('code')=='123456' else (401,b'{"error":"wrong_code"}',None)
    if path=='/api/auth/logout': return 200,b'{}','__Host-nullink_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax'
    return (200,b'{"authenticated":true,"auth_type":"session"}',None) if cookie=='__Host-nullink_session=fixture' else (401,b'{}',None)

def fake_control(data):
    if data['op']=='register':
        label=control.validate_label(data['label'])
        return {'registered':label,'dns':'pending'}
    return FIXTURE

def fixture(root):
    store=MailStore(root)
    m=email.message.EmailMessage();m['Return-Path']='<sender@example.com>';m['X-Original-To']='hello@nullverse.cloud';m['Delivered-To']='john@nullverse.cloud';m['Received']='by mail.nullverse.cloud for <hello@nullverse.cloud>';m['From']='Fixture Sender <sender@example.com>';m['To']='hello@nullverse.cloud';m['Subject']='<img src=x onerror=alert(1)> Fixture inbox';m['Message-ID']='<fixture@example.com>'
    m.set_content('Isolated fixture text. <script>window.pwned=1</script>');m.add_alternative('<script>window.pwned=1</script><img src="https://evil.invalid/pixel">',subtype='html')
    m.add_attachment(b'<script>alert(1)</script>',maintype='text',subtype='html',filename='../../unsafe".html')
    (root/'new'/'fixture-message').write_bytes(m.as_bytes())
    return store

class CoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.tmp.name);self.mail=fixture(self.root/'mail');self.ids=['john@nullverse.cloud','hello@nullverse.cloud']
        self.key=self.mail.listing()[0]['id']
    def tearDown(self):self.tmp.cleanup()
    def test_read_flags_trash_restore_preserve_bytes(self):
        before=self.mail.locate('inbox',self.key).read_bytes()
        self.assertTrue(self.mail.listing()[0]['unread']);m=self.mail.message('inbox',self.key)
        self.assertTrue(self.mail.listing()[0]['unread']) # GET has no side effects
        self.assertNotIn('https://evil.invalid',m['body']);self.assertEqual(m['recipient'],'hello@nullverse.cloud')
        self.mail.flag('inbox',self.key,True);self.assertFalse(self.mail.listing()[0]['unread'])
        self.mail.move('inbox',self.key,'trash');self.assertEqual(self.mail.listing(),[])
        self.mail.move('trash',self.key,'inbox');self.mail.flag('inbox',self.key,False)
        self.assertEqual(before,self.mail.locate('inbox',self.key).read_bytes())
    def test_paths_symlinks_and_attachment(self):
        for value in ['../secrets','%2e%2e%2f','/etc/passwd','a'*63]:
            with self.assertRaises(ValueError):self.mail.locate('inbox',value)
        (self.root/'mail/new/evil').symlink_to('/etc/passwd');self.assertEqual(len(self.mail.listing()),1)
        with self.assertRaises(ValueError):self.mail.listing('../../etc')
        m=self.mail.message('inbox',self.key);name,raw=self.mail.attachment('inbox',self.key,m['attachments'][0]['id'])
        self.assertNotIn('/',name);self.assertNotIn('"',name)
        with self.assertRaises(FileNotFoundError):self.mail.attachment('inbox',self.key,1)
    def test_search_and_original_recipient(self):
        self.assertEqual(len(self.mail.listing(query='fixture',recipient='hello@nullverse.cloud')),1)
        self.assertEqual(self.mail.listing(recipient='billing@nullverse.cloud'),[])
    def test_drafts_and_header_injection(self):
        drafts=Drafts(self.root/'drafts.db');d={'from':self.ids[0],'to':'reader@example.com','subject':'Example','body':'Hello'}
        for field,value in [('from','evil@example.com'),('to','a@example.com\r\nBcc: b@example.com'),('subject','Hi\nBcc: leak@example.com'),('in_reply_to','x\r\nInjected: yes')]:
            with self.assertRaises(ValueError):drafts.save(dict(d,**{field:value}),self.ids)
        saved=drafts.save(d,self.ids);recipients,raw=build_message(saved,self.ids)
        self.assertEqual(recipients,['reader@example.com']);self.assertIn(b'From: john@nullverse.cloud',raw)
        with patch('smtplib.SMTP',side_effect=AssertionError('No SMTP permitted')):
            self.assertEqual(DirectPostfix().submit(d['from'],recipients,raw)['status'],'paused')
        drafts.status(saved['id'],'paused');self.assertEqual(drafts.get(saved['id'])['status'],'paused')
    def test_project_schema(self):
        for s in ['../etc','abc\nthing','mail','nullmail','a.b','-evil','UPPER','a'*33,'x;id','x/xx']:
            with self.assertRaises(ValueError):control.validate_label(s)
        for s in ['nullink','axis','storycast','my-project','a']:self.assertEqual(control.validate_label(s),s)

class HttpTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();root=pathlib.Path(self.tmp.name)
        self.server=app.ThreadingHTTPServer(('127.0.0.1',0),app.Handler);self.server.mail=fixture(root/'mail');self.server.drafts=Drafts(root/'drafts.db')
        self.p1=patch('app.nullink',fake_nullink);self.p2=patch('app.control',fake_control);self.p1.start();self.p2.start()
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.csrf=self.req('/api/session')[1]['csrf']
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join();self.p1.stop();self.p2.stop();self.tmp.cleanup()
    def req(self,path,data=None,cookie='__Host-nullink_session=fixture',origin=app.ORIGIN,csrf=None,host='nullmail.nullverse.cloud'):
        c=http.client.HTTPConnection('127.0.0.1',self.server.server_port)
        h={'Host':host,'Cookie':cookie,'Origin':origin,'Content-Type':'application/json','X-CSRF-Token':csrf if csrf is not None else getattr(self,'csrf','')}
        if origin is None: del h['Origin']
        c.request('GET' if data is None else 'POST',path,body=None if data is None else json.dumps(data),headers=h)
        r=c.getresponse();raw=r.read();status=r.status;headers=dict(r.getheaders());c.close()
        try:body=json.loads(raw)
        except Exception:body=raw
        return status,body,headers
    def test_all_mail_apis_require_human_auth(self):
        for path in ['/api/messages','/api/message?id=../etc','/api/attachment','/api/drafts','/api/projects','/api/config']:
            for cookie in ['','__Host-nullink_session=forged']:
                self.assertEqual(self.req(path,cookie=cookie)[0],401,path)
        self.assertEqual(self.req('/api/messages',host='evil.invalid')[0],421)
    def test_every_write_requires_origin_and_csrf(self):
        for path in ['/api/projects','/api/drafts','/api/send','/api/message/read','/api/message/move','/api/auth/logout']:
            self.assertEqual(self.req(path,{},origin='https://evil.invalid')[0],403)
            self.assertEqual(self.req(path,{},csrf='bad')[0],403)
            self.assertEqual(self.req(path,{},cookie='')[0],401)
        self.assertEqual(self.req('/api/auth/verify',{'code':'123456'},origin='https://evil.invalid')[0],403)
    def test_dual_host_exact_origin_binding(self):
        sslip='nullmail.216.158.238.236.sslip.io'; sslip_origin='https://'+sslip
        self.assertEqual(self.req('/',host=sslip)[0],200)
        self.assertEqual(self.req('/health',host=sslip)[0],200)
        for path in ['/api/messages','/api/drafts','/api/config']:
            self.assertEqual(self.req(path,cookie='',host=sslip)[0],401,path)
        csrf=self.req('/api/session',host=sslip)[1]['csrf']
        self.assertEqual(self.req('/api/drafts',{'from':'john@nullverse.cloud','to':'','subject':'s','body':'b'},host=sslip,origin=sslip_origin,csrf=csrf)[0],200)
        self.assertEqual(self.req('/api/auth/verify',{'code':'123456'},host=sslip,origin=sslip_origin)[0],200)
        # Origins never cross hosts, and unlisted origins/hosts are refused.
        for host,origin in [(sslip,app.ORIGIN),('nullmail.nullverse.cloud',sslip_origin),(sslip,'https://evil.invalid'),
                            (sslip,'http://'+sslip),(sslip,sslip_origin+':443'),(sslip,'null'),(sslip,None),('127.0.0.1:8789',sslip_origin)]:
            self.assertEqual(self.req('/api/drafts',{},host=host,origin=origin,csrf=csrf)[0],403,(host,origin))
            self.assertEqual(self.req('/api/auth/verify',{'code':'123456'},host=host,origin=origin)[0],403,(host,origin))
        for host in ['nullmail.216.158.238.236.sslip.io.evil.invalid','nullverse.216.158.238.236.sslip.io','evil.sslip.io']:
            self.assertEqual(self.req('/api/messages',host=host)[0],421,host)
    def test_read_download_draft_and_paused_send(self):
        rows=self.req('/api/messages')[1]['messages'];key=rows[0]['id']
        status,msg,_=self.req('/api/message?id='+key);self.assertEqual(status,200)
        part=msg['attachments'][0]['id'];status,raw,h=self.req(f'/api/attachment?id={key}&part={part}')
        self.assertEqual(h['Content-Type'],'application/octet-stream');self.assertTrue(h['Content-Disposition'].startswith('attachment;'))
        self.assertEqual(h['X-Content-Type-Options'],'nosniff')
        self.assertEqual(self.req('/api/message/read',{'id':key,'folder':'inbox','read':True})[0],200)
        d=self.req('/api/drafts',{'from':'hello@nullverse.cloud','to':'reader@example.com','subject':'Fixture','body':'Hello'})[1]
        with patch('smtplib.SMTP',side_effect=AssertionError('No transmission')):
            self.assertEqual(self.req('/api/send',{'id':d['id']})[1]['status'],'paused')
        self.assertEqual(self.req('/api/projects',{'label':'fixture-project'})[0],200)
        self.assertEqual(self.req('/api/projects',{'label':'fixture-project','path':'/etc/passwd'})[0],400)

    def test_enabled_submission_acceptance_and_duplicate_protection(self):
        self.server.outbound_enabled=True
        d=self.req('/api/drafts',{'from':'hello@nullverse.cloud','to':'reader@example.com','subject':'Fixture','body':'Hello'})[1]
        with patch('transport.ssl.create_default_context'), patch('transport.smtplib.SMTP') as factory:
            smtp=factory.return_value
            smtp.mail.return_value=(250,b'OK');smtp.rcpt.return_value=(250,b'OK')
            smtp.data.return_value=(250,b'Ok: queued as ABC123')
            status,result,_=self.req('/api/send',{'id':d['id']})
            self.assertEqual(status,200);self.assertEqual(result['status'],'accepted');self.assertEqual(result['queue_id'],'ABC123')
            self.assertEqual(self.req('/api/send',{'id':d['id']})[0],400)
            self.assertEqual(self.req('/api/drafts',dict(d,body='changed'))[0],400)
            smtp.data.assert_called_once()
        self.assertEqual(self.server.mail.listing('sent'),[])

    def test_ambiguous_data_result_and_crash_claim_block_resend(self):
        self.server.outbound_enabled=True
        d=self.req('/api/drafts',{'from':'hello@nullverse.cloud','to':'reader@example.com','subject':'Fixture','body':'Hello'})[1]
        with patch('transport.ssl.create_default_context'), patch('transport.smtplib.SMTP') as factory:
            smtp=factory.return_value
            smtp.mail.return_value=(250,b'OK');smtp.rcpt.return_value=(250,b'OK')
            smtp.data.side_effect=TimeoutError('Lost acceptance response')
            self.assertEqual(self.req('/api/send',{'id':d['id']})[1]['status'],'unknown')
            self.assertEqual(self.req('/api/send',{'id':d['id']})[0],400)
            smtp.data.assert_called_once()
        e=self.req('/api/drafts',{'from':'hello@nullverse.cloud','to':'reader@example.com','body':'Crash fixture'})[1]
        self.server.drafts.claim(e['id'])
        self.assertEqual(self.req('/api/send',{'id':e['id']})[0],400)

    def test_recipient_rejection_never_submits_data(self):
        with patch('transport.ssl.create_default_context'), patch('transport.smtplib.SMTP') as factory:
            smtp=factory.return_value
            smtp.mail.return_value=(250,b'OK');smtp.rcpt.return_value=(550,b'No')
            self.assertEqual(DirectPostfix(enabled=True).submit('hello@nullverse.cloud',['reader@example.com'],b'fixture')['status'],'rejected')
            smtp.data.assert_not_called();smtp.rset.assert_called_once()

if __name__=='__main__':unittest.main()
