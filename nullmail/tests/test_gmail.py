import pathlib,sys,tempfile,unittest,base64,json,time,types
from urllib.parse import parse_qs,urlsplit
from cryptography.fernet import Fernet
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from workspace import Workspace,OWNER,permissions,require_read
from core import MailStore,Drafts
from gmail import Gmail,CombinedMail,ProviderError,RetryLater,FullSyncRequired,SCOPE
from cases import Cases
import api_v1

RAW=b'From: fixture@example.test\r\nTo: person@gmail.com\r\nSubject: Gmail fixture\r\nMessage-ID: <gmail-fixture@example.test>\r\n\r\nFixture body'
class GmailTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.tmp.name);self.state=Workspace(self.root/'state.db');self.calls=[];self.subject='google-stable-subject';self.email='person@gmail.com';self.pages={};self.fail=None
  self.client=Gmail(self.state,{'client_id':'fixture-client','client_secret':'fixture-secret','redirect_uris':['https://nullmail.nullverse.cloud/api/v1/gmail/callback'],'egress_ready':True},self.http,Fernet.generate_key())
 def tearDown(self):self.tmp.cleanup()
 def http(self,url,data=None,token=None,**kw):
  self.calls.append((url,data,token));path=urlsplit(url).path;q=parse_qs(urlsplit(url).query)
  if self.fail:raise self.fail
  if path=='/token':return {'access_token':'fixture-access','refresh_token':'fixture-refresh','scope':SCOPE,'expires_in':3600}
  if path.endswith('/userinfo'):return {'sub':self.subject,'email':self.email,'email_verified':True}
  if path.endswith('/profile'):return {'emailAddress':self.email,'historyId':'100'}
  if path.endswith('/messages/send'):return {'id':'sent123'}
  if path.endswith('/messages'):return self.pages.get(q.get('pageToken',[''])[0],{'messages':[{'id':'abc123'}]})
  if path.endswith('/history'):return self.pages.get('history',{'historyId':'101','history':[]})
  return {'id':path.split('/')[-1],'threadId':'thread123','raw':base64.urlsafe_b64encode(RAW).decode(),'labelIds':['INBOX','UNREAD'],'internalDate':'1700000000000'}
 def connect(self,actor=OWNER):
  url=self.client.begin(actor,'fixture-session','https://nullmail.nullverse.cloud/api/v1/gmail/callback');q=parse_qs(urlsplit(url).query)
  return self.client.complete(actor,'fixture-session',q['state'][0],'fixture-code')['account_id']
 def tick(self,key):
  with self.state.db() as db:db.execute('UPDATE gmail_accounts SET retry=0 WHERE id=?',(key,))
  return self.client.sync_page(OWNER,key)
 def test_oauth_pkce_state_one_use_encrypted_and_bound(self):
  url=self.client.begin(OWNER,'session','https://nullmail.nullverse.cloud/api/v1/gmail/callback');q=parse_qs(urlsplit(url).query);nonce=q['state'][0]
  self.assertEqual(q['code_challenge_method'],['S256']);self.assertNotIn('fixture-secret',url)
  with self.assertRaises(ProviderError):self.client.complete(OWNER,'wrong',nonce,'code')
  result=self.client.complete(OWNER,'session',nonce,'code');self.assertNotIn('access_token',str(result))
  with self.assertRaises(ProviderError):self.client.complete(OWNER,'session',nonce,'code')
  self.assertTrue(self.calls[0][1]['code_verifier']);self.assertEqual(self.client.access_token(OWNER,result['account_id']),'fixture-access')
  with self.state.db() as db:encrypted=db.execute('SELECT token FROM gmail_accounts').fetchone()[0]
  self.assertNotIn('fixture-access',encrypted);self.assertNotIn('fixture-refresh',encrypted)
  with self.assertRaises(PermissionError):self.client.access_token('other',result['account_id'])
 def test_no_config_no_network(self):
  g=Gmail(self.state,{},lambda *a,**k:self.fail('Network must not run'),key=b'')
  with self.assertRaises(ProviderError):g.begin(OWNER,'s','https://example.com')
  self.assertEqual(len(g.blockers()),3)
 def test_malformed_config_fails_closed_without_network(self):
  g=Gmail(self.state,['invalid'],lambda *a,**k:self.fail('No network'),Fernet.generate_key())
  self.assertTrue(g.blockers())
  with self.assertRaises(ProviderError):g.begin(OWNER,'session','https://example.test')
 def test_bad_redirect_and_expired_state(self):
  with self.assertRaises(ProviderError):self.client.begin(OWNER,'s','https://evil.test')
  url=self.client.begin(OWNER,'s','https://nullmail.nullverse.cloud/api/v1/gmail/callback');nonce=parse_qs(urlsplit(url).query)['state'][0]
  with self.state.db() as db:db.execute('UPDATE google_states SET expires=0')
  with self.assertRaises(ProviderError):self.client.complete(OWNER,'s',nonce,'code')
 def test_stable_account_and_import_pagination_dedup(self):
  key=self.connect();self.assertEqual(key,self.connect());self.client.set_backfill(OWNER,key,False);self.pages={'':{'messages':[{'id':'a'}],'nextPageToken':'next'},'next':{'messages':[{'id':'a'},{'id':'b'}]}}
  with self.assertRaises(ValueError):self.client.start_import(OWNER,key,False)
  self.client.start_import(OWNER,key,True);self.assertTrue(self.tick(key)['has_more']);r=self.tick(key);self.assertEqual((r['has_more'],r['stage']),(True,'older'));self.assertTrue(self.tick(key)['has_more']);r=self.tick(key);self.assertEqual((r['has_more'],r['stage']),(False,'complete'))
  with self.state.db() as db:
   self.assertEqual(db.execute('SELECT count(*) FROM gmail_messages').fetchone()[0],2);self.assertEqual(db.execute('SELECT count(*) FROM seen').fetchone()[0],2)
   self.assertEqual(db.execute('SELECT history FROM gmail_accounts').fetchone()[0],'100')
  self.tick(key)
  with self.state.db() as db:self.assertEqual(db.execute('SELECT history FROM gmail_accounts').fetchone()[0],'101')
 def test_backoff_preserves_checkpoint_and_expired_history_requires_action(self):
  key=self.connect();self.client.start_import(OWNER,key,True);self.tick(key);self.fail=RetryLater('fixture429')
  self.assertEqual(self.tick(key)['status'],'backoff');a=self.client.account(OWNER,key);self.assertGreater(a['retry'],time.time());self.assertEqual(a['history'],'100')
  calls=len(self.calls);self.client.sync_page(OWNER,key);self.assertEqual(calls,len(self.calls))
  self.fail=FullSyncRequired('expired');self.assertEqual(self.tick(key)['status'],'resync_required')
 def test_cache_routing_cases_move_labels_and_unauthorized(self):
  key=self.connect();self.client.start_import(OWNER,key,True);self.tick(key)
  mail=CombinedMail(MailStore(self.root/'local'),self.client);m=mail.listing()[0];ids=['john@nullverse.cloud',key];perm=permissions(OWNER,ids)
  enriched=self.state.enrich(m,ids);self.assertEqual(enriched['accounts'],[key]);self.assertEqual(enriched['routing_recipients'],[])
  with self.assertRaises(PermissionError):require_read(enriched,{'read':['john@nullverse.cloud']})
  service=Cases(self.state,mail,ids,OWNER,perm);ref=mail.reference(m['id']);c=service.create({'title':'Fixture case','request_id':'fixture-case-request','message':ref})['case']
  self.assertEqual(service.detail(c['id'])['case']['member_count'],1)
  self.assertEqual(self.state.enrich(mail.message('inbox',m['id']),ids)['labels'],[])
  mail.move('inbox',m['id'],'archive');self.assertEqual(service.resolve(ref)['folder'],'archive')
  self.client.ingest(OWNER,key,'abc123',False);self.assertEqual(service.resolve(ref)['folder'],'archive')
  with self.assertRaises(FileNotFoundError):Cases(self.state,mail,ids,OWNER,{'read':['john@nullverse.cloud']}).detail(c['id'])
  with self.assertRaises(FileNotFoundError):service.resolve(dict(ref,account_id='gmail:'+'0'*32))
 def test_two_accounts_native_id_collision_and_visibility(self):
  one=self.connect();self.email='other@gmail.com';self.subject='other-sub';two=self.connect()
  a=self.client.ingest(OWNER,one,'abc123',True);b=self.client.ingest(OWNER,two,'abc123',True);self.assertNotEqual(a,b)
  server=types.SimpleNamespace(workspace=self.state,gmail=self.client,mail=CombinedMail(MailStore(self.root/'local'),self.client),drafts=Drafts(self.root/'drafts.db'))
  handler=types.SimpleNamespace(server=server,identities=lambda:['john@nullverse.cloud'],auth_data={})
  self.assertEqual(len(api_v1.read(handler,'messages',{})['messages']),2)
  self.state.select(OWNER,[],['john@nullverse.cloud',one,two]);self.assertEqual(api_v1.read(handler,'messages',{})['total'],0)
  self.assertEqual(api_v1.read(handler,'messages',{'account':[one]})['total'],1)
  m=api_v1.message(handler,'inbox',a);self.assertEqual(m['reply_identity']['from'],'person@gmail.com')
  handler.auth_data={'user_id':'other-principal'}
  with self.assertRaises(PermissionError):api_v1.message(handler,'inbox',a)
  self.assertEqual(api_v1.read(handler,'accounts',{})['accounts'],[])
 def test_send_primary_only_and_unknown_not_retried(self):
  key=self.connect()
  with self.assertRaises(PermissionError):self.client.submit(OWNER,key,'spoof@example.test',RAW)
  self.assertEqual(self.client.submit(OWNER,key,'person@gmail.com',RAW)['status'],'accepted')
  self.fail=RetryLater('timeout');before=len(self.calls)
  self.assertEqual(self.client.submit(OWNER,key,'person@gmail.com',RAW)['status'],'unknown');self.assertEqual(len(self.calls),before+1)
 def test_historical_rules_zero_runs_and_preview_zero_writes(self):
  key=self.connect();local=MailStore(self.root/'local');self.state.initialize_baseline(local);self.client.start_import(OWNER,key,True);self.tick(key);mail=CombinedMail(local,self.client)
  self.assertEqual(self.state.process_new(mail,['john@nullverse.cloud',key]),0)
  before=self.state.path;before=pathlib.Path(before).read_bytes();result=self.state.preview(mail,['john@nullverse.cloud',key],[mail.listing()[0]['id']]);self.assertEqual(result['writes'],0);self.assertEqual(pathlib.Path(self.state.path).read_bytes(),before)

 def test_new_inbox_rules_case_action_scope_and_no_provider_writes(self):
  from test_workspace import rule
  from test_nullmail import fixture
  key=self.connect();local=fixture(self.root/'local');mail=CombinedMail(local,self.client);ids=['john@nullverse.cloud','hello@nullverse.cloud',key]
  self.state.initialize_baseline(mail)
  service=Cases(self.state,mail,ids,OWNER,permissions(OWNER,ids));local_id=local.listing()[0]['id']
  c=service.create({'title':'Cross provider','request_id':'cross-provider-request','message':mail.reference(local_id)})['case']
  label=self.state.label_save({'name':'Local label'})
  self.state.save_rule(rule(scope=[key],condition={'field':'subject','op':'contains','value':'fixture'},actions=[{'type':'add_label','value':label},{'type':'add_to_case','value':c['id']}]),OWNER,ids)
  mid=self.client.ingest(OWNER,key,'new123',False);calls=len(self.calls)
  self.assertEqual(self.state.process_new(mail,ids),1);self.assertEqual(self.state.process_new(mail,ids),0)
  self.assertEqual(service.detail(c['id'])['total'],2);self.assertEqual(self.state.enrich(mail.message('inbox',mid),ids)['labels'],[label])
  self.assertEqual(self.state.enrich(local.message('inbox',local_id),ids)['labels'],[]);self.assertEqual(len(self.calls),calls)
 def test_failed_page_does_not_advance_checkpoint_and_replay_dedups(self):
  key=self.connect();self.client.start_import(OWNER,key,True)
  original=self.client.ingest;count=[0]
  self.pages={'':{'messages':[{'id':'a'},{'id':'b'}],'nextPageToken':'next'}}
  def failing(*a,**kw):
   count[0]+=1
   if count[0]==2:raise RetryLater('partial page outage')
   return original(*a,**kw)
  self.client.ingest=failing;self.assertEqual(self.tick(key)['status'],'backoff')
  self.assertIsNone(self.client.account(OWNER,key)['page'])
  self.client.ingest=original;self.tick(key)
  with self.state.db() as db:self.assertEqual(db.execute('SELECT count(*) FROM gmail_messages').fetchone()[0],2)
  self.assertEqual(self.client.account(OWNER,key)['page'],'next')

if __name__=='__main__':unittest.main()

# HTTP fixtures exercise the same CSRF/auth/idempotency routes as the browser.
import test_nullmail as base
from unittest.mock import patch
class GmailApiTests(unittest.TestCase):
 req=base.HttpTests.req
 def setUp(self):
  base.HttpTests.setUp(self)
  self.g=GmailTests();self.g.setUp()
  self.server.workspace=self.g.state;self.server.gmail=self.g.client
  self.server.mail=CombinedMail(self.server.mail,self.g.client)
  self.key=self.g.connect();self.mid=self.g.client.ingest(OWNER,self.key,'abc123',True)
 def tearDown(self):
  base.HttpTests.tearDown(self);self.g.tearDown()
 def test_gmail_routes_csrf_auth_callback_and_send_idempotency_audit(self):
  self.assertEqual(self.req('/api/v1/gmail/status',cookie='')[0],401)
  for path in ('connect','import','sync'):
   self.assertEqual(self.req('/api/v1/gmail/'+path,{},csrf='bad')[0],403)
   self.assertEqual(self.req('/api/v1/gmail/'+path,{},origin='https://evil.invalid')[0],403)
  status,r,_=self.req('/api/v1/gmail/connect',{});self.assertEqual(status,200)
  nonce=parse_qs(urlsplit(r['authorization_url']).query)['state'][0]
  self.assertEqual(self.req('/api/v1/gmail/callback?state='+nonce+'&code=fixture')[0],303)
  self.assertEqual(self.req('/api/v1/gmail/callback?state='+nonce+'&code=fixture')[0],400)
  self.assertEqual(self.req('/api/v1/message?id='+self.mid)[1]['reply_identity']['from'],'person@gmail.com')
  self.assertEqual(self.req('/api/v1/drafts',{'from':'spoof@gmail.com','to':'fixture@example.test','body':'Fixture'})[0],400)
  d=self.req('/api/v1/drafts',{'from':'person@gmail.com','to':'fixture@example.test','body':'Fixture'})[1]
  with patch('app.DirectPostfix',side_effect=AssertionError('Google must never use SMTP')):
   one=self.req('/api/v1/send',{'id':d['id'],'request_id':'gmail-fixture-send-key'});two=self.req('/api/v1/send',{'id':d['id'],'request_id':'gmail-fixture-send-key'})
  self.assertEqual(one[0],200);self.assertEqual(one[1],two[1]);self.assertEqual(one[1]['provider'],'gmail')
  self.assertEqual(sum(url.endswith('/messages/send') for url,_,_ in self.g.calls),1)
  audit=self.req('/api/v1/sent')[1]['records'][0];self.assertEqual(audit['actor'],OWNER);self.assertEqual(audit['identity'],'person@gmail.com')
  def delegated(path,*a,**kw):
   if path=='/api/me':return 200,b'{"authenticated":true,"auth_type":"session","user_id":"other"}',None
   return base.fake_nullink(path,*a,**kw)
  with patch('app.nullink',delegated):
   self.assertEqual(self.req('/api/v1/message?id='+self.mid)[0],403)
   self.assertEqual(self.req('/api/v1/gmail/status')[1]['accounts'],[])
   self.assertEqual(self.req('/api/v1/gmail/import',{'account_id':self.key,'confirm':True})[0],403)
   self.assertEqual(self.req('/api/v1/send',{'id':d['id'],'request_id':'gmail-fixture-other-key'})[0],403)
