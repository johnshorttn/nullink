import pathlib,sys,tempfile,unittest,base64,json,time
from urllib.parse import parse_qs,urlsplit
from cryptography.fernet import Fernet
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from workspace import Workspace,OWNER
from core import MailStore
import gmail
from gmail import Gmail,CombinedMail,SCOPE,TooLarge,RetryLater

BIG=bytes(range(256))*(3*1024*1024//256+7)   # > 2 MiB attachment
def b64(b):return base64.urlsafe_b64encode(b).decode()
class LargeGmailTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.tmp.name);self.state=Workspace(self.root/'state.db')
  self.lists=[];self.scope=SCOPE;self.posts=[];self.glabels={};self.rawcalls=0;self.fail_attach=0;self.big_ids={'big1'}
  self.client=Gmail(self.state,{'client_id':'c','client_secret':'s','redirect_uris':['https://nullmail.nullverse.cloud/api/v1/gmail/callback'],'egress_ready':True},self.http,Fernet.generate_key())
  self.client.stream=self.stream
 def tearDown(self):self.tmp.cleanup()
 def http(self,url,data=None,token=None,**kw):
  p=urlsplit(url).path;q={k:v[0] for k,v in parse_qs(urlsplit(url).query).items()}
  if p=='/token':return {'access_token':'a','refresh_token':'r','scope':self.scope,'expires_in':3600}
  if data is not None and p.endswith('/modify'):self.posts.append((p,data));return {'id':'x','labelIds':['INBOX']+data['addLabelIds']}
  if data is not None and p.endswith('/me/labels'):self.posts.append((p,data));return {'id':'Label_9','name':data['name']}
  if p.endswith('/userinfo'):return {'sub':'sub','email':'person@gmail.com','email_verified':True}
  if p.endswith('/profile'):return {'emailAddress':'person@gmail.com','historyId':'100'}
  if p.endswith('/messages'):
   self.lists.append(q)
   if q.get('q')=='newer_than:30d':return {'messages':[{'id':'big1'},{'id':'small1'}]}
   return {'messages':[{'id':'old1'}]}
  if p.endswith('/history'):return {'historyId':'101','history':[]}
  native=p.split('/')[-1]
  if p.endswith('/labels'):return {'labels':[{'id':'INBOX','name':'INBOX','type':'system'},{'id':'Label_1','name':'Clients/Acme','type':'user'},{'id':'Label_2','name':'Receipts','type':'user'}]}
  if q.get('format')=='minimal':return {'id':native,'sizeEstimate':5_000_000 if native in self.big_ids else 300,'labelIds':self.glabels.get(native,['INBOX'])}
  if q.get('format')=='raw':
   self.rawcalls+=1
   if native in self.big_ids:raise TooLarge('Provider response exceeds limit')
   labels=['SPAM'] if native.startswith('spam') else ['TRASH'] if native.startswith('trash') else ['INBOX']
   labels=self.glabels.get(native,labels)
   when=str(int(time.time()*1000)-86400000) if native.endswith('new') else '1700000000000'
   return {'id':native,'raw':b64(b'From: a@example.test\r\nSubject: small '+native.encode()+b'\r\n\r\nhi'),'labelIds':labels,'internalDate':when}
  if q.get('format')=='full':
   self.assertEqual(kw.get('limit'),gmail.MAX_FULL)
   return {'id':native,'threadId':'t','labelIds':['INBOX','UNREAD'],'internalDate':'1700000000000','payload':{'mimeType':'multipart/mixed','headers':[{'name':'From','value':'big@example.test'},{'name':'Subject','value':'Big one'},{'name':'Content-Type','value':'multipart/mixed; boundary="xyz"'}],'parts':[
    {'mimeType':'text/plain','headers':[{'name':'Content-Type','value':'text/plain; charset=utf-8'}],'body':{'data':b64(b'Body of the big mail')}},
    {'mimeType':'application/pdf','filename':'report.pdf','headers':[{'name':'Content-Type','value':'application/pdf'},{'name':'Content-Disposition','value':'attachment; filename="report.pdf"'}],'body':{'attachmentId':'ATT1','size':len(BIG)}}]}}
  raise AssertionError(url)
 def stream(self,url,token,dest,limit):
  self.assertIn('/attachments/ATT1',url);self.assertEqual(limit,gmail.MAX_PART)
  if self.fail_attach:self.fail_attach-=1;raise RetryLater('fixture 503')
  pathlib.Path(dest).write_bytes(json.dumps({'size':len(BIG),'data':b64(BIG)}).encode())
 def connect(self):
  url=self.client.begin(OWNER,'s','https://nullmail.nullverse.cloud/api/v1/gmail/callback');n=parse_qs(urlsplit(url).query)['state'][0]
  return self.client.complete(OWNER,'s',n,'code')['account_id']
 def tick(self,key):
  with self.state.db() as db:db.execute('UPDATE gmail_accounts SET retry=0 WHERE id=?',(key,))
  return self.client.sync_page(OWNER,key)
 def test_recent_first_then_older_including_spam_trash_and_large_segmented(self):
  key=self.connect();self.client.set_backfill(OWNER,key,False);self.client.start_import(OWNER,key,True)
  r=self.tick(key);self.assertEqual((r['status'],r['stage']),('import','older'))
  self.assertEqual(self.lists[0]['q'],'newer_than:30d');self.assertEqual(self.lists[0]['includeSpamTrash'],'true')
  r=self.tick(key);self.assertEqual((r['status'],r['stage']),('history','complete'));self.assertEqual(self.lists[1]['q'],'older_than:30d')
  a=self.client.accounts(OWNER)[0];self.assertEqual((a['imported'],a['skipped']),(3,0))
  mail=CombinedMail(MailStore(self.root/'local'),self.client)
  big=[m for m in mail.listing() if m['subject']=='Big one'][0]
  msg=mail.message('inbox',big['id']);self.assertIn('Body of the big mail',msg['body'])
  att=msg['attachments'];self.assertEqual([(x['name'],x['size']) for x in att],[('report.pdf',len(BIG))])
  name,body=mail.attachment('inbox',big['id'],att[0]['id']);self.assertEqual(name,'report.pdf');self.assertEqual(body,BIG)
  self.assertLessEqual(mail.gmail.cache.locate('inbox',big['id']).stat().st_size,gmail.MAX_MAIL)
  raw,parts=mail.source('inbox',big['id']);self.assertEqual([p['name'] for p in parts],['report.pdf'])
  eml,full=mail.eml('inbox',big['id']);self.assertTrue(full)
  import email as _e,email.policy as _p;att=[p for p in _e.message_from_bytes(eml,policy=_p.default).walk() if p.get_filename()=='report.pdf'][0]
  self.assertEqual(att.get_payload(decode=True),BIG);self.assertIsNone(att.get('X-Nullmail-Gmail-Attachment'))
 def test_failure_recorded_and_retried_not_dropped(self):
  key=self.connect();self.client.set_backfill(OWNER,key,False);self.client.start_import(OWNER,key,True);self.fail_attach=1
  # transient failure of the attachment backs off the page; the page is retried, nothing is lost
  self.assertEqual(self.tick(key)['status'],'backoff');self.assertEqual(self.tick(key)['stage'],'older')
  self.assertEqual(self.client.accounts(OWNER)[0]['skipped'],0)
  # a hard failure is recorded and retried on later ticks
  self.client.record_failure(key,'big1',gmail.ProviderError('fixture'))
  with self.state.db() as db:db.execute('UPDATE gmail_skipped SET retry=0')
  self.tick(key);self.assertEqual(self.client.accounts(OWNER)[0]['skipped'],0)
 def test_attachment_json_stream_decoder_bounded(self):
  src=self.root/'a.json';src.write_bytes(json.dumps({'size':1,'data':b64(BIG)}).encode())
  self.assertEqual(gmail.decode_attachment_json(src,self.root/'o.bin'),len(BIG));self.assertEqual((self.root/'o.bin').read_bytes(),BIG)
  with self.assertRaises(TooLarge):gmail.decode_attachment_json(src,self.root/'o2.bin',1000)
 def test_spam_folder_retention_tombstone_and_migration(self):
  key=self.connect();mail=CombinedMail(MailStore(self.root/'local'),self.client)
  for n in ('spamold','spamnew','trashold'):self.client.ingest(OWNER,key,n,True)
  subj=lambda f:sorted(m['subject'] for m in mail.listing(f))
  self.assertEqual(subj('spam'),['small spamnew','small spamold']);self.assertEqual(subj('trash'),['small trashold'])
  self.assertEqual(mail.purge_spam(),1);self.assertEqual(subj('spam'),['small spamnew']);self.assertEqual(subj('trash'),['small trashold'])
  self.assertIsNone(self.client.ingest(OWNER,key,'spamold',True));self.assertEqual(subj('spam'),['small spamnew'])
  with self.state.db() as db:self.assertEqual(db.execute("SELECT count(*) FROM gmail_messages WHERE native='spamold'").fetchone()[0],0)
  # Not spam -> Inbox, Mark as spam -> Spam
  sid=mail.listing('spam')[0]['id'];mail.move('spam',sid,'inbox');self.assertIn('small spamnew',subj('inbox'));mail.move('inbox',sid,'spam')
  # one-time migration: Gmail SPAM filed in Trash moves to Spam, real trash stays
  p=mail.gmail.cache.locate('spam',sid);import os;os.replace(p,mail.gmail.cache.root/'.Trash'/p.parent.name/p.name)
  with self.state.db() as db:db.execute("DELETE FROM gmail_meta")
  self.assertEqual(self.client.migrate_spam(),1);self.assertEqual(subj('spam'),['small spamnew']);self.assertEqual(subj('trash'),['small trashold'])
  self.assertEqual(self.client.migrate_spam(),0)
 def test_local_spam_move_and_purge(self):
  local=MailStore(self.root/'local');f=local.root/'cur'/'m1:2,S';f.write_bytes(b'Subject: local\r\n\r\nx')
  k=local.key(f);local.move('inbox',k,'spam');mail=CombinedMail(local,self.client)
  self.assertEqual(mail.purge_spam(),0);import os;p=local.locate('spam',k);os.utime(p,(1,1))
  self.assertEqual(mail.purge_spam(),1);self.assertEqual(list(local.files('spam')),[])
 def test_backfill_paused_by_default_new_mail_continues_and_resume(self):
  key=self.connect();self.assertTrue(self.client.accounts(OWNER)[0]['backfill_paused']);self.client.start_import(OWNER,key,True)
  r=self.tick(key);self.assertEqual((r['status'],r['stage']),('history','older_paused'))
  n=len(self.lists);self.tick(key);self.assertEqual(len(self.lists),n)   # no older listing while paused
  self.assertEqual(self.client.accounts(OWNER)[0]['imported'],2)
  self.assertEqual(self.client.set_backfill(OWNER,key,False),{'backfill_paused':False,'phase':'import','stage':'older'})
  r=self.tick(key);self.assertEqual(self.lists[-1]['q'],'older_than:30d');self.assertEqual((r['status'],r['stage']),('history','complete'))
  # pausing mid-backfill stops it immediately
  self.client.start_import(OWNER,key,True);self.client.set_backfill(OWNER,key,False);self.tick(key)
  self.assertEqual(self.client.set_backfill(OWNER,key,True)['stage'],'older_paused')
  with self.assertRaises(ValueError):self.client.set_backfill(OWNER,key,'no')
 def test_provider_labels_backfill_operators_and_mapping(self):
  import api_v1
  key=self.connect();self.client.ingest(OWNER,key,'small1',True)
  with self.state.db() as db:db.execute('UPDATE gmail_messages SET labels_checked=0')
  self.glabels['small1']=['INBOX','Label_1','CATEGORY_PROMOTIONS','STARRED','IMPORTANT','UNREAD'];raws=self.rawcalls
  self.assertTrue(self.client.refresh_labels(OWNER,key,force=True));self.assertFalse(self.client.refresh_labels(OWNER,key))
  self.assertEqual(self.client.label_backfill(OWNER,key),1);self.assertEqual(self.rawcalls,raws)   # labels only, no body
  self.assertEqual(self.client.label_backfill(OWNER,key),0)
  cat={l['id']:l for l in self.client.label_catalog(OWNER)[0]['labels']}
  self.assertEqual((cat['Label_1']['name'],cat['Label_1']['count'],cat['Label_1']['unread'],cat['Label_1']['kind']),('Clients/Acme',1,1,'user'))
  self.assertEqual((cat['CATEGORY_PROMOTIONS']['name'],cat['CATEGORY_PROMOTIONS']['kind']),('Promotions','category'))
  self.assertEqual(cat['STARRED']['kind'],'system')
  mail=CombinedMail(MailStore(self.root/'local'),self.client);m=mail.listing()[0]
  self.assertTrue(all(d['provider']=='gmail' for d in m['provider_label_details']))
  ok=lambda q:api_v1.operator_match(m,api_v1.parse_query(q)[1])
  for q in ('category:promotions','glabel:Clients','glabel:"Clients/Acme"','is:starred','is:important'):self.assertTrue(ok(q),q)
  for q in ('category:social','glabel:Receipts','glabel:Cli'):self.assertFalse(ok(q),q)
  self.assertEqual(api_v1.parse_query('invoice category:promotions')[0],'invoice')
  self.assertTrue(api_v1.operator_match(m,[],'Label_1'));self.assertFalse(api_v1.operator_match(m,[],'Label_2'))
  # changed labels on sync: minimal fetch only, no body re-download
  self.glabels['small1']=['INBOX','Label_2'];self.client.ingest(OWNER,key,'small1',False);self.assertEqual(self.rawcalls,raws)
  self.assertEqual(mail.listing()[0]['provider_labels'],['INBOX','Label_2'])
  # mapping to Nullmail labels: once + auto, local only
  lid='a'*24;self.state.label_save({'id':lid,'name':'Money','color':'#336699','parent':None})
  self.assertEqual(self.client.map_label(OWNER,key,'Label_2',lid,'once'),{'applied':1,'mode':'once'})
  self.assertEqual(self.client.map_label(OWNER,key,'Label_2',lid,'auto')['applied'],0)
  self.glabels['small2']=['INBOX','Label_2'];self.client.ingest(OWNER,key,'small2',True)
  n2=[x for x in mail.listing() if x['subject']=='small small2'][0]
  self.assertEqual(self.state.enrich(n2,[key])['labels'],[lid])
  self.assertEqual(self.client.unmap_label(OWNER,key,'Label_2',lid),{'removed':1})
  with self.assertRaises(ValueError):self.client.map_label(OWNER,key,'Label_2','b'*24,'auto')
  with self.assertRaises(ValueError):self.client.map_label(OWNER,key,'Label_2',lid,'forever')
 def test_write_back_disabled_without_modify_scope(self):
  self.scope=' '.join(x for x in SCOPE.split() if 'modify' not in x and 'labels' not in x)
  key=self.connect();st=self.client.sync.status('gmail',key)
  self.assertEqual((st['enabled'],st['reason']),(False,'Reconnect Gmail to allow label sync'))
  self.client.ingest(OWNER,key,'small1',True);mail=CombinedMail(MailStore(self.root/'local'),self.client)
  mid=mail.listing()[0]['id'];mail.move('inbox',mid,'spam');mail.flag('spam',mid,True)
  self.assertIsNone(self.client.sync.enqueue('gmail',key,'small1',add_names=['X']))
  with self.state.db() as db:self.assertEqual(db.execute('SELECT count(*) FROM provider_ops').fetchone()[0],0)
  with self.assertRaises(PermissionError):self.client.sync.create_label('gmail',key,'X')
  self.client.sync.process();self.assertEqual(self.posts,[])
 def test_write_back_labels_cases_folders_read_and_create_prompt(self):
  key=self.connect();self.assertTrue(self.client.sync.status('gmail',key)['enabled'])
  self.client.refresh_labels(OWNER,key,force=True);self.client.ingest(OWNER,key,'small1',True)
  sync=self.client.sync;ad=sync.adapter('gmail')
  self.assertEqual(ad.case_label('Acme dispute'),'Cases/Acme dispute')
  self.assertEqual(sync.missing('gmail',key,['receipts','Cases/Acme dispute']),['Cases/Acme dispute'])
  sync.enqueue('gmail',key,'small1',add_names=['Receipts']);sync.process()
  self.assertEqual(self.posts[-1],('/gmail/v1/users/me/messages/small1/modify',{'addLabelIds':['Label_2'],'removeLabelIds':[]}))
  sync.enqueue('gmail',key,'small1',add_names=['Cases/Acme dispute']);sync.process()
  self.assertEqual(sync.status('gmail',key)['queue'].get('needs_label'),1);n=len(self.posts)
  self.assertEqual(sync.create_label('gmail',key,'Cases/Acme dispute'),'Label_9');self.assertEqual(self.posts[n][1]['name'],'Cases/Acme dispute')
  sync.process();self.assertEqual(self.posts[-1][1]['addLabelIds'],['Label_9'])
  self.assertEqual(sync.create_label('gmail',key,'cases/acme dispute'),'Label_9')   # no duplicate create
  mail=CombinedMail(MailStore(self.root/'local'),self.client);mid=mail.listing()[0]['id']
  mail.move('inbox',mid,'spam');mail.move('spam',mid,'inbox');mail.move('inbox',mid,'archive');mail.flag('archive',mid,True);mail.move('archive',mid,'trash')
  self.posts.clear();sync.process()
  self.assertEqual([(d['addLabelIds'],d['removeLabelIds']) for _,d in self.posts],[(['SPAM'],['INBOX']),(['INBOX'],['SPAM']),([],['INBOX']),([],['UNREAD'])])
  self.assertTrue(all(p.endswith(('/modify','/me/labels')) for p,_ in self.posts))   # trash not mirrored; nothing deleted
  sync.enqueue('gmail',key,'small1',remove_names=['Nonexistent']);self.posts.clear();sync.process();self.assertEqual(self.posts,[])
 def test_legacy_readonly_send_grant_keeps_import_but_disables_write_back(self):
  self.scope='openid email '+gmail.READ+' '+gmail.SEND
  key=self.connect();self.client.ingest(OWNER,key,'small1',True)
  self.assertEqual(self.client.accounts(OWNER)[0]['imported'],1)
  self.assertFalse(self.client.sync.status('gmail',key)['enabled'])
  self.assertEqual(gmail.missing_scopes(self.client.granted_scopes(key)),gmail.REQUESTED)
  self.assertEqual(gmail.SCOPE.split(),['openid','email','https://mail.google.com/','https://www.googleapis.com/auth/gmail.modify','https://www.googleapis.com/auth/gmail.labels','https://www.googleapis.com/auth/gmail.compose','https://www.googleapis.com/auth/gmail.settings.basic','https://www.googleapis.com/auth/gmail.settings.sharing'])
 def test_setup_status_details_never_leak_tokens_and_shortcuts(self):
  key=self.connect();self.client.start_import(OWNER,key,True);self.client.sync_now(OWNER,key)
  d=self.client.details(OWNER)[0];blob=json.dumps(d)
  for secret in ('"a"','"r"','refresh_token":"','access_token'):self.assertNotIn(secret,blob)
  self.assertEqual(d['provider'],'gmail');self.assertTrue(d['token']['decryptable']);self.assertTrue(d['token']['refresh_token'])
  self.assertEqual(d['last_sync']['status'],'ok');self.assertEqual(d['missing_scopes'],[]);self.assertTrue(d['writeback']['enabled'])
  self.client.record_failure(key,'big1',gmail.ProviderError('x'))
  with self.state.db() as db:db.execute("INSERT INTO provider_ops VALUES ('op1','gmail',?,'small1','[]','[]','[]','[]','failed',8,0,'e',0)",(key,))
  self.assertEqual(self.client.retry_failed_now(OWNER,key),{'messages_requeued':1,'writeback_requeued':1})
  with self.assertRaises(PermissionError):self.client.sync_now('intruder',key)
if __name__=='__main__':unittest.main()
