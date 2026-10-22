"""Loopback fixture: real Nullink auth in temporary storage, fake DNS/maps only."""
import pathlib,sys,threading,copy,os
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from test_auth_integration import AuthIntegration
from test_nullmail import fixture,FIXTURE
import app,control
from core import Drafts,ALIASES
state=AuthIntegration();state.setUp()
import server as nullink
nullink.write_otp('123456')
config=copy.deepcopy(FIXTURE);config['inbound']['max_message_bytes']=262144
for label in ['nullink','storycast','axis']:
 config['projects'].append({'name':label,'domain':label+'.nullverse.cloud','dns_status':'pending','mx_required':label+'.nullverse.cloud. MX 25 mail.nullverse.cloud.','aliases':[a+'@'+label+'.nullverse.cloud' for a in ALIASES]})
def fake_control(data):
 if data['op']=='register':
  label=control.validate_label(data['label']);config['projects'].append({'name':label,'domain':label+'.nullverse.cloud','dns_status':'pending','mx_required':label+'.nullverse.cloud. MX 25 mail.nullverse.cloud.','aliases':[a+'@'+label+'.nullverse.cloud' for a in ALIASES]});return {'registered':label}
 return config
app.control=fake_control
root=pathlib.Path(state.tmp.name)
httpd=app.ThreadingHTTPServer(('127.0.0.1',int(os.environ.get('NULLMAIL_FIXTURE_PORT','8798'))),app.Handler);httpd.mail=fixture(root/'mail');httpd.drafts=Drafts(root/'drafts.db')
if os.environ.get('NULLMAIL_FIXTURE_GMAIL')=='1':
 from test_gmail import GmailTests
 from gmail import CombinedMail
 gmail_fixture=GmailTests();gmail_fixture.setUp()
 httpd.workspace=gmail_fixture.state;httpd.gmail=gmail_fixture.client
 gmail_account=gmail_fixture.connect();gmail_fixture.client.ingest('local-owner',gmail_account,'abc123',True)
 httpd.mail=CombinedMail(httpd.mail,httpd.gmail)
if os.environ.get('NULLMAIL_FIXTURE_CASES')=='1':
 config['projects'][0]['aliases'].append('support@nullverse.cloud')
 first=httpd.mail.listing()[0]['id']
 raw=httpd.mail.locate('inbox',first).read_bytes().replace(b'hello@nullverse.cloud',b'support@nullverse.cloud').replace(b'<fixture@example.com>',b'<another-thread@example.com>').replace(b'Fixture inbox',b'Second work item')
 (root/'mail/new/second-case-fixture').write_bytes(raw)
if os.environ.get('NULLMAIL_FIXTURE_OUTBOUND')=='1':
 httpd.outbound_enabled=True
 class NonTransmitting:
  def __init__(self,**kwargs):pass
  def submit(self,*args,**kw):return {'status':'accepted','queue_id':'FIXTURE123'}
 app.DirectPostfix=NonTransmitting
def _simulate_receipts():
 # Plays the remote side: for each accepted outbound message, drop a DSN (delivered) and an MDN (read) into the inbox, then scan.
 import receipts,api_v1,time as _t
 store=api_v1.state(httpd)
 with store.db() as db:
  receipts.init(db)
  for draft,mid,envid,rcpts in db.execute("SELECT draft,message_id,envid,recipients FROM outbound_meta WHERE draft NOT IN (SELECT draft FROM receipt_events)").fetchall():
   r=rcpts.split(',')[0]
   dsn=(f'From: MAILER-DAEMON@mail.example.test\nTo: john@nullverse.cloud\nSubject: Successful Mail Delivery Report\nMIME-Version: 1.0\nContent-Type: multipart/report; report-type=delivery-status; boundary=B\n\n--B\nContent-Type: text/plain\n\nDelivered\n--B\nContent-Type: message/delivery-status\n\nReporting-MTA: dns; mail.example.test\nOriginal-Envelope-Id: {envid}\n\nFinal-Recipient: rfc822; {r}\nAction: delivered\nStatus: 2.0.0\n\n--B\nContent-Type: text/rfc822-headers\n\nMessage-ID: {mid}\n\n--B--\n')
   mdn=(f'From: {r}\nTo: john@nullverse.cloud\nSubject: Read: receipt\nMIME-Version: 1.0\nContent-Type: multipart/report; report-type=disposition-notification; boundary=C\n\n--C\nContent-Type: text/plain\n\nRead\n--C\nContent-Type: message/disposition-notification\n\nFinal-Recipient: rfc822; {r}\nOriginal-Message-ID: {mid}\nDisposition: manual-action/MDN-sent-manually; displayed\n\n--C--\n')
   for i,raw in enumerate((dsn,mdn)):(root/'mail/new'/f'report-{draft[:10]}-{i}').write_text(raw)
  receipts.scan(db,httpd.mail)
 _t.sleep(0)
if os.environ.get('NULLMAIL_FIXTURE_RECEIPTS')=='1':
 first=httpd.mail.listing()[0]['id'];src=httpd.mail.locate('inbox',first).read_bytes()
 (root/'mail/new/mdn-request-fixture').write_bytes(b'Disposition-Notification-To: sender@example.com\n'+src.replace(b'<fixture@example.com>',b'<mdn-request@example.com>').replace(b'Fixture inbox',b'Please confirm you read this'))
if os.environ.get('NULLMAIL_FIXTURE_UNDO'):
 import threading,time
 httpd.undo_default=int(os.environ['NULLMAIL_FIXTURE_UNDO'])
 def _sched():
  while True:
   time.sleep(1)
   try:
    app.send_due(httpd)
    if os.environ.get('NULLMAIL_FIXTURE_RECEIPTS')=='1':_simulate_receipts()
   except Exception as e:print('fixture scheduler',e,flush=True)
 threading.Thread(target=_sched,daemon=True).start()
try:
 print('Isolated browser fixture ready',flush=True);httpd.serve_forever()
finally:httpd.server_close();state.tearDown()
