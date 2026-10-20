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
  def submit(self,*args):return {'status':'accepted','queue_id':'FIXTURE123'}
 app.DirectPostfix=NonTransmitting
try:
 print('Isolated browser fixture ready',flush=True);httpd.serve_forever()
finally:httpd.server_close();state.tearDown()
