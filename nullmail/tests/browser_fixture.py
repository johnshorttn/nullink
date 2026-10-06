"""Loopback fixture: real Nullink auth in temporary storage, fake DNS/maps only."""
import pathlib,sys,threading,copy
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
httpd=app.ThreadingHTTPServer(('127.0.0.1',8798),app.Handler);httpd.mail=fixture(root/'mail');httpd.drafts=Drafts(root/'drafts.db')
try:
 print('Isolated browser fixture ready',flush=True);httpd.serve_forever()
finally:httpd.server_close();state.tearDown()
