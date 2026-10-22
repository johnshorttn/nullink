"""Undo send / retract, DSN + bounce + MDN parsing, open pixel, read-receipt prompt (never automatic)."""
import email,email.policy,json,pathlib,sqlite3,sys,tempfile,time,unittest
from email.message import EmailMessage
from unittest.mock import patch,MagicMock
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent));sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import app,receipts,prefs
from core import Drafts,build_message
from transport import DirectPostfix
import test_nullmail
D={'from':'john@nullverse.cloud','to':'reader@example.com','subject':'Out','body':'Hi'}
IDS=['john@nullverse.cloud']

def dsn_report(envid,action,mid='<orig@nm>',rcpt='reader@example.com',status='2.0.0'):
    m=EmailMessage();m['From']='MAILER-DAEMON@nullverse.cloud';m['To']='john@nullverse.cloud';m['Subject']='Delivery status'
    m.set_content('report');m.make_mixed()
    ds=EmailMessage();ds.set_content(f'Reporting-MTA: dns; mail\nOriginal-Envelope-Id: {envid}\n\nFinal-Recipient: rfc822; {rcpt}\nAction: {action}\nStatus: {status}\nDiagnostic-Code: smtp; 250 ok\n'.encode(),'message','delivery-status',cte='7bit') if False else None
    raw=(f'From: MAILER-DAEMON@nullverse.cloud\r\nTo: john@nullverse.cloud\r\nSubject: Delivery Status Notification\r\nMIME-Version: 1.0\r\n'
         f'Content-Type: multipart/report; report-type=delivery-status; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nreport\r\n'
         f'--B\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; mail\r\nOriginal-Envelope-Id: {envid}\r\n\r\nFinal-Recipient: rfc822; {rcpt}\r\nAction: {action}\r\nStatus: {status}\r\n\r\n'
         f'--B\r\nContent-Type: text/rfc822-headers\r\n\r\nMessage-ID: {mid}\r\nSubject: Out\r\n\r\n--B--\r\n')
    return email.message_from_string(raw,policy=email.policy.default)

class ScheduleTests(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.d=Drafts(pathlib.Path(self.tmp.name)/'d.db')
    def tearDown(self):self.tmp.cleanup()
    def test_schedule_retract_returns_to_drafts(self):
        k=self.d.save(D,IDS)['id'];self.d.schedule(k,time.time()+30,'r1','local-owner')
        self.assertEqual(self.d.get(k)['status'],'scheduled');self.assertEqual(self.d.due(),[])
        self.assertEqual(self.d.retract(k)['status'],'draft');self.assertEqual(self.d.get(k)['status'],'draft')
        with self.assertRaises(ValueError):self.d.retract(k)
    def test_too_late_after_claim(self):
        k=self.d.save(D,IDS)['id'];self.d.schedule(k,time.time()-1,'r1','a');self.assertEqual([x['id'] for x in self.d.due()],[k])
        self.d.claim_scheduled(k)
        with self.assertRaisesRegex(ValueError,'Too late'):self.d.retract(k)
        with self.assertRaises(ValueError):self.d.claim_scheduled(k)          # never sent twice
    def test_retract_wins_race(self):
        k=self.d.save(D,IDS)['id'];self.d.schedule(k,time.time()-1,'r','a');self.d.retract(k)
        with self.assertRaises(ValueError):self.d.claim_scheduled(k)
    def test_trash_cancels_scheduled(self):
        k=self.d.save(D,IDS)['id'];self.d.schedule(k,time.time()+30,'r','a');self.assertTrue(self.d.trash(k)['cancelled']);self.assertEqual(self.d.due(time.time()+99),[])
    def test_headers_and_pixel(self):
        k=self.d.save(dict(D,read_receipt=True,track_opens=True),IDS)['id'];dr=self.d.get(k)
        _,raw=build_message(dr,IDS,message_id='<x@nm>',track_url='https://nullmail.nullverse.cloud/t/abc.gif')
        m=email.message_from_bytes(raw if isinstance(raw,bytes) else raw.as_bytes(),policy=email.policy.default)
        self.assertEqual(m['Disposition-Notification-To'],'john@nullverse.cloud');self.assertIn('/t/abc.gif',m.get_body(('html',)).get_content())
        k2=self.d.save(D,IDS)['id'];m2=build_message(self.d.get(k2),IDS)[1];m2=email.message_from_bytes(m2 if isinstance(m2,bytes) else m2.as_bytes())
        self.assertIsNone(m2['Disposition-Notification-To'])

class ReceiptParseTests(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(':memory:');receipts.init(self.db)
        receipts.record_outbound(self.db,'d1','<orig@nm>','d1',True,True,'T'*24,['reader@example.com'],'postfix')
    def test_dsn_states(self):
        for i,(a,s) in enumerate([('delayed','delayed'),('delivered','delivered')]):
            self.assertEqual(receipts.ingest(self.db,f'k{i}',dsn_report('d1',a)),'d1')
        self.assertEqual(receipts.summary(self.db,'d1')['status'],'delivered')
        self.assertIsNone(receipts.ingest(self.db,'k1',dsn_report('d1','failed')))   # idempotent per key
        receipts.ingest(self.db,'k9',dsn_report('zz','failed',status='5.1.1'))       # falls back to Message-ID
        self.assertEqual(receipts.summary(self.db,'d1')['status'],'bounced')
    def test_relayed_flag(self):
        receipts.ingest(self.db,'r',dsn_report('d1','relayed'));s=receipts.summary(self.db,'d1');self.assertEqual(s['status'],'delivered');self.assertTrue(s['relayed_only'])
    def test_plain_bounce(self):
        raw='From: Mail Delivery Subsystem <mailer-daemon@googlemail.com>\r\nTo: john@nullverse.cloud\r\nSubject: Delivery Status Notification (Failure)\r\nX-Failed-Recipients: reader@example.com\r\nIn-Reply-To: <orig@nm>\r\n\r\nAddress not found\r\n'
        receipts.ingest(self.db,'b',email.message_from_string(raw,policy=email.policy.default));self.assertEqual(receipts.summary(self.db,'d1')['status'],'bounced')
    def test_mdn_roundtrip(self):
        orig=EmailMessage();orig['From']='john@nullverse.cloud';orig['To']='reader@example.com';orig['Subject']='Out';orig['Message-ID']='<orig@nm>';orig['Disposition-Notification-To']='john@nullverse.cloud';orig.set_content('hi')
        mdn=receipts.build_mdn(orig,'reader@example.com','john@nullverse.cloud');mdn=mdn if not isinstance(mdn,bytes) else email.message_from_bytes(mdn,policy=email.policy.default)
        self.assertEqual(receipts.parse(mdn)['kind'],'mdn');receipts.ingest(self.db,'m',mdn);self.assertTrue(receipts.summary(self.db,'d1')['read_at'])
    def test_unrelated_mail_ignored(self):
        m=EmailMessage();m['From']='a@b.c';m['Subject']='hello';m.set_content('x');self.assertIsNone(receipts.ingest(self.db,'u',m))
    def test_open_pixel_rate_limit(self):
        self.assertTrue(receipts.record_open(self.db,'T'*24,1000));self.assertFalse(receipts.record_open(self.db,'T'*24,1030))
        self.assertTrue(receipts.record_open(self.db,'T'*24,1100));self.assertFalse(receipts.record_open(self.db,'bad',1200));self.assertFalse(receipts.record_open(self.db,'U'*24,1200))
        self.assertEqual(receipts.summary(self.db,'d1')['opens'],2)
        cols=[r[1] for r in self.db.execute('PRAGMA table_info(receipt_events)')];self.assertFalse({'ip','user_agent'}&set(cols))
    def test_mdn_request_and_once(self):
        m=EmailMessage();m['Disposition-Notification-To']='x@evil.example';m['Return-Path']='<y@other.example>'
        self.assertTrue(receipts.mdn_request(m)['return_path_mismatch']);receipts.mdn_claim(self.db,'k','ignore')
        with self.assertRaises(ValueError):receipts.mdn_claim(self.db,'k','send')

class TransportDsnTests(unittest.TestCase):
    def run_submit(self,has_dsn):
        smtp=MagicMock();smtp.has_extn.return_value=has_dsn;smtp.mail.return_value=(250,b'');smtp.rcpt.return_value=(250,b'');smtp.data.return_value=(250,b'queued as ABC1')
        with patch('smtplib.SMTP',return_value=smtp),patch('ssl.create_default_context'):r=DirectPostfix(enabled=True).submit('john@nullverse.cloud',['r@example.com'],b'x',envid='d1')
        return r,smtp
    def test_dsn_options_when_advertised(self):
        r,s=self.run_submit(True);self.assertTrue(r['dsn']);self.assertEqual(s.mail.call_args[0][1],['RET=HDRS','ENVID=d1']);self.assertIn('NOTIFY=SUCCESS,FAILURE,DELAY',s.rcpt.call_args[0][1])
    def test_no_dsn_options_otherwise(self):
        r,s=self.run_submit(False);self.assertFalse(r['dsn']);self.assertEqual(s.mail.call_args[0][1],[])

class PrefTests(unittest.TestCase):
    def test_validation(self):
        db=sqlite3.connect(':memory:')
        P=lambda k,v:prefs.put(db,'a',{'prefs':{k:{'value':v,'updated':1}}})
        for bad in (-1,121,'30',True):
            with self.assertRaises(ValueError):P('undo_send_seconds',bad)
        with self.assertRaises(ValueError):P('track_opens_default',1)
        P('undo_send_seconds',0);self.assertEqual(P('track_opens_default',True)['track_opens_default']['value'],True)

class HttpReceiptTests(unittest.TestCase):
    setUp=test_nullmail.HttpTests.setUp;tearDown=test_nullmail.HttpTests.tearDown;req=test_nullmail.HttpTests.req
    def test_undo_send_then_retract_then_send_due(self):
        self.server.undo_default=30;k=self.req('/api/drafts',D)[1]['id']
        with patch('smtplib.SMTP',side_effect=AssertionError('No SMTP during undo window')):
            s,r,_=self.req('/api/send',{'id':k,'request_id':'undo-request-0001'})
        self.assertEqual((s,r['status'],r['delay']),(200,'scheduled',30))
        self.assertEqual(self.req('/api/retract',{'id':k})[1]['status'],'draft')
        self.req('/api/send',{'id':k,'request_id':'undo-request-0002'});self.assertEqual(app.send_due(self.server,time.time()+31),1)
        self.assertEqual(self.server.drafts.get(k)['status'],'paused')   # fixture outbound disabled: nothing transmitted
        self.assertEqual(self.req('/api/retract',{'id':k})[0],400)
    def test_zero_delay_sends_immediately(self):
        k=self.req('/api/drafts',D)[1]['id'];self.assertEqual(self.req('/api/send',{'id':k})[1]['status'],'paused')
    def test_retract_and_mdn_need_csrf(self):
        for p in ('/api/retract','/api/mdn/respond'):self.assertEqual(self.req(p,{},csrf='bad')[0],403)
    def test_pixel_is_public_gif_and_unknown_tokens_ignored(self):
        s,b,h=self.req('/t/'+'A'*24+'.gif',cookie='');self.assertEqual(s,200);self.assertTrue(b[:6]==b'GIF89a' or b[:6]==b'GIF87a')
    def test_mdn_respond_requires_confirm_and_request(self):
        key=self.server.mail.listing()[0]['id']
        self.assertEqual(self.req('/api/mdn/respond',{'folder':'inbox','id':key,'action':'send'})[0],400)
        self.assertEqual(self.req('/api/mdn/respond',{'folder':'inbox','id':key,'action':'ignore'})[0],400)  # fixture message has no request
        p=self.server.mail.locate('inbox',key);p.write_bytes(b'Disposition-Notification-To: sender@example.com\n'+p.read_bytes().replace(b'hello@nullverse.cloud',b'john@nullverse.cloud'))
        with patch('smtplib.SMTP',side_effect=AssertionError('no smtp')):
            s,r,_=self.req('/api/mdn/respond',{'folder':'inbox','id':key,'action':'send','confirm':True})
        self.assertEqual((s,r.get('status')),(200,'paused'),r)
        self.assertEqual(self.req('/api/mdn/respond',{'folder':'inbox','id':key,'action':'send','confirm':True})[0],400)  # answered once
