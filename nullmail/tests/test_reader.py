import email, email.policy, json, pathlib, sys, tempfile, unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'deploy'))
import reader, review, rules
from test_nullmail import HttpTests as _Base

def parse(raw):return email.message_from_bytes(raw,policy=email.policy.default)
HTML=(b'From: Shop <a@shop.test>\r\nTo: john@nullverse.cloud\r\nCc: c@x.test\r\nList-Id: <news.shop.test>\r\nSubject: s\r\n'
 b'Authentication-Results: mx.google.com; dkim=pass header.i=@shop.test; spf=softfail; dmarc=fail\r\nDKIM-Signature: v=1; d=shop.test; s=k\r\n'
 b'Content-Type: multipart/related; boundary=b\r\n\r\n--b\r\nContent-Type: text/html\r\n\r\n'
 b'<p onclick="x()">Hi<script>alert(1)</script><a href="javascript:evil()">j</a><a href="https://ok.test">ok</a>'
 b'<img src="https://track.test/p.gif"><img src="cid:im1"><iframe src="https://x"></iframe><form action="https://x"><input name=a></form>'
 b'<div style="background:url(https://t.test/x)">bg</div></p>\r\n--b\r\nContent-Type: image/png\r\nContent-ID: <im1>\r\nContent-Transfer-Encoding: base64\r\n\r\niVBORw0KGgo=\r\n--b--\r\n')

class SanitizerTests(unittest.TestCase):
 def test_strips_active_content_blocks_remote_and_inlines_cid(self):
  r=reader.render(parse(HTML));h=r['html'].split('<body>',1)[1]
  for bad in ('<script','onclick','javascript:','<iframe','<form','<input','track.test','t.test/x'):self.assertNotIn(bad,h)
  self.assertIn('href="https://ok.test" target="_blank" rel="noopener noreferrer nofollow"',h);self.assertIn('src="data:image/png;base64,iVBORw0KGgo="',h)
  self.assertEqual(r['blocked_remote'],2);self.assertIn("script-src &#x27;none&#x27;",r['html']);self.assertNotIn('https:',reader.csp(False))
 def test_remote_opt_in_keeps_https_images_but_never_scripts(self):
  r=reader.render(parse(HTML),remote=True);h=r['html'].split('<body>',1)[1]
  self.assertIn('https://track.test/p.gif',h);self.assertNotIn('<script',h);self.assertIn('img-src data: cid: https: http:',r['html'])
 def test_plain_message_has_no_html(self):self.assertIsNone(reader.render(parse(b'Subject: x\r\n\r\nhi')))
 def test_header_details_and_auth(self):
  d=reader.details(parse(HTML))
  self.assertEqual(d['auth'],{'spf':'softfail','dkim':'pass','dmarc':'fail'});self.assertEqual(d['cc'],'c@x.test');self.assertEqual(d['list_id'],'<news.shop.test>');self.assertEqual(d['dkim_domains'],['shop.test'])

class ScanTests(unittest.TestCase):
 def test_detects_scripts_handlers_urls_frames_forms(self):
  kinds={f['kind'] for f in reader.scan(parse(HTML))}
  self.assertTrue({'script tag','inline event handler','javascript: URL','iframe/frame','form'}<=kinds,kinds)
 def test_detects_risky_attachments_macros_and_obfuscation(self):
  m=email.message.EmailMessage();m['Subject']='a';m.set_content('hello')
  m.add_attachment(b'MsgBox 1',maintype='application',subtype='octet-stream',filename='run.vbs')
  m.add_attachment(b'PK\x03\x04....word/vbaProject.bin....',maintype='application',subtype='octet-stream',filename='invoice.docm')
  m.add_attachment(b'<html><body>x=eval(atob("YWxlcnQoMSk="))</body></html>',maintype='text',subtype='html',filename='page.html')
  kinds=[f['kind'] for f in reader.scan(parse(m.as_bytes()))]
  self.assertIn('risky attachment',kinds);self.assertIn('Office macro',kinds);self.assertIn('obfuscated script',kinds)
 def test_clean_mail_has_no_findings(self):
  self.assertEqual(reader.scan(parse(b'Subject: x\r\nContent-Type: text/html\r\n\r\n<p>Hello <b>there</b> <a href="https://a.test">a</a></p>')),[])

class ReviewQueueTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();root=pathlib.Path(self.tmp.name)
  from workspace import Workspace
  self.state=Workspace(root/'w.db');self.q=review.FileQueueReviewer(root/'mail-review');self.r=review.Reviews(self.state,self.q);self.root=root
 def tearDown(self):self.tmp.cleanup()
 def test_submit_queue_format_dedupe_and_verdict(self):
  m={'id':'f'*64,'folder':'inbox','from':'a@shop.test','subject':'s','message_id':'<x>'};f=[{'kind':'script tag','detail':'d','where':'w'}]
  with self.assertRaises(ValueError):self.r.submit(m,[],b'raw','owner')
  rv=self.r.submit(m,f,b'RAW-EML','owner');rid=rv['request_id'];self.assertEqual(rv['status'],'pending')
  req=json.loads((self.root/'mail-review/requests'/(rid+'.json')).read_text())
  self.assertEqual(req['format'],'nullmail-review/1');self.assertEqual(req['findings'],f);self.assertEqual((self.root/'mail-review/requests'/(rid+'.eml')).read_bytes(),b'RAW-EML')
  self.assertEqual(self.r.submit(m,f,b'RAW-EML','owner')['request_id'],rid)
  (self.root/'mail-review/verdicts/bad.json').write_text('{"format":"x"}')
  (self.root/'mail-review/verdicts'/(rid+'.json')).write_text(json.dumps({'format':'nullmail-review/1','request_id':rid,'verdict':'malicious','reason':'credential phish','reviewer':'morc'}))
  self.assertEqual(self.r.collect(),1);got=self.r.get(m['id'])
  self.assertEqual((got['status'],got['reason'],got['reviewer']),('malicious','credential phish','morc'))
  self.assertFalse((self.root/'mail-review/verdicts'/(rid+'.json')).exists());self.assertTrue((self.root/'mail-review/processed/bad.json.invalid').exists())
 def test_relay_copies_requests_out_and_verdicts_back(self):
  import review_relay as rr
  src=self.root/'mail-review';dst=self.root/'morc-review'
  m={'id':'e'*64,'folder':'inbox','from':'a@shop.test'};rid=self.r.submit(m,[{'kind':'form','detail':'d','where':'w'}],b'EML','owner')['request_id']
  with patch.object(rr,'SRC',src),patch.object(rr,'DST',dst),patch.object(rr,'LOG',dst/'relay.log'),patch.object(rr,'TOKEN',self.root/'none'),patch.object(rr,'own',lambda *a,**k:None):
   rr.main()
   self.assertTrue((dst/'requests'/(rid+'.json')).exists());self.assertTrue((dst/'requests'/(rid+'.eml')).exists())
   self.assertIn('notification pending',(dst/'relay.log').read_text());self.assertNotIn('EML',(dst/'relay.log').read_text())
   (dst/'verdicts'/(rid+'.json')).write_text(json.dumps({'format':'nullmail-review/1','request_id':rid,'verdict':'clean','reason':'newsletter','reviewer':'morc'}))
   rr.main()
  self.assertEqual(self.r.collect(),1);self.assertEqual(self.r.get(m['id'])['status'],'clean')
  self.assertEqual(rr.ROOM,'morc')

class RuleTests(unittest.TestCase):
 def test_rules_may_move_to_spam_but_not_trash(self):
  base={'name':'r','priority':1,'enabled':True,'stop':False,'scope':['john@nullverse.cloud'],'condition':{'field':'sender','op':'equals','value':'a@b.test'},'exception':None}
  rules.validate_rule(dict(base,actions=[{'type':'move','value':'spam'}]),['john@nullverse.cloud'],[],[])
  with self.assertRaises(ValueError):rules.validate_rule(dict(base,actions=[{'type':'move','value':'trash'}]),['john@nullverse.cloud'],[],[])

class ReaderHttpTests(_Base):
 def mid(self):return self.req('/api/v1/messages')[1]['messages'][0]['id']
 def test_html_source_eml_and_review_endpoints(self):
  mid=self.mid();s,h,_=self.req('/api/v1/message/html?'+'folder=inbox&id='+mid)
  self.assertEqual(s,200);self.assertNotIn('<script',h['html'].split('<body>',1)[1]);self.assertGreaterEqual(h['blocked_remote'],1);self.assertFalse(h['remote'])
  m=self.req('/api/v1/message?folder=inbox&id='+mid)[1];self.assertTrue(m['has_html']);self.assertIn('script tag',{f['kind'] for f in m['script_findings']});self.assertFalse(m['scripts_enabled'])
  src=self.req('/api/v1/message/source?folder=inbox&id='+mid)[1];self.assertIn('Subject:',src['raw']);self.assertFalse(src['segmented'])
  s,body,hd=self.req('/api/v1/message/eml?folder=inbox&id='+mid);self.assertEqual(s,200);self.assertIn(b'Message-ID',body);self.assertIn('.eml',hd['Content-Disposition'])
  r=self.req('/api/v1/message/review',{'folder':'inbox','id':mid})[1];self.assertEqual(r['review']['status'],'pending');self.assertFalse(r['scripts_enabled'])
  self.assertEqual(self.req('/api/v1/message?folder=inbox&id='+mid)[1]['review']['status'],'pending')
  self.assertEqual(self.req('/api/v1/message/remote-images',{'sender':'sender@example.com','allow':True})[0],200)
  self.assertTrue(self.req('/api/v1/message/html?folder=inbox&id='+mid)[1]['remote_always'])
  self.assertEqual(self.req('/api/v1/message/remote-images',{'sender':'not an address','allow':True})[0],400)
  self.assertEqual(self.req('/api/v1/message/html?folder=inbox&id='+mid,cookie='')[0],401)
if __name__=='__main__':unittest.main()
