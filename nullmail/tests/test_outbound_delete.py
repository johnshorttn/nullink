"""Outbound delete: Outbox/Drafts trash cancels send, permanent delete needs confirm, Sent -> Trash, Gmail Trash mirror."""
import json,pathlib,sys,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent));sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import app
from core import Drafts
from provider_sync import GmailAdapter
import test_nullmail,test_gmail
from workspace import OWNER

D={'from':'john@nullverse.cloud','to':'reader@example.com','subject':'Out','body':'Hi'}
IDS=['john@nullverse.cloud']

class DraftTrashTests(unittest.TestCase):
    def setUp(self):
        import tempfile;self.tmp=tempfile.TemporaryDirectory();self.d=Drafts(pathlib.Path(self.tmp.name)/'d.db')
    def tearDown(self):self.tmp.cleanup()
    def test_trash_cancels_paused_send_and_restore_stays_paused(self):
        k=self.d.save(D,IDS)['id'];self.d.status(k,'paused')
        r=self.d.trash(k);self.assertTrue(r['cancelled']);self.assertEqual(self.d.get(k)['status'],'trashed')
        with self.assertRaises(ValueError):self.d.claim(k)          # send is cancelled: cannot be claimed
        with self.assertRaises(ValueError):self.d.save(dict(D,id=k),IDS)
        self.assertEqual(self.d.restore(k)['status'],'paused');self.d.claim(k)  # explicit Send works again
    def test_rejected_and_draft_trash(self):
        for st in ('draft','rejected'):
            k=self.d.save(D,IDS)['id'];self.d.status(k,st);self.assertTrue(self.d.trash(k)['cancelled']);self.assertEqual(self.d.restore(k)['status'],st)
    def test_submitted_cannot_be_recalled_and_submitting_refused(self):
        k=self.d.save(D,IDS)['id'];self.d.status(k,'accepted','Q1');r=self.d.trash(k)
        self.assertTrue(r['already_submitted']);self.assertFalse(r['cancelled']);self.assertEqual(self.d.restore(k)['status'],'accepted')
        k2=self.d.save(D,IDS)['id'];self.d.claim(k2)
        with self.assertRaises(ValueError):self.d.trash(k2)
        with self.assertRaises(ValueError):self.d.purge(k2,True)
    def test_purge_needs_confirm(self):
        k=self.d.save(D,IDS)['id']
        with self.assertRaises(ValueError):self.d.purge(k)
        with self.assertRaises(ValueError):self.d.purge(k,'yes')
        self.d.purge(k,True);self.assertIsNone(self.d.get(k))
    def test_legacy_table_migrates(self):
        import sqlite3;p=pathlib.Path(self.tmp.name)/'old.db';db=sqlite3.connect(p)
        db.execute('CREATE TABLE drafts (id TEXT PRIMARY KEY, data TEXT NOT NULL, status TEXT NOT NULL, updated REAL NOT NULL, queue_id TEXT)')
        db.execute("INSERT INTO drafts VALUES ('a'||hex(randomblob(15)),?, 'paused', 1, NULL)",(json.dumps(D),));db.commit();db.close()
        d=Drafts(p);self.assertEqual(d.list()[0]['status'],'paused');self.assertNotIn('trashed_from',d.list()[0])

class GmailFolderTests(unittest.TestCase):
    def test_sent_to_trash_mirrors_only_for_sent(self):
        a=GmailAdapter(None)
        self.assertEqual(a.folder_change('sent','trash'),(['TRASH'],[]))
        self.assertEqual(a.folder_change('inbox','trash'),([],[]))      # inbox deletes stay local-only
        self.assertEqual(a.folder_change('trash','inbox'),([],['TRASH']))

class GmailCacheDeleteTests(unittest.TestCase):
    setUp=test_gmail.GmailTests.setUp;tearDown=test_gmail.GmailTests.tearDown;http=test_gmail.GmailTests.http;connect=test_gmail.GmailTests.connect
    def test_gmail_sent_trash_enqueues_and_purge_tombstones(self):
        from core import MailStore
        from gmail import CombinedMail
        acct=self.connect();self.client.ingest(OWNER,acct,'abc123',True)
        mail=CombinedMail(MailStore(self.root/'local'),self.client) if (self.root/'local').exists() else None
        (self.root/'local').mkdir(exist_ok=True)
        for sub in ('','.Trash','.Sent','.Archive','.Junk'):
            for d in ('new','cur','tmp'):(self.root/'local'/sub/d).mkdir(parents=True,exist_ok=True)
        mail=CombinedMail(MailStore(self.root/'local'),self.client)
        key=next(MailStore.key(p) for p in self.client.cache.files('inbox'))
        p=self.client.cache.locate('inbox',key);p.rename(self.client.cache.root/'.Sent'/p.parent.name/p.name)  # pretend it is a Sent message
        mail.move('sent',key,'trash')
        with self.client.state.db() as db:ops=db.execute('SELECT add_ids FROM provider_ops').fetchall()
        self.assertIn('TRASH',json.loads(ops[-1][0]))
        with self.assertRaises(ValueError):mail.delete('trash',key)
        mail.delete('trash',key,True)
        with self.assertRaises(FileNotFoundError):mail.locate('trash',key)
        with self.client.state.db() as db:self.assertTrue(db.execute('SELECT 1 FROM gmail_purged').fetchone())
        self.assertFalse(any(c[0].endswith('/delete') for c in self.calls))  # nothing deleted at Google

class OutboundHttpTests(unittest.TestCase):
    setUp=test_nullmail.HttpTests.setUp;tearDown=test_nullmail.HttpTests.tearDown;req=test_nullmail.HttpTests.req
    def draft(self,status='paused'):
        k=self.req('/api/drafts',D)[1]['id'];self.server.drafts.status(k,status);return k
    def test_bulk_trash_restore_purge(self):
        a,b=self.draft(),self.draft('accepted')
        s,r,_=self.req('/api/outbound/delete',{'drafts':[a,b]});self.assertEqual(s,200);self.assertEqual(r['ok'],2)
        self.assertEqual([x.get('cancelled') for x in r['results']],[True,False]);self.assertTrue(r['results'][1]['already_submitted'])
        self.assertEqual(self.req('/api/outbound/restore',{'drafts':[a]})[1]['results'][0]['status'],'paused')
        self.assertEqual(self.req('/api/outbound/delete',{'drafts':[a],'permanent':True})[0],400)
        self.assertEqual(self.req('/api/outbound/delete',{'drafts':[a],'permanent':True,'confirm':True})[1]['ok'],1)
        self.assertIsNone(self.server.drafts.get(a))
    def test_trashed_paused_item_cannot_be_sent(self):
        a=self.draft();self.req('/api/outbound/delete',{'drafts':[a]})
        with patch('smtplib.SMTP',side_effect=AssertionError('No SMTP')):s,r,_=self.req('/api/send',{'id':a})
        self.assertNotEqual(s,200)
    def test_sent_folder_message_trash_then_permanent(self):
        m=self.server.mail;key=m.listing()[0]['id'];p=m.locate('inbox',key);p.rename(m.root/'.Sent'/p.parent.name/p.name)
        self.assertEqual(self.req('/api/message/delete',{'folder':'sent','id':key,'confirm':True})[0],400)  # trash first
        self.assertEqual(self.req('/api/outbound/delete',{'messages':[{'folder':'sent','id':key}]})[1]['ok'],1)
        self.assertEqual(self.req('/api/message/delete',{'folder':'trash','id':key})[0],400)
        self.assertEqual(self.req('/api/message/delete',{'folder':'trash','id':key,'confirm':True})[0],200)
        with self.assertRaises(FileNotFoundError):m.locate('trash',key)
    def test_writes_need_csrf(self):
        for path in ['/api/outbound/delete','/api/outbound/restore','/api/message/delete']:
            self.assertEqual(self.req(path,{},csrf='bad')[0],403);self.assertEqual(self.req(path,{},cookie='')[0],401)
    def test_inbox_cannot_be_permanently_deleted(self):
        key=self.server.mail.listing()[0]['id']
        self.assertEqual(self.req('/api/message/delete',{'folder':'inbox','id':key,'confirm':True})[0],400)
        self.assertEqual(self.req('/api/outbound/delete',{'messages':[{'folder':'inbox','id':key}]})[0],400)
