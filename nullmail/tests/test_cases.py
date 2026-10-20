"""Only synthetic Maildir and SQLite state; never live mail or transport."""
import copy, hashlib, json, pathlib, sqlite3, sys, tempfile, unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import api_v1, cases, test_nullmail as base
from core import Drafts
from workspace import Workspace, OWNER, permissions
from test_workspace import rule

class CaseStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.tmp.name)
        self.mail=base.fixture(self.root/'mail');self.store=Workspace(self.root/'state.db')
        self.ids=['john@nullverse.cloud','hello@nullverse.cloud','support@nullverse.cloud']
        self.key=self.mail.listing()[0]['id']
        raw=self.mail.locate('inbox',self.key).read_bytes().replace(b'hello@nullverse.cloud',b'support@nullverse.cloud').replace(b'<fixture@example.com>',b'<other-thread@example.com>')
        (self.root/'mail/new/second').write_bytes(raw);self.second=self.mail.key(self.root/'mail/new/second')
        self.service=cases.Cases(self.store,self.mail,self.ids,OWNER,permissions(OWNER,self.ids))
    def tearDown(self):self.tmp.cleanup()
    def create(self,**kw):return self.service.create(dict(title='Work ticket',request_id='fixture-create-request',**kw))['case']
    def hashes(self):return {str(p.relative_to(self.root/'mail')):hashlib.sha256(p.read_bytes()).hexdigest() for p in (self.root/'mail').rglob('*') if p.is_file()}
    def test_cross_account_thread_multiple_cases_label_independence_and_idempotency(self):
        label=self.store.label_save({'name':'Normal label'});self.store.set_state(self.key,[label],'normal');before=self.hashes()
        case=self.create(message=cases.reference(self.key));self.assertEqual(case['display_number'],'CASE-000001')
        action={'id':case['id'],'message':cases.reference(self.second),'linked':True}
        self.assertTrue(self.service.membership(action)['changed']);self.assertFalse(self.service.membership(action)['changed'])
        other=self.service.create({'title':'Other case','request_id':'fixture-create-second','message':cases.reference(self.key)})['case']
        self.assertEqual(len(self.service.badges(cases.reference(self.key))),2)
        self.assertEqual(self.service.detail(case['id'])['total'],2)
        self.assertEqual(self.store.enrich(self.mail.message('inbox',self.key),self.ids)['labels'],[label])
        self.assertEqual(before,self.hashes())
        self.assertEqual(len([x for x in self.service.history(case['id'])['events'] if x['kind']=='linked']),2)
        self.assertEqual(self.create(message=cases.reference(self.key))['id'],case['id'])
        with self.assertRaises(cases.Conflict):self.service.create({'title':'Changed replay','request_id':'fixture-create-request'})
    def test_move_close_reopen_notes_and_optimistic_update(self):
        c=self.create(message=cases.reference(self.key));self.mail.move('inbox',self.key,'archive')
        self.assertEqual(self.service.detail(c['id'])['members'][0]['folder'],'archive')
        before=self.hashes()
        c=self.service.save({k:c[k] for k in ('id','version','title','description')}|{'status':'Closed'})['case']
        c=self.service.save({k:c[k] for k in ('id','version','title','description')}|{'status':'Open'})['case']
        request={'id':c['id'],'body':'Private note','request_id':'fixture-note-request'}
        self.assertFalse(self.service.add_note(request)['duplicate']);self.assertTrue(self.service.add_note(request)['duplicate'])
        self.assertEqual(self.service.notes(c['id'])['total'],1)
        with self.assertRaises(cases.Conflict):self.service.save({k:c[k] for k in ('id','version','title','description')}|{'status':'Waiting'})
        self.service.membership({'id':c['id'],'message':cases.reference(self.key),'linked':False})
        self.assertEqual(self.service.detail(c['id'])['total'],0);self.assertEqual(before,self.hashes())
        self.assertEqual([e['data']['status']['after'] for e in self.service.history(c['id'])['events'] if e['kind']=='updated'],['Open','Closed'])
    def test_fail_closed_metadata_notes_counts_badges_and_past_members(self):
        actor='fixture-delegate';perm={'read':['hello@nullverse.cloud','support@nullverse.cloud'],'send':[],'admin':False}
        delegate=cases.Cases(self.store,self.mail,self.ids,actor,perm)
        c=delegate.create({'title':'Secret combined work','message':cases.reference(self.key),'request_id':'fixture-delegate-create'})['case']
        delegate.membership({'id':c['id'],'message':cases.reference(self.second),'linked':True})
        delegate.add_note({'id':c['id'],'body':'Support subject is private','request_id':'fixture-delegate-note'})
        delegate.membership({'id':c['id'],'message':cases.reference(self.second),'linked':False})
        restricted=cases.Cases(self.store,self.mail,self.ids,actor,{'read':['hello@nullverse.cloud'],'send':[],'admin':False})
        self.assertEqual(restricted.listing()['total'],0);self.assertEqual(restricted.badges(cases.reference(self.key)),[])
        for operation in [restricted.detail,restricted.notes,restricted.history]:
            with self.assertRaises(FileNotFoundError):operation(c['id'])
        with self.assertRaises(FileNotFoundError):self.service.detail(c['id'])
    def test_pagination_validation_and_provider_namespaces(self):
        for i in range(4):self.service.create({'title':'Ticket '+str(i),'request_id':'fixture-pagination-'+str(i)})
        result=self.service.listing(query='Ticket',offset=0,limit=2);self.assertEqual(result['total'],4);self.assertEqual(result['next_offset'],2)
        self.assertEqual(self.service.listing(status='Closed')['total'],0)
        for ref in [{'provider':'gmail','account_id':'primary','id':self.key},{'provider':'local','account_id':'hello@nullverse.cloud','id':self.key}]:
            with self.assertRaises(ValueError):self.service.resolve(ref)
        with self.assertRaises(ValueError):self.service.create({'title':'x'*121,'request_id':'fixture-invalid-create'})
        self.assertEqual(Workspace(self.root/'state.db').case_ids(),self.store.case_ids())
        with self.store.db() as db:
            cols=[r[1] for r in db.execute('pragma table_info(case_members)') if r[5]]
            self.assertEqual(cols,['case_id','provider','account_id','message_id'])
    def test_rule_dryrun_zero_writes_audit_and_no_mail_mutations(self):
        c=self.create();self.store.save_rule(rule(actions=[{'type':'add_to_case','value':c['id']}]),OWNER,self.ids)
        before=self.hashes();state=pathlib.Path(self.store.path).read_bytes()
        preview=self.store.preview(self.mail,self.ids,[self.key]);self.assertEqual(state,pathlib.Path(self.store.path).read_bytes());self.assertEqual(before,self.hashes())
        self.assertEqual(preview['plans'][0]['result']['case_ids'],[c['id']]);self.assertEqual(self.service.detail(c['id'])['total'],0)
        self.store.execute_plan(self.mail,preview['plans'][0],OWNER,'explicit');self.assertEqual(before,self.hashes())
        self.assertEqual(self.service.detail(c['id'])['total'],1)
        events=self.service.history(c['id'])['events'];self.assertTrue(any(e['kind']=='linked' and e['data']['source'].startswith('rule:') for e in events))
        self.store.execute_plan(self.mail,preview['plans'][0],OWNER,'explicit');self.assertEqual(self.service.detail(c['id'])['total'],1)

class CaseApiTests(base.HttpTests):
    def test_case_routes_auth_csrf_independent_visibility_and_badges(self):
        for path in ['/api/v1/cases','/api/v1/cases/detail?id='+'a'*24,'/api/v1/cases/notes?id='+'a'*24,'/api/v1/cases/history?id='+'a'*24]:
            self.assertEqual(self.req(path,cookie='')[0],401)
        for path in ['create','save','membership','notes']:
            self.assertEqual(self.req('/api/v1/cases/'+path,{},csrf='bad')[0],403)
            self.assertEqual(self.req('/api/v1/cases/'+path,{},origin='https://evil.invalid')[0],403)
        m=self.req('/api/v1/messages')[1]['messages'][0]
        self.req('/api/v1/accounts/selection',{'selection':[]})
        created=self.req('/api/v1/cases/create',{'title':'Fixture case','request_id':'fixture-http-create','message':m['message_ref']})
        self.assertEqual(created[0],200);c=created[1]['case'];self.assertEqual(self.req('/api/v1/messages')[1]['total'],0)
        detail=self.req('/api/v1/cases/detail?id='+c['id'])[1];self.assertEqual(detail['total'],1)
        self.assertEqual(self.req('/api/v1/message?id='+m['id'])[1]['cases'][0]['id'],c['id'])
        self.req('/api/v1/message/move',{'id':m['id'],'folder':'inbox','target':'archive'})
        self.assertEqual(self.req('/api/v1/cases/detail?id='+c['id'])[1]['members'][0]['folder'],'archive')
        update={k:c[k] for k in ('id','version','title','description')}|{'status':'Closed'}
        self.assertEqual(self.req('/api/v1/cases/save',update)[0],200)
        status,error,_=self.req('/api/v1/cases/save',update);self.assertEqual(status,409);self.assertEqual(error['code'],'conflict')
        def delegated(path,*args,**kwargs):
            if path=='/api/me':return 200,b'{"authenticated":true,"auth_type":"session","user_id":"delegate"}',None
            return base.fake_nullink(path,*args,**kwargs)
        with patch('app.nullink',delegated):
            self.assertEqual(self.req('/api/v1/cases')[1]['total'],0)
            for suffix in ['detail','notes','history']:self.assertEqual(self.req('/api/v1/cases/'+suffix+'?id='+c['id'])[0],404)
            self.assertEqual(self.req('/api/v1/cases/notes',{'id':c['id'],'body':'No','request_id':'fixture-denied-note'})[0],404)
            self.assertEqual(self.req('/api/v1/cases/membership',{'id':c['id'],'message':m['message_ref'],'linked':False})[0],404)

if __name__=='__main__':unittest.main()
