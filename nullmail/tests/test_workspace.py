"""Fixture-only regression tests; no SMTP, private messages or external APIs."""
import copy, hashlib, json, pathlib, sys, unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import app, rules, api_v1
from workspace import Workspace, permissions, routing, require_read, reply_identity
import test_nullmail as base


def rule(**kw):
    return dict({'id':'a'*24,'name':'Fixture rule','priority':100,'enabled':True,'stop':False,'scope':['hello@nullverse.cloud'],'condition':{'field':'subject','op':'contains','value':'fixture'},'exception':None,'actions':[{'type':'priority','value':'high'}]},**kw)

class RuleTests(unittest.TestCase):
    def setUp(self):
        self.m={'id':'x','folder':'inbox','accounts':['hello@nullverse.cloud'],'routing_recipients':['hello@nullverse.cloud'],'from':'sender@example.com','subject':'fixture','body':'Example body','date':'Sat, 10 Oct 2026 10:00:00 +0000','unread':True,'labels':[],'attachments':[]}
    def test_nested_negation_exceptions_and_scopes(self):
        tree={'group':'ALL','children':[{'group':'ANY','children':[{'field':'subject','op':'equals','value':'fixture'},{'field':'body','op':'contains','value':'absent'}]},{'group':'NOT','children':[{'field':'read','op':'equals','value':True}]}]}
        rules.validate_tree(tree);self.assertTrue(rules.evaluate(tree,self.m)['matched'])
        self.assertEqual(len(rules.plan([rule(condition=tree)],self.m)['actions']),1)
        self.assertEqual(rules.plan([rule(condition=tree,exception={'field':'sender_domain','op':'equals','value':'example.com'})],self.m)['actions'],[])
        self.assertEqual(rules.plan([rule(scope=['other@example.com'])],self.m)['actions'],[])
    def test_order_stop_simulated_state_conflicts(self):
        a=rule(priority=20,actions=[{'type':'unread'}]);b=rule(id='b'*24,priority=10,stop=True,actions=[{'type':'read'}])
        result=rules.plan([a,b],self.m);self.assertEqual(len(result['actions']),1);self.assertFalse(result['result']['unread'])
        b['stop']=False;result=rules.plan([a,b],self.m);self.assertTrue(result['warnings']);self.assertTrue(result['result']['unread'])
        a['condition']={'field':'read','op':'equals','value':True};self.assertEqual(len(rules.plan([a,b],self.m)['actions']),2)
    def test_regex_and_complexity_limits_and_types(self):
        for value in ['(a+)+$','a'*100000]:
            with self.assertRaises(ValueError):rules.validate_tree({'field':'body','op':'regex','value':value})
        for node in [{'field':'read','op':'equals','value':'true'},{'field':'age_days','op':'less','value':True},{'field':'date','op':'before','value':'yesterday'},{'group':'NOT','children':[{'field':'read','op':'equals','value':True}]*2}]:
            with self.assertRaises(ValueError):rules.validate_tree(node)
        node={'field':'read','op':'equals','value':True}
        for _ in range(8):node={'group':'ALL','children':[node]}
        with self.assertRaises(ValueError):rules.validate_tree(node)
        with self.assertRaises(ValueError):rules.validate_rule(rule(actions=[{'type':'send'}]),self.m['accounts'],[])
    def test_fields_and_unavailable_date(self):
        for field,op,value in [('sender_domain','equals','example.com'),('recipient_domain','equals','nullverse.cloud'),('date','after','2026-01-01'),('has_attachments','equals',False),('body','contains','example')]:
            node={'field':field,'op':op,'value':value};rules.validate_tree(node);self.assertTrue(rules.evaluate(node,self.m)['matched'])
        self.m['date']='invalid';self.assertFalse(rules.evaluate({'field':'age_days','op':'greater','value':1},self.m)['matched'])

class StateTests(base.CoreTests):
    def setUp(self):
        super().setUp();self.state=Workspace(self.root/'workspace.db')
    def test_dry_run_zero_writes_and_explicit_process(self):
        r=self.state.save_rule(rule(actions=[{'type':'archive'},{'type':'read'}]),'local-owner',self.ids)
        files=lambda:{str(p.relative_to(self.root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in self.root.rglob('*') if p.is_file()}
        before=files();result=self.state.preview(self.mail,self.ids,[self.key]);self.assertEqual(before,files());self.assertEqual(result['writes'],0)
        self.state.execute_plan(self.mail,result['plans'][0],'local-owner','explicit')
        self.assertEqual(self.mail.listing(),[]);self.assertFalse(self.mail.listing('archive')[0]['unread']);self.assertEqual(self.state.history()[0]['status'],'completed')
    def test_baseline_new_only_loop_prevention_and_restart(self):
        self.state.save_rule(rule(actions=[{'type':'archive'}]),'local-owner',self.ids)
        self.state.initialize_baseline(self.mail);self.assertEqual(self.state.process_new(self.mail,self.ids),0);self.assertEqual(len(self.mail.listing()),1)
        source=self.mail.locate('inbox',self.key).read_bytes();(self.root/'mail/new/new-fixture').write_bytes(source)
        self.assertEqual(self.state.process_new(self.mail,self.ids),1);self.assertEqual(len(self.mail.listing('archive')),1)
        key=self.mail.listing('archive')[0]['id'];self.mail.move('archive',key,'inbox')
        restarted=Workspace(self.root/'workspace.db');self.assertEqual(restarted.process_new(self.mail,self.ids),0)
    def test_interrupted_run_is_not_automatically_replayed(self):
        self.state.save_rule(rule(actions=[{'type':'archive'}]),'local-owner',self.ids)
        self.state.initialize_baseline(self.mail)
        (self.root/'mail/new/interrupted-fixture').write_bytes(self.mail.locate('inbox',self.key).read_bytes())
        with patch.object(self.mail,'move',side_effect=OSError('fixture failure')):
            with self.assertRaises(OSError):self.state.process_new(self.mail,self.ids)
        self.assertEqual(self.state.history()[0]['status'],'interrupted')
        self.assertEqual(self.state.process_new(self.mail,self.ids),0)

    def test_labels_cycles_versions_and_migration(self):
        parent=self.state.label_save({'name':'Parent'});child=self.state.label_save({'name':'Child','parent':parent})
        with self.assertRaises(ValueError):self.state.label_save({'id':parent,'name':'Cycle','parent':child})
        with self.assertRaises(ValueError):self.state.label_delete(parent)
        r=self.state.save_rule(rule(actions=[{'type':'add_label','value':child}]),'local-owner',self.ids)
        r2=self.state.save_rule(dict(r,name='Changed'),'local-owner',self.ids);self.assertEqual(r2['version'],2)
        with self.assertRaises(ValueError):self.state.save_rule(r,'local-owner',self.ids)
        self.assertEqual(len(self.state.versions(r['id'])),2)
        self.assertEqual(Workspace(self.root/'workspace.db').rules(),self.state.rules())
    def test_trusted_alias_and_spoofed_historic_header(self):
        m=self.state.enrich(self.mail.message('inbox',self.key),self.ids);self.assertEqual(m['routing_recipients'],['hello@nullverse.cloud'])
        self.assertEqual(reply_identity(m,permissions('local-owner',self.ids))['from'],'hello@nullverse.cloud')
        raw=self.mail.locate('inbox',self.key).read_bytes();raw=raw[raw.index(b'From:'):];(self.root/'mail/new/untrusted').write_bytes(raw)
        key=self.mail.key(self.root/'mail/new/untrusted');m=self.state.enrich(self.mail.message('inbox',key),self.ids);self.assertEqual(m['routing_status'],'ambiguous');self.assertEqual(m['accounts'],['john@nullverse.cloud'])
        grant=permissions('delegate',self.ids,{'delegate':{'read':['hello@nullverse.cloud'],'send':['hello@nullverse.cloud']}})
        with self.assertRaises(PermissionError):require_read(m,grant)
        self.assertTrue(reply_identity(m,permissions('local-owner',self.ids))['fallback'])
    def test_visibility_none_persists_and_is_per_principal(self):
        self.state.select('local-owner',[],self.ids);self.assertEqual(self.state.selection('local-owner',self.ids),[]);self.assertEqual(self.state.selection('someone',self.ids),self.ids)
        self.assertEqual(Workspace(self.root/'workspace.db').selection('local-owner',self.ids),[])

class ApiTests(base.HttpTests):
    def test_versioned_selection_and_sender_independence(self):
        self.assertEqual(self.req('/api/v1/accounts/selection',{'selection':[]})[0],200)
        self.assertEqual(self.req('/api/v1/messages')[1]['total'],0)
        self.assertEqual(self.req('/api/v1/messages?account=hello%40nullverse.cloud')[1]['total'],1)
        self.assertIn('hello@nullverse.cloud',self.req('/api/v1/accounts')[1]['identities'])
    def test_preview_run_replay_and_stale(self):
        self.req('/api/v1/rules/save',rule(actions=[{'type':'read'}]))
        key=self.req('/api/v1/messages')[1]['messages'][0]['id'];request={'ids':[key],'folder':'inbox'}
        status,preview,_=self.req('/api/v1/rules/preview',request);self.assertEqual(status,200)
        self.assertTrue(self.server.mail.listing()[0]['unread'])
        self.assertEqual(self.req('/api/v1/rules/run',dict(request,token=preview['token']))[0],400)
        run=dict(request,token=preview['token'],confirm=True)
        self.assertEqual(self.req('/api/v1/rules/run',run)[1]['status'],'completed')
        self.assertTrue(self.req('/api/v1/rules/run',run)[1]['duplicate']);self.assertEqual(len(api_v1.state(self.server).history()),1)
        preview=self.req('/api/v1/rules/preview',request)[1];self.server.mail.flag('inbox',key,False)
        self.assertEqual(self.req('/api/v1/rules/run',dict(run,token=preview['token']))[0],400)
    def test_request_idempotency_actor_and_from_audit(self):
        self.server.outbound_enabled=True
        draft=self.req('/api/v1/drafts',{'from':'hello@nullverse.cloud','to':'fixture@example.com','body':'Synthetic'})[1]
        with patch('app.DirectPostfix') as transport:
            transport.return_value.submit.return_value={'status':'accepted','queue_id':'FIXTURE'}
            request={'id':draft['id'],'request_id':'test-idempotency-key-001'}
            first=self.req('/api/v1/send',request);second=self.req('/api/v1/send',request)
            self.assertEqual(first[0],200);self.assertEqual(first[1],second[1]);transport.return_value.submit.assert_called_once()
        record=self.req('/api/v1/sent')[1]['records'][0];self.assertEqual(record['actor'],'local-owner');self.assertEqual(record['identity'],'hello@nullverse.cloud')
        self.assertEqual(self.req('/api/v1/send',{'id':draft['id']})[0],400)
    def test_send_key_cannot_be_reused_with_changed_payload(self):
        draft=self.req('/api/v1/drafts',{'from':'hello@nullverse.cloud','to':'fixture@example.com','body':'first'})[1]
        request={'id':draft['id'],'request_id':'test-payload-protection'}
        self.assertEqual(self.req('/api/v1/send',request)[1]['status'],'paused')
        self.req('/api/v1/drafts',dict(draft,body='changed'))
        self.assertEqual(self.req('/api/v1/send',request)[0],400)

    def test_delegated_deny_read_send_rules_and_legacy_endpoints(self):
        key=self.server.mail.listing()[0]['id']
        draft=self.req('/api/v1/drafts',{'from':'hello@nullverse.cloud','to':'fixture@example.com','body':'Synthetic'})[1]
        def delegated(path,*args,**kwargs):
            if path=='/api/me':return 200,b'{"authenticated":true,"auth_type":"session","user_id":"delegate"}',None
            return base.fake_nullink(path,*args,**kwargs)
        with patch('app.nullink',delegated):
            self.assertEqual(self.req('/api/v1/messages')[1]['messages'],[])
            for path in ['/api/v1/message?id='+key,'/api/message?id='+key,'/api/attachment?id='+key+'&part=4']:
                self.assertEqual(self.req(path)[0],403)
            self.assertEqual(self.req('/api/v1/send',{'id':draft['id'],'request_id':'deny-test-request-id'})[0],403)
            self.assertEqual(self.req('/api/v1/rules/save',rule())[0],403)
            self.assertEqual(self.req('/api/drafts',{'from':'hello@nullverse.cloud','body':'bad'})[0],400)
            self.server.grants={'delegate':{'read':['hello@nullverse.cloud'],'send':[]}}
            self.assertEqual(self.req('/api/v1/message?id='+key)[0],200)
            self.assertEqual(self.req('/api/v1/message?id='+key)[1]['reply_identity']['from'],None)
    def test_versioned_errors_and_invalid_scopes(self):
        status,response,_=self.req('/api/v1/accounts/selection',{'selection':['unknown@example.com']});self.assertEqual(status,400);self.assertEqual(response['code'],'invalid_request')
        self.assertEqual(self.req('/api/v1/rules/save',rule(scope=['unknown@example.com']))[0],400)
        self.assertEqual(self.req('/api/v1/messages?limit=1000')[0],400)

if __name__=='__main__':unittest.main()
