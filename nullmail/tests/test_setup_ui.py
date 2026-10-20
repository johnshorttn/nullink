import pathlib,re,unittest
S=pathlib.Path(__file__).resolve().parents[1]/'static'
class SetupUiTests(unittest.TestCase):
 def setUp(self):
  self.html=(S/'index.html').read_text();self.app=(S/'app.js').read_text();self.ws=(S/'workspace.js').read_text()
 def test_setup_is_in_app_view_with_three_tabs_and_back(self):
  self.assertIn('id="setup-view"',self.html);self.assertIn('<h1>Setup</h1>',self.html);self.assertIn('id="setup-back"',self.html)
  self.assertEqual(re.findall(r'data-setup-tab="(\w+)"',self.html),['local','external','status'])
  self.assertIn('role="tablist"',self.html);self.assertIn('<button id="setup-tab">Setup</button>',self.html)
 def test_setup_separate_from_settings_and_deep_links(self):
  self.assertNotIn('ettings',self.html+self.app)
  self.assertIn("#setup\\/(\\w+)",self.app);self.assertIn("'#setup/'+tab",self.app);self.assertIn('hashchange',self.app)
 def test_local_tab_no_longer_mixes_external(self):
  i=self.app.index('async function setupLocal');j=self.app.index('\n',i)
  self.assertNotIn('gmailSetup',self.app[i:j]);self.assertNotIn('setupExternal',self.app[i:j])
 def test_external_and_status_tabs(self):
  for s in ('async function setupExternal','async function setupStatus',"api('gmail/details')","'gmail/sync-now'","'gmail/retry-failed'",'Reconnect Gmail','Resume backfill','Export','Outlook'):self.assertIn(s,self.ws)
 def test_outbound_notice_dismissible_until_status_changes(self):
  self.assertIn('id="banner-dismiss"',self.html);self.assertIn('BANNER_KEY',self.app)
  self.assertIn("(config.outbound.paused?'paused':'ready')+'|'+(config.outbound.reason||'')",self.app)
  self.assertIn("['Outbound notice',c.outbound.reason",self.ws)
if __name__=='__main__':unittest.main()
