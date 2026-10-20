import unittest, pathlib
S = pathlib.Path(__file__).resolve().parents[1] / 'static'
class GmailViews(unittest.TestCase):
    def test_views_above_categories_scoped_to_account(self):
        js = (S / 'workspace.js').read_text()
        self.assertLess(js.index("['all','All Mail',allUnread]"), js.index("row(ckey,'Categories'"))
        self.assertIn("inbox:['all','INBOX'],unread:['all','INBOX,UNREAD'],archived:['all','-INBOX,-SENT,-SPAM,-TRASH'],all:['all','']", js)
        line=js[js.index("for(const [view,label,count] of"):];line=line[:line.index('\n')]
        order=[line.index(x) for x in ("['inbox','Inbox'","['unread','Unread'","['archived','Archived'","['all','All Mail'","['sent','Sent'","['spam','Spam'","['trash','Trash'")]
        self.assertEqual(order,sorted(order))
        self.assertIn("accountView=acc.account_id", js)
if __name__ == '__main__': unittest.main()

import sys
sys.path.insert(0,str(S.parent))
class LabelSpec(unittest.TestCase):
    def test_label_spec_matching(self):
        import api_v1
        m=lambda *ids:{'provider':'gmail','provider_label_details':[{'id':i,'name':i} for i in ids]}
        self.assertTrue(api_v1.operator_match(m('INBOX','UNREAD'),[],'INBOX,UNREAD'))
        self.assertFalse(api_v1.operator_match(m('UNREAD'),[],'INBOX,UNREAD'))
        arch='-INBOX,-SENT,-SPAM,-TRASH'
        self.assertTrue(api_v1.operator_match(m('CATEGORY_UPDATES','UNREAD'),[],arch))
        self.assertFalse(api_v1.operator_match(m('SENT'),[],arch))
        self.assertFalse(api_v1.operator_match(m('INBOX'),[],arch))
        self.assertFalse(api_v1.operator_match(m('TRASH'),[],arch))
