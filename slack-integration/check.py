#!/usr/bin/env python3
"""Read-only deployment readiness. Never prints tokens; never posts or starts AI."""
import argparse
import json
from pathlib import Path
from adapters import Slack

p=argparse.ArgumentParser()
p.add_argument('registry')
p.add_argument('--auth-test',action='store_true',help='Call Slack auth.test using configured bot token files')
a=p.parse_args()
r=json.loads(Path(a.registry).read_text())
report={'bots':{},'live_smoke':'not run'}
for name,c in r['bots'].items():
    b={'enabled':c.get('enabled',False),'runtime_id':c.get('runtime_id'),'user_id':c.get('user_id'),'missing':[]}
    for field in ('token_file','signing_secret_file'):
        path=Path(c.get(field,''))
        if not path.is_file(): b['missing'].append(field)
    for field in ('app_id','bot_id'):
        if not c.get(field) or c[field].startswith('REQUIRED_'): b['missing'].append(field)
    if a.auth_test and 'token_file' not in b['missing']:
        try: b['identity']=Slack(r).identity(name)
        except Exception as e: b['identity_error']=type(e).__name__
    report['bots'][name]=b
print(json.dumps(report,indent=2))
