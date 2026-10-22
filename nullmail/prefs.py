"""Per-user UI preferences synced across devices. Last-write-wins per key (client timestamp in ms, clamped to server time)."""
import json, re, time
SCHEMA_SQL='CREATE TABLE IF NOT EXISTS ui_prefs(actor TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, updated REAL NOT NULL, PRIMARY KEY(actor,key))'
MAX_TOTAL=64*1024
SETUP_TABS=('local','external','status')
def _s(v,n):
    if not isinstance(v,str) or len(v)>n: raise ValueError(f'string up to {n} chars required')
    return v
def _tree(v):
    if not isinstance(v,dict) or len(v)>3000: raise ValueError('tree must be an object (max 3000 keys)')
    for k,b in v.items():
        _s(k,300)
        if not isinstance(b,bool): raise ValueError('tree values must be boolean')
    return v
def _view(v):
    allowed={'folder':40,'account':200,'glabel':200,'gview':300,'recipient':320}
    if not isinstance(v,dict) or not set(v)<=set(allowed): raise ValueError('last_view has unknown fields')
    for k,x in v.items():_s(x,allowed[k])
    if v.get('folder') and not re.fullmatch(r'[a-z]{1,40}',v['folder']): raise ValueError('bad folder')
    return v
def _dismissed(v):
    if not isinstance(v,dict) or len(v)>50: raise ValueError('dismissed must be an object (max 50)')
    for k,x in v.items():_s(k,80);_s(x,500)
    return v
def _enum(*opts):
    def f(v):
        if v not in opts: raise ValueError('must be one of '+', '.join(opts))
        return v
    return f
def _undo(v):
    if isinstance(v,bool) or not isinstance(v,int) or not 0<=v<=120: raise ValueError('undo_send_seconds must be 0–120')
    return v
def _bool(v):
    if not isinstance(v,bool): raise ValueError('boolean required')
    return v
KEYS={'undo_send_seconds':_undo,'track_opens_default':_bool,'tree':_tree,'last_view':_view,'body_mode':_enum('html','text'),'dismissed':_dismissed,'setup_tab':_enum(*SETUP_TABS)}
def validate(data):
    if not isinstance(data,dict) or set(data)!={'prefs'} or not isinstance(data['prefs'],dict): raise ValueError('Body must be {"prefs": {key: {value, updated}}}')
    out={};now=time.time()*1000
    for k,item in data['prefs'].items():
        if k not in KEYS: raise ValueError('Unknown preference '+str(k)[:40])
        if not isinstance(item,dict) or set(item)!={'value','updated'}: raise ValueError('Each preference needs value and updated')
        u=item['updated']
        if isinstance(u,bool) or not isinstance(u,(int,float)) or u<0: raise ValueError('updated must be a timestamp in ms')
        out[k]=(KEYS[k](item['value']),min(float(u),now))
    if len(json.dumps({k:v for k,(v,_) in out.items()}))>MAX_TOTAL: raise ValueError('Preferences too large')
    return out
def get(db,actor):
    db.execute(SCHEMA_SQL)
    return {k:{'value':json.loads(v),'updated':u} for k,v,u in db.execute('SELECT key,value,updated FROM ui_prefs WHERE actor=?',(actor,))}
def put(db,actor,data):
    items=validate(data);db.execute(SCHEMA_SQL);current=get(db,actor)
    merged={**{k:v['value'] for k,v in current.items()},**{k:v for k,(v,_) in items.items()}}
    if len(json.dumps(merged))>MAX_TOTAL: raise ValueError('Preferences too large')
    for k,(v,u) in items.items():
        if k not in current or u>current[k]['updated']:
            db.execute('INSERT OR REPLACE INTO ui_prefs VALUES (?,?,?,?)',(actor,k,json.dumps(v,separators=(',',':')),u))
    return get(db,actor)
