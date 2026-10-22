"""Versioned, authenticated API shared by web and future Android."""
import hashlib, hmac, json, secrets, time
from pathlib import Path
import rules
import reader
import review as review_mod
import cases
from workspace import Workspace, accounts, permissions, principal, require_read, reply_identity


def state(server):
    if not hasattr(server,'preview_key'): server.preview_key=secrets.token_bytes(32)
    if not hasattr(server,'workspace'):
        server.workspace=Workspace(Path(server.drafts.path).with_name('workspace.sqlite3'))
    return server.workspace


def context(handler):
    identities=handler.identities()
    actor=principal(getattr(handler,'auth_data',{}))
    perm=permissions(actor,identities,getattr(handler.server,'grants',{}))
    if hasattr(handler.server,'gmail'):
        external=handler.server.gmail.accounts(actor)
        identities+= [a['id'] for a in external]
        perm['read']+= [a['id'] for a in external]
        perm['send']+= [a['address'] for a in external if a['address'] not in perm['send']]
    return state(handler.server),identities,actor,perm


def admin(perm):
    if not perm['admin']: raise PermissionError('Owner permission required')


def reviews(server):
    if not hasattr(server,'reviews'):
        server.reviews=review_mod.Reviews(state(server),review_mod.FileQueueReviewer(Path(server.drafts.path).parent/'mail-review'))
    return server.reviews


def message(handler,folder,key):
    store,ids,actor,perm=context(handler)
    m=store.enrich(handler.server.mail.message(folder,key),ids);m['folder']=folder
    require_read(m,perm);m['reply_identity']=reply_identity(m,perm)
    try:
        parsed=handler.server.mail.read(handler.server.mail.locate(folder,key));m.update(reader.details(parsed))
        m['has_html']=any(p.get_content_type()=='text/html' and p.get_content_disposition()!='attachment' for p in parsed.walk() if not p.is_multipart())
        m['script_findings']=reader.scan(parsed)
    except (OSError,ValueError):m['has_html']=False;m['script_findings']=[]
    m['review']=reviews(handler.server).get(key);m['scripts_enabled']=False
    service=cases.Cases(store,handler.server.mail,ids,actor,perm)
    if m.get('gmail_account') and hasattr(handler.server,'gmail'):
        account=handler.server.gmail.account(actor,m['gmail_account'])
        m['reply_identity']={'from':account['address'],'fallback':False,'reason':'Verified Google primary identity'}
    m['message_ref']=handler.server.mail.reference(key) if hasattr(handler.server.mail,'reference') else cases.reference(key);m['cases']=service.badges(m['message_ref'])
    return m


OPERATOR=__import__('re').compile(r'(?i)\b(category|glabel|is):("([^"]{1,200})"|\S{1,200})')
CATEGORIES={'primary':'CATEGORY_PERSONAL','personal':'CATEGORY_PERSONAL','social':'CATEGORY_SOCIAL','promotions':'CATEGORY_PROMOTIONS','updates':'CATEGORY_UPDATES','forums':'CATEGORY_FORUMS'}
def parse_query(text):
    """Split Gmail-style operators (category:, glabel:, is:) from free text."""
    ops=[]
    for m in OPERATOR.finditer(text):ops.append((m.group(1).lower(),(m.group(3) if m.group(3) is not None else m.group(2)).strip()))
    return OPERATOR.sub(' ',text).strip(),ops
def operator_match(m,ops,glabel_id=''):
    if not ops and not glabel_id:return True
    details=m.get('provider_label_details') or []
    if not details and m.get('provider')!='gmail':return False
    ids={d['id'] for d in details};names={d['name'].casefold() for d in details}|{i.casefold() for i in ids}
    if glabel_id:
        # Comma-separated label spec; '-ID' means the label must be absent (e.g. 'INBOX,UNREAD' or '-INBOX,-SENT').
        for part in str(glabel_id).split(',')[:8]:
            part=part.strip()
            if part.startswith('-'):
                if part[1:] in ids:return False
            elif part and part not in ids:return False
    for kind,value in ops:
        v=value.casefold()
        if kind=='category' and CATEGORIES.get(v,'CATEGORY_'+value.upper()) not in ids:return False
        if kind=='is' and value.upper() not in ids:return False
        if kind=='glabel' and v not in names and not any(n.startswith(v+'/') for n in names):return False
    return True
def filter_messages(handler,store,ids,actor,perm,folder,single='',query='',recipient='',unread=False,label='',glabel=''):
    server=handler.server
    if single and single not in perm['read']: raise PermissionError('Account read permission required')
    selected=[single] if single else store.selection(actor,perm['read'])
    text,ops=parse_query(query);text=text.casefold()[:200]
    rows=[]
    folders=('inbox','archive','sent') if folder=='all' else (folder,)
    listing=[(f,row) for f in folders for row in server.mail.listing(f,'',recipient,unread)]
    if folder=='all':listing.sort(key=lambda x:x[1]['timestamp'],reverse=True)
    for real,row in listing:
        m=store.enrich(row,ids);m['folder']=real
        if not set(m['accounts']).intersection(perm['read']): continue
        if (folder=='inbox' or single) and not set(m['accounts']).intersection(selected) and not (glabel or ops): continue
        if label and label not in m['labels']: continue
        if not operator_match(m,ops,glabel): continue
        if text:
            full=server.mail.message(real,m['id'])
            if text not in ' '.join(str(full.get(k,'')) for k in ('subject','from','to','body')).casefold(): continue
        rows.append(m)
    return rows


def read(handler,path,q):
    store,ids,actor,perm=context(handler);server=handler.server
    arg=lambda k,default='':q.get(k,[default])[0]
    offset=int(arg('offset','0'));limit=int(arg('limit','100'))
    if not 0<=offset<=1000000 or not 1<=limit<=100: raise ValueError('offset 0–1000000 and limit 1–100 required')
    if path=='capabilities':
        return {'version':'1','principal':actor,'permissions':perm,'features':{'accounts':True,'cases':True,'case_statuses':list(cases.STATUSES),'case_sharing':False,'rules':perm['admin'],'labels':'local-only','regex':False,'gmail':hasattr(server,'gmail'),'android_apk':False,'threading':'references','scheduled_actions':False,'ai_actions':False},'rule_fields':rules.FIELDS,'rule_actions':rules.ACTIONS,'limits':{'page':100,'preview':50,'condition_nodes':64,'condition_depth':6},'gmail':gmail_status(server,actor)}
    if path=='gmail/status':return gmail_status(server,actor)
    if path=='message/html':
        m=message(handler,arg('folder','inbox'),arg('id'));sender=(reader.addresses(m.get('from')) or [''])[0].lower()
        with store.db() as db:always=bool(sender) and db.execute('SELECT 1 FROM meta WHERE key=?',('remote-images:'+sender,)).fetchone() is not None
        remote=arg('remote')=='1' or always
        out=reader.render(server.mail.read(server.mail.locate(m['folder'],m['id'])),remote)
        if out is None:return {'html':None}
        return dict(out,remote=remote,remote_always=always,sender=sender)
    if path=='message/source':
        m=message(handler,arg('folder','inbox'),arg('id'));raw,parts=server.mail.source(m['folder'],m['id'])
        return {'raw':raw.decode('utf-8','replace'),'size':len(raw),'segmented':bool(parts),'external_parts':parts}
    if path=='gmail/details':return {'accounts':server.gmail.details(actor) if hasattr(server,'gmail') else [],'export':{'available':False,'reason':'Export (mbox / .eml zip) is not built yet'}}
    if path=='gmail/labels':return {'accounts':server.gmail.label_catalog(actor) if hasattr(server,'gmail') else [],'provider':'gmail','read_only':True}
    case_service=cases.Cases(store,server.mail,ids,actor,perm)
    if path=='cases':return case_service.listing(arg('q'),arg('status'),offset,limit)
    if path=='cases/detail':return case_service.detail(arg('id'),offset,limit)
    if path=='cases/notes':return case_service.notes(arg('id'),offset,limit)
    if path=='cases/history':return case_service.history(arg('id'),offset,limit)
    if path=='accounts':
        rows=[a for a in accounts(ids) if a['id'] in perm['read']]
        if hasattr(server,'gmail'):
            rows += [dict(id=a['id'],address=a['address'],provider='gmail',kind='mailbox',capabilities={'read':True,'send':True,'labels':'local-only','folders':'local-only','read_flags':'local-only'}) for a in server.gmail.accounts(actor)]
        unread={a['id']:0 for a in rows}
        for row in server.mail.listing():
            m=store.enrich(row,ids)
            if row['unread']:
                for a in m['accounts']:
                    if a in unread: unread[a]+=1
        for a in rows: a['unread']=unread[a['id']]
        return {'accounts':rows,'selection':store.selection(actor,perm['read']),'identities':perm['send']}
    if path=='messages':
        folder=arg('folder','inbox')
        rows=filter_messages(handler,store,ids,actor,perm,folder,arg('account'),arg('q')[:400],arg('recipient'),arg('unread')=='1',arg('label'),arg('glabel'))
        for m in rows[offset:offset+limit]:
            m['message_ref']=server.mail.reference(m['id']) if hasattr(server.mail,'reference') else cases.reference(m['id']);m['cases']=case_service.badges(m['message_ref'])
        return {'messages':rows[offset:offset+limit],'total':len(rows),'offset':offset,'next_offset':offset+limit if offset+limit<len(rows) else None}
    if path=='message':
        import receipts
        m=message(handler,arg('folder','inbox'),arg('id'))
        try:raw=server.mail.read(server.mail.locate(arg('folder','inbox'),m['id']))
        except Exception:raw=None
        with store.db() as db:
            m['delivery']=receipts.by_message_id(db,m.get('message_id')) if m.get('message_id') else None
            req=receipts.mdn_request(raw) if raw is not None and arg('folder','inbox') in ('inbox','archive') else None
            if req and m.get('from') and any(a.lower() in m['from'].lower() for a in perm['send']):req=None
            m['mdn_request']=dict(req,answered=receipts.mdn_state(db,m['id'])) if req else None
        return m
    if path=='thread':
        original=message(handler,arg('folder','inbox'),arg('id'))
        # References are message identifiers, not subject-based guesses. Return
        # only messages this principal may read; cap scan and result explicitly.
        def refs(m): return set((m.get('references','')+' '+m.get('in_reply_to','')+' '+m.get('message_id','')).split())
        wanted=refs(original);rows=[];scanned=0
        for folder in ('inbox','archive','sent','spam','trash'):
            for row in server.mail.listing(folder):
                scanned+=1
                if scanned>1000: break
                m=store.enrich(server.mail.message(folder,row['id']),ids);m['folder']=folder
                if not set(m['accounts']).intersection(perm['read']): continue
                if (wanted and wanted.intersection(refs(m))) or m['id']==original['id']: rows.append(m)
            if scanned>1000: break
        rows.sort(key=lambda m:m['timestamp'])
        return {'messages':rows[:100],'truncated':scanned>1000 or len(rows)>100}
    if path=='labels': return {'labels':store.labels()}
    if path=='rules':
        admin(perm);return {'rules':store.rules(),'templates':rules.TEMPLATES}
    if path=='rules/history':
        admin(perm);return {'runs':store.history(offset)}
    if path=='rules/versions':
        admin(perm);return {'versions':store.versions(arg('id'))}
    if path=='sent':
        # Audit rows are kept; rows whose outbound message was trashed or permanently deleted are hidden here.
        live={d['id']:d['status'] for d in handler.server.drafts.list()}
        import receipts
        rows=[r for r in store.sent(actor,offset) if live.get(r['draft']) not in (None,'trashed') and r['result'].get('status')!='retracted']
        with store.db() as db:
            for r in rows:r['delivery']=receipts.summary(db,r['draft'])
        return {'records':rows,'delivery_verified':False}
    raise FileNotFoundError()


def write(handler,path,data):
    store,ids,actor,perm=context(handler);server=handler.server
    case_service=cases.Cases(store,server.mail,ids,actor,perm)
    if path.startswith('gmail/'):
        admin(perm)
        if not hasattr(server,'gmail'):raise ValueError('Gmail adapter is unavailable')
        expected={'gmail/connect':set(),'gmail/import':{'account_id','confirm'},'gmail/sync':{'account_id'},'gmail/backfill':{'account_id','paused'},'gmail/label-map':{'account_id','provider_label','label','mode'},'gmail/label-unmap':{'account_id','provider_label','label'},'gmail/sync-now':{'account_id'},'gmail/retry-failed':{'account_id'}}
        if path in expected and set(data)!=expected[path]:raise ValueError('Invalid Gmail request fields')
        if path=='gmail/create-label':
            if set(data)!={'account_id','name','confirm'} or data.get('confirm') is not True:raise ValueError('Explicit confirmation required to create a Gmail label')
            name=str(data['name']).strip()
            if not 1<=len(name)<=225:raise ValueError('Invalid label name')
            server.gmail.account(actor,data['account_id'])
            return {'id':server.gmail.sync.create_label('gmail',data['account_id'],name),'name':name}
        if path=='gmail/sync-now':return server.gmail.sync_now(actor,data['account_id'])
        if path=='gmail/retry-failed':return server.gmail.retry_failed_now(actor,data['account_id'])
        if path=='gmail/label-map':return server.gmail.map_label(actor,data['account_id'],data['provider_label'],data['label'],data['mode'])
        if path=='gmail/label-unmap':return server.gmail.unmap_label(actor,data['account_id'],data['provider_label'],data['label'])
        if path in ('gmail/import','gmail/sync','gmail/backfill') and (not isinstance(data.get('account_id'),str) or not __import__('re').fullmatch('gmail:[a-f0-9]{32}',data['account_id'])):raise ValueError('Invalid Gmail account ID')
        if path=='gmail/connect':return {'authorization_url':server.gmail.begin(actor,handler.cookie(),handler.expected_origin()+'/api/v1/gmail/callback')}
        if path=='gmail/import':return server.gmail.start_import(actor,data.get('account_id'),data.get('confirm'))
        if path=='gmail/backfill':return server.gmail.set_backfill(actor,data.get('account_id'),data.get('paused'))
        if path=='gmail/sync':return server.gmail.sync_page(actor,data.get('account_id'))
    if path=='cases/create':return case_service.create(data)
    if path=='cases/save':return case_service.save(data)
    if path=='cases/membership':
        result=case_service.membership(data)
        ref=data.get('message') or {}
        if result.get('changed') and ref.get('provider')=='gmail' and hasattr(server,'gmail'):
            row=server.gmail.native(ref['id'])
            if row:
                name=server.gmail.sync.adapter('gmail').case_label(str(result['case'].get('title','Case'))[:200].replace('/','-'))
                server.gmail.sync.enqueue('gmail',row[0],row[1],add_names=[name] if data['linked'] else [],remove_names=[] if data['linked'] else [name])
                if data['linked']:result.update(provider_missing_labels=server.gmail.sync.missing('gmail',row[0],[name]),account_id=row[0])
        return result
    if path=='cases/notes':return case_service.add_note(data)
    if path=='accounts/selection': return {'selection':store.select(actor,data.get('selection'),perm['read'])}
    if path in ('labels/save','labels/delete'):
        admin(perm)
        if path.endswith('save'): return {'id':store.label_save(data)}
        store.label_delete(data.get('id'));return {'ok':True}
    if path=='messages/bulk-label':
        label=data.get('label');folder=data.get('folder','inbox')
        if label not in [l['id'] for l in store.labels()]: raise ValueError('Invalid label')
        if data.get('confirm') is not True: raise ValueError('Explicit confirmation required')
        rows=filter_messages(handler,store,ids,actor,perm,folder,data.get('account',''),str(data.get('q',''))[:400],data.get('recipient',''),data.get('unread') is True,data.get('filter_label',''),data.get('glabel',''))
        if len(rows)>5000: raise ValueError('More than 5000 results; narrow the filter')
        changed=0
        for m in rows:
            if label not in m['labels']: store.set_state(m['id'],m['labels']+[label],m['priority']);changed+=1
        return {'matched':len(rows),'labeled':changed}
    if path=='message/review':
        if set(data)!={'folder','id'}:raise ValueError('folder and id required')
        m=message(handler,data['folder'],data['id'])
        raw,_=server.mail.eml(m['folder'],m['id'])
        return {'review':reviews(server).submit(m,m['script_findings'],raw,actor),'scripts_enabled':False}
    if path=='message/remote-images':
        if set(data)!={'sender','allow'} or not isinstance(data['allow'],bool):raise ValueError('sender and boolean allow required')
        sender=str(data['sender']).strip().lower()
        if not __import__('re').fullmatch(r'[^\s<>@]{1,200}@[^\s<>@]{1,200}',sender):raise ValueError('Invalid sender address')
        with store.db() as db:
            if data['allow']:db.execute('INSERT OR REPLACE INTO meta VALUES (?,?)',('remote-images:'+sender,str(time.time())))
            else:db.execute('DELETE FROM meta WHERE key=?',('remote-images:'+sender,))
        return {'sender':sender,'allow':data['allow']}
    if path=='message/labels':
        m=message(handler,data.get('folder','inbox'),data.get('id'));labels=data.get('labels')
        known=[l['id'] for l in store.labels()]
        if not isinstance(labels,list) or any(l not in known for l in labels): raise ValueError('Invalid labels')
        store.set_state(m['id'],list(dict.fromkeys(labels)),m['priority'])
        return dict({'ok':True},**push_labels(server,store,m,set(m['labels']),set(labels)))
    if path.startswith('rules/'):
        admin(perm)
        if path=='rules/save': return store.save_rule(data,actor,ids)
        if path=='rules/restore':
            historic=next((v for v in store.versions(data.get('id')) if v['version']==data.get('restore_version')),None)
            if not historic: raise FileNotFoundError()
            return store.save_rule(dict(historic['data'],id=historic['id'],version=data.get('version')),actor,ids)
        if path=='rules/apply-existing':
            if set(data)!={'id','folder','confirm'} or data['confirm'] is not True:raise ValueError('Rule ID, folder and explicit confirmation required')
            if data['folder'] not in ('inbox','archive'):raise ValueError('Apply to inbox or archive')
            rule=next((r for r in store.rules() if r['id']==data['id']),None)
            if not rule:raise FileNotFoundError()
            keys=[row['id'] for row in server.mail.listing(data['folder'])][:500];matched=0
            for i in range(0,len(keys),50):
                batch=keys[i:i+50]
                if not batch:break
                for plan in store.preview(server.mail,ids,batch,data['folder'],rule)['plans']:
                    if plan['actions']:store.execute_plan(server.mail,plan,actor,'explicit');matched+=1
            return {'scanned':len(keys),'applied':matched}
        if path=='rules/preview':
            result=store.preview(server.mail,ids,data.get('ids'),data.get('folder','inbox'),data.get('rule'))
            if data.get('rule') is None:
                expires=int(time.time())+600
                payload=result['digest']+':'+str(expires)
                result['token']=payload+':'+hmac.new(server.preview_key,payload.encode(),hashlib.sha256).hexdigest()
            return result
        if path=='rules/run':
            if data.get('confirm') is not True: raise ValueError('Preview and explicit confirmation required')
            token=data.get('token','');parts=token.split(':')
            if len(parts)!=3: raise ValueError('Preview token required')
            payload=':'.join(parts[:2])
            if not hmac.compare_digest(parts[2],hmac.new(server.preview_key,payload.encode(),hashlib.sha256).hexdigest()) or int(parts[1])<time.time(): raise ValueError('Preview expired; preview again')
            with store.db() as db: prior=db.execute('SELECT value FROM meta WHERE key=?',('run:'+token,)).fetchone()
            if prior: return {'status':prior[0],'duplicate':True}
            result=store.preview(server.mail,ids,data.get('ids'),data.get('folder','inbox'))
            if result['digest']!=parts[0]: raise ValueError('Messages or rules changed; preview again')
            with store.db() as db: db.execute('INSERT INTO meta VALUES (?,?)',('run:'+token,'claimed'))
            for plan in result['plans']: store.execute_plan(server.mail,plan,actor,'explicit')
            with store.db() as db: db.execute('UPDATE meta SET value=? WHERE key=?',('completed','run:'+token))
            return {'status':'completed','count':result['count']}
    raise FileNotFoundError()


def push_labels(server,store,m,old,new):
    """Queue Nullmail label changes on a Gmail message for write-back; report labels Gmail lacks."""
    if m.get('provider')!='gmail' or not hasattr(server,'gmail'):return {}
    row=server.gmail.native(m['id'])
    if not row:return {}
    names={l['id']:l['name'] for l in store.labels()}
    add=[names[i] for i in new-old if i in names];remove=[names[i] for i in old-new if i in names]
    sync=server.gmail.sync;status=sync.status('gmail',row[0])
    if not status['enabled']:return {'provider_sync':status}
    sync.enqueue('gmail',row[0],row[1],add_names=add,remove_names=remove)
    return {'provider_sync':status,'provider_missing_labels':sync.missing('gmail',row[0],add),'account_id':row[0]}


def gmail_status(server,actor):
    if not hasattr(server,'gmail'):return {'connected':False,'blockers':['Gmail adapter unavailable in this runtime'],'accounts':[]}
    rows=server.gmail.accounts(actor)
    import gmail as _g
    for a in rows:a['label_sync']=server.gmail.sync.status('gmail',a['id']);a['missing_scopes']=_g.missing_scopes(server.gmail.granted_scopes(a['id']))
    return {'connected':bool(rows),'configured':not server.gmail.blockers(),'accounts':rows,'blockers':server.gmail.blockers(),'sync':'bounded polling after explicit import','labels':'local-only','folders':'local-only','read_flags':'local-only','provider_labels':'observed IDs only','send_identities':'verified Google primary address only','historical_rules':False}
