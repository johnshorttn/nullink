"""Pure, bounded rule validation/evaluation. No I/O, regex, scripts or sends."""
from datetime import datetime, timezone
from email.utils import getaddresses, parsedate_to_datetime
import time

FIELDS = {
 'sender':['contains','equals','starts_with','ends_with'],
 'recipient':['contains','equals','starts_with','ends_with'],
 'sender_domain':['equals','ends_with'], 'recipient_domain':['equals','ends_with'],
 'subject':['contains','equals','starts_with','ends_with'],
 'body':['contains','equals','starts_with','ends_with'],
 'headers':['contains'], 'attachment_name':['contains','equals','ends_with'],
 'has_attachments':['equals'], 'read':['equals'], 'labels':['contains'],
 'date':['before','after'], 'age_days':['greater','less'],
}
ACTIONS = ['add_label','remove_label','archive','move','read','unread','priority','add_to_case']

def validate_tree(node, depth=0, budget=None):
    if budget is None: budget=[0]
    budget[0]+=1
    if depth>6 or budget[0]>64: raise ValueError('Condition limit: 64 nodes, 6 nested levels')
    if not isinstance(node,dict): raise ValueError('Condition must be an object')
    if 'group' in node:
        if set(node)!={'group','children'} or node['group'] not in ('ALL','ANY','NOT'): raise ValueError('Invalid condition group')
        children=node['children']
        if not isinstance(children,list) or not 1<=len(children)<=16 or (node['group']=='NOT' and len(children)!=1): raise ValueError('Groups need 1–16 children; NOT needs one')
        for child in children: validate_tree(child,depth+1,budget)
    else:
        if set(node)!={'field','op','value'}: raise ValueError('Condition needs field, op and value')
        field,op,value=node['field'],node['op'],node['value']
        if not isinstance(field,str) or field not in FIELDS or op not in FIELDS[field]: raise ValueError('Unsupported field/operator; regex is not supported')
        if field in ('has_attachments','read'):
            if not isinstance(value,bool): raise ValueError('Boolean value required')
        elif field=='age_days':
            if type(value) not in (int,float) or not 0<=value<=365000: raise ValueError('Age must be 0–365000 days')
        else:
            if not isinstance(value,str) or not 1<=len(value)<=500: raise ValueError('Text value must be 1–500 characters')
            if field=='date':
                try: datetime.strptime(value,'%Y-%m-%d')
                except ValueError: raise ValueError('Date must be YYYY-MM-DD')
    return node

def validate_rule(rule, accounts, labels, cases=()):
    if not isinstance(rule,dict): raise ValueError('Rule object required')
    if set(rule)-{'id','name','priority','enabled','stop','scope','condition','exception','actions','version'}: raise ValueError('Unknown rule fields')
    if not isinstance(rule.get('name'),str) or not 1<=len(rule['name'])<=100: raise ValueError('Rule name required (100 characters maximum)')
    if type(rule.get('priority')) is not int or not -100000<=rule['priority']<=100000: raise ValueError('Numeric integer priority required')
    for key in ('enabled','stop'):
        if type(rule.get(key)) is not bool: raise ValueError(key+' must be boolean')
    scope=rule.get('scope')
    if not isinstance(scope,list) or not scope or len(scope)>1000 or any(not isinstance(x,str) or x not in accounts for x in scope): raise ValueError('Select authorized account scope explicitly')
    budget=[0];validate_tree(rule.get('condition'),budget=budget)
    if rule.get('exception') is not None: validate_tree(rule['exception'],budget=budget)
    actions=rule.get('actions')
    if not isinstance(actions,list) or not 1<=len(actions)<=16: raise ValueError('Select 1–16 actions')
    for action in actions:
        if not isinstance(action,dict) or action.get('type') not in ACTIONS or set(action)-{'type','value'}: raise ValueError('Unsupported action')
        kind,value=action['type'],action.get('value')
        if kind in ('add_label','remove_label') and value not in labels: raise ValueError('Unknown label')
        if kind=='add_to_case' and value not in cases: raise ValueError('Choose an existing authorized case')
        if kind=='move' and value not in ('inbox','archive','spam'): raise ValueError('Rules can move only to inbox, archive or spam; no trash/delete')
        if kind=='priority' and value not in ('low','normal','high'): raise ValueError('Invalid message priority')
        if kind in ('read','unread','archive') and value is not None: raise ValueError('Action does not take a value')
    return rule

def values(field, message, now):
    if field=='sender': return [a.lower() for _,a in getaddresses([message.get('from','')])]
    if field=='recipient': return message.get('routing_recipients',[])
    if field.endswith('_domain'): return [a.rsplit('@',1)[-1] for a in values(field[:-7],message,now)]
    if field=='has_attachments': return [bool(message.get('attachments'))]
    if field=='attachment_name': return [a['name'] for a in message.get('attachments',[])]
    if field=='read': return [not message['unread']]
    if field=='labels': return message.get('labels',[])
    if field in ('date','age_days'):
        try:
            date=parsedate_to_datetime(message.get('date',''))
            if date.tzinfo is None: date=date.replace(tzinfo=timezone.utc)
            return [date.timestamp() if field=='date' else (now-date.timestamp())/86400]
        except (ValueError,TypeError,OverflowError): return []
    return [message.get(field,'')[:200000]]

def evaluate(node, message, now=None):
    now=time.time() if now is None else now
    if 'group' in node:
        children=[evaluate(c,message,now) for c in node['children']]
        results=[c['matched'] for c in children]; group=node['group']
        matched=all(results) if group=='ALL' else any(results) if group=='ANY' else not results[0]
        return {'group':group,'matched':matched,'children':children}
    field,op,want=node['field'],node['op'],node['value']
    if field=='date': want=datetime.strptime(want,'%Y-%m-%d').replace(tzinfo=timezone.utc).timestamp()
    def matches(actual):
        a,b=(actual.casefold(),want.casefold()) if isinstance(actual,str) and isinstance(want,str) else (actual,want)
        if op=='equals': return a==b
        if op=='contains': return a==b if field=='labels' else b in a
        if op=='starts_with': return a.startswith(b)
        if op=='ends_with': return a.endswith(b)
        if op in ('before','less'): return a<b
        if op in ('after','greater'): return a>b
        return False
    actual=values(field,message,now)
    return {'field':field,'op':op,'matched':any(matches(v) for v in actual),'available':bool(actual)}

def plan(rules,message,now=None):
    """Evaluate ordered rules on a simulated copy, including preceding actions."""
    m=dict(message,labels=list(message.get('labels',[])),case_ids=list(message.get('case_ids',[])))
    explanations=[];actions=[];writes={};warnings=[]
    for rule in sorted(rules,key=lambda r:(r['priority'],r['id'])):
        if not rule['enabled'] or not set(rule['scope']).intersection(m.get('accounts',[])): continue
        condition=evaluate(rule['condition'],m,now)
        exception=evaluate(rule['exception'],m,now) if rule.get('exception') else None
        matched=condition['matched'] and not (exception and exception['matched'])
        explanations.append({'rule_id':rule['id'],'name':rule['name'],'version':rule.get('version',1),'matched':bool(matched),'condition':condition,'exception':exception})
        if not matched: continue
        for action in rule['actions']:
            kind=action['type']; value=action.get('value')
            key='read' if kind in ('read','unread') else 'folder' if kind in ('archive','move') else 'label:'+str(value) if kind in ('add_label','remove_label') else kind
            if kind=='add_to_case':key='case:'+str(value)
            effect=kind if kind!='move' else value
            if key in writes and writes[key]!=effect: warnings.append('Conflicting actions for '+key+'; later action wins')
            writes[key]=effect;actions.append(dict(action,rule_id=rule['id']))
            if kind=='add_label' and value not in m['labels']: m['labels'].append(value)
            if kind=='remove_label' and value in m['labels']: m['labels'].remove(value)
            if kind in ('read','unread'): m['unread']=kind=='unread'
            if kind in ('archive','move'): m['folder']='archive' if kind=='archive' else value
            if kind=='priority': m['priority']=value
            if kind=='add_to_case' and value not in m['case_ids']: m['case_ids'].append(value)
        if rule['stop']: break
    return {'id':message['id'],'folder':message['folder'],'actions':actions,'explanations':explanations,'warnings':warnings,'result':m}

TEMPLATES=[{'name':'Archive a newsletter','priority':100,'enabled':False,'stop':False,'scope':[],
 'condition':{'field':'sender','op':'equals','value':'newsletter@example.com'},'exception':None,'actions':[{'type':'archive'}]},
 {'name':'Unread important subject','priority':50,'enabled':False,'stop':True,'scope':[],
 'condition':{'group':'ALL','children':[{'field':'subject','op':'contains','value':'urgent'},{'group':'NOT','children':[{'field':'read','op':'equals','value':True}]}]},'exception':None,'actions':[{'type':'priority','value':'high'}]}]
