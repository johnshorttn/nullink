'use strict';
let ruleCaps=null, localLabels=[], ruleCases=[];
const button=(text,fn)=>{const b=el('button',text);b.type='button';b.onclick=task(fn);return b;};
let fieldSequence=0;
const field=(title,input)=>{const wrap=el('div',undefined,'field-control'),label=el('label',title);input.id=input.id||'field-'+(++fieldSequence);label.htmlFor=input.id;wrap.append(label,input);return wrap;};
const input=(value,type='text')=>{const n=el('input');n.type=type;n.value=value;return n;};
const select=(items,value)=>{const n=el('select');for(const [v,t] of items)n.add(new Option(t,v));n.value=value;return n;};
async function loadAccounts(){
 accountConfig=await api('accounts');const root=$('#accounts-panel');root.replaceChildren();
 root.append(el('h2','Accounts'),el('p','Checkboxes only control the unified inbox. Delivery and rule processing stay active.','small muted'));
 const controls=el('div',undefined,'actions');for(const [name,selection] of [['All',accountConfig.accounts.map(a=>a.id)],['None',[]],['Local only',accountConfig.accounts.filter(a=>a.provider==='local').map(a=>a.id)]])controls.append(button(name,async()=>{await api('accounts/selection',{selection});accountView='';await loadAccounts();folder='inbox';await loadMail();}));root.append(controls);
 for(const [provider,title] of [['local','Local server accounts'],['gmail','External']]){
  if(provider==='local'){root.append(localAccountTree(accountConfig.accounts.filter(a=>a.provider==='local')));continue;}
  const group=el('details');group.open=false;group.append(el('summary',title));
  const rows=accountConfig.accounts.filter(a=>a.provider===provider);
  if(!rows.length)group.append(el('p','Gmail not connected','small muted'));
  for(const a of rows){const row=el('div',undefined,'account-row'),check=input('','checkbox');check.checked=accountConfig.selection.includes(a.id);check.setAttribute('aria-label','Show '+a.address+' in unified inbox');check.onchange=task(async()=>{const chosen=new Set(accountConfig.selection);if(check.checked)chosen.add(a.id);else chosen.delete(a.id);await api('accounts/selection',{selection:[...chosen]});accountView='';await loadAccounts();folder='inbox';await loadMail();});const name=button(`${a.address} (${a.unread})`,async()=>{accountView=a.id;folder='inbox';await leave();await loadMail();$('#folder-title').textContent=a.address;});name.title=a.provider==='gmail'?'Google account cache; changes here are local only':a.kind==='alias'?'Virtual alias inbox: trusted original recipient only':'Real mailbox: all local deliveries';row.append(check,name,el('small',a.kind==='alias'?'Alias':'Mailbox'));group.append(row);}
  root.append(group);
 }
 root.append(button('Unified inbox',async()=>{accountView='';folder='inbox';await leave();await loadMail();}));
 loadGmailTree().catch(()=>{});
 if(typeof refreshRecipients==='function'&&refreshRecipients()&&typeof loadMail==='function')loadMail().catch(()=>{});
}
async function showSent(){
 const {records}=await api('sent');$('#list').replaceChildren();$('#more').hidden=true;
 $('#list').append(el('p','Submission history. Accepted means queued, not confirmed delivery.','small muted'));
 for(const record of records){const b=button(`${record.identity} · ${record.result.status}`,async()=>{const {drafts}=await api('drafts');const d=drafts.find(x=>x.id===record.draft);if(d)openDraft(d);});b.className='message-row';b.append(el('small',`Actor: ${record.actor} · ${new Date(record.created*1000).toLocaleString()}`));$('#list').append(b);}
 if(!records.length)$('#list').append(el('p','No audited submissions yet. Earlier submissions remain in Outbox.'));
}
async function decorateMessage(m,actions){
 const root=$('#reader');root.append(el('p',m.routing_status==='trusted'?'Verified delivery recipient: '+m.routing_recipients.join(', '):'Ambiguous historical recipient. Shown in the physical mailbox; no alias is guessed.','small muted'));
 scriptBanner(m);
 actions.append(button('View source',()=>viewSource(m)),button('Create rule from this email',()=>ruleFromMessage(m)));
 actions.append(button('Thread',async()=>{const t=await api('thread?'+new URLSearchParams({folder,id:m.id}));const section=el('section');section.append(el('h3','Thread · Message-ID references'));for(const x of t.messages){const d=el('details');d.append(el('summary',x.subject+' · '+x.from),el('pre',x.body,'message-body'));section.append(d);}if(t.truncated)section.append(el('p','Thread scan is bounded; more messages may exist.'));root.append(section);}));
 const {labels}=await api('labels');const group=el('details');group.append(el('summary','Local labels · '+m.labels.length));
 for(const label of labels){const check=input('','checkbox');check.checked=m.labels.includes(label.id);check.onchange=task(async()=>{const chosen=new Set(m.labels);if(check.checked)chosen.add(label.id);else chosen.delete(label.id);await offerProviderLabels(await api('message/labels',{folder,id:m.id,labels:[...chosen]}));m.labels=[...chosen];});group.append(field(label.name,check));}root.append(group);
 if(m.provider==='gmail'){const chips=el('div',undefined,'gchips');gmailChips(chips,m);if(chips.childNodes.length){root.append(el('p','Gmail labels (read-only, from Gmail)','small muted'),chips);}}
 if(folder==='inbox')actions.append(button('Archive',async()=>{await api('message/move',{folder,id:m.id,target:'archive'});await loadMail();}));
 if(folder==='archive')actions.append(button('Restore to inbox',async()=>{await api('message/move',{folder,id:m.id,target:'inbox'});await loadMail();}));
}
const stageText=a=>a.phase==='import'?(a.stage==='older'?'Recent 30 days done, backfilling older mail':'Importing recent 30 days'):a.stage==='older_paused'?'Recent 30 days done, older mail paused · new mail syncing':a.stage==='complete'?'Full history imported, syncing':a.phase==='idle'?'Not imported yet':a.phase;
const when=t=>t?new Date(t*1000).toLocaleString():'never';
const kv=(rows)=>{const d=el('dl',undefined,'kv');for(const [k,v] of rows){d.append(el('dt',k),el('dd',String(v)));}return d;};
const setupCard=(title,sub)=>{const c=el('section',undefined,'panel setup-card');c.append(el('h3',title));if(sub)c.append(el('p',sub,'small muted'));return c;};
const connectGmail=async()=>{const r=await api('gmail/connect',{});location.assign(r.authorization_url);};
async function setupExternal(root){
 const g=await api('gmail/status');
 root.append(el('p','Connected mail providers. Local nullverse.cloud mail stays primary. Gmail is imported read-side; write-back (labels, Cases, Spam, read, archive) needs the full permission grant.','muted'));
 for(const blocker of g.blockers)root.append(el('p','⚠ '+blocker,'warning'));
 for(const a of g.accounts){
  const acct=el('section',undefined,'panel provider-account');acct.append(el('h2',a.address),el('p','Provider: Gmail · '+(a.error?'⚠ '+a.error:'Connected'),'small muted'));
  const perm=setupCard('Connection & permissions');
  if(a.missing_scopes&&a.missing_scopes.length){perm.append(el('p','⚠ Reconnect Gmail to allow label sync. Import and sending keep working meanwhile.','warning'),el('p','Not yet granted: '+a.missing_scopes.join(', '),'small muted'));}
  else perm.append(el('p','All requested permissions granted.','small muted'));
  if(g.configured)perm.append(button(a.missing_scopes&&a.missing_scopes.length?'Reconnect Gmail':'Reconnect',connectGmail));
  const imp=setupCard('Import',stageText(a)+` · ${a.imported||0} imported · ${a.skipped||0} pending retry`);
  const acts=el('div',undefined,'actions');
  acts.append(button(a.phase==='idle'?'Import Gmail history':'Restart historical import',async()=>{if(!confirm('Import this Gmail account into Nullmail? Historical mail will not run rules automatically. No messages are changed at Google.'))return;await api('gmail/import',{account_id:a.id,confirm:true});await showSetup();}));
  if(a.stage==='older_paused'||a.stage==='older'||(a.stage==='recent'&&a.backfill_paused))acts.append(button(a.backfill_paused?'Resume backfill':'Pause backfill',async()=>{await api('gmail/backfill',{account_id:a.id,paused:!a.backfill_paused});await showSetup();}));
  acts.append(button('Sync now',async()=>{await api('gmail/sync-now',{account_id:a.id});await showSetup();}));imp.append(acts);
  const wb=setupCard('Write-back to Gmail');const q=(a.label_sync&&a.label_sync.queue)||{};
  wb.append(el('p',a.label_sync&&a.label_sync.enabled?`On · ${q.pending||0} pending · ${q.needs_label||0} waiting for a Gmail label · ${q.failed||0} failed`:'Off · '+((a.label_sync&&a.label_sync.reason)||'Reconnect Gmail to allow label sync'),'small'),el('p','Never deletes Gmail mail or labels. Trash is not mirrored.','small muted'));
  const maps=setupCard('Gmail labels → Nullmail labels');await gmailMapping(maps,a);
  acct.append(perm,imp,wb,maps);root.append(acct);
 }
 if(g.configured&&!g.accounts.length)root.append(button('Connect Gmail with Google',connectGmail));
 const more=setupCard('Add a provider');more.append(el('p','Gmail: '+(g.configured?'available':'not configured')+' · Outlook / Microsoft 365: coming next (categories + folders via the same adapter).','small muted'));
 if(g.configured&&g.accounts.length)more.append(button('Connect another Gmail account',connectGmail));
 root.append(more);
}
const gmailSetup=setupExternal;
async function setupStatus(root){
 const d=await api('gmail/details');await loadConfig().catch(()=>{});const c=typeof config!=='undefined'?config:null;
 if(c){const local=setupCard('Local mailbox · nullverse.cloud');local.append(kv([['Address',c.inbound.address],['Outbound',c.outbound.paused?'Paused':'Ready'],['Outbound notice',c.outbound.reason||'—'],['Storage free',c.capacity?(c.capacity.free/1024**3).toFixed(1)+' GiB of '+(c.capacity.total/1024**3).toFixed(1)+' GiB':'—'],['Aliases / projects',c.projects.length]]));root.append(local);}
 for(const a of d.accounts){
  const s=el('section',undefined,'panel provider-account');s.append(el('h2',a.address),el('p','Provider: Gmail','small muted'));
  const tok=a.token;const exp=tok.access_expires;
  const conn=setupCard('Connection');conn.append(kv([['Status',a.error?'⚠ '+a.error:a.status],['Credentials',tok.decryptable?'Stored encrypted':'⚠ Unreadable — reconnect'],['Refresh token',tok.refresh_token?'Present (auto-renews)':'⚠ Missing — reconnect'],['Access token',exp?(exp*1000>Date.now()?'Valid until '+when(exp):'Expired '+when(exp)+' · renews on next sync'):'—'],['Write-back',a.writeback.enabled?'On':'Off · '+a.writeback.reason],['Granted scopes',a.granted_scopes.join(' ')||'—'],['Missing scopes',a.missing_scopes.join(' ')||'none']]));
  const ls=a.last_sync||{};
  const sync=setupCard('Sync');sync.append(kv([['Current stage',stageText(a)],['Backfill',a.backfill_paused?'Paused':'Running / allowed'],['Last sync',when(ls.at)+(ls.status?' · '+ls.status:'')],['Last successful sync',when(ls.last_ok)],['Last page',(ls.items??0)+' messages imported/updated'],['Imported total',a.imported],['Skipped / pending retry',a.pending_retry],['Errors',a.error||ls.error||'none'],['Consecutive failures',a.failures],['Backoff until',a.backoff_until?when(a.backoff_until):'—']]));
  const lab=setupCard('Labels');lab.append(kv([['User labels',a.label_counts.user],['Categories',Object.entries(a.categories).map(([k,v])=>k+' '+v).join(' · ')||'—'],['System labels',a.label_counts.system],['Messages awaiting label read',a.labels_pending],['Label list refreshed',when(a.labels_refreshed)],['Auto-maps',a.auto_maps]]));
  const qq=a.writeback.queue||{};const wq=setupCard('Outbound write-back queue');wq.append(kv([['Pending',qq.pending||0],['Waiting for a Gmail label',qq.needs_label||0],['Failed',qq.failed||0],['Done (7 days)',qq.done||0],['Disabled',qq.disabled||0]]));
  const acts=el('div',undefined,'actions');
  acts.append(button('Sync now',async()=>{const r=await api('gmail/sync-now',{account_id:a.account_id});notice('Sync: '+r.status);await showSetup('status');}));
  acts.append(a.phase==='idle'?button('Import',async()=>{if(!confirm('Import this Gmail account into Nullmail?'))return;await api('gmail/import',{account_id:a.account_id,confirm:true});await showSetup('status');}):button(a.backfill_paused?'Resume backfill':'Pause backfill',async()=>{await api('gmail/backfill',{account_id:a.account_id,paused:!a.backfill_paused});await showSetup('status');}));
  acts.append(button('Export',async()=>notice(d.export.reason)));
  acts.append(button('Retry failed',async()=>{const r=await api('gmail/retry-failed',{account_id:a.account_id});notice(`Re-queued ${r.messages_requeued} message(s) and ${r.writeback_requeued} write-back change(s)`);await showSetup('status');}));
  s.append(acts,conn,sync,lab,wq);root.append(s);
 }
 if(!d.accounts.length)root.append(el('p','No external providers connected. Use the External tab to connect Gmail.','muted'));
}
function leaf(){return {field:'subject',op:'contains',value:'example'};}
function conditionEditor(node,change,depth=0){
 const box=el('fieldset',undefined,'condition');box.append(el('legend','Condition '+(depth+1)));
 const kind=select([['condition','Field'],['ALL','ALL'],['ANY','ANY'],['NOT','NOT']],node.group||'condition');box.append(field('Match',kind));
 kind.onchange=()=>{const next=kind.value==='condition'?leaf():{group:kind.value,children:[leaf()]};Object.keys(node).forEach(k=>delete node[k]);Object.assign(node,next);change();};
 if(node.group){node.children.forEach((child,index)=>{const row=el('div');row.append(conditionEditor(child,change,depth+1));if(node.children.length>1)row.append(button('Remove condition',()=>{node.children.splice(index,1);change();}));box.append(row);});if(node.group!=='NOT'&&node.children.length<16&&depth<6){box.append(button('＋ Condition',()=>{node.children.push(leaf());change();}),button('＋ Nested group',()=>{node.children.push({group:'ANY',children:[leaf()]});change();}));}}
 else{
  const f=select(Object.keys(ruleCaps.rule_fields).map(k=>[k,k.replaceAll('_',' ')]),node.field);box.append(field('Field',f));f.onchange=()=>{node.field=f.value;node.op=ruleCaps.rule_fields[f.value][0];node.value=['read','has_attachments'].includes(f.value)?true:f.value==='age_days'?7:f.value==='date'?'2026-01-01':'example';change();};
  const op=select(ruleCaps.rule_fields[node.field].map(x=>[x,x.replaceAll('_',' ')]),node.op);box.append(field('Operator',op));op.onchange=()=>node.op=op.value;
  let val;if(['read','has_attachments'].includes(node.field)){val=select([['true','Yes'],['false','No']],String(node.value));val.onchange=()=>node.value=val.value==='true';}
  else if(node.field==='labels'){val=select(localLabels.map(l=>[l.id,l.name]),node.value);val.onchange=()=>node.value=val.value;}
  else{val=input(node.value,node.field==='age_days'?'number':node.field==='date'?'date':'text');val.maxLength=500;val.oninput=()=>node.value=node.field==='age_days'?Number(val.value):val.value;}
  box.append(field('Value',val));
 }
 return box;
}
async function showRules(){
 await leave();view('rules');ruleCaps=await api('capabilities');localLabels=(await api('labels')).labels;ruleCases=[];let casePage=0;do{const r=await api('cases?limit=100&offset='+casePage);ruleCases.push(...r.cases);casePage=r.next_offset;}while(casePage!==null);const response=await api('rules');const root=$('#rules-content');root.replaceChildren();
 const tools=el('div',undefined,'actions');tools.append(button('New rule',()=>editRule({name:'New rule',priority:100,enabled:false,stop:false,scope:['john@nullverse.cloud'],condition:leaf(),exception:null,actions:[{type:'priority',value:'high'}]})),button('Preview / run existing mail',()=>previewPicker(root)),button('Run history',async()=>{const {runs}=await api('rules/history');const list=el('section',undefined,'panel');list.append(el('h2','Latest 100 runs'));for(const run of runs){const row=el('details');row.append(el('summary',`${new Date(run.created*1000).toLocaleString()} · ${run.source} · ${run.status}`));for(const e of run.details.explanations)row.append(el('p',e.name+': '+(e.matched?'matched':'not matched')));row.append(el('p','Actor: '+run.actor));list.append(row);}root.append(list);}));root.append(tools);
 const templates=el('details');templates.append(el('summary','Templates · start disabled'));for(const template of response.templates)templates.append(button(template.name,()=>editRule({...structuredClone(template),scope:['john@nullverse.cloud']})));root.append(templates);
 const list=el('div');response.rules.forEach((rule,index)=>{const card=el('section',undefined,'panel');card.append(el('h2',rule.name),el('p',`Priority ${rule.priority} · ${rule.enabled?'Enabled':'Disabled'} · ${rule.stop?'Stop after match':'Continue'} · version ${rule.version}`),el('p','Account scope: '+rule.scope.join(', '),'small muted'));
 const buttons=el('div',undefined,'actions');buttons.append(button('Edit',()=>editRule(rule)),button('Apply to existing mail',async()=>{const f=prompt('Apply "'+rule.name+'" now to existing mail in which folder? (inbox or archive)','inbox');if(!f)return;if(!confirm('Run this rule on up to 500 messages in '+f+' now?'))return;const r=await api('rules/apply-existing',{id:rule.id,folder:f.trim(),confirm:true});notice(`Applied to ${r.applied} of ${r.scanned} messages`);}),button(rule.enabled?'Disable':'Enable',async()=>{await api('rules/save',{...rule,enabled:!rule.enabled});await showRules();}));
 for(const [name,other] of [['Move up',response.rules[index-1]],['Move down',response.rules[index+1]]]){const b=button(name,async()=>{await api('rules/save',{...rule,priority:other.priority+(name==='Move up'?-1:1)});await showRules();});b.disabled=!other;buttons.append(b);}
 buttons.append(button('Versions / restore',async()=>{const {versions}=await api('rules/versions?id='+rule.id);const details=el('div');for(const v of versions)details.append(button(`Restore version ${v.version}`,async()=>{await api('rules/restore',{id:rule.id,version:rule.version,restore_version:v.version});await showRules();}));card.append(details);}));card.append(buttons);list.append(card);});root.append(list);
}
function editRule(original){
 const rule=structuredClone(original),root=$('#rules-content');root.replaceChildren();const form=el('form',undefined,'panel');
 const name=input(rule.name),priority=input(rule.priority,'number'),enabled=input('','checkbox'),stop=input('','checkbox');enabled.checked=rule.enabled;stop.checked=rule.stop;name.maxLength=100;
 name.oninput=()=>rule.name=name.value;priority.oninput=()=>rule.priority=Number(priority.value);enabled.onchange=()=>rule.enabled=enabled.checked;stop.onchange=()=>rule.stop=stop.checked;
 form.append(field('Rule name',name),field('Numeric priority (lower runs first)',priority),field('Enabled for new mail',enabled),field('Stop after this rule matches',stop));
 const scope=el('details');scope.open=false;scope.append(el('summary','Account scope · independent of inbox checkboxes'));
 for(const a of accountConfig.accounts){const check=input('','checkbox');check.checked=rule.scope.includes(a.id);check.onchange=()=>{const set=new Set(rule.scope);if(check.checked)set.add(a.id);else set.delete(a.id);rule.scope=[...set];};scope.append(field(a.address,check));}form.append(scope);
 const conditions=el('div');const redraw=()=>conditions.replaceChildren(conditionEditor(rule.condition,redraw));redraw();form.append(conditions);
 const except=input('','checkbox');except.checked=!!rule.exception;form.append(field('Except when these conditions match',except));const exceptions=el('div');const drawException=()=>exceptions.replaceChildren(...(rule.exception?[conditionEditor(rule.exception,drawException)]:[]));except.onchange=()=>{rule.exception=except.checked?leaf():null;drawException();};drawException();form.append(exceptions);
 const actionBox=el('fieldset');actionBox.append(el('legend','Actions'));const actionRows=el('div');
 const drawActions=()=>{actionRows.replaceChildren();rule.actions.forEach((action,index)=>{const row=el('div',undefined,'action-row');const kind=select(ruleCaps.rule_actions.map(k=>[k,k.replaceAll('_',' ')]),action.type);kind.onchange=()=>{action.type=kind.value;delete action.value;if(['add_label','remove_label'].includes(action.type))action.value=localLabels[0]?.id||'';if(action.type==='move')action.value='archive';if(action.type==='add_to_case')action.value=ruleCases[0]?.id||'';if(action.type==='priority')action.value='high';drawActions();};row.append(field('Action',kind));let options=null;if(['add_label','remove_label'].includes(action.type))options=localLabels.map(l=>[l.id,l.name]);if(action.type==='add_to_case')options=ruleCases.map(c=>[c.id,c.display_number+' · '+c.title]);if(action.type==='move')options=[['inbox','Inbox'],['archive','Archive']];if(action.type==='priority')options=['low','normal','high'].map(v=>[v,v]);if(options){const val=select(options,action.value);val.onchange=()=>action.value=val.value;row.append(field('Action value',val));}if(rule.actions.length>1)row.append(button('Remove action',()=>{rule.actions.splice(index,1);drawActions();}));actionRows.append(row);});};drawActions();actionBox.append(actionRows,button('Add action',()=>{rule.actions.push({type:'read'});drawActions();}));form.append(actionBox);
 const saveButton=el('button','Save rule');saveButton.type='submit';form.onsubmit=task(async e=>{e.preventDefault();await api('rules/save',rule);notice('Rule saved. Existing mail was not processed.');await showRules();});form.append(saveButton,button('Preview without saving',()=>previewPicker(root,rule)),button('Cancel',showRules));root.append(form);
}
async function previewPicker(root,rule=null){
 const section=el('section',undefined,'panel');section.append(el('h2','Preview existing messages'),el('p','Choose up to 50 messages. Preview never writes mail or rule state. Running requires a second explicit action.'));
 const folderSelect=select([['inbox','Inbox'],['archive','Archive'],['trash','Trash']],folder==='archive'?'archive':'inbox');section.append(field('Folder',folderSelect));const rows=el('div');let selected=new Set();
 const refresh=async()=>{selected=new Set();rows.replaceChildren();const response=await api('messages?'+new URLSearchParams({folder:folderSelect.value,account:'john@nullverse.cloud',limit:50}));for(const m of response.messages){const check=input('','checkbox');check.onchange=()=>{if(check.checked)selected.add(m.id);else selected.delete(m.id);};rows.append(field(m.subject,check));}rows.append(el('p',`Showing ${response.messages.length} of ${response.total}. This run is bounded to the selected messages.`));};folderSelect.onchange=task(refresh);await refresh();section.append(rows);
 section.append(button('Dry run selected messages',async()=>{const ids=[...selected],folder=folderSelect.value;const result=await api('rules/preview',{ids,folder,...(rule?{rule}: {})});const report=el('div');report.append(el('h3',`Preview · ${result.count} messages · zero writes`));
 const explain=(e)=>{const d=el('div',undefined,'explanation');d.append(el('span',`${e.group||e.field+' '+e.op}: ${e.matched?'match':'no match'}${e.available===false?' (source unavailable)':''}`));for(const child of e.children||[])d.append(explain(child));return d;};
 for(const p of result.plans){const d=el('details');d.open=true;d.append(el('summary',`${p.actions.length} action(s) · ${p.id.slice(0,12)}`));for(const e of p.explanations){d.append(el('h4',e.name+(e.matched?' · matched':' · skipped')),explain(e.condition));if(e.exception){d.append(el('p','Exception'),explain(e.exception));}}for(const a of p.actions)d.append(el('p',a.type+(a.value?' → '+a.value:'')));for(const w of p.warnings)d.append(el('p',w,'warning'));report.append(d);}
 if(!rule){const run=button('Confirm: apply this preview to selected messages',async()=>{run.disabled=true;try{const outcome=await api('rules/run',{ids,folder,token:result.token,confirm:true});notice('Run '+outcome.status);run.textContent='Run '+outcome.status;}catch(e){run.disabled=false;throw e;}});report.append(run);}else report.append(el('p','Save this rule before running it on existing mail. Disabled rules do not match.'));
 section.append(report);
 }));root.append(section);section.scrollIntoView({block:'start'});
}
async function showLabels(){
 await leave();view('labels');localLabels=(await api('labels')).labels;const root=$('#labels-content');root.replaceChildren();
 const editor=(existing={})=>{const form=el('form',undefined,'panel'),name=input(existing.name||''),color=input(existing.color||'#b2a2ff','color'),parent=select([['','No parent'],...localLabels.filter(l=>l.id!==existing.id).map(l=>[l.id,l.name])],existing.parent||'');name.required=true;name.maxLength=80;form.append(field('Label name',name),field('Color',color),field('Parent label',parent));const save=el('button',existing.id?'Save label':'Create label');save.type='submit';form.append(save);form.onsubmit=task(async e=>{e.preventDefault();await api('labels/save',{...existing,name:name.value,color:color.value,parent:parent.value});await showLabels();});root.append(form);};editor();
 for(const label of localLabels){const row=el('section',undefined,'panel');row.append(el('h2',label.name),el('p',`${label.color} · ${label.parent?'Parent: '+(localLabels.find(l=>l.id===label.parent)?.name||''):'Top level'} · local only`),button('Edit',()=>editor(label)),button('Delete label',async()=>{if(!confirm('Remove this local label from all messages? Mail is preserved.'))return;await api('labels/delete',{id:label.id});await showLabels();}));root.append(row);}
}
$('#rules-tab').onclick=task(showRules);$('#labels-tab').onclick=task(showLabels);

/* ---- Gmail provider labels: account tree, chips, operators, mapping (read-only toward Gmail) ---- */
const treeOpen={};
let gmailLabelData=null,glabelView='',glabelTitle='';
const HIDDEN_GLABELS=new Set(['INBOX','SENT','DRAFT','SPAM','TRASH','CHAT','UNREAD']);
function saveTree(){prefSet('tree',{...treeOpen});}
function gmailChips(target,m){for(const d of (m.provider_label_details||[])){if(HIDDEN_GLABELS.has(d.id)||d.id==='CATEGORY_PERSONAL'&&false)continue;const c=el('button',(d.kind==='category'?'▦ ':d.id==='STARRED'?'★ ':'')+d.name,'gchip gchip-'+d.kind);c.type='button';c.title='Gmail label · '+d.kind+' · provider=gmail';c.onclick=task(async e=>{e.stopPropagation();await openGlabel(d.id,d.name);});target.append(c);}}
async function openGlabel(id,name){gmailViewKey='';glabelView=id;glabelTitle='Gmail · '+name;folder='all';$('#search').value='';await leave();await loadMail();renderGmailTree();}
async function loadGmailTree(){const root=$('#gmail-tree');if(!root)return;gmailLabelData=await api('gmail/labels');renderGmailTree();}
function renderGmailTree(){
 const root=$('#gmail-tree');if(!root||!gmailLabelData)return;root.replaceChildren();
 for(const acc of gmailLabelData.accounts){
  const row=(key,text,unread,depth,kids,open)=>{const r=el('div',undefined,'tree-row'+((gmailViewKey?key===gmailViewKey:glabelView&&key===acc.account_id+':'+glabelView)?' selected':''));r.style.paddingLeft=(4+depth*14)+'px';const chev=el('button',kids?(treeOpen[key]?'▾':'▸'):'','tree-chevron');chev.type='button';if(kids){chev.setAttribute('aria-expanded',String(!!treeOpen[key]));chev.setAttribute('aria-label',(treeOpen[key]?'Collapse ':'Expand ')+text);chev.onclick=()=>{treeOpen[key]=!treeOpen[key];saveTree();renderGmailTree();};}const name=el('button',text,'tree-name');name.type='button';name.onclick=open?task(open):()=>{treeOpen[key]=!treeOpen[key];saveTree();renderGmailTree();};r.append(chev,name);if(unread)r.append(el('span',String(unread),'tree-count'));root.append(r);};
  const akey='acct:'+acc.account_id;if(treeOpen[akey]===undefined){treeOpen[akey]=true;}
  const total=acc.labels.find(l=>l.id==='UNREAD');row(akey,acc.address,total?total.count:0,0,true,null);
  if(!treeOpen[akey])continue;
  const byId=Object.fromEntries(acc.labels.map(l=>[l.id,l]));
  const un=id=>byId[id]?.unread||0,vw=acc.views||{},allUnread=vw.all_unread??Math.max(0,(byId.UNREAD?.count||0)-un('SPAM')-un('TRASH'));
  for(const [view,label,count] of [['inbox','Inbox',un('INBOX')],['unread','Unread',vw.inbox_unread??0],['archived','Archived',vw.archived_unread??0],['all','All Mail',allUnread],['sent','Sent',0],['spam','Spam',un('SPAM')],['trash','Trash',un('TRASH')]])row(acc.account_id+':view:'+view,label,count,1,false,()=>openGmailView(acc,view,label));
  const ckey=akey+':cat';row(ckey,'Categories',0,1,true,null);
  if(treeOpen[ckey])for(const [id,label] of [['CATEGORY_PERSONAL','Primary'],['CATEGORY_SOCIAL','Social'],['CATEGORY_PROMOTIONS','Promotions'],['CATEGORY_UPDATES','Updates'],['CATEGORY_FORUMS','Forums']])row(acc.account_id+':'+id,label,byId[id]?.unread||0,2,false,()=>openGlabel(id,label));
  for(const [id,label] of [['STARRED','Starred'],['IMPORTANT','Important']])if(byId[id])row(acc.account_id+':'+id,label,byId[id].unread||0,1,false,()=>openGlabel(id,label));
  const tree={};for(const l of acc.labels.filter(l=>l.kind==='user').sort((a,b)=>a.name.localeCompare(b.name))){let node=tree;const parts=l.name.split('/');parts.forEach((p,i)=>{node[p]=node[p]||{_kids:{}};if(i===parts.length-1)node[p]._label=l;node=node[p]._kids;});}
  const walk=(nodes,depth,path)=>{for(const [name,n] of Object.entries(nodes)){const key=akey+':u:'+path+name;const kids=Object.keys(n._kids).length>0;const l=n._label;row(l?acc.account_id+':'+l.id:key,name,l?l.unread:0,depth,kids,l?()=>openGlabel(l.id,l.name):null);if(kids&&!l)treeOpen[key]=treeOpen[key]??false;const ok=l?acc.account_id+':'+l.id:key;if(kids&&treeOpen[ok])walk(n._kids,depth+1,path+name+'/');}};
  walk(tree,1,'');
  if(acc.labels_pending)root.append(el('p',`Reading Gmail labels… ${acc.labels_pending} messages left`,'small muted'));
 }
 if(gmailLabelData.accounts.length)root.append(button('Add Nullmail label to results',async()=>{const {labels}=await api('labels');if(!labels.length){notice('Create a Nullmail label first');return;}const name=prompt('Nullmail label to add to every message in the current list:\n'+labels.map(l=>l.name).join(', '));const l=labels.find(x=>x.name===name);if(!l)return;if(!confirm('Add "'+l.name+'" to all messages matching the current view and search?'))return;const r=await api('messages/bulk-label',{folder,glabel:folder==='all'?glabelView:'',q:$('#search').value,recipient:$('#recipient').value,unread:$('#unread').checked,account:accountView,label:l.id,confirm:true});notice(`Labeled ${r.labeled} of ${r.matched} matching messages`);await loadMail();}));
}
async function gmailMapping(panel,a){
 const data=gmailLabelData||await api('gmail/labels');const acc=data.accounts.find(x=>x.account_id===a.id);if(!acc)return;const {labels}=await api('labels');
 const box=el('div');box.append(el('p','Read-only toward Gmail. "Apply once" tags current matches; "Auto-map" also tags future matches as they sync.','small muted'));
 const src=select(acc.labels.filter(l=>!HIDDEN_GLABELS.has(l.id)).map(l=>[l.id,`${l.name} (${l.count})`]),'');const dst=select(labels.map(l=>[l.id,l.name]),labels[0]?.id||'');
 box.append(field('Gmail label',src),field('Nullmail label',dst));
 for(const [mode,text] of [['once','Apply once'],['auto','Auto-map']])box.append(button(text,async()=>{if(!dst.value){notice('Create a Nullmail label first');return;}const r=await api('gmail/label-map',{account_id:a.id,provider_label:src.value,label:dst.value,mode});notice(`Applied to ${r.applied} message(s)`+(mode==='auto'?'; auto-map saved':''));await showSetup();}));
 for(const m of acc.maps){const pl=acc.labels.find(l=>l.id===m.provider_label),nl=labels.find(l=>l.id===m.label);const r=el('p',`Auto: ${pl?pl.name:m.provider_label} → ${nl?nl.name:m.label} `);r.append(button('Remove',async()=>{await api('gmail/label-unmap',{account_id:a.id,provider_label:m.provider_label,label:m.label});await showSetup();}));box.append(r);}
 box.append(el('p','Search: category:promotions · glabel:"Name" · glabel:Parent (includes sublabels) · is:starred · is:important','small muted'));
 panel.append(box);
}

async function offerProviderLabels(r){
 for(const name of (r&&r.provider_missing_labels)||[]){
  if(confirm(`Create label "${name}" in Gmail?`)){await api('gmail/create-label',{account_id:r.account_id,name,confirm:true});notice(`Created "${name}" in Gmail; syncing`);}
  else notice(`"${name}" stays local only; Gmail was not changed`);
 }
 return r;
}

/* ---- Reader: expandable header, safe HTML, view source, rule from email ---- */
function headerBlock(m){
 const box=el('div',undefined,'message-meta header-block');const sum=el('div',undefined,'header-summary');
 sum.append(el('div','From: '+m.from),el('div','To: '+m.to),el('div',m.date));
 const toggle=el('button','Details ▸','header-toggle');toggle.type='button';toggle.setAttribute('aria-expanded','false');
 const full=el('div',undefined,'header-details');full.hidden=true;
 const a=m.auth||{};const badge=k=>a[k]?`${k.toUpperCase()} ${a[k]}`:`${k.toUpperCase()} —`;
 full.append(kv([['From',m.from],['To',m.to||'—'],['Cc',m.cc||'—'],['Bcc',m.bcc||'—'],['Reply-To',m.reply_to_header||'—'],['Date',m.date],['Original recipient',m.recipient||'—'],['Message-ID',m.message_id||'—'],['List-Id',m.list_id||'—'],['Authentication',['spf','dkim','dmarc'].map(badge).join(' · ')+(m.dkim_domains&&m.dkim_domains.length?' · signed by '+m.dkim_domains.join(', '):'')]]));
 const all=el('details');all.append(el('summary','Show all headers'),el('pre',m.headers||'','message-headers'));full.append(all);
 toggle.onclick=()=>{full.hidden=!full.hidden;toggle.textContent=full.hidden?'Details ▸':'Details ▾';toggle.setAttribute('aria-expanded',String(!full.hidden));};
 box.append(sum,toggle,full);return box;
}
function bodyBlock(m){
 const wrap=el('div',undefined,'body-block');const plain=el('pre',m.body,'message-body');
 if(!m.has_html){wrap.append(plain);return wrap;}
 const bar=el('div',undefined,'actions body-toggle');const frameBox=el('div',undefined,'html-frame');let mode='html';
 const bHtml=el('button','HTML'),bText=el('button','Plain text');bHtml.type=bText.type='button';
 const remoteBar=el('div',undefined,'remote-bar');remoteBar.hidden=true;
 const load=async remote=>{const r=await api('message/html?'+new URLSearchParams({folder:m.folder||folder,id:m.id,remote:remote?'1':'0'}));frameBox.replaceChildren();if(!r.html){frameBox.append(plain);return;}
  const f=document.createElement('iframe');f.setAttribute('sandbox','allow-popups allow-popups-to-escape-sandbox');f.setAttribute('referrerpolicy','no-referrer');f.title='HTML message (sandboxed)';f.setAttribute('scrolling','yes');f.src='/api/v1/message/frame?'+new URLSearchParams({folder:m.folder||folder,id:m.id,remote:r.remote?'1':'0'});frameBox.append(f);
  remoteBar.replaceChildren();remoteBar.hidden=!(r.blocked_remote>0||r.remote_always);
  if(r.blocked_remote>0&&!r.remote){remoteBar.append(el('span',`Remote images blocked (${r.blocked_remote})`,'small'),button('Load remote images',()=>load(true)));if(r.sender)remoteBar.append(button('Always for '+r.sender,async()=>{await api('message/remote-images',{sender:r.sender,allow:true});await load(true);}));}
  else if(r.remote_always)remoteBar.append(el('span','Remote images always load for '+r.sender,'small'),button('Stop',async()=>{await api('message/remote-images',{sender:r.sender,allow:false});await load(false);}));};
 const show=x=>{mode=x;bHtml.classList.toggle('selected',x==='html');bText.classList.toggle('selected',x==='text');bHtml.setAttribute('aria-pressed',String(x==='html'));bText.setAttribute('aria-pressed',String(x==='text'));frameBox.hidden=x!=='html';remoteBar.style.display=x==='html'?'':'none';plain.hidden=x!=='text';if(x==='html'&&!frameBox.childNodes.length)load(false).catch(e=>notice(e.message));};
 bHtml.onclick=()=>show('html');bText.onclick=()=>show('text');bar.append(bHtml,bText);
 bHtml.addEventListener('click',()=>prefSet('body_mode','html'));bText.addEventListener('click',()=>prefSet('body_mode','text'));wrap.append(bar,remoteBar,frameBox,plain);show(prefGet('body_mode','html')==='text'?'text':'html');return wrap;
}
async function viewSource(m){
 const r=await api('message/source?'+new URLSearchParams({folder:m.folder||folder,id:m.id}));
 const root=$('#reader');const sec=el('section',undefined,'panel source-view');sec.append(el('h3','Message source'));
 if(r.segmented){sec.append(el('p','Large message: attachments are stored separately and shown as placeholders below. Download .eml reassembles the full message (up to 25 MB).','small muted'));const ul=el('ul');for(const p of r.external_parts)ul.append(el('li',`${p.name} · ${p.content_type} · ${Math.ceil(p.size/1024)} KB`));sec.append(ul);}
 const pre=el('pre',r.raw,'raw-source');const acts=el('div',undefined,'actions');
 acts.append(button('Copy',async()=>{await navigator.clipboard.writeText(r.raw);notice('Source copied');}));
 const dl=el('a','Download .eml');dl.href='/api/v1/message/eml?'+new URLSearchParams({folder:m.folder||folder,id:m.id});dl.className='button-link';dl.download='message.eml';acts.append(dl,button('Close',()=>sec.remove()));
 sec.append(acts,pre);root.append(sec);sec.scrollIntoView({behavior:'smooth'});
}
async function ruleFromMessage(m){
 const addr=(m.from.match(/<([^>]+)>/)||[null,m.from])[1].trim().toLowerCase();const domain=addr.split('@')[1]||'';
 const to=(m.to.match(/<([^>]+)>/)||[null,m.to.split(',')[0]])[1].trim().toLowerCase();
 const listId=(m.list_id||'').trim();
 const labels=(await api('labels')).labels;
 const root=$('#reader');const sec=el('section',undefined,'panel rule-from');sec.append(el('h3','Create rule from this email'),el('p','Choose what to match and what to do. You can refine everything in the rule editor before saving. Rules start disabled for new mail until you enable them.','small muted'));
 const conds=[['From address is '+addr,{field:'sender',op:'equals',value:addr},true],['From domain is '+domain,{field:'sender_domain',op:'equals',value:domain},false],['Subject contains “'+(m.subject||'').slice(0,80)+'”',{field:'subject',op:'contains',value:(m.subject||'').slice(0,200)},false]];
 if(listId)conds.push(['Mailing list (List-Id) is '+listId,{field:'headers',op:'contains',value:listId.slice(0,500)},!!listId]);
 if(to)conds.push(['Sent to '+to,{field:'headers',op:'contains',value:to},false]);
 const checks=conds.filter(c=>c[1].value).map(([t,c,on])=>{const i=input('','checkbox');i.checked=on;sec.append(field(t,i));return [i,c];});
 const action=select([['archive','Move to Archive'],['spam','Move to Spam'],['read','Mark as read'],['priority','Mark high priority'],...labels.map(l=>['label:'+l.id,'Add Nullmail label: '+l.name])],'archive');sec.append(field('Action',action));
 const enabled=input('','checkbox');enabled.checked=true;sec.append(field('Enable for new mail',enabled));
 sec.append(button('Open in rule editor',async()=>{
  const chosen=checks.filter(([i])=>i.checked).map(([,c])=>c);if(!chosen.length){notice('Pick at least one condition');return;}
  const v=action.value;const act=v==='archive'?{type:'archive'}:v==='spam'?{type:'move',value:'spam'}:v==='read'?{type:'read'}:v==='priority'?{type:'priority',value:'high'}:{type:'add_label',value:v.slice(6)};
  const scope=(m.accounts&&m.accounts.length?m.accounts:['john@nullverse.cloud']);
  const rule={name:'From '+(addr||domain),priority:100,enabled:enabled.checked,stop:false,scope,condition:chosen.length===1?chosen[0]:{group:'ALL',children:chosen},exception:null,actions:[act]};
  await leave();view('rules');ruleCaps=await api('capabilities');localLabels=(await api('labels')).labels;ruleCases=[];editRule(rule);
  notice('Rule prefilled from the email. Save it, then use “Apply to existing mail” on the rule to run it on current mail.');
 }),button('Cancel',()=>sec.remove()));
 root.append(sec);sec.scrollIntoView({behavior:'smooth'});
}

function scriptBanner(m){
 const f=m.script_findings||[];if(!f.length)return;const r=m.review;
 const b=el('section',undefined,'panel script-warning');b.setAttribute('role','alert');
 b.append(el('strong','⚠ This email contains scripts, blocked'),el('p','Scripts never run in Nullmail. Found: '+[...new Set(f.map(x=>x.kind))].join(', ')+'.','small'));
 const d=el('details');d.append(el('summary','Details'));for(const x of f)d.append(el('p',`${x.kind} · ${x.detail}`,'small muted'));b.append(d);
 const verdict=el('p','', 'small review-verdict');
 const paint=rv=>{verdict.textContent=!rv?'Not reviewed yet.':rv.status==='pending'?'Review pending (requested '+new Date(rv.requested*1000).toLocaleString()+').':`Review verdict: ${rv.status.toUpperCase()}${rv.reason?' · '+rv.reason:''}${rv.reviewer?' · by '+rv.reviewer:''}. Scripts stay blocked regardless.`;verdict.dataset.status=rv?rv.status:'none';};
 paint(r);b.append(verdict);
 if(!r||r.status!=='pending')b.append(button(r?'Submit again for review':'Submit for review',async()=>{const x=await api('message/review',{folder:m.folder||folder,id:m.id});paint(x.review);notice('Queued for AI review (Morc)');}));
 $('#reader').insertBefore(b,$('#reader').children[2]||null);
}

/* Local accounts: domain/subdomain -> mailbox -> folders. Collapsed by default; expansion remembered. */
const LOCAL_FOLDERS=[['inbox','Inbox'],['archive','Archive'],['sent','Sent'],['spam','Spam'],['trash','Trash']];
function localDomain(address){return String(address).split('@')[1]||'local';}
function localAccountTree(rows){
 const root=el('div',undefined,'local-tree');root.setAttribute('role','tree');root.setAttribute('aria-label','Local server accounts');
 const open=k=>!!treeOpen[k];
 const toggle=k=>{treeOpen[k]=!treeOpen[k];saveTree();root.replaceWith(localAccountTree(rows));};
 const line=(key,depth,label,count,{kids=true,onclick=null,extra=null}={})=>{const r=el('div',undefined,'tree-row');r.style.paddingLeft=(4+depth*14)+'px';r.setAttribute('role','treeitem');if(kids)r.setAttribute('aria-expanded',String(open(key)));
  const chev=el('button',kids?(open(key)?'▾':'▸'):'','tree-chevron');chev.type='button';if(kids){chev.setAttribute('aria-label',(open(key)?'Collapse ':'Expand ')+label);chev.onclick=()=>toggle(key);}
  if(extra)r.append(extra);const name=el('button',label,'tree-name');name.type='button';name.onclick=onclick?task(onclick):(kids?()=>toggle(key):null);r.append(chev,name);if(count)r.append(el('span',String(count),'tree-count'));return r;};
 const total=rows.reduce((n,a)=>n+(a.unread||0),0);
 root.append(line('local-root',0,'Local server accounts',total));
 if(!open('local-root'))return root;
 const domains={};for(const a of rows)(domains[localDomain(a.address)]=domains[localDomain(a.address)]||[]).push(a);
 const names=Object.keys(domains).sort((x,y)=>x.split('.').reverse().join('.').localeCompare(y.split('.').reverse().join('.')));
 for(const d of names){const key='ldom:'+d;const list=domains[d].sort((x,y)=>x.address.localeCompare(y.address));
  root.append(line(key,1,d,list.reduce((n,a)=>n+(a.unread||0),0)));
  if(!open(key))continue;
  for(const a of list){const ukey='luser:'+a.id;const check=input('','checkbox');check.checked=accountConfig.selection.includes(a.id);check.setAttribute('aria-label','Show '+a.address+' in unified inbox');check.title='Show in unified inbox';
   check.onchange=task(async()=>{const chosen=new Set(accountConfig.selection);if(check.checked)chosen.add(a.id);else chosen.delete(a.id);await api('accounts/selection',{selection:[...chosen]});accountView='';await loadAccounts();folder='inbox';await loadMail();});
   const r=line(ukey,2,a.address.split('@')[0]+(a.kind==='alias'?' · alias':''),a.unread||0,{extra:check});r.title=a.kind==='alias'?'Virtual alias inbox: trusted original recipient only':'Real mailbox: all local deliveries';root.append(r);
   if(!open(ukey))continue;
   for(const [f,label] of LOCAL_FOLDERS)root.append(line(ukey+':'+f,3,label,f==='inbox'?(a.unread||0):0,{kids:false,onclick:async()=>{accountView=a.id;folder=f;await leave();await loadMail();$('#folder-title').textContent=a.address+' · '+label;}}));
  }
 }
 return root;
}

/* Gmail account views: Inbox / Unread / All Mail (not Spam/Trash) / Sent / Spam / Trash, scoped to that account; search + recipient filter still apply. */
let gmailViewKey='';
const GMAIL_VIEWS={inbox:['all','INBOX'],unread:['all','INBOX,UNREAD'],archived:['all','-INBOX,-SENT,-SPAM,-TRASH'],all:['all',''],sent:['sent',''],spam:['spam',''],trash:['trash','']};
async function openGmailView(acc,view,label){const [f,g]=GMAIL_VIEWS[view];gmailViewKey=acc.account_id+':view:'+view;accountView=acc.account_id;folder=f;glabelView=g;glabelTitle=acc.address+' · '+label;await leave();await loadMail();$('#folder-title').textContent=acc.address+' · '+label;renderGmailTree();}

/* ---- Cross-device UI preferences: server is the source of truth, localStorage is only an offline cache. LWW per key. ---- */
const PREF_CACHE='nullmail-prefs',PREF_KEYS=['tree','last_view','body_mode','dismissed','setup_tab'];
let prefState={},prefDirty=new Set(),prefTimer=null,prefReady=false;
try{prefState=JSON.parse(localStorage.getItem(PREF_CACHE)||'{}')||{};}catch(e){prefState={};}
function prefCache(){try{localStorage.setItem(PREF_CACHE,JSON.stringify(prefState));}catch(e){}}
function prefGet(k,d){const v=prefState[k];return v&&v.value!==undefined?v.value:d;}
function prefSet(k,v){if(JSON.stringify(prefGet(k))===JSON.stringify(v))return;prefState[k]={value:v,updated:Date.now()};prefDirty.add(k);prefCache();clearTimeout(prefTimer);prefTimer=setTimeout(()=>prefFlush().catch(()=>{}),800);}
async function prefPut(body){const r=await fetch('/api/v1/prefs',{method:'PUT',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({prefs:body})});const j=await r.json();if(!r.ok)throw Error(j.error||'Preference save failed');return j.prefs;}
async function prefFlush(){if(!prefDirty.size||!csrf)return;const keys=[...prefDirty];prefDirty.clear();const body={};for(const k of keys)if(prefState[k])body[k]=prefState[k];try{prefMerge(await prefPut(body));}catch(e){keys.forEach(k=>prefDirty.add(k));throw e;}}
function prefApply(changed){
 if(changed.has('tree')){for(const k of Object.keys(treeOpen))delete treeOpen[k];Object.assign(treeOpen,prefGet('tree',{}));if(typeof renderGmailTree==='function')renderGmailTree();const lt=document.querySelector('.local-tree');if(lt&&accountConfig)lt.replaceWith(localAccountTree(accountConfig.accounts.filter(a=>a.provider==='local')));}
 if(changed.has('dismissed')&&typeof outboundBanner==='function')outboundBanner();
}
function prefMerge(server){const changed=new Set();for(const [k,v] of Object.entries(server||{})){const mine=prefState[k];if(!mine||v.updated>mine.updated){if(!mine||JSON.stringify(mine.value)!==JSON.stringify(v.value))changed.add(k);prefState[k]=v;prefDirty.delete(k);}else if(mine.updated>v.updated)prefDirty.add(k);}
 for(const k of Object.keys(prefState))if(!(k in (server||{}))&&PREF_KEYS.includes(k))prefDirty.add(k);prefCache();prefApply(changed);return changed;}
async function prefsSync(){try{const r=await api('prefs');prefMerge(r.prefs);await prefFlush();}catch(e){}}
async function prefsInit(){
 /* One-time migration of legacy localStorage keys (only where the server has nothing yet). */
 let server={};try{server=(await api('prefs')).prefs||{};}catch(e){}
 const legacyTree=localStorage.getItem('nullmail-gmail-tree'),legacyBanner=localStorage.getItem('nullmail-outbound-notice-dismissed');
 if(legacyTree&&!server.tree&&!prefState.tree){try{prefState.tree={value:JSON.parse(legacyTree),updated:Date.now()};prefDirty.add('tree');}catch(e){}}
 if(legacyBanner&&!server.dismissed&&!prefState.dismissed){prefState.dismissed={value:{outbound:legacyBanner},updated:Date.now()};prefDirty.add('dismissed');}
 prefMerge(server);Object.assign(treeOpen,prefGet('tree',{}));
 try{await prefFlush();localStorage.removeItem('nullmail-gmail-tree');localStorage.removeItem('nullmail-outbound-notice-dismissed');}catch(e){}
 prefReady=true;
 document.addEventListener('visibilitychange',()=>{if(document.visibilityState==='visible')prefsRemote();else prefFlush().catch(()=>{});});
 window.addEventListener('focus',()=>prefsRemote());
 setInterval(()=>{if(document.visibilityState==='visible')prefsRemote();},60000);
}
/* Remote refresh: prefs plus the server-side account selection (unified-inbox checkboxes). */
let prefsBusy=false;
async function prefsRemote(){if(prefsBusy)return;prefsBusy=true;try{await prefsSync();if(accountConfig){const a=await api('accounts');if(JSON.stringify(a.selection)!==JSON.stringify(accountConfig.selection))await loadAccounts();}}catch(e){}finally{prefsBusy=false;}}
function restoreLastView(){const v=prefGet('last_view',null);if(!v)return;folder=v.folder||'inbox';accountView=v.account||'';glabelView=v.glabel||'';gmailViewKey=v.gview||'';const rec=$('#recipient');if(rec&&v.recipient&&[...rec.options].some(o=>o.value===v.recipient))rec.value=v.recipient;}
{const original=loadMail;loadMail=async function(more){const r=await original.apply(this,arguments);if(!more&&prefReady)prefSet('last_view',{folder:String(folder||'inbox'),account:String(accountView||''),glabel:String(glabelView||''),gview:String(gmailViewKey||''),recipient:String(($('#recipient')||{}).value||'')});return r;};}
