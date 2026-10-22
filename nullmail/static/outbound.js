'use strict';
/* Outbound delete: Drafts, Outbox (paused / rejected / accepted / unknown), Sent, and Trash.
   Default is a reversible move to Trash. Trashing an unsent Outbox item cancels its send.
   Permanent delete always asks for confirmation. Gmail Sent messages also move to Gmail Trash, after a confirm. */
const OB_STATUS={paused:'Paused · nothing sent',accepted:'Accepted / queued · delivery unverified',rejected:'Rejected · not sent',unknown:'Outcome uncertain',submitting:'Submitting…',draft:'Draft'};
function gmailView(){return !!(accountConfig&&accountView&&accountConfig.accounts.some(a=>a.id===accountView&&a.provider==='gmail'));}
function obReport(r,verb){const bits=[`${r.ok} ${verb}`];if(r.failed)bits.push(`${r.failed} failed: `+r.results.filter(x=>x.error).map(x=>x.error).filter((v,i,a)=>a.indexOf(v)===i).join('; '));const late=r.results.filter(x=>x.already_submitted).length;if(late)bits.push(`${late} had already been handed to the mail server and cannot be recalled`);const cancelled=r.results.filter(x=>x.cancelled).length;if(cancelled)bits.push(`${cancelled} send${cancelled>1?'s':''} cancelled`);notice(bits.join(' · '));}
function obConfirmPermanent(n){return confirm(`Permanently delete ${n} message${n>1?'s':''}? This cannot be undone.`);}
function obConfirmGmail(n){return confirm(`${n} of these ${n>1?'are':'is'} Gmail message${n>1?'s':''}. Deleting also moves ${n>1?'them':'it'} to Gmail Trash, which Gmail empties after 30 days. Continue?`);}
/* items: [{kind:'draft',id} | {kind:'message',folder,id,gmail}] */
async function obDelete(items,permanent){
 if(!items.length)return;
 if(permanent&&!obConfirmPermanent(items.length))return;
 const gm=items.filter(i=>i.kind==='message'&&i.gmail&&i.folder==='sent').length;
 if(!permanent&&gm&&!obConfirmGmail(gm))return;
 const r=await api('outbound/delete',{drafts:items.filter(i=>i.kind==='draft').map(i=>i.id),messages:items.filter(i=>i.kind==='message').map(i=>({folder:i.folder,id:i.id})),permanent,confirm:permanent,confirm_provider:gm>0});
 obReport(r,permanent?'deleted permanently':'moved to Trash');$('#reader')?.replaceChildren();await loadMail();
}
async function obRestore(ids){const r=await api('outbound/restore',{drafts:ids});obReport(r,'restored (unsent items come back paused; nothing is sent)');await loadMail();}
/* Selection toolbar + per-row checkboxes. */
function obToolbar(rows,{trash=false}={}){
 const bar=el('div',undefined,'ob-toolbar');bar.setAttribute('role','toolbar');bar.setAttribute('aria-label','Selected messages');
 const all=document.createElement('input');all.type='checkbox';all.setAttribute('aria-label','Select all');const allL=el('label',undefined,'ob-all');allL.append(all,el('span','Select all'));
 const count=el('span','','ob-count');
 const del=el('button',trash?'Delete permanently':'Move to Trash',trash?'danger':'');const perm=el('button','Delete permanently','danger');const rest=el('button','Restore');
 const chosen=()=>rows.filter(r=>r.check.checked).map(r=>r.item);
 const sync=()=>{const n=chosen().length;count.textContent=n?n+' selected':'';for(const b of [del,perm,rest])b.disabled=!n;all.checked=n>0&&n===rows.length;all.indeterminate=n>0&&n<rows.length;};
 all.onchange=()=>{for(const r of rows)r.check.checked=all.checked;sync();};
 for(const r of rows)r.check.onchange=sync;
 del.onclick=task(()=>obDelete(chosen(),trash));perm.onclick=task(()=>obDelete(chosen(),true));
 rest.onclick=task(async()=>{const c=chosen();const ds=c.filter(i=>i.kind==='draft').map(i=>i.id);if(ds.length)await obRestore(ds);const ms=c.filter(i=>i.kind==='message');for(const m of ms)await api('message/move',{folder:'trash',id:m.id,target:'inbox'});if(ms.length){notice(ms.length+' restored to Inbox');await loadMail();}});
 bar.append(allL,count,del);if(trash)bar.append(rest);else bar.append(perm);sync();return bar;
}
function obCheck(item,label){const c=document.createElement('input');c.type='checkbox';c.className='ob-check';c.setAttribute('aria-label','Select '+(label||'message'));c.onclick=e=>e.stopPropagation();return {check:c,item};}
function obRow(check,main){const wrap=el('div',undefined,'message-item ob-item');wrap.append(check,main);return wrap;}
async function obDraftList(){
 const {drafts}=await api('drafts');const list=$('#list');$('#more').hidden=true;
 const rows=drafts.filter(d=>folder==='drafts'?d.status==='draft':!['draft','trashed'].includes(d.status));const sel=[];const items=[];
 for(const d of rows){const b=el('button',undefined,'message-row');b.dataset.id=d.id;b.append(el('span',d.to||'No recipient','row-from'),el('span',d.subject||'(No subject)','subject'),el('span',OB_STATUS[d.status]||d.status,'recipient-label'));b.onclick=task(()=>openDraft(d));const s=obCheck({kind:'draft',id:d.id,status:d.status},d.subject);sel.push(s);items.push(obRow(s.check,b));}
 if(rows.length)list.append(obToolbar(sel),...items);else emptyList();
}
async function obSentAudit(){
 const {records}=await api('sent');const list=$('#list');list.replaceChildren();$('#more').hidden=true;
 list.append(el('p','Submission history. Accepted means queued, not confirmed delivery.','small muted'));
 const {drafts}=await api('drafts');const byId=Object.fromEntries(drafts.map(d=>[d.id,d]));const sel=[];const items=[];const seen=new Set();
 for(const record of records){if(seen.has(record.draft))continue;seen.add(record.draft);const d=byId[record.draft];
  const b=el('button',undefined,'message-row');b.dataset.id=record.draft;b.append(el('span',d?.to||record.identity,'row-from'),el('span',d?.subject||'(No subject)','subject'),el('span',`${record.identity} · ${record.result.status} · ${new Date(record.created*1000).toLocaleString()}`,'recipient-label'));b.onclick=task(()=>{if(d)openDraft(d);});
  const s=obCheck({kind:'draft',id:record.draft},d?.subject);sel.push(s);items.push(obRow(s.check,b));}
 if(items.length)list.append(obToolbar(sel),...items);else list.append(el('p','No audited submissions yet. Earlier submissions remain in Outbox.'));
}
/* Message lists (Gmail Sent view, Trash): add checkboxes to rows rendered by app.js. */
function obDecorateMessages(trash){
 const list=$('#list');const sel=[];
 for(const item of list.querySelectorAll('.message-item:not(.ob-item)')){const b=item.querySelector('.message-row');if(!b?.dataset.id)continue;const s=obCheck({kind:'message',folder,id:b.dataset.id,gmail:/^Gmail/.test(item.querySelector('.recipient-label')?.textContent||'')},item.querySelector('.subject')?.textContent);item.classList.add('ob-item');item.prepend(s.check);sel.push(s);}
 return sel;
}
async function obTrashOutbound(){
 const {drafts}=await api('drafts');const rows=drafts.filter(d=>d.status==='trashed');if(!rows.length)return [];
 const box=el('div',undefined,'ob-trash-outbound');box.append(el('p','Outbound in Trash · restore brings unsent mail back paused; nothing is sent.','small muted'));const sel=[];
 for(const d of rows){const b=el('button',undefined,'message-row');b.dataset.id=d.id;b.append(el('span',d.to||'No recipient','row-from'),el('span',d.subject||'(No subject)','subject'),el('span','Outbound · was '+(OB_STATUS[d.trashed_from]||d.trashed_from||'draft'),'recipient-label'));b.onclick=task(()=>openDraft(d));const s=obCheck({kind:'draft',id:d.id},d.subject);sel.push(s);box.append(obRow(s.check,b));}
 $('#list').prepend(box);return sel;
}
const _obLoadMail=loadMail;
loadMail=async function(more=false){
 if(!more&&['drafts','outbox'].includes(folder)){view('mail');$('#folder-title').textContent=folder[0].toUpperCase()+folder.slice(1);document.querySelectorAll('[data-folder]').forEach(b=>b.classList.toggle('selected',b.dataset.folder===folder));$('#filters').hidden=true;offset=0;$('#list').replaceChildren();$('.mail-grid').classList.remove('reading');return obDraftList();}
 await _obLoadMail(more);
 if(folder==='trash'){$('#list .ob-toolbar')?.remove();$('#list .ob-trash-outbound')?.remove();const a=more?[]:await obTrashOutbound();const b=obDecorateMessages(true);const all=[...a,...b];if(all.length)$('#list').prepend(obToolbar(all,{trash:true}));}
 else if(folder==='sent'&&gmailView()){$('#list .ob-toolbar')?.remove();const b=obDecorateMessages(false);if(b.length)$('#list').prepend(obToolbar(b));}
};
const _obShowSent=showSent;
showSent=async function(){
 if(!gmailView())return obSentAudit();
 /* Gmail account Sent view: list the cached Gmail Sent folder (not the local submission audit). */
 const r=await api('messages?'+new URLSearchParams({folder:'sent',account:accountView,q:$('#search').value,offset:'0'}));$('#list').replaceChildren();
 for(const m of r.messages){const b=el('button',undefined,'message-row');b.dataset.id=m.id;const top=el('span',undefined,'row-top');top.append(el('span',m.to||m.from||'','row-from'),el('span',dateLabel(m.date),'row-date'));b.append(top,el('span',m.subject||'(No subject)','subject'),el('span','Gmail · Sent','recipient-label'));b.onclick=task(()=>readMessage(m.id));const item=el('div',undefined,'message-item');item.append(b);$('#list').append(item);}
 $('#more').hidden=true;if(!r.total)$('#list').append(el('div','Nothing here yet.','empty'));
};
/* Message view: Sent → Move to Trash; Trash → Delete permanently. */
const _obReadMessage=readMessage;
readMessage=async function(id){
 await _obReadMessage(id);const actions=$('#reader .actions');if(!actions)return;const gmail=current?.provider==='gmail';
 if(folder==='sent'){const t=el('button','Move to Trash');t.onclick=task(()=>obDelete([{kind:'message',folder:'sent',id,gmail}],false));const p=el('button','Delete permanently','danger');p.title='Moves to Trash first, then deletes';p.onclick=task(async()=>{if(!obConfirmPermanent(1))return;if(gmail&&!obConfirmGmail(1))return;await api('message/move',{folder:'sent',id,target:'trash',confirm_provider:gmail});await api('message/delete',{folder:'trash',id,confirm:true});notice('Deleted permanently');$('#reader').replaceChildren();await loadMail();});actions.append(t,p);}
 if(folder==='trash'){const p=el('button','Delete permanently','danger');p.onclick=task(()=>obDelete([{kind:'message',folder:'trash',id,gmail}],true));actions.append(p);}
};
/* Compose view of a saved draft / Outbox item: Delete (to Trash, cancels a paused send) or Restore if trashed. */
const _obOpenDraft=openDraft;
openDraft=function(d={}){
 _obOpenDraft(d);let box=$('#ob-draft-actions');if(!box){box=el('span',undefined,'ob-draft-actions');box.id='ob-draft-actions';$('#send').after(box);}box.replaceChildren();
 if(d.status==='trashed'){$('#draft-status').textContent='In Trash · was '+(OB_STATUS[d.trashed_from]||d.trashed_from||'draft')+' · nothing will be sent';for(const n of ['from','to','subject','body','send'])$('#'+n).disabled=true;$('#draft-form button[type=submit]').disabled=true;if(typeof composer!=='undefined')composer.enable(false);
  const r=el('button','Restore');r.type='button';r.onclick=task(async()=>{await obRestore([d.id]);});const p=el('button','Delete permanently','danger');p.type='button';p.onclick=task(async()=>{await obDelete([{kind:'draft',id:d.id}],true);folder='trash';await loadMail();});box.append(r,p);return;}
 if(!d.id)return;
 const t=el('button',['paused','rejected'].includes(d.status)?'Delete · cancel send':'Delete');t.type='button';t.disabled=d.status==='submitting';t.onclick=task(async()=>{dirty=false;await obDelete([{kind:'draft',id:d.id}],false);if(!['drafts','outbox','sent','trash'].includes(folder))folder='outbox';await loadMail();});box.append(t);
};
