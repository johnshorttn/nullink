'use strict';
/* Undo send / Retract, delivery status (DSN + bounces), read receipts (MDN) and optional open tracking.
   Honest limits: once a message is handed to the mail server it cannot be recalled. A missing delivery
   receipt proves nothing; read receipts are voluntary; open pixels are blocked or pre-fetched by many clients. */
OB_STATUS.scheduled='Sending soon · can retract';
const RC_LABEL={sent:'Sent',delivered:'Delivered',delayed:'Delayed',bounced:'Bounced'};
function rcTime(t){return new Date(t*1000).toLocaleString([], {dateStyle:'medium',timeStyle:'short'});}
function rcSecs(at){return Math.max(0,Math.ceil(at-Date.now()/1000));}
async function rcRetract(id){const r=await api('retract',{id});notice(r.message);rcUndoHide();if(draft&&draft.id===id){const {drafts}=await api('drafts');const d=drafts.find(x=>x.id===id);if(d)openDraft(d);}else await loadMail();return r;}
/* Undo bar: shown right after Send while the delay window runs. */
function rcUndoHide(){const b=$('#rc-undo');if(b){b.hidden=true;clearInterval(b.timer);}}
function rcUndo(id,sendAt){
 let b=$('#rc-undo');if(!b){b=el('div',undefined,'rc-undo');b.id='rc-undo';b.setAttribute('role','status');document.body.append(b);}
 clearInterval(b.timer);b.hidden=false;const txt=el('span','','rc-undo-text');const u=el('button','Undo');u.onclick=task(()=>rcRetract(id));b.replaceChildren(txt,u);
 const tick=()=>{const s=rcSecs(sendAt);if(!s){txt.textContent='Handed to the mail server · can no longer be recalled';u.remove();clearInterval(b.timer);setTimeout(rcUndoHide,4000);return;}txt.textContent=`Sending in ${s}s`;};tick();b.timer=setInterval(tick,500);
}
const _rcApi=api;
api=async function(path,data){
 if(path==='drafts'&&data&&typeof data==='object'){data={...data,read_receipt:!!$('#rc-mdn')?.checked,track_opens:!!$('#rc-track')?.checked};}
 const r=await _rcApi(path,data);
 if(path==='send'&&r&&r.status==='scheduled')setTimeout(()=>rcUndo(r.id,r.send_at),0);
 return r;
};
/* Compose: per-message toggles (account default for tracking from Settings). */
function rcToggles(){
 let box=$('#rc-options');if(box)return box;box=el('div',undefined,'rc-options');box.id='rc-options';
 const mk=(id,label,hint)=>{const l=el('label',undefined,'rc-toggle');const c=document.createElement('input');c.type='checkbox';c.id=id;c.onchange=()=>{dirty=true;};l.append(c,el('span',label),el('small',hint,'muted'));return l;};
 box.append(mk('rc-mdn','Request read receipt','Asks the recipient\u2019s app to confirm; they may decline.'),mk('rc-track','Track opens','Adds a 1-pixel image from Nullmail. Often blocked or pre-loaded; a hint, not proof.'));
 $('#send').closest('.compose-actions,.actions,div')?.before(box)||$('#draft-form').append(box);return box;
}
const _rcOpenDraft=openDraft;
openDraft=function(d={}){
 _rcOpenDraft(d);rcToggles();const locked=d.id&&!['draft','paused','rejected'].includes(d.status);
 $('#rc-mdn').checked=d.id?!!d.read_receipt:false;$('#rc-track').checked=d.id?!!d.track_opens:!!prefGet('track_opens_default',false);
 for(const n of ['rc-mdn','rc-track'])$('#'+n).disabled=!!locked;
 const box=$('#ob-draft-actions');clearInterval(openDraft.timer);
 if(d.status==='scheduled'&&d.send_at&&box){const r=el('button','Retract','rc-retract');r.type='button';r.onclick=task(()=>rcRetract(d.id));box.prepend(r);
  const tick=()=>{const s=rcSecs(d.send_at);$('#draft-status').textContent=s?`Sending in ${s}s · Retract returns it to Drafts`:'Handing off… once handed to the mail server it cannot be recalled';if(!s){r.disabled=true;clearInterval(openDraft.timer);}};tick();openDraft.timer=setInterval(tick,500);}
};
/* Outbox: countdown + Retract on scheduled rows. Sent: delivery / read badges. */
function rcBadge(dv){if(!dv)return null;const parts=[RC_LABEL[dv.status]||dv.status];if(dv.status==='delivered'&&dv.relayed_only)parts[0]='Delivered (relayed)';if(dv.read_at)parts.push('Read '+rcTime(dv.read_at));if(dv.opens)parts.push(`Opened ${dv.opens}× · last ${rcTime(dv.last_open)}`);const b=el('span',parts.join(' · '),'rc-badge rc-'+dv.status);b.title=dv.dsn_requested?'Delivery receipt requested':'No delivery receipt requested (server did not offer DSN or Gmail send); bounces still shown';return b;}
const _rcLoadMail=loadMail;
loadMail=async function(more=false){
 await _rcLoadMail(more);clearInterval(loadMail.timer);
 if(folder==='outbox'){const {drafts}=await api('drafts');const due=drafts.filter(d=>d.status==='scheduled');const tick=()=>{for(const d of due){const row=$(`#list .message-row[data-id="${d.id}"]`);if(!row)continue;const lab=row.querySelector('.recipient-label');const s=rcSecs(d.send_at);lab.textContent=s?`Sending in ${s}s · can retract`:'Handing off… cannot be recalled after hand-off';let btn=row.parentElement.querySelector('.rc-retract');if(!btn&&s){btn=el('button','Retract','rc-retract');btn.onclick=task(()=>rcRetract(d.id));row.after(btn);}if(btn&&!s)btn.disabled=true;}};tick();if(due.length)loadMail.timer=setInterval(tick,500);}
};
const _rcShowSent=showSent;
showSent=async function(){
 await _rcShowSent();if(gmailView())return;
 const {records}=await api('sent');const by=Object.fromEntries(records.map(r=>[r.draft,r.delivery]));
 for(const row of document.querySelectorAll('#list .message-row')){const b=rcBadge(by[row.dataset.id]);if(b)row.append(b);}
};
/* Message view: delivery status for Sent copies; prompt (never automatic) to answer read-receipt requests. */
const _rcReadMessage=readMessage;
readMessage=async function(id){
 await _rcReadMessage(id);const m=current;const actions=$('#reader .actions');if(!m||!actions)return;
 if(m.delivery){const box=el('div',undefined,'rc-status');box.append(rcBadge(m.delivery));for(const [r,v] of Object.entries(m.delivery.recipients||{}))box.append(el('div',`${r==='*'?'Recipient':r}: ${RC_LABEL[v.status]||v.status}${v.detail?' · '+v.detail:''}`,'small muted'));actions.after(box);}
 const q=m.mdn_request;if(q){const box=el('div',undefined,'rc-mdn-request');box.setAttribute('role','region');box.setAttribute('aria-label','Read receipt request');
  if(q.answered){box.append(el('span',q.answered.action==='send'?'Read receipt '+(q.answered.status==='accepted'?'sent':q.answered.status||'pending'):'Read receipt request ignored','small muted'));}
  else{box.append(el('span',`${q.to} asked for a read receipt.`+(q.return_path_mismatch?' The receipt address differs from the sender\u2019s return path.':'')));const s=el('button','Send receipt');const i=el('button','Ignore');
   s.onclick=task(async()=>{if(!confirm(`Send a read receipt to ${q.to}? It tells them you opened this message.`))return;const r=await api('mdn/respond',{folder,id,action:'send',confirm:true});notice(r.message);box.replaceChildren(el('span',r.message,'small muted'));});
   i.onclick=task(async()=>{const r=await api('mdn/respond',{folder,id,action:'ignore'});notice(r.message);box.replaceChildren(el('span','Read receipt request ignored','small muted'));});box.append(s,i);}
  actions.before(box);}
};
/* Settings → Sending (synced preference). */
const _rcShowSetup=showSetup;
showSetup=async function(tab){
 await _rcShowSetup(tab);if(setupTab!=='local'||$('#rc-settings'))return;
 const p=el('div',undefined,'panel rc-settings');p.id='rc-settings';p.append(el('h2','Sending'));
 const l1=el('label',undefined,'rc-setting');const n=document.createElement('input');n.type='number';n.min='0';n.max='120';n.step='1';n.id='rc-undo-seconds';n.value=prefGet('undo_send_seconds',30);
 n.onchange=()=>{const v=Math.max(0,Math.min(120,Math.round(+n.value||0)));n.value=v;prefSet('undo_send_seconds',v);notice(v?`Undo send: ${v}s`:'Undo send off: messages go out immediately');};
 l1.append(el('span','Undo send delay (seconds, 0–120)'),n);
 const l2=el('label',undefined,'rc-setting');const c=document.createElement('input');c.type='checkbox';c.id='rc-track-default';c.checked=!!prefGet('track_opens_default',false);c.onchange=()=>prefSet('track_opens_default',c.checked);l2.append(c,el('span','Track opens by default (off unless you turn it on)'));
 p.append(l1,el('p','During the delay you can Undo or Retract from the Outbox. After the message is handed to the mail server it cannot be recalled.','small muted'),l2);
 $('#setup-content').prepend(p);
};
