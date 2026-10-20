'use strict';
/* Nullmail rich-text composer. Quill 2.0.3 (BSD-3-Clause), vendored at /vendor/quill.js — no CDN.
   Browser HTML is untrusted: the server re-sanitizes it on every save/send and generates text/plain. */
const composer=(()=>{
 let q=null,box=null;
 const FONTS=['sans-serif','serif','monospace','wide','narrow','comic','garamond','georgia','tahoma','trebuchet','verdana'];
 const FONT_LABEL={'sans-serif':'Sans Serif',serif:'Serif',monospace:'Fixed width',wide:'Wide',narrow:'Narrow',comic:'Comic Sans MS',garamond:'Garamond',georgia:'Georgia',tahoma:'Tahoma',trebuchet:'Trebuchet MS',verdana:'Verdana'};
 const EMOJI='😀 😂 🙂 😉 😍 🤔 😅 😢 😮 😎 👍 👎 👏 🙏 💪 🎉 ❤️ 🔥 ✅ ❌ ⚠️ ⭐ 📎 📅'.split(' ');
 const MAX_IMG=1000,MAX_IMG_BYTES=90000;
 function mk(tag,cls,attrs={}){const n=document.createElement(tag);if(cls)n.className=cls;for(const [k,v] of Object.entries(attrs))n.setAttribute(k,v);return n;}
 function toolbar(){
  const t=mk('div','compose-toolbar',{id:'compose-toolbar',role:'toolbar','aria-label':'Formatting options'});
  const group=(...items)=>{const g=mk('span','ql-formats');g.append(...items);t.append(g);};
  const btn=(cls,label,value,text)=>{const b=mk('button',cls,{type:'button','aria-label':label,title:label});if(value)b.value=value;if(text)b.textContent=text;return b;};
  const font=mk('select','ql-font',{'aria-label':'Font',title:'Font'});for(const f of FONTS){const o=new Option(FONT_LABEL[f],f==='sans-serif'?'':f);if(f==='sans-serif')o.selected=true;font.add(o);}
  const size=mk('select','ql-size',{'aria-label':'Size',title:'Size'});for(const [v,l] of [['small','Small'],['','Normal'],['large','Large'],['huge','Huge']]){const o=new Option(l,v);if(!v)o.selected=true;size.add(o);}
  group(btn('ql-undo','Undo (Ctrl+Z)',null,'↶'),btn('ql-redo','Redo (Ctrl+Y)',null,'↷'));
  group(font);group(size);
  group(btn('ql-bold','Bold (Ctrl+B)'),btn('ql-italic','Italic (Ctrl+I)'),btn('ql-underline','Underline (Ctrl+U)'));
  group(mk('select','ql-color',{'aria-label':'Text color',title:'Text color'}),mk('select','ql-background',{'aria-label':'Highlight color',title:'Highlight color'}));
  group(mk('select','ql-align',{'aria-label':'Align',title:'Align'}));
  group(btn('ql-list','Numbered list','ordered'),btn('ql-list','Bulleted list','bullet'));
  group(btn('ql-indent','Indent less','-1'),btn('ql-indent','Indent more','+1'));
  group(btn('ql-blockquote','Quote'),btn('ql-strike','Strikethrough'),btn('ql-clean','Remove formatting'));
  group(btn('ql-link','Insert link (Ctrl+K)'),btn('ql-image','Insert photo'),btn('ql-emoji','Insert emoji',null,'☺'));
  return t;
 }
 function readImage(file){return new Promise((ok,bad)=>{if(!/^image\/(png|jpeg|gif|webp)$/.test(file.type))return bad(Error('Only PNG, JPEG, GIF or WebP images'));
  createImageBitmap(file).then(bmp=>{let scale=Math.min(1,MAX_IMG/Math.max(bmp.width,bmp.height));const c=document.createElement('canvas');let url='';
   for(let quality=0.82;;){c.width=Math.max(1,Math.round(bmp.width*scale));c.height=Math.max(1,Math.round(bmp.height*scale));const x=c.getContext('2d');x.fillStyle='#fff';x.fillRect(0,0,c.width,c.height);x.drawImage(bmp,0,0,c.width,c.height);url=c.toDataURL('image/jpeg',quality);
    if(url.length*0.75<=MAX_IMG_BYTES||c.width<120)break;if(quality>0.55)quality-=0.12;else scale*=0.75;}
   if(url.length*0.75>MAX_IMG_BYTES)return bad(Error('Image is too large to inline'));ok(url);},bad);});}
 async function insertImages(range,files){for(const f of files){try{const url=await readImage(f);const at=(range||q.getSelection(true)||{index:q.getLength()}).index;q.insertEmbed(at,'image',url,'user');q.setSelection(at+1,0,'silent');}catch(e){if(typeof notice==='function')notice(e.message);}}}
 function pickImage(){const i=mk('input','',{type:'file',accept:'image/png,image/jpeg,image/gif,image/webp'});i.multiple=true;i.onchange=()=>insertImages(q.getSelection(true),[...i.files]);i.click();}
 function emojiPanel(){let p=$('#emoji-panel');if(p){p.hidden=!p.hidden;return;}p=mk('div','emoji-panel',{id:'emoji-panel',role:'listbox','aria-label':'Emoji'});
  for(const e of EMOJI){const b=mk('button','',{type:'button','aria-label':'Insert '+e});b.textContent=e;b.onclick=()=>{const r=q.getSelection(true);q.insertText(r.index,e,'user');q.setSelection(r.index+e.length,0);p.hidden=true;};p.append(b);}
  $('#compose-toolbar').after(p);}
 function init(){
  if(q||typeof Quill==='undefined')return;
  const Font=Quill.import('formats/font');Font.whitelist=FONTS.filter(f=>f!=='sans-serif');Quill.register(Font,true);
  const ta=$('#body');ta.hidden=true;box=mk('div','compose-editor',{id:'compose-editor'});ta.after(box);box.after(toolbar());
  q=new Quill(box,{theme:'snow',placeholder:'Write your message…',modules:{
   toolbar:{container:'#compose-toolbar',handlers:{undo(){q.history.undo();},redo(){q.history.redo();},image:pickImage,emoji:emojiPanel}},
   history:{delay:800,maxStack:200,userOnly:true},uploader:{mimetypes:['image/png','image/jpeg','image/gif','image/webp'],handler:insertImages}}});
  // Pasted remote images (tracking pixels) are dropped; only inline data: images are kept. The server re-checks.
  const Delta=Quill.import('delta');for(const tag of ['SCRIPT','STYLE','TEMPLATE','NOSCRIPT','TITLE','META'])q.clipboard.addMatcher(tag,()=>new Delta());q.clipboard.addMatcher('IMG',(node,delta)=>/^data:image\/(png|jpeg|gif|webp);base64,/i.test(node.getAttribute('src')||'')?delta:new Delta());
  q.root.setAttribute('aria-label','Message body');q.root.setAttribute('role','textbox');q.root.setAttribute('aria-multiline','true');q.root.id='body-editor';
  $('label[for=body]')?.setAttribute('for','body-editor');
  q.on('text-change',(d,o,source)=>{if(source==='user'&&$('#draft-form').oninput)$('#draft-form').oninput();ta.value=q.getText();});
  q.keyboard.addBinding({key:'k',shortKey:true},()=>{$('#compose-toolbar .ql-link').click();return false;});
 }
 function setText(text){q.setContents([{insert:(text||'').replace(/\r\n/g,'\n')+(String(text||'').endsWith('\n')?'':'\n')}],'silent');}
 function load(d){init();if(!q)return;q.history.clear();
  if(d.body_delta){try{q.setContents(JSON.parse(d.body_delta),'silent');q.history.clear();return;}catch(e){}}
  if(d.body_html){q.setContents(q.clipboard.convert({html:d.body_html}),'silent');}else setText(d.body||'');q.history.clear();}
 function empty(){return !q||(q.getLength()<=1&&!q.root.querySelector('img'));}
 function html(){return empty()?'':q.getSemanticHTML();}
 function text(){return q?q.getText().replace(/\n$/,''):$('#body').value;}
 function delta(){if(!q)return '';const s=JSON.stringify(q.getContents());return s.length<=60000?s:'';}
 function enable(on){if(q)q.enable(on);$('#compose-toolbar')?.classList.toggle('disabled',!on);document.querySelectorAll('#compose-toolbar button,#compose-toolbar .ql-picker-label').forEach(b=>{b.disabled=!on;});}
 function focusStart(){if(!q)return;q.focus();q.setSelection(0,0,'silent');}
 function dateLine(m){const d=new Date(m.date);return Number.isNaN(+d)?m.date:d.toLocaleString(undefined,{weekday:'short',year:'numeric',month:'short',day:'numeric',hour:'numeric',minute:'2-digit'});}
 function quote(m,mode){init();if(!q)return;const ops=[{insert:'\n\n'}];const lines=String(m.body||'').replace(/\r\n/g,'\n').replace(/\n+$/,'').split('\n');
  if(mode==='forward'){ops.push({insert:'---------- Forwarded message ---------\nFrom: '+m.from+'\nDate: '+dateLine(m)+'\nSubject: '+(m.subject||'')+'\nTo: '+m.to+'\n\n'});ops.push({insert:lines.join('\n')+'\n'});}
  else{ops.push({insert:'On '+dateLine(m)+', '+m.from+' wrote:\n'});for(const l of lines){if(l)ops.push({insert:l});ops.push({insert:'\n',attributes:{blockquote:true}});}}
  q.setContents(ops,'silent');q.history.clear();$('#body').value=q.getText();}
 return {init,load,html,text,delta,enable,focusStart,quote,get quill(){return q;}};
})();
document.addEventListener('DOMContentLoaded',()=>composer.init());
