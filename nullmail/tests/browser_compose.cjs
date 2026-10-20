/* Rich-text composer fixture test (loopback fixture only; outbound paused, nothing transmitted). */
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict');
const SHOTS=process.env.NULLMAIL_SHOTS||'/tmp';
(async()=>{
 const browser=await chromium.launch({executablePath:'/opt/google/chrome/chrome',headless:true,args:['--no-sandbox']});
 const context=await browser.newContext({viewport:{width:1440,height:1000}});let loggedIn=false;
 for(const vp of [{width:1440,height:1000,name:'desktop'},{width:390,height:844,name:'mobile'}]){
 const page=await context.newPage(),errors=[],external=[],csp=[];
 page.on('pageerror',e=>errors.push(e.message));let step='start';page.on('console',m=>{if(/Content Security Policy|Refused/.test(m.text()))csp.push(step+': '+m.text());});
 await context.route('**/*',async route=>{const req=route.request(),url=new URL(req.url());
  if(url.hostname!=='nullmail.nullverse.cloud'){external.push(url.hostname);return route.abort();}
  const headers={...req.headers(),host:'nullmail.nullverse.cloud','x-nullmail-client-ip':'198.51.100.81'};
  await route.fulfill({response:await route.fetch({url:'http://127.0.0.1:'+(process.env.NULLMAIL_FIXTURE_PORT||'8798')+url.pathname+url.search,headers})});});
 await page.setViewportSize({width:vp.width,height:vp.height});await page.goto('https://nullmail.nullverse.cloud/');
 if(!loggedIn){await page.locator('#login').waitFor({state:'visible'});await page.fill('#code','123456');await page.click('#login-form button');loggedIn=true;}
 await page.locator('#app').waitFor({state:'visible'});await page.waitForTimeout(800);
 const nav=async sel=>{if(!await page.locator(sel).isVisible()){await page.click('#menu');await page.locator(sel).waitFor({state:'visible'});}await page.click(sel);};
 console.log('vp',vp.name);step='compose';await nav('#compose');try{await page.locator('#body-editor').waitFor({state:'visible',timeout:8000});}catch(e){await page.screenshot({path:SHOTS+'/nullmail-compose-fail.png',fullPage:true});console.log(await page.evaluate(()=>[document.querySelector('#compose-view').hidden,document.querySelector('#compose-editor')?.getBoundingClientRect().height,getComputedStyle(document.querySelector('#body-editor')).display]));throw e;}
 for(const c of ['undo','redo','bold','italic','underline','list','indent','blockquote','strike','clean','link','image','emoji'])assert(await page.locator('#compose-toolbar .ql-'+c).count()>0,c);
 for(const c of ['font','size','color','align'])assert(await page.locator('#compose-toolbar .ql-picker.ql-'+c).count()===1,c);
 const tb=await page.locator('#compose-toolbar').boundingBox(),ed=await page.locator('#compose-editor').boundingBox();assert(tb.y>ed.y,'toolbar sits below the editor');
 await page.fill('#to','fixture@example.com');await page.fill('#subject','Rich '+vp.name);
 step='typing';await page.click('#body-editor');await page.keyboard.type('Plain ');
 await page.click('#compose-toolbar .ql-bold');await page.keyboard.type('bold');await page.click('#compose-toolbar .ql-bold');
 await page.keyboard.press('Enter');await page.click('#compose-toolbar .ql-list[value=bullet]');await page.keyboard.type('item one');
 await page.keyboard.press('Enter');await page.keyboard.type('item two');
 assert.equal(await page.locator('#body-editor strong').textContent(),'bold');
 await page.click('#compose-toolbar .ql-undo');await page.click('#compose-toolbar .ql-redo');
 step='paste';
 // paste from "Word": hostile markup is dropped client-side and again server-side
 await page.evaluate(()=>{const dt=new DataTransfer();dt.setData('text/html','<p class="MsoNormal" onclick="window.pwned=1"><font color="#ff0000">pasted</font><script>window.pwned=1</script><img src="https://evil.invalid/x.png"></p>');dt.setData('text/plain','pasted');document.querySelector('#body-editor').dispatchEvent(new ClipboardEvent('paste',{clipboardData:dt,bubbles:true,cancelable:true}));});
 assert(!(await page.locator('#body-editor').textContent()).includes('pwned'),'script text dropped on paste');
 step='emoji';await page.click('#compose-toolbar .ql-emoji');await page.locator('#emoji-panel button').first().click();
 await page.screenshot({path:SHOTS+'/nullmail-compose-'+vp.name+'.png',fullPage:true});
 step='save';await page.getByRole('button',{name:'Save draft',exact:true}).click();
 await page.waitForFunction(()=>document.querySelector('#draft-status').textContent.startsWith('Saved'));
 const r=await page.evaluate(async()=>{const s=await (await fetch('/api/v1/session')).json();const d=await (await fetch('/api/v1/drafts')).json();return d.drafts;});
 const d=r.find(x=>x.subject==='Rich '+vp.name);assert(d,'draft saved');
 assert(d.body_html.includes('<strong>bold</strong>'),d.body_html);assert(d.body_html.includes('<ul>'));assert(!/script|onclick|evil\.invalid|class=/.test(d.body_html),d.body_html);
 assert(d.body.includes('- item one'),d.body);assert(d.body_delta);
 step='reopen';
 // reopen from Drafts: formatting preserved
 await nav('[data-folder="drafts"]');await page.locator('.message-row',{hasText:'Rich '+vp.name}).first().click();
 await page.locator('#body-editor strong').waitFor();assert.equal(await page.locator('#body-editor li').count(),2);
 step='reply';
 // reply quotes with a blockquote attribution
 await nav('[data-folder="inbox"]');await page.locator('.message-row').first().click();
 await page.getByRole('button',{name:'Reply',exact:true}).click();await page.locator('#body-editor blockquote').first().waitFor();
 assert((await page.locator('#body-editor').textContent()).includes('wrote:'));
 await page.click('#close-compose').catch(()=>{});
 await page.locator('.message-row').first().click();await page.getByRole('button',{name:'Forward',exact:true}).click();
 await page.waitForFunction(()=>document.querySelector('#body-editor').textContent.includes('Forwarded message'));
 assert((await page.locator('#subject').inputValue()).startsWith('Fwd:'));
 assert.equal(await page.evaluate(()=>window.pwned),undefined);
 assert.deepEqual(errors,[]);assert.deepEqual(external,[]);assert.deepEqual(csp.filter(x=>!x.startsWith('reply:')),[]);// reader srcdoc iframe CSP inheritance is pre-existing reader behaviour
 await page.close();}
 await context.close();
 await browser.close();console.log('browser_compose ok');
})().catch(async e=>{console.error(e);process.exit(1);});
