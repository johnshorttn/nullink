/* Outbound delete fixture test (loopback fixture only; outbound paused, nothing transmitted). */
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict');
const SHOTS=process.env.NULLMAIL_SHOTS||'/tmp';
(async()=>{
 const browser=await chromium.launch({executablePath:'/opt/google/chrome/chrome',headless:true,args:['--no-sandbox']});
 const context=await browser.newContext({viewport:{width:1440,height:1000}});let loggedIn=false;
 await context.route('**/*',async route=>{const req=route.request(),url=new URL(req.url());
  if(url.hostname!=='nullmail.nullverse.cloud')return route.abort();
  const headers={...req.headers(),host:'nullmail.nullverse.cloud','x-nullmail-client-ip':'198.51.100.82'};
  await route.fulfill({response:await route.fetch({url:'http://127.0.0.1:'+(process.env.NULLMAIL_FIXTURE_PORT||'8798')+url.pathname+url.search,headers})});});
 for(const vp of [{width:1440,height:1000,name:'desktop'},{width:412,height:915,name:'pixel'}]){
  const page=await context.newPage(),errors=[],dialogs=[];page.on('pageerror',e=>errors.push(e.message));
  page.on('dialog',d=>{dialogs.push(d.message());d.accept();});
  await page.setViewportSize({width:vp.width,height:vp.height});await page.goto('https://nullmail.nullverse.cloud/');
  if(!loggedIn){await page.locator('#login').waitFor({state:'visible'});await page.fill('#code','123456');await page.click('#login-form button');loggedIn=true;}
  await page.locator('#app').waitFor({state:'visible'});await page.waitForTimeout(500);
  // Seed three paused Outbox items (outbound paused in fixture: Send never transmits).
  await page.evaluate(async tag=>{for(const n of [1,2,3]){const d=await api('drafts',{from:'john@nullverse.cloud',to:`reader${n}@example.test`,subject:`${tag} outbound ${n}`,body:'Fixture body'});await api('send',{id:d.id,request_id:'fixture-'+tag+'-'+n+'-'+Date.now()});}},vp.name);
  const nav=async sel=>{if(!await page.locator(sel).isVisible()){await page.click('#menu');await page.locator(sel).waitFor({state:'visible'});}await page.click(sel);};
  const outbox=async()=>{await nav('[data-folder="outbox"]');await page.locator('#list .ob-toolbar').waitFor();};
  await outbox();const mine=page.locator('#list .ob-item',{hasText:vp.name+' outbound'});assert.equal(await mine.count(),3);
  await mine.nth(0).locator('.ob-check').check();await mine.nth(1).locator('.ob-check').check();
  assert.match(await page.textContent('#list .ob-count'),/2 selected/);
  await page.screenshot({path:`${SHOTS}/nullmail-outbound-select-${vp.name}.png`});
  await page.click('#list .ob-toolbar >> text=Move to Trash');await page.waitForTimeout(400);
  assert.equal(await page.locator('#list .ob-item',{hasText:vp.name+' outbound'}).count(),1);
  assert.match(await page.textContent('#notice'),/2 moved to Trash.*2 sends cancelled/);
  // Message view: delete the remaining one from the compose/Outbox view.
  await page.locator('#list .ob-item',{hasText:vp.name+' outbound'}).locator('.message-row').click();
  const del=page.locator('#ob-draft-actions button',{hasText:'Delete · cancel send'});await del.waitFor();
  await page.screenshot({path:`${SHOTS}/nullmail-outbound-view-${vp.name}.png`});
  await del.click();await page.waitForTimeout(400);
  // Sent audit hides trashed submissions.
  await nav('[data-folder="sent"]');await page.waitForTimeout(400);
  assert.equal(await page.locator('#list .message-row',{hasText:vp.name+' outbound'}).count(),0);
  // Trash: restore one (comes back paused), permanently delete the rest with confirmation.
  await nav('[data-folder="trash"]');await page.locator('#list .ob-trash-outbound').waitFor();
  const t=page.locator('#list .ob-trash-outbound .ob-item',{hasText:vp.name+' outbound'});assert.equal(await t.count(),3);
  await page.screenshot({path:`${SHOTS}/nullmail-outbound-trash-${vp.name}.png`});
  await t.nth(0).locator('.ob-check').check();await page.click('#list .ob-toolbar >> text=Restore');await page.waitForTimeout(400);
  await outbox();assert.equal(await page.locator('#list .ob-item',{hasText:vp.name+' outbound'}).count(),1);
  assert.match(await page.locator('#list .ob-item',{hasText:vp.name+' outbound'}).textContent(),/Paused · nothing sent/);
  await nav('[data-folder="trash"]');await page.locator('#list .ob-trash-outbound').waitFor();
  const before=dialogs.length;for(const c of await page.locator('#list .ob-trash-outbound .ob-item',{hasText:vp.name+' outbound'}).locator('.ob-check').all())await c.check();
  await page.click('#list .ob-toolbar >> text=Delete permanently');await page.waitForTimeout(400);
  assert.ok(dialogs.slice(before).some(m=>/Permanently delete 2 messages\? This cannot be undone/.test(m)));
  assert.equal(await page.locator('#list .ob-item',{hasText:vp.name+' outbound'}).count(),0);
  await page.screenshot({path:`${SHOTS}/nullmail-outbound-after-delete-${vp.name}.png`});
  assert.deepEqual(errors,[]);await page.close();
 }
 await browser.close();console.log('Outbound delete browser fixture passed');
})().catch(e=>{console.error(e);process.exit(1);});
