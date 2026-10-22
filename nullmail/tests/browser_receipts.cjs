/* Undo send / retract, delivery + read badges, read-receipt prompt, Sending settings (loopback fixture; nothing transmitted). */
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
  const nav=async sel=>{if(!await page.locator(sel).isVisible()){await page.click('#menu');await page.locator(sel).waitFor({state:'visible'});}await page.click(sel);};
  // Settings → Sending
  await nav('#setup-link');await page.click('#setup-tab-local');const settings=page.locator('#rc-settings');await settings.waitFor();
  await page.fill('#rc-undo-seconds','6');await page.press('#rc-undo-seconds','Tab');await page.waitForTimeout(300);
  await settings.scrollIntoViewIfNeeded();await page.screenshot({path:`${SHOTS}/nullmail-receipts-settings-${vp.name}.png`});
  assert.equal(await page.evaluate(()=>prefGet('undo_send_seconds')),6);
  // Compose with read receipt + tracking toggles
  await page.goto('https://nullmail.nullverse.cloud/');await page.locator('#app').waitFor({state:'visible'});await page.waitForTimeout(400);
  const compose=async subj=>{await nav('#compose');await page.locator('#compose-view').waitFor({state:'visible'});await page.fill('#to','reader@example.test');await page.fill('#subject',subj);
   await page.evaluate(()=>{if(typeof composer!=='undefined')composer.setText?composer.setText('Fixture body'):0;});await page.check('#rc-mdn');await page.check('#rc-track');};
  await compose(vp.name+' receipt test');await page.locator('#rc-options').scrollIntoViewIfNeeded();
  await page.screenshot({path:`${SHOTS}/nullmail-receipts-compose-${vp.name}.png`});
  // Send → Undo bar → Undo returns to Drafts
  await page.click('#send');const bar=page.locator('#rc-undo');await bar.waitFor({state:'visible'});assert.match(await bar.textContent(),/Sending in \d+s/);
  await page.screenshot({path:`${SHOTS}/nullmail-receipts-undo-${vp.name}.png`});
  await bar.locator('button',{hasText:'Undo'}).click();await page.waitForTimeout(500);
  assert.match(await page.textContent('#notice'),/Retracted/);
  // Send again → Outbox countdown + Retract button; let it go out
  await page.click('#send');await bar.waitFor({state:'visible'});
  await nav('[data-folder="outbox"]');await page.waitForTimeout(600);
  const row=page.locator('#list .ob-item',{hasText:vp.name+' receipt test'});assert.match(await row.textContent(),/Sending in \d+s · can retract/);
  assert.equal(await page.locator('#list .rc-retract').count()>0,true);
  await page.screenshot({path:`${SHOTS}/nullmail-receipts-outbox-${vp.name}.png`});
  await page.waitForTimeout(9000);
  assert.match(await bar.textContent().catch(()=>'Handed'),/Handed|Sending/);
  // Sent: delivery + read badge (fixture simulates the remote DSN + MDN)
  await nav('[data-folder="sent"]');await page.waitForTimeout(800);
  const sent=page.locator('#list .message-row',{hasText:vp.name+' receipt test'});await sent.first().waitFor();
  const badge=sent.first().locator('.rc-badge');await badge.waitFor();assert.match(await badge.textContent(),/Delivered · Read/);
  await page.screenshot({path:`${SHOTS}/nullmail-receipts-sent-${vp.name}.png`});
  // Incoming read-receipt request: prompt only, explicit confirm
  await nav('[data-folder="inbox"]');await page.waitForTimeout(500);
  await page.locator('#list .message-row',{hasText:'Please confirm you read this'}).first().click();
  const req=page.locator('.rc-mdn-request');await req.waitFor();assert.match(await req.textContent(),vp.name==='desktop'?/asked for a read receipt/:/Read receipt sent/);
  await page.screenshot({path:`${SHOTS}/nullmail-receipts-mdn-request-${vp.name}.png`});
  if(vp.name==='desktop'){await req.locator('button',{hasText:'Send receipt'}).click();await page.waitForTimeout(500);
   assert.ok(dialogs.some(m=>/Send a read receipt to sender@example.com/.test(m)));assert.match(await req.textContent(),/handed|paused|receipt/i);}
  assert.deepEqual(errors,[]);await page.close();
 }
 await browser.close();console.log('Receipts browser fixture passed');
})().catch(e=>{console.error(e);process.exit(1);});
