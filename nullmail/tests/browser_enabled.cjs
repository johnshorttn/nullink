/* All requests routed to temporary fixture, whose SMTP adapter cannot transmit. */
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({executablePath:'/opt/google/chrome/chrome',headless:true,args:['--no-sandbox']});
 try {
 const context=await browser.newContext(),page=await context.newPage(),errors=[];
 page.on('pageerror',e=>errors.push(e.message));
 await context.route('**/*',async route=>{
  const req=route.request(),url=new URL(req.url());
  if(url.hostname!=='nullmail.nullverse.cloud')return route.abort();
  const response=await route.fetch({url:'http://127.0.0.1:'+(process.env.NULLMAIL_FIXTURE_PORT||'8799')+url.pathname+url.search,headers:{...req.headers(),host:'nullmail.nullverse.cloud'}});
  await route.fulfill({response});
 });
 await page.goto('https://nullmail.nullverse.cloud/');
 await page.fill('#code','123456');await page.click('#login-form button');
 await page.locator('.message-row').first().waitFor();
 assert.equal(await page.locator('.pause-banner strong').textContent(),'Outbound submission ready');
 await page.click('#compose');await page.fill('#to','fixture@example.com');await page.fill('#subject','Nontransmitting fixture');await page.fill('#body-editor','No external mail.');
 await page.click('#send');await page.waitForFunction(()=>document.querySelector('#draft-status').textContent.includes('FIXTURE123'));
 assert(await page.locator('#send').isDisabled());assert((await page.locator('#body-editor').getAttribute('contenteditable'))==='false');
 await page.click('[data-folder="outbox"]');await page.locator('.message-row').first().waitFor();
 assert((await page.locator('#list').textContent()).includes('Accepted / queued · delivery unverified'));
 await page.locator('.message-row').first().click();assert(await page.locator('#send').isDisabled());
 assert.deepEqual(errors,[]);console.log('PASS enabled send UI: simulated acceptance, queue ID, locked resend/edit, Outbox delivery uncertainty');
 } finally {await browser.close();}
})().catch(e=>{console.error(e.message);process.exit(1)});
