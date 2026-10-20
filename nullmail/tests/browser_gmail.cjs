/* All Google/SMTP operations are fixtures; browser traffic stays on loopback. */
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({executablePath:'/opt/google/chrome/chrome',headless:true,args:['--no-sandbox']});
 try{
 const context=await browser.newContext({viewport:{width:1440,height:1000}}),page=await context.newPage(),errors=[],external=[];
 page.on('pageerror',e=>errors.push(e.message));
 await context.route('**/*',async route=>{const req=route.request(),url=new URL(req.url());if(url.hostname!=='nullmail.nullverse.cloud'){external.push(url.hostname);return route.abort();}const response=await route.fetch({url:'http://127.0.0.1:'+process.env.NULLMAIL_FIXTURE_PORT+url.pathname+url.search,headers:{...req.headers(),host:'nullmail.nullverse.cloud','x-nullmail-client-ip':'198.51.100.80'}});await route.fulfill({response});});
 await page.goto('https://nullmail.nullverse.cloud/');await page.fill('#code','123456');await page.click('#login-form button');await page.locator('.message-row').first().waitFor();assert.equal(await page.locator('.message-row').count(),2);
 const accounts=await page.locator('#accounts-panel').textContent();assert(accounts.indexOf('Local server accounts')<accounts.indexOf('External'));
 await page.locator('#accounts-panel').getByRole('button',{name:'None',exact:true}).click();await page.waitForFunction(()=>document.querySelectorAll('.message-row').length===0);
 await page.getByText('External',{exact:true}).click();await page.getByRole('button',{name:'person@gmail.com (1)',exact:true}).click();await page.locator('.message-row').first().waitFor();assert.equal(await page.locator('.message-row').count(),1);
 await page.locator('.message-row').click();await page.getByRole('button',{name:'Reply',exact:true}).click();await page.locator('#compose-view').waitFor({state:'visible'});assert.equal(await page.locator('#from').inputValue(),'person@gmail.com');assert.equal(await page.locator('#send').textContent(),'Send via Gmail');assert((await page.locator('#from option').allTextContents()).includes('person@gmail.com · Gmail'));
 await page.getByText('External',{exact:true}).click();await page.locator('#accounts-panel').getByRole('button',{name:/person@gmail.com/}).click();await page.locator('.message-row').click();await page.getByRole('button',{name:'Create case from this message',exact:true}).click();await page.getByLabel('Case title',{exact:true}).fill('Gmail case fixture');await page.locator('.case-form').getByRole('button',{name:'Create case',exact:true}).click();await page.getByRole('heading',{name:'CASE-000001 · Gmail case fixture',exact:true}).waitFor();assert.equal(await page.locator('.case-member').count(),1);
 await page.setViewportSize({width:412,height:915});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
 await page.evaluate(()=>showSetup());await page.getByRole('heading',{name:'External Gmail',exact:true}).waitFor();await page.getByRole('button',{name:'Connect Gmail with Google',exact:true}).waitFor();assert((await page.locator('#setup-content').textContent()).includes('local only'));
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await page.screenshot({path:'/root/nullmail-build-backup/gmail-mobile-fixture.png',fullPage:true});
 await page.setViewportSize({width:1440,height:1000});await page.screenshot({path:'/root/nullmail-build-backup/gmail-desktop-fixture.png',fullPage:true});
 assert.deepEqual(errors,[]);assert.deepEqual(external,[]);console.log('PASS Gmail desktop/mobile: local-first sidebar, None and single-account view, verified reply identity, independent From, Gmail Case, setup controls/semantics, no overflow/external traffic');
 }finally{await browser.close();}
})().catch(e=>{console.error(e.stack);process.exit(1)});
