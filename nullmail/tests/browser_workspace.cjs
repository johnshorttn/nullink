/* Synthetic mail only, loopback route; no real SMTP or Google requests. */
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict');
(async()=>{
 const browser=await chromium.launch({executablePath:'/opt/google/chrome/chrome',headless:true,args:['--no-sandbox']});
 const context=await browser.newContext({viewport:{width:1440,height:1000}}),page=await context.newPage(),errors=[],external=[];
 page.on('pageerror',e=>errors.push(e.message));
 await context.route('**/*',async route=>{const req=route.request(),url=new URL(req.url());if(url.hostname!=='nullmail.nullverse.cloud'){external.push(url.hostname);return route.abort();}const response=await route.fetch({url:'http://127.0.0.1:'+(process.env.NULLMAIL_FIXTURE_PORT||'8797')+url.pathname+url.search,headers:{...req.headers(),host:'nullmail.nullverse.cloud','x-nullmail-client-ip':'198.51.100.80'}});await route.fulfill({response});});
 await page.goto('https://nullmail.nullverse.cloud/');await page.locator('#login').waitFor({state:'visible'});await page.fill('#code','123456');await page.click('#login-form button');await page.locator('.message-row').first().waitFor();
 await page.locator('#accounts-panel').getByRole('button',{name:'None',exact:true}).click();await page.waitForFunction(()=>document.querySelector('#list').textContent.includes('Nothing here yet'));
 await page.reload();await page.locator('#accounts-panel').waitFor();assert.equal(await page.locator('.message-row').count(),0);
 await page.getByRole('button',{name:'hello@nullverse.cloud (1)',exact:true}).click();await page.locator('.message-row').first().waitFor();
 await page.click('#compose');assert((await page.locator('#from option').allTextContents()).includes('hello@nullverse.cloud'));
 await page.click('#labels-tab');await page.getByLabel('Label name',{exact:true}).fill('Fixture label');await page.getByRole('button',{name:'Create label',exact:true}).click();await page.getByRole('heading',{name:'Fixture label',exact:true}).waitFor();
 await page.click('#rules-tab');await page.getByRole('button',{name:'New rule',exact:true}).click();await page.getByLabel('Rule name',{exact:true}).fill('Browser nested rule');await page.getByLabel('Enabled for new mail',{exact:true}).check();
 await page.getByLabel('Match',{exact:true}).selectOption('ALL');await page.getByLabel('Value',{exact:true}).fill('Fixture');await page.getByRole('button',{name:'＋ Nested group',exact:true}).click();await page.getByLabel('Value',{exact:true}).nth(1).fill('Fixture');
 await page.setViewportSize({width:412,height:915});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await page.screenshot({path:'/root/nullmail-build-backup/fixture-mobile-nested-rules.png',fullPage:true});
 await page.getByRole('button',{name:'Save rule',exact:true}).click();await page.getByRole('heading',{name:'Browser nested rule',exact:true}).waitFor();
 await page.getByRole('button',{name:'Preview / run existing mail',exact:true}).click();await page.locator('#rules-content section').last().locator('input[type=checkbox]').first().check();
 const before=await page.evaluate(()=>api('messages?account=john%40nullverse.cloud'));await page.getByRole('button',{name:'Dry run selected messages',exact:true}).click();await page.getByRole('heading',{name:'Preview · 1 messages · zero writes'}).waitFor();assert.deepEqual(await page.evaluate(()=>api('messages?account=john%40nullverse.cloud')),before);
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);await page.screenshot({path:'/root/nullmail-build-backup/fixture-mobile-rule-preview.png',fullPage:true});
 await page.getByRole('button',{name:'Confirm: apply this preview to selected messages',exact:true}).click();await page.getByRole('button',{name:'Run completed',exact:true}).waitFor();
 const after=await page.evaluate(()=>api('messages?account=john%40nullverse.cloud'));assert.equal(after.messages[0].priority,'high');assert.equal((await page.evaluate(()=>api('rules/history'))).runs.length,1);
 await page.setViewportSize({width:1440,height:1000});await page.screenshot({path:'/root/nullmail-build-backup/fixture-desktop-rule-preview.png',fullPage:true});
 assert.deepEqual(errors,[]);assert.deepEqual(external,[]);await browser.close();console.log('PASS: desktop/mobile account None persistence, single alias view, independent From, label CRUD create, nested visual rules, dry-run zero writes, explicit bounded run, history, overflow and no external content');
})().catch(e=>{console.error(e.stack);process.exit(1)});
