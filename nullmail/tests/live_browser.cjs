/* Read-only live inbox check. Session supplied only via stdin; no screenshots/content logs. */
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs');
(async()=>{
 const {token}=JSON.parse(fs.readFileSync(0,'utf8'));
 const browser=await chromium.launch({executablePath:'/opt/google/chrome/chrome',headless:true,args:['--no-sandbox']});
 const ctx=await browser.newContext({viewport:{width:412,height:915}}),page=await ctx.newPage(),errors=[];
 page.on('pageerror',e=>errors.push(e.message));
 await page.goto('https://nullmail.nullverse.cloud/');await page.locator('#login').waitFor({state:'visible'});
 await ctx.addCookies([{name:'__Host-nullink_session',value:token,url:'https://nullmail.nullverse.cloud/',secure:true,httpOnly:true,sameSite:'Lax'}]);
 await page.reload();await page.locator('#app').waitFor({state:'visible'});
 await page.waitForFunction(()=>document.querySelector('#inbox-count').textContent.trim()!=='');
 const count=Number(await page.locator('#inbox-count').textContent());
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
 await page.click('#menu');await page.click('#projects-tab');await page.locator('#project-list .panel').first().waitFor();
 assert.equal(await page.locator('#project-list .panel').count(),4);
 await page.setViewportSize({width:1440,height:1000});await page.click('#setup-tab');await page.locator('#setup-content .panel').first().waitFor();
 assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
 assert.deepEqual(errors,[]);
 console.log('PASS live TLS + desktop/Pixel 9 authenticated inbox count:',count,'; projects/setup, no horizontal overflow or JavaScript errors. No messages opened.');
 await page.click('#logout');await page.locator('#login').waitFor({state:'visible'});
 assert.equal((await ctx.cookies()).filter(c=>c.name==='__Host-nullink_session').length,0);
 await browser.close();
})().catch(e=>{console.error('Live browser check failed:',e.message);process.exit(1)});
