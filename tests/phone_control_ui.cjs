// Exercise actual viewer handlers with a DOM/fetch harness; no phone commands leave this process.
const assert = require('node:assert/strict'), fs = require('node:fs'), vm = require('node:vm');
class Element {
  constructor() { this.style={};this.handlers={};this.children=[];this.dataset={};this.naturalWidth=100;this.naturalHeight=200; }
  addEventListener(k,f){this.handlers[k]=f;} append(...children){this.children.push(...children);} replaceChildren(...children){this.children=children;}
  setPointerCapture(){} getBoundingClientRect(){return {left:0,top:0,width:300,height:300};}
}
const elements=new Map(), get=id=>{if(!elements.has(id))elements.set(id,new Element());return elements.get(id);};
const buttons=['back','home','recents'].map(action=>{const el=new Element();el.dataset.control=action;return el;});
const sent=[], devices=[{id:'a',name:'A',online:true,screen_active:true,control_enabled:true},{id:'b',name:'B',online:true,screen_active:true,control_enabled:true}];
const response=data=>({ok:true,status:200,headers:{get:k=>k==='content-type'?'application/json':null},json:async()=>data});
const context={document:{getElementById:get,querySelectorAll:()=>buttons,createElement:()=>new Element(),createDocumentFragment:()=>new Element()},
  URLSearchParams,URL:{createObjectURL:()=> 'blob:frame',revokeObjectURL(){}},Date,Math,Number,Error,console,setTimeout(){},setInterval(){},
  fetch:async(url,options)=>{
    if(url==='/api/phone/devices')return response({devices});
    if(url.startsWith('/api/phone/screen/frame'))return {ok:true,status:200,headers:{get:()=> '1'},blob:async()=>({})};
    if(url==='/api/phone/control'){sent.push(JSON.parse(options.body));return response({ok:true});}
    throw Error(url);
  }};
vm.runInNewContext(fs.readFileSync('static/phone-drive.js','utf8'),context);
const tick=()=>new Promise(resolve=>setImmediate(resolve));
const event=(x,y)=>({clientX:x,clientY:y,button:0,pointerId:1,preventDefault(){},currentTarget:get('screen-frame')});
async function select(index){get('devices').children[0].children[index].children[0].children[2].handlers.click();await tick();get('screen-frame').onload?.();}
(async()=>{
 await tick();await select(0);
 const frame=get('screen-frame');
 // 100x200 image inside a 300x300 box has 75px horizontal letterboxing.
 frame.handlers.pointerdown(event(20,150));frame.handlers.pointerup(event(20,150));await tick();assert.equal(sent.length,0);
 frame.handlers.pointerdown(event(150,150));frame.handlers.pointerup(event(150,150));await tick();
 assert.deepEqual(sent.pop(),{device_id:'a',command:{action:'tap',x:.5,y:.5}});
 frame.handlers.pointerdown(event(150,75));frame.handlers.pointerup(event(150,225));await tick();
 const swipe=sent.pop();assert.equal(swipe.command.action,'swipe');assert.equal(swipe.command.y,.25);assert.equal(swipe.command.end_y,.75);
 frame.handlers.pointerdown(event(150,150));await select(1);frame.handlers.pointerup(event(150,150));await tick();assert.equal(sent.length,0);
 await buttons[1].handlers.click();await tick();assert.equal(sent.pop().device_id,'b');
 get('stop-screen').handlers.click();frame.handlers.pointerdown(event(150,150));frame.handlers.pointerup(event(150,150));await tick();assert.equal(sent.length,0);
 console.log('PASS: letterboxing, tap, swipe, selected-device isolation, navigation, stop');
})().catch(e=>{console.error(e);process.exitCode=1;});
