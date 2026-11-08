import { createRequire } from 'node:module';
import path from 'node:path';
import { readFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
import { installLiveMock, startLiveMock, finishLiveMock, emit } from './live-mock.mjs';
const require=createRequire(path.resolve(process.env.PLAYWRIGHT_ROOT??process.cwd(),'package.json'));
const { chromium }=require('playwright-core');
const base=process.env.PREVIEW_URL??'http://127.0.0.1:4318';
const bundle=JSON.parse(await readFile(new URL('../public/data/bundle.json',import.meta.url),'utf8'));
const browser=await chromium.launch({channel:'chromium'}), passed=[], errors=[];
async function load(page){page.on('pageerror',error=>errors.push(error.message));await page.emulateMedia({reducedMotion:'reduce'});await page.goto(base);await page.waitForFunction(()=>document.querySelector('main')?.getAttribute('aria-busy')==='false');}
async function deck(page){await page.keyboard.press('p');for(let i=0;i<4;i++)await page.keyboard.press('ArrowRight');}
async function check(name,fn){const page=await browser.newPage({viewport:{width:1440,height:900},deviceScaleFactor:2});try{await fn(page);passed.push(name);}finally{await page.close();}}
try{
 await check('live stream finishes into the exact run approval, with evidence and dropped claims',async page=>{
  await installLiveMock(page);await load(page);await deck(page);
  const cve=await page.getByRole('textbox',{name:'2026 CVE to investigate'}).inputValue();const run=await startLiveMock(page,bundle.runs.find(run=>run.cve_id===cve));
  assert.equal(await page.getByRole('button',{name:'Approve ticket'}).count(),0);
  assert.match(await page.locator('.live-trace').textContent(),/working/);
  await emit(page,'claim',{id:'drop',text:'Unsupported claim',verified:false,reason:'No evidence'});assert.equal(await page.locator('.live-claims s').textContent(),'Unsupported claim');
  await finishLiveMock(page,run);await page.keyboard.press('ArrowRight');
  let sent;await page.route('http://localhost:8765/runs/**/approval',async route=>{sent={url:route.request().url(),body:route.request().postDataJSON()};await route.fulfill({json:{run:{...run,state:'TICKET_FILED'}}});});
  await page.getByRole('button',{name:'Approve ticket'}).click();await page.getByText('Service response: ticket filed.').waitFor();assert.match(sent.url,/browser-live-run\/approval$/);assert.equal(sent.body.briefing_hash,run.briefing_hash);
 });
 await check('offline replay retains the original identity and never sends an approval request',async page=>{
  await page.route('http://127.0.0.1:8765/**',route=>route.abort());let writes=0;await page.route('http://localhost:8765/**',route=>{writes++;return route.abort();});await load(page);await deck(page);
  await page.getByRole('textbox',{name:'2026 CVE to investigate'}).fill('CVE-2026-99999999');await page.getByRole('button',{name:'Run live with Granite'}).click();await page.locator('.live-complete').waitFor();assert.match(await page.locator('.live-message').textContent(),/No recording.*Replaying CVE-/);
  await page.keyboard.press('ArrowRight');await page.getByRole('button',{name:'Approve ticket'}).click();await page.getByText(/Simulated approval only/).waitFor();assert.equal(writes,0);
 });
 await check('cancel and stream errors cannot leave a stale approval behind',async page=>{
  await installLiveMock(page);await load(page);await deck(page);const cve=await page.getByRole('textbox',{name:'2026 CVE to investigate'}).inputValue();await startLiveMock(page,bundle.runs.find(run=>run.cve_id===cve));await page.getByRole('button',{name:'Stop',exact:true}).click();assert.equal(await page.evaluate(()=>window.__streams.at(-1).closed),true);
  await page.keyboard.press('ArrowRight');assert.equal(await page.getByRole('button',{name:'Approve ticket'}).count(),0);await page.keyboard.press('ArrowLeft');await startLiveMock(page,bundle.runs.find(run=>run.cve_id===cve));await emit(page,'error',{message:'CVE not present in the scoreboard.'});await page.getByText('CVE not present in the scoreboard.').waitFor();await page.keyboard.press('ArrowRight');assert.equal(await page.getByRole('button',{name:'Approve ticket'}).count(),0);
 });
 await check('closing the briefing drawer cancels its active EventSource',async page=>{
  await installLiveMock(page);await load(page);await page.getByRole('button',{name:'Inspect the briefing'}).click();const cve=await page.getByRole('textbox',{name:'2026 CVE to investigate'}).inputValue();await startLiveMock(page,bundle.runs.find(run=>run.cve_id===cve));await page.getByRole('button',{name:'Close briefing'}).click();assert.equal(await page.evaluate(()=>window.__streams.at(-1).closed),true);
 });
 await check('replay end state and scrubber stay accurate with reduced motion',async page=>{
  await load(page);const counts=await page.locator('.lane-heading>strong').allTextContents();assert.deepEqual(counts,bundle.replay_2025.methods.map(method=>`${method.hits}caught`));const range=page.getByRole('slider',{name:'Replay date'});await range.fill('0');assert.ok((await page.locator('.lane-heading>strong').allTextContents()).every(count=>count==='0caught'));await range.fill('1000');await page.getByRole('button',{name:'Inspect confirmed CVEs'}).click();await page.locator('.replay-accessible-list button').first().click();assert.match(await page.locator('.ember-tooltip').textContent(),/Published.*KEV inclusion/);
 });
 assert.deepEqual(errors,[]);console.log(JSON.stringify({passed,errors},null,2));
}finally{await browser.close();}
