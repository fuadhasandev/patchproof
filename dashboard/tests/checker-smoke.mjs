// Uses the existing controlled demo script, isolated marker directory, and real local API.
import {chromium,expect} from '@playwright/test';
import {spawn} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {createServer} from 'node:net';
import {once} from 'node:events';
import {mkdtemp,writeFile,mkdir} from 'node:fs/promises';
import {createWriteStream} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
const root=path.resolve('..'),work=await mkdtemp(path.join(tmpdir(),'patchproof-checker-'));
const env={...process.env,PATCHPROOF_MODE:'local',PATCHPROOF_API_TOKEN:randomBytes(32).toString('hex'),PATCHPROOF_DB_PATH:path.join(work,'history.sqlite3'),PATCHPROOF_FIXTURE_ORIGIN:'http://127.0.0.1:8765',NEXT_TELEMETRY_DISABLED:'1'};
delete env.OPENROUTER_API_KEY;delete env.OPENROUTER_MODEL;
const children=[];let browser,fixture;
const ipv6=process.env.PATCHPROOF_SMOKE_IPV6==='1';
const dashboardHost=ipv6?'::1':'127.0.0.1';
const dashboardOrigin=ipv6?'http://[::1]:3000':'http://127.0.0.1:3000';
function start(command,args,name,cwd=root){const child=spawn(command,args,{cwd,env,stdio:['ignore','pipe','pipe']});const log=createWriteStream(path.join(work,name+'.log'));child.stdout.pipe(log);child.stderr.pipe(log);children.push(child);return child;}
async function ready(url,headers={}){for(let i=0;i<150;i++){try{if((await fetch(url,{headers,signal:AbortSignal.timeout(1000)})).ok)return;}catch{}await new Promise(r=>setTimeout(r,200));}throw Error('Server unavailable; logs: '+work);}
async function stop(child){if(child&&child.exitCode===null&&child.signalCode===null){const ended=once(child,'exit');child.kill('SIGTERM');await ended;}}
try{
 for(const port of [8765,8000,3000]){const probe=createServer();await new Promise((resolve,reject)=>{probe.once('error',reject);probe.listen(port,port===3000?dashboardHost:'127.0.0.1',resolve);});await new Promise(resolve=>probe.close(resolve));}
 fixture=start(path.join(root,'.venv/bin/python'),[path.join(root,'examples/local_server.py')],'fixture',work);await ready('http://127.0.0.1:8765');
 start(path.join(root,'.venv/bin/python'),['-m','uvicorn','patchproof.api:create_app','--factory','--host','127.0.0.1','--port','8000','--no-access-log'],'api');await ready('http://127.0.0.1:8000/v1/capabilities',{Authorization:'Bearer '+env.PATCHPROOF_API_TOKEN});
 const dashboard=start(process.execPath,['node_modules/next/dist/bin/next','start','--hostname',dashboardHost,'--port','3000'],'dashboard',path.join(root,'dashboard'));await ready(dashboardOrigin);
 browser=await chromium.launch({channel:process.env.PATCHPROOF_BROWSER_CHANNEL||'chrome',args:[ipv6?'--host-resolver-rules=MAP localhost [::1]':'--host-resolver-rules=MAP localhost 127.0.0.1']});
 const page=await browser.newPage({viewport:{width:1440,height:1000}});const errors=[],submissions=[];
 page.on('pageerror',e=>errors.push(e.message));page.on('request',r=>{if(r.url().endsWith('/api/scans')&&r.method()==='POST')submissions.push(r.postDataJSON());});
 await page.goto('http://localhost:3000');
 await expect(page.locator('input:visible')).toHaveCount(1);
 await page.getByRole('button',{name:'Try sample report'}).click();
 await expect(page.getByRole('heading',{name:'Website security configuration report'})).toBeVisible();
 const report=page.getByRole('region',{name:'Website security configuration report'});
 const card=title=>report.locator('article').filter({has:page.getByRole('heading',{name:title,exact:true})});
 await expect(card('Content Security Policy (CSP)').getByText('Needs attention',{exact:true})).toBeVisible();
 await expect(card('HTTP Strict Transport Security (HSTS)').getByText('Passed',{exact:true})).toBeVisible();
 await expect(card('Secure flag on named session cookies').getByText('Could not verify',{exact:true})).toBeVisible();
 await page.getByRole('button',{name:'Check again',exact:true}).click();
 await expect(page.getByRole('heading',{name:'What changed'})).toBeVisible();assert.equal(submissions.length,0);
 await page.setViewportSize({width:390,height:844});
 assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
 await mkdir('test-results',{recursive:true});await page.screenshot({path:'test-results/checker-sample-mobile.png',fullPage:true});
 await page.setViewportSize({width:1440,height:1000});
 await page.getByLabel('Website URL').fill('http://127.0.0.1:8765');await page.getByRole('button',{name:'Check website',exact:true}).click();
 await expect(page.getByText('Sample report · preloaded example',{exact:true})).toHaveCount(0);
 await expect(card('Content Security Policy (CSP)').getByText('Needs attention',{exact:true})).toBeVisible({timeout:20000});
 await writeFile(path.join(work,'.demo-csp'),'');
 // Editing the field must not change the target of Check again.
 await page.getByLabel('Website URL').fill('https://unused.example/');
 await page.getByRole('button',{name:'Check again',exact:true}).click();
 await expect(card('Content Security Policy (CSP)').getByText('Passed',{exact:true})).toBeVisible({timeout:20000});
 await expect(page.locator('.changes')).toContainText('Needs attention → Passed');
 await page.screenshot({path:'test-results/checker-fixed.png',fullPage:true});
 await stop(fixture);
 await page.getByRole('button',{name:'Check again',exact:true}).click();
 await expect(card('Content Security Policy (CSP)').getByText('Could not verify',{exact:true})).toBeVisible({timeout:20000});
 await expect(page.locator('.changes')).toContainText('Passed → Could not verify');
 await page.screenshot({path:'test-results/checker-unavailable.png',fullPage:true});
 assert.equal(submissions.length,3);assert.deepEqual(submissions[0],submissions[1]);assert.deepEqual(submissions[1],submissions[2]);
 await page.getByRole('link',{name:'Advanced',exact:true}).click();
 await page.getByRole('button',{name:'Scan History',exact:true}).click();
 await expect(page.getByRole('button',{name:'Open report'})).toHaveCount(3);
 await page.getByRole('button',{name:'Open report'}).first().click();
 await expect(page.locator('.report-meta').getByText('http://127.0.0.1:8765',{exact:true})).toBeVisible();
 // Hosted UI contract test: mocked API responses, no external DNS or website traffic.
 await stop(dashboard);env.PATCHPROOF_MODE='hosted';
 start(process.execPath,['node_modules/next/dist/bin/next','start','--hostname',dashboardHost,'--port','3000'],'hosted-dashboard',path.join(root,'dashboard'));await ready(dashboardOrigin);
 const project='a'.repeat(32),target='b'.repeat(32);let verified=false,allowVerify=false,hostedScans=0;
 await page.route('**/api/hosted/**',async route=>{
  const req=route.request(),pathname=new URL(req.url()).pathname.replace('/api/hosted/','');
  const reply=(body,status=200)=>route.fulfill({status,json:body});
  if(pathname==='projects')return reply({items:[{id:project,name:'Existing'}],next_cursor:null});
  if(pathname===`projects/${project}/targets`&&req.method()==='GET')return reply({items:verified?[{id:target,hostname:'fixture.example',verified_until:Date.now()/1000+3600,revoked:false}]:[],next_cursor:null});
  if(pathname===`projects/${project}/targets`)return reply({id:target,record:'_patchproof.fixture.example',value:'controlled-test-token',expires_at:Date.now()/1000+3600});
  if(pathname===`targets/${target}/verify`){if(!allowVerify)return reply({detail:'DNS TXT record does not match.'},422);verified=true;return reply({id:target});}
  if(pathname==='scans'){assert.ok(verified,'Scan submitted before successful verification');hostedScans++;const body=req.postDataJSON();assert.equal(body.target_id,target);assert.equal(body.project_id,project);assert.equal(body.ai,false);assert.equal(body.browser,false);return reply({id:'c'.repeat(32)});}
  if(pathname.startsWith('jobs/'))return reply({id:'c'.repeat(32),state:'completed',target_url:'https://fixture.example/',created_at:Date.now()/1000,report:{baseline:{checks:[]}},findings:[]});
  throw Error('Unexpected hosted request: '+pathname);
 });
 await page.goto('http://localhost:3000');await page.getByRole('button',{name:'Try sample report'}).click();assert.equal(hostedScans,0);
 await page.getByLabel('Website URL').fill('https://fixture.example/');await page.getByRole('button',{name:'Check website',exact:true}).click();
 await expect(page.getByRole('heading',{name:'Verify your domain before checking'})).toBeVisible();assert.equal(hostedScans,0);
 await page.getByRole('button',{name:'Verify domain and check website'}).click();await expect(page.locator('.notice[role=alert]')).toContainText('Could not verify');assert.equal(hostedScans,0);
 allowVerify=true;await page.getByRole('button',{name:'Verify domain and check website'}).click();await expect(page.locator('.report-url')).toHaveText('https://fixture.example/');assert.equal(hostedScans,1);
 // A malformed/incomplete report must never turn into a pass.
 await expect(page.locator('article .badge').filter({hasText:'Could not verify'})).toHaveCount(3);
 await page.getByRole('button',{name:'Check again',exact:true}).click();await expect(page.getByRole('heading',{name:'What changed'})).toBeVisible();assert.equal(hostedScans,2);
 await page.getByRole('button',{name:'Check website',exact:true}).click();await expect(page.getByRole('button',{name:'Check website',exact:true})).toBeEnabled();assert.equal(hostedScans,3);
 assert.deepEqual(errors,[]);
 console.log('PASS: hosted UI requires successful DNS verification, reuses verified domains, and keeps missing results unverified (mock API).');
 console.log('PASS: preloaded sample without scan requests; mobile layout; controlled demo check → fixed → same-input recheck → unavailable/Could not verify; Advanced. Logs: '+work);
}finally{if(browser)await browser.close();for(const child of children.reverse())await stop(child);}
