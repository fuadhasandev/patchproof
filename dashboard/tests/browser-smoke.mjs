// Owns temporary loopback servers and SQLite data; no model calls or public network.
import {chromium, expect} from '@playwright/test';
import {createServer} from 'node:https';
import {createServer as tcpServer} from 'node:net';
import {spawn, execFileSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {once} from 'node:events';
import {mkdtemp, readFile, mkdir} from 'node:fs/promises';
import {createWriteStream} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
const root=path.resolve('..');
const work=await mkdtemp(path.join(tmpdir(),'patchproof-browser-smoke-'));
execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',path.join(work,'key.pem'),'-out',path.join(work,'cert.pem'),'-days','2','-subj','/CN=127.0.0.1','-addext','subjectAltName=IP:127.0.0.1,DNS:localhost'],{stdio:'ignore'});
const token=randomBytes(32).toString('hex');
const env={...process.env,PATCHPROOF_API_TOKEN:token,PATCHPROOF_DB_PATH:path.join(work,'history.sqlite3'),PATCHPROOF_FIXTURE_ORIGIN:'https://127.0.0.1:8765',SSL_CERT_FILE:path.join(work,'cert.pem'),PATCHPROOF_BROWSER_CA_FILE:path.join(work,'cert.pem'),NEXT_TELEMETRY_DISABLED:'1'};
delete env.OPENROUTER_API_KEY;delete env.OPENROUTER_MODEL;
const ipv6=process.env.PATCHPROOF_SMOKE_IPV6==='1';
const dashboardHost=ipv6?'::1':'localhost';
let fixed=false, requests=0, apiProcess, dashboard, browser;
const fixture=createServer({key:await readFile(path.join(work,'key.pem')),cert:await readFile(path.join(work,'cert.pem'))},(req,res)=>{requests++;res.setHeader('Content-Type','text/html');res.setHeader('Set-Cookie','session=BROWSER_SECRET_VALUE');res.setHeader('Content-Security-Policy',"default-src * 'unsafe-inline'");res.setHeader('Strict-Transport-Security','max-age=1');res.end(fixed?'<p>Fixed</p>':'<img src="http://outside.invalid/BROWSER_SECRET_PATH?token=BROWSER_SECRET_QUERY"><p>BROWSER_SECRET_BODY</p>');});
function start(command,args,name,cwd=root){
 const process=spawn(command,args,{cwd,env,stdio:['ignore','pipe','pipe']});
 const log=createWriteStream(path.join(work,name+'.log'),{flags:'a'});
 process.stdout.pipe(log);process.stderr.pipe(log);
 return process;
}
async function ready(url,headers={}){
 for(let i=0;i<150;i++){
  try{if((await fetch(url,{headers,signal:AbortSignal.timeout(1000)})).ok)return;}catch{}
  await new Promise(resolve=>setTimeout(resolve,200));
 }
 throw new Error('Local test server did not become ready. Logs: '+work);
}
async function startApi(){
 apiProcess=start(path.join(root,'.venv/bin/python'),['-m','uvicorn','patchproof.api:create_app','--factory','--host','127.0.0.1','--port','8000','--no-access-log'],'api');
 await ready('http://127.0.0.1:8000/v1/capabilities',{Authorization:'Bearer '+token});
}
async function stop(process,signal='SIGTERM'){
 if(process && process.exitCode===null && process.signalCode===null){const exit=once(process,'exit');process.kill(signal);await exit;}
}
try{
 const probe=tcpServer();await new Promise((resolve,reject)=>{probe.once('error',reject);probe.listen(3000,dashboardHost,resolve);});await new Promise(resolve=>probe.close(resolve));
 await new Promise((resolve,reject)=>{fixture.once('error',reject);fixture.listen(8765,'127.0.0.1',resolve);});
 await startApi();
 dashboard=start(process.execPath,['node_modules/next/dist/bin/next','start','--hostname',dashboardHost,'--port','3000'],'dashboard',path.join(root,'dashboard'));
 await ready(ipv6?'http://[::1]:3000':'http://localhost:3000');
 browser=await chromium.launch({channel:process.env.PATCHPROOF_BROWSER_CHANNEL||'chrome',args:ipv6?['--host-resolver-rules=MAP localhost [::1]']:[]});
 const page=await browser.newPage({viewport:{width:1440,height:1100}});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://localhost:3000');
 await expect(page.getByText('API connected',{exact:true})).toBeVisible();
 await page.getByLabel('Target URL').fill('https://127.0.0.1:8765')
 await page.getByLabel('Browser check').check();
 await page.getByRole('button',{name:'Run security scan'}).click();
 await expect(page.getByRole('heading',{name:'HTTP resource reference on an HTTPS page'})).toBeVisible({timeout:40000});
 assert.equal(requests,2);
 // Abrupt API restart, keeping the same SQLite path and server credential.
 await stop(apiProcess,'SIGKILL');await startApi();
 assert.equal(requests,2);
 await page.reload();
 await page.getByRole('button',{name:'Scan History',exact:true}).click();
 await expect(page.getByRole('button',{name:'Open report'})).toBeVisible();
 await page.getByRole('button',{name:'Open report'}).click();
 const finding=page.locator('article.finding');
 await expect(finding.locator('.comparison').getByText('still present',{exact:true})).toBeVisible();
 const downloading=page.waitForEvent('download');
 await finding.getByRole('link',{name:'Download CheckSpec'}).click();
 const downloaded=await downloading;
 const spec=JSON.parse(await readFile(await downloaded.path(),'utf8'));
 assert.equal(spec.schema_version,'3');assert.equal(spec.rule_id,'browser.mixed-content.references');assert.equal(spec.parameters.profile,'chromium-static-v1');
 assert.ok(!JSON.stringify(spec).includes('BROWSER_SECRET'));
 await expect(finding.getByText('insecure references',{exact:true})).toBeVisible();
 fixed=true;
 await finding.getByRole('button',{name:'Recheck',exact:false}).click();
 await expect(finding.locator('.comparison').getByText('resolved',{exact:true})).toBeVisible({timeout:40000});
 await expect(finding.locator('.comparison').getByText('still present',{exact:true})).toBeVisible();
 await expect(finding.locator('.timeline').getByText('resolved',{exact:true})).toBeVisible();
 await mkdir('test-results',{recursive:true});
 await page.screenshot({path:'test-results/browser-resolved.png',fullPage:true});
 await new Promise(resolve=>fixture.close(resolve));
 await finding.getByRole('button',{name:'Recheck',exact:false}).click();
 await expect(finding.locator('.comparison').getByText('unverified',{exact:true})).toBeVisible({timeout:40000});
 await expect(finding.locator('.timeline').getByText('unverified',{exact:true})).toBeVisible();
 await expect(finding.locator('.timeline').getByText('resolved',{exact:true})).toBeVisible();
 await page.screenshot({path:'test-results/browser-unverified.png',fullPage:true});
 assert.equal(requests,3);
 assert.ok(!(await page.locator('body').innerText()).includes('BROWSER_SECRET'));
 assert.deepEqual(errors,[]);
 console.log('PASS: isolated HTTPS browser scan → restart/history → inspect evidence → schema-3 export → fix → resolved → fixture stopped → unverified; original finding preserved.');
 console.log('Temporary test database and server logs: '+work);
}finally{
 if(browser)await browser.close();
 if(fixture.listening)await new Promise(resolve=>fixture.close(resolve));
 await stop(dashboard);await stop(apiProcess);
}
