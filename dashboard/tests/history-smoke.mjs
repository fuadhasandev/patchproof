// Owns temporary loopback servers and SQLite data; no model calls or public network.
import {chromium, expect} from '@playwright/test';
import {createServer} from 'node:http';
import {spawn} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {once} from 'node:events';
import {mkdtemp, readFile, mkdir, readdir} from 'node:fs/promises';
import {createWriteStream} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
const root=path.resolve('..');
const work=await mkdtemp(path.join(tmpdir(),'patchproof-history-'));
const token=randomBytes(32).toString('hex');
const env={...process.env,PATCHPROOF_API_TOKEN:token,PATCHPROOF_DB_PATH:path.join(work,'history.sqlite3'),PATCHPROOF_FIXTURE_ORIGIN:'http://127.0.0.1:8765',NEXT_TELEMETRY_DISABLED:'1'};
delete env.OPENROUTER_API_KEY;delete env.OPENROUTER_MODEL;
let fixed=false, requests=0, apiProcess, dashboard, browser;
const fixture=createServer((req,res)=>{requests++;res.setHeader('Content-Type','text/html');res.setHeader('Set-Cookie','session=HISTORY_SECRET_VALUE');if(fixed)res.setHeader('Content-Security-Policy',"default-src 'self'");res.end('<p>HISTORY_SECRET_BODY</p>');});
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
 await new Promise((resolve,reject)=>{fixture.once('error',reject);fixture.listen(8765,'127.0.0.1',resolve);});
 await startApi();
 dashboard=start(process.execPath,['node_modules/next/dist/bin/next','start','--hostname','localhost','--port','3000'],'dashboard',path.join(root,'dashboard'));
 await ready('http://localhost:3000');
 browser=await chromium.launch({channel:process.env.PATCHPROOF_BROWSER_CHANNEL||'chrome'});
 const page=await browser.newPage({viewport:{width:1440,height:1100}});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://localhost:3000');
 await expect(page.getByText('API connected',{exact:true})).toBeVisible();
 await page.getByLabel('Target URL').fill('http://127.0.0.1:8765');
 await page.getByRole('button',{name:'Run security scan'}).click();
 await expect(page.getByRole('heading',{name:'Missing Content-Security-Policy header'})).toBeVisible({timeout:20000});
 assert.equal(requests,1);
 // Abrupt API restart, keeping the same SQLite path and server credential.
 await stop(apiProcess,'SIGKILL');await startApi();
 assert.equal(requests,1);
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
 assert.equal(spec.schema_version,'1');assert.equal(spec.rule_id,'http.csp.present');
 fixed=true;
 await finding.getByRole('button',{name:'Recheck',exact:false}).click();
 await expect(finding.locator('.comparison').getByText('resolved',{exact:true})).toBeVisible({timeout:20000});
 await expect(finding.locator('.comparison').getByText('still present',{exact:true})).toBeVisible();
 await expect(finding.locator('.timeline').getByText('resolved',{exact:true})).toBeVisible();
 await mkdir('test-results',{recursive:true});
 await page.screenshot({path:'test-results/history-resolved.png',fullPage:true});
 await new Promise(resolve=>fixture.close(resolve));
 await finding.getByRole('button',{name:'Recheck',exact:false}).click();
 await expect(finding.locator('.comparison').getByText('unverified',{exact:true})).toBeVisible({timeout:20000});
 await expect(finding.locator('.timeline').getByText('unverified',{exact:true})).toBeVisible();
 await expect(finding.locator('.timeline').getByText('resolved',{exact:true})).toBeVisible();
 await page.screenshot({path:'test-results/history-unverified.png',fullPage:true});
 assert.equal(requests,2);
 assert.ok(!(await page.locator('body').innerText()).includes('HISTORY_SECRET'));
 assert.deepEqual(errors,[]);
 console.log('PASS: scan → API restart with same SQLite → history → spec download → resolved → fixture stopped → unverified timeline.');
 console.log('Temporary test database and server logs: '+work);
}finally{
 if(browser)await browser.close();
 if(fixture.listening)await new Promise(resolve=>fixture.close(resolve));
 await stop(dashboard);await stop(apiProcess);
 for (const file of await readdir(work)) {
  if (file.endsWith('.pem')) continue;
  const bytes=await readFile(path.join(work,file));
  assert.ok(!bytes.includes(Buffer.from(token)), 'Credential leaked to runtime file');
  assert.ok(!bytes.includes(Buffer.from('HISTORY_SECRET')), 'Sensitive fixture evidence leaked');
 }
}
