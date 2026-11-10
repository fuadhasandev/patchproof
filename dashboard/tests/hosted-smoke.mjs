// Normal dashboard root/proxy/API paths, with a test-only identity gateway and
// controlled DNS/target fixtures. No live identity provider or OpenRouter key.
import {chromium,expect} from '@playwright/test';
import {spawn,execFileSync} from 'node:child_process';
import {createServer,request as httpRequest} from 'node:http';
import {mkdtemp,readFile,readdir,cp} from 'node:fs/promises';
import {createWriteStream} from 'node:fs';
import {tmpdir} from 'node:os';
import {once} from 'node:events';
import path from 'node:path';
import assert from 'node:assert/strict';
if(!process.env.PATCHPROOF_TEST_DATABASE_URL)throw Error('Isolated PostgreSQL test database required');
const root=path.resolve('..'),python=path.join(root,'.venv/bin/python'),fixture=path.join(root,'tests/hosted/e2e_fixture.py');
const work=await mkdtemp(path.join(tmpdir(),'patchproof-hosted-ui-'));
const env={...process.env,PATCHPROOF_MODE:'hosted',PATCHPROOF_PUBLIC_ORIGIN:'http://localhost:3100',PATCHPROOF_BACKEND_URL:'http://127.0.0.1:8000',NEXT_TELEMETRY_DISABLED:'1'};
delete env.OPENROUTER_API_KEY;delete env.OPENROUTER_MODEL;
execFileSync(python,[fixture,'init'],{cwd:root,env,stdio:'inherit'});
let children=[],browser,gateway,token,api;
function start(cmd,args,name,cwd=root,childEnv=env){const p=spawn(cmd,args,{cwd,env:childEnv,stdio:['ignore','pipe','pipe']});const log=createWriteStream(path.join(work,name+'.log'),{flags:'a'});p.stdout.pipe(log);p.stderr.pipe(log);children.push(p);return p;}
async function stop(p){if(p&&p.exitCode===null&&p.signalCode===null){const ended=once(p,'exit');p.kill('SIGTERM');await ended;}}
async function ready(url){for(let i=0;i<150;i++){try{if((await fetch(url,{signal:AbortSignal.timeout(1000)})).ok)return;}catch{}await new Promise(r=>setTimeout(r,200));}throw Error('Readiness timed out: '+url+'; logs '+work);}
async function control(data){await fetch('http://127.0.0.1:8776/state',{method:'POST',body:JSON.stringify(data)});}
try{
 start(python,[fixture,'control'],'control');await ready('http://127.0.0.1:8776/state');
 token=(await(await fetch('http://127.0.0.1:8776/token')).json()).token;
 api=start(python,[fixture,'api'],'api');
 start(python,[fixture,'worker'],'worker');await ready('http://127.0.0.1:8000/health/ready');
 if(process.env.PATCHPROOF_TEST_STANDALONE==='1'){
  const directory=path.join(work,'standalone');
  await cp('.next/standalone',directory,{recursive:true});
  await cp('.next/static',path.join(directory,'.next/static'),{recursive:true});
  start(process.execPath,['server.js'],'dashboard',directory,{...env,HOSTNAME:'127.0.0.1',PORT:'3101'});
 }else start(process.execPath,['node_modules/next/dist/bin/next','start','--hostname','127.0.0.1','--port','3101'],'dashboard',path.join(root,'dashboard'));
 await ready('http://127.0.0.1:3101');
 gateway=createServer((req,res)=>{
  const upstream=httpRequest({hostname:'127.0.0.1',port:3101,path:req.url,method:req.method,headers:{...req.headers,'x-forwarded-access-token':token}},reply=>{res.writeHead(reply.statusCode,reply.headers);reply.pipe(res);});
  upstream.on('error',()=>{res.writeHead(502);res.end();});req.pipe(upstream);
 });
 await new Promise((resolve,reject)=>{gateway.once('error',reject);gateway.listen(3100,'localhost',resolve);});
 browser=await chromium.launch({channel:process.env.PATCHPROOF_BROWSER_CHANNEL||'chrome'});
 const page=await browser.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('http://localhost:3100');
 await expect(page.getByRole('link',{name:'Sign out'})).toBeVisible();
 await page.getByLabel('Project name',{exact:true}).fill('Production fixture');await page.getByRole('button',{name:'Create project',exact:true}).click();
 await page.getByLabel('Hostname',{exact:true}).fill('fixture.example');await page.getByRole('button',{name:'Create DNS challenge'}).click();
 await expect(page.getByText('TXT value:',{exact:false})).toBeVisible();
 const txt=await page.locator('code').nth(1).innerText();await control({txt:[txt]});
 await page.getByRole('button',{name:'Verify DNS',exact:true}).click();await expect(page.getByText('fixture.example · verified',{exact:false})).toBeVisible();
 await page.getByLabel('Target URL',{exact:true}).fill('https://fixture.example/');await page.getByRole('button',{name:'Run security scan'}).click();
 await expect(page.getByRole('heading',{name:'Missing Content-Security-Policy header'})).toBeVisible({timeout:20000});
 await page.getByText('Observed evidence',{exact:true}).click();await expect(page.getByText('csp_present',{exact:false})).toBeVisible();
 const downloadPromise=page.waitForEvent('download');await page.getByRole('link',{name:'Download CheckSpec'}).click();
 const download=await downloadPromise;const spec=JSON.parse(await readFile(await download.path(),'utf8'));assert.equal(spec.schema_version,'1');
 await stop(api);api=start(python,[fixture,'api'],'api');await ready('http://127.0.0.1:8000/health/ready');
 await page.reload();await page.getByLabel('Project',{exact:true}).selectOption({label:'Production fixture'});await page.getByRole('button',{name:'Open report',exact:true}).click();
 await control({fixed:true});await page.getByRole('button',{name:'Recheck',exact:true}).click();
 await expect(page.locator('article.finding strong')).toHaveText('resolved',{timeout:20000});
 await control({offline:true});await page.getByRole('button',{name:'Recheck',exact:true}).click();
 await expect(page.locator('article.finding strong')).toHaveText('unverified',{timeout:20000});
 assert.ok(!(await page.locator('body').innerText()).includes('HOSTED_SECRET'));assert.deepEqual(errors,[]);
 console.log('PASS hosted dashboard: project → DNS challenge → JWT authenticated scan → evidence → export → API restart → history → fix/recheck → unavailable/unverified');
}finally{
 if(browser)await browser.close();if(gateway)await new Promise(r=>gateway.close(r));for(const child of children.reverse())await stop(child);
 for(const file of await readdir(work,{withFileTypes:true})){if(!file.isFile())continue;const bytes=await readFile(path.join(work,file.name));assert.ok(!bytes.includes(Buffer.from('HOSTED_SECRET')));if(token)assert.ok(!bytes.includes(Buffer.from(token)));}
 console.log('Fixture logs checked for secret evidence and tokens.');
}
