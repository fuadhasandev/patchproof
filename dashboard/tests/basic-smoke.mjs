import {chromium,expect} from '@playwright/test';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {randomBytes} from 'node:crypto';
import assert from 'node:assert/strict';
import path from 'node:path';
const root=path.resolve('..');
const env={...process.env,PATCHPROOF_BASIC_TOKEN:randomBytes(32).toString('hex'),PATCHPROOF_BASIC_BACKEND_URL:'http://127.0.0.1:8017',PATCHPROOF_PUBLIC_ORIGIN:'http://localhost:3017',PATCHPROOF_MODE:'local'};
const children=[];let browser;
function start(cmd,args,cwd=root){const p=spawn(cmd,args,{cwd,env,stdio:'inherit'});children.push(p);}
async function ready(url){for(let i=0;i<100;i++){try{if((await fetch(url)).ok)return;}catch{}await new Promise(r=>setTimeout(r,200));}throw Error('Not ready: '+url);}
try{
 start(path.join(root,'.venv/bin/python'),['tests/basic_e2e_fixture.py']);await ready('http://127.0.0.1:8017/health');
 start(process.execPath,['node_modules/next/dist/bin/next','start','--hostname','127.0.0.1','--port','3017'],path.join(root,'dashboard'));await ready(env.PATCHPROOF_PUBLIC_ORIGIN);
 browser=await chromium.launch({channel:'chrome',args:['--host-resolver-rules=MAP localhost 127.0.0.1']});
 const page=await browser.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto(env.PATCHPROOF_PUBLIC_ORIGIN);
 async function check(url){await page.getByLabel('Website URL').fill(url);await page.getByRole('button',{name:'Check website',exact:true}).click();await expect(page.locator('.report-url')).toHaveText(url);}
 const csp=page.locator('article').filter({has:page.getByRole('heading',{name:'Content Security Policy (CSP)',exact:true})});
 await check('http://fixture.example/');await expect(csp.getByText('Needs attention',{exact:true})).toBeVisible();
 await check('http://fixture.example/fixed');await expect(csp.getByText('Passed',{exact:true})).toBeVisible();
 await page.getByRole('button',{name:'Check again',exact:true}).click();await expect(page.getByRole('heading',{name:'What changed'})).toBeVisible();
 await check('http://127.0.0.1/');await expect(csp.getByText('Could not verify',{exact:true})).toBeVisible();
 const blocked=await page.request.post(env.PATCHPROOF_PUBLIC_ORIGIN+'/api/basic-reports',{headers:{Origin:'https://evil.invalid'},data:{target_url:'http://fixture.example/'}});assert.equal(blocked.status(),403);
 assert.equal((await fetch('http://127.0.0.1:8017/v1/basic-reports',{method:'POST'})).status,401);
 assert.deepEqual(errors,[]);
 console.log('PASS basic homepage → Next.js → FastAPI → fixture; CSP missing/present, check again, loopback block, origin/auth boundaries');
}finally{
 if(browser)await browser.close();
 for(const child of children.reverse()){if(child.exitCode===null&&child.signalCode===null){const ended=once(child,'exit');child.kill('SIGTERM');await ended;}}
}
