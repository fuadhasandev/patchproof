// Dashboard E2E only: never used by the Python scanner.
import { chromium, expect } from '@playwright/test';
import {createServer} from 'node:http';
import {readFile, mkdir} from 'node:fs/promises';
import assert from 'node:assert/strict';
let fixed=false, requests=0;
const fixture=createServer((req,res)=>{
  requests++;
  res.setHeader('Content-Type','text/html');
  res.setHeader('Set-Cookie','session=E2E_SECRET_VALUE');
  if(fixed)res.setHeader('Content-Security-Policy',"default-src 'self'");
  res.end('<h1>E2E_SECRET_BODY</h1>');
});
await new Promise((resolve,reject)=>{fixture.once('error',reject);fixture.listen(8765,'127.0.0.1',resolve);});
const browser=await chromium.launch({channel:process.env.PATCHPROOF_BROWSER_CHANNEL || 'chrome'});
const page=await browser.newPage({viewport:{width:1440,height:1100}});
const errors=[];page.on('pageerror',e=>errors.push(e.message));
try {
  await page.goto('http://localhost:3000');
  await expect(page.getByText('API connected',{exact:true})).toBeVisible();
  await page.getByLabel('Target URL').fill('http://127.0.0.1:8765');
  await page.getByRole('button',{name:'Run security scan'}).click();
  await expect(page.getByRole('heading',{name:'Missing Content-Security-Policy header'})).toBeVisible({timeout:20000});
  const finding=page.locator('article.finding');
  await expect(finding.getByText('still present',{exact:true})).toBeVisible();
  const downloadPromise=page.waitForEvent('download');
  await finding.getByRole('link',{name:'Download CheckSpec'}).click();
  const download=await downloadPromise;
  const spec=JSON.parse(await readFile(await download.path(),'utf8'));
  assert.equal(spec.rule_id,'http.csp.present');assert.equal(spec.schema_version,'1');
  assert.equal(new URL(spec.target_url).origin,'http://127.0.0.1:8765');
  assert.ok(!JSON.stringify(spec).includes('E2E_SECRET'));
  fixed=true;
  await finding.getByRole('button',{name:'Recheck',exact:false}).click();
  await expect(finding.getByText('resolved',{exact:true})).toBeVisible({timeout:20000});
  await expect(finding.getByText('still present',{exact:true})).toBeVisible();
  await mkdir('test-results',{recursive:true});
  await page.screenshot({path:'test-results/resolved.png',fullPage:true});
  await new Promise(resolve=>fixture.close(resolve));
  await finding.getByRole('button',{name:'Recheck',exact:false}).click();
  await expect(finding.getByText('unverified',{exact:true})).toBeVisible({timeout:20000});
  await page.screenshot({path:'test-results/unverified.png',fullPage:true});
  assert.equal(requests,2); // baseline + successful replay; stopped fixture cannot receive a third request
  assert.ok(!(await page.locator('body').innerText()).includes('E2E_SECRET'));
  assert.deepEqual(errors,[]);
  console.log('PASS: scan → finding → downloaded schema-1 spec → fixed same URL → resolved → stopped fixture → unverified.');
} finally {
  await browser.close();
  if(fixture.listening)await new Promise(resolve=>fixture.close(resolve));
}
