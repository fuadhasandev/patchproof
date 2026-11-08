// Build with fake secrets and ensure no credential reaches browser assets.
import {spawnSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {readdir, readFile} from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
const token=randomBytes(32).toString('hex');
const key='sk-release-'+randomBytes(24).toString('hex');
const result=spawnSync('npm',['run','build'],{
 env:{...process.env,NEXT_TELEMETRY_DISABLED:'1',PATCHPROOF_API_TOKEN:token,OPENROUTER_API_KEY:key},
 stdio:'inherit',
});
assert.equal(result.status,0,'Production build failed');
let count=0;
async function inspect(directory){
 for(const item of await readdir(directory,{withFileTypes:true})){
  const file=path.join(directory,item.name);
  if(item.isDirectory()) await inspect(file);
  else {
   const bytes=await readFile(file);count++;
   for(const secret of [token,key,'HISTORY_SECRET_VALUE','BROWSER_SECRET_VALUE','BROWSER_SECRET_BODY'])
    assert.ok(!bytes.includes(Buffer.from(secret)),'Sensitive data in browser asset');
  }
 }
}
await inspect('.next/static');
await inspect('.next/server/app');
assert.ok(count>0);
console.log(`PASS: ${count} built frontend assets exclude fake credentials and fixture evidence`);
