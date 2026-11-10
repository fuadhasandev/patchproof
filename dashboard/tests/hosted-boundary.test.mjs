import {test} from 'node:test';
import assert from 'node:assert/strict';
import {allowedHostedPath,hostedOriginAllowed} from '../lib/hosted-boundary.mjs';
test('hosted proxy exposes only explicit user-scoped paths',()=>{
 const id='a'.repeat(32);
 assert.ok(allowedHostedPath(`projects/${id}/scans`,'GET'));
 assert.ok(allowedHostedPath(`jobs/${id}/cancel`,'POST'));
 for(const path of ['../health/ready','https://outside.invalid','jobs/../../metrics',`jobs/${id}/retry`])assert.equal(allowedHostedPath(path,'POST'),false);
});
test('hosted cookie session boundary rejects cross-origin writes',()=>{
 const origin='https://patchproof.example';
 const req=(headers)=>new Request(origin+'/api/hosted/scans',{method:'POST',headers});
 assert.ok(hostedOriginAllowed(req({host:'patchproof.example',origin}),origin));
 assert.equal(hostedOriginAllowed(req({host:'patchproof.example'}),origin),false);
 assert.equal(hostedOriginAllowed(req({host:'patchproof.example',origin:'https://evil.invalid'}),origin),false);
});
