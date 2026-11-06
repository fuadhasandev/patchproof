import {test} from 'node:test';
import assert from 'node:assert/strict';
import {allowedRequest,allowedPath,validId} from '../lib/boundary.mjs';
function request(headers={},method='POST'){return new Request('http://localhost:3000/api/scans',{method,headers:{host:'localhost:3000',origin:'http://localhost:3000',...headers}});}
test('reject cross-origin, missing origin, unexpected host and cross-site requests',()=>{
 assert.ok(allowedRequest(request()));
 for(const headers of [{origin:'https://evil.example'},{origin:''},{host:'evil.example:3000'},{'sec-fetch-site':'cross-site'}]) assert.equal(allowedRequest(request(headers)),false);
 assert.ok(allowedRequest(request({origin:''},'GET')));
});
test('only explicit API paths and opaque IDs can reach backend',()=>{
 assert.ok(allowedPath('/v1/scans','POST'));
 assert.ok(validId('a'.repeat(32)));
 assert.ok(allowedPath('/v1/findings/'+'a'.repeat(32)+'/spec','GET'));
 for(const path of ['https://evil.example','/v1/admin','/v1/scans/../secrets','/v1/jobs/../../secret']) assert.equal(allowedPath(path,'POST'),false);
 assert.equal(validId('../secret'),false);
});
