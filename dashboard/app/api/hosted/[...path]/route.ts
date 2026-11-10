import {allowedHostedPath,hostedOriginAllowed} from '@/lib/hosted-boundary.mjs';
import {historyQuery} from '@/lib/boundary.mjs';
async function proxy(request:Request, context:{params:Promise<{path:string[]}>}) {
 if(process.env.PATCHPROOF_MODE!=='hosted') return Response.json({detail:'Hosted mode is disabled.'},{status:404});
 const origin=process.env.PATCHPROOF_PUBLIC_ORIGIN || '';
 if(!hostedOriginAllowed(request,origin)) return Response.json({detail:'Request origin rejected.'},{status:403});
 const path=(await context.params).path.join('/');
 if(!allowedHostedPath(path,request.method)) return Response.json({detail:'Unknown operation.'},{status:404});
 const incoming=new URL(request.url), query=incoming.search;
 const pagination=/^(projects|projects\/[a-f0-9]{32}\/(scans|targets)|findings\/[a-f0-9]{32}\/rechecks)$/.test(path);
 if(query && (request.method!=='GET'||!pagination||historyQuery(query)===null)) return Response.json({detail:'Invalid pagination.'},{status:422});
 // OAuth2 Proxy replaces this header after validating its secure OIDC session.
 // API independently validates the JWT; spoofed headers never establish identity.
 const token=request.headers.get('x-forwarded-access-token');
 if(!token || token.length>16384) return Response.json({detail:'Sign in required.'},{status:401});
 let body:Uint8Array|undefined;
 if(request.method==='POST'){
  if(request.headers.get('content-type')?.split(';')[0]!=='application/json')return Response.json({detail:'JSON required.'},{status:415});
  const reader=request.body?.getReader();const chunks:Uint8Array[]=[];let size=0;
  if(reader)while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>8192){await reader.cancel();return Response.json({detail:'Request too large.'},{status:413});}chunks.push(value);}
  body=Buffer.concat(chunks);
 }
 const endpoint=process.env.PATCHPROOF_BACKEND_URL;
 if(!endpoint)return Response.json({detail:'Backend not configured.'},{status:503});
 try{
  const headers:Record<string,string>={'Authorization':'Bearer '+token,'Origin':origin,'Content-Type':'application/json'};
  const key=request.headers.get('idempotency-key');if(key && key.length<=128)headers['Idempotency-Key']=key;
  const result=await fetch(endpoint+'/v2/'+path+query,{method:request.method,headers,body:body as BodyInit|undefined,cache:'no-store',redirect:'error',signal:AbortSignal.timeout(15000)});
  const output=new Headers({'Content-Type':'application/json','Cache-Control':'no-store'});
  if(result.headers.has('content-disposition'))output.set('Content-Disposition','attachment; filename="patchproof-check.json"');
  if(result.headers.has('x-request-id'))output.set('X-Request-ID',result.headers.get('x-request-id')!);
  return new Response(await result.text(),{status:result.status,headers:output});
 }catch{return Response.json({detail:'Backend unavailable; retry with the same submission.'},{status:503});}
}
export const GET=proxy;
export const POST=proxy;
