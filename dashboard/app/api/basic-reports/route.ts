import {hostedOriginAllowed} from '@/lib/hosted-boundary.mjs';
export const runtime = 'nodejs';
export const maxDuration = 20;
export async function POST(request:Request) {
 const origin=process.env.PATCHPROOF_PUBLIC_ORIGIN || '';
 if(!hostedOriginAllowed(request,origin)) return Response.json({detail:'Request origin rejected.'},{status:403});
 const endpoint=process.env.PATCHPROOF_BASIC_BACKEND_URL;
 const token=process.env.PATCHPROOF_BASIC_TOKEN;
 if(!endpoint || !token || token.length<32) return Response.json({detail:'Basic reports are not configured.'},{status:503});
 if(request.headers.get('content-type')?.split(';')[0]!=='application/json') return Response.json({detail:'JSON required.'},{status:415});
 const reader=request.body?.getReader();const chunks:Uint8Array[]=[];let size=0;
 if(reader)while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>4096){await reader.cancel();return Response.json({detail:'Request too large.'},{status:413});}chunks.push(value);}
 try{
  const response=await fetch(endpoint.replace(/\/$/,'')+'/v1/basic-reports',{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:Buffer.concat(chunks),cache:'no-store',redirect:'error',signal:AbortSignal.timeout(12000)});
  const headers=new Headers({'Content-Type':'application/json','Cache-Control':'no-store'});
  if(response.headers.has('retry-after'))headers.set('Retry-After',response.headers.get('retry-after')!);
  return new Response(await response.text(),{status:response.status,headers});
 }catch{return Response.json({detail:'Basic report service unavailable.'},{status:503});}
}
