import 'server-only';
import { allowedRequest, allowedPath } from './boundary.mjs';
export async function backend(request: Request, path: string) {
  if (!allowedRequest(request) || !allowedPath(path, request.method))
    return Response.json({detail: 'Request blocked by local dashboard policy.'}, {status: 403});
  const token = process.env.PATCHPROOF_API_TOKEN;
  if (!token || token.length < 32)
    return Response.json({detail: 'Dashboard server credential is not configured.'}, {status: 503});
  let body: string | undefined;
  if (request.method === 'POST') {
    if (request.headers.get('content-type')?.split(';')[0] !== 'application/json')
      return Response.json({detail: 'JSON request required.'}, {status: 415});
    const reader = request.body?.getReader();
    const chunks: Uint8Array[] = []; let size = 0;
    if (reader) { while (true) {
      const {done, value} = await reader.read(); if (done) break;
      size += value.length;
      if (size > 8192) { await reader.cancel(); return Response.json({detail: 'Request too large.'}, {status: 413}); }
      chunks.push(value);
    }}
    body = Buffer.concat(chunks).toString('utf8');
  }
  try {
    const response = await fetch('http://127.0.0.1:8000' + path, {
      method: request.method, body, cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(10000),
      headers: {'Authorization': `Bearer ${token}`, 'Origin': 'http://localhost:3000', 'Content-Type': 'application/json'},
    });
    const headers = new Headers({'Content-Type': 'application/json', 'Cache-Control': 'no-store'});
    if (response.headers.has('content-disposition')) headers.set('Content-Disposition', 'attachment; filename="patchproof-check.json"');
    return new Response(await response.text(), {status: response.status, headers});
  } catch {
    return Response.json({detail: 'Local API unavailable. Start the backend on 127.0.0.1:8000.'}, {status: 503});
  }
}
