export function allowedRequest(request) {
  if (request.headers.get('host') !== 'localhost:3000') return false;
  const origin = request.headers.get('origin');
  const site = request.headers.get('sec-fetch-site');
  if (site && !['same-origin', 'none'].includes(site)) return false;
  if (origin && origin !== 'http://localhost:3000') return false;
  if (!['GET', 'HEAD'].includes(request.method) && origin !== 'http://localhost:3000') return false;
  return true;
}
export function validId(id) { return /^[a-f0-9]{32}$/.test(id); }
export function allowedPath(path, method) {
  return (method === 'GET' && path === '/v1/capabilities') ||
    (method === 'POST' && path === '/v1/scans') ||
    (method === 'GET' && /^\/v1\/jobs\/[a-f0-9]{32}$/.test(path)) ||
    (method === 'GET' && /^\/v1\/findings\/[a-f0-9]{32}\/spec$/.test(path)) ||
    (method === 'POST' && /^\/v1\/findings\/[a-f0-9]{32}\/rechecks$/.test(path));
}
