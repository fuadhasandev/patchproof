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
export function historyQuery(search) {
  const params = new URLSearchParams(search);
  if ([...params.keys()].some(k => !['limit','before'].includes(k)) ||
      params.getAll('limit').length > 1 || params.getAll('before').length > 1) return null;
  const limit = params.get('limit') || '20';
  const before = params.get('before');
  if (!/^\d+$/.test(limit) || Number(limit) < 1 || Number(limit) > 50 || (before !== null && !validId(before))) return null;
  return '?limit=' + Number(limit) + (before ? '&before=' + before : '');
}
export function allowedPath(path, method) {
  const [pathname, query] = path.split('?');
  if (path.split('?').length > 2) return false;
  if (query !== undefined && (method !== 'GET' ||
      !(pathname === '/v1/scans' || /^\/v1\/findings\/[a-f0-9]{32}\/rechecks$/.test(pathname)) ||
      historyQuery(query) === null)) return false;
  return (method === 'GET' && pathname === '/v1/capabilities') ||
    (['GET','POST'].includes(method) && pathname === '/v1/scans') ||
    (method === 'GET' && /^\/v1\/jobs\/[a-f0-9]{32}$/.test(pathname)) ||
    (method === 'POST' && /^\/v1\/jobs\/[a-f0-9]{32}\/retry$/.test(pathname)) ||
    (method === 'GET' && /^\/v1\/findings\/[a-f0-9]{32}\/spec$/.test(pathname)) ||
    (['GET','POST'].includes(method) && /^\/v1\/findings\/[a-f0-9]{32}\/rechecks$/.test(pathname));
}
