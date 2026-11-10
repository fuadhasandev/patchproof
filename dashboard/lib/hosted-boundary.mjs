export function allowedHostedPath(path, method) {
 const id='[a-f0-9]{32}';
 const get=[/^me$/, /^projects$/, /^metrics$/, new RegExp(`^projects/${id}/(targets|scans)$`),new RegExp(`^jobs/${id}$`),new RegExp(`^findings/${id}/(spec|rechecks)$`)];
 const post=[/^projects$/, /^scans$/,new RegExp(`^projects/${id}/targets$`),new RegExp(`^targets/${id}/(verify|revoke)$`),new RegExp(`^jobs/${id}/cancel$`),new RegExp(`^findings/${id}/rechecks$`)];
 return (method==='GET'?get:method==='POST'?post:[]).some(pattern=>pattern.test(path));
}
export function hostedOriginAllowed(request, origin) {
 let url;try{url=new URL(origin);}catch{return false;}
 if(request.headers.get('host')!==url.host) return false;
 const supplied=request.headers.get('origin'),site=request.headers.get('sec-fetch-site');
 if(site && !['same-origin','none'].includes(site)) return false;
 if(supplied && supplied!==origin) return false;
 return request.method==='GET'||supplied===origin;
}
