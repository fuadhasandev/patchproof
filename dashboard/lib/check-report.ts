import type {Job, Result} from './types';
export const checks = [
  {id:'http.csp.present', title:'Content Security Policy (CSP)', scope:'Checks for a nonempty enforcing Content-Security-Policy header on a successful (2xx) HTML or XHTML response. Report-only headers do not count. It does not assess policy strength.', fail:'This page did not send an enforcing Content Security Policy. This header can help limit which content a browser may load.', pass:'An enforcing Content Security Policy header was present. Its rules were not assessed.', fix:'Configure your server to send a Content-Security-Policy header. Start with a policy suited to your site and test it before enforcing it.'},
  {id:'http.hsts.present', title:'HTTP Strict Transport Security (HSTS)', scope:'Checks for a nonempty Strict-Transport-Security header on a successful (2xx) HTTPS response. HTTP pages cannot be evaluated. Presence only: even max-age=0 passes.', fail:'The HTTPS response did not send HSTS. This header tells browsers to use HTTPS for future visits.', pass:'An HSTS header was present. Its duration and directives were not assessed.', fix:'Configure your HTTPS server to send Strict-Transport-Security with an appropriate max-age after confirming HTTPS works throughout your site.'},
  {id:'http.session-cookie.secure', title:'Secure flag on named session cookies', scope:'Checks every observed instance of explicitly named cookies for the Secure flag on a successful HTTPS response. No cookie names are selected in this simple check; it does not sign in or infer session cookies.', fail:'An observed named cookie was missing the Secure flag, which limits sending that cookie to HTTPS connections.', pass:'All observed instances of the named cookie had the Secure flag.', fix:'Set Secure on each named session cookie in your application or framework. Use Advanced to configure case-sensitive cookie names.'},
];
export function outcome(result?:Result) {
  if(result?.run.applicability==='evaluated' && result.status==='resolved') return 'Passed';
  if(result?.run.applicability==='evaluated' && result.status==='still_present') return 'Needs attention';
  return 'Could not verify';
}
export function results(job:Job|null):Result[] {return job?.report?.baseline?.checks || [];}
// Preloaded, illustrative data in the same shape as the deterministic API report.
export const sampleJob:Job = {
 id:'sample',kind:'scan',state:'completed',target_url:'https://example.com/',created_at:0,retry_of:null,error:null,findings:[],
 report:{baseline:{status:'still_present',checks:checks.map((check,i)=>({status:['still_present','resolved','skipped'][i],run:{rule_id:check.id,applicability:i===2?'skipped':'evaluated',cookie_name:null,reason:i===2?'No session cookie names were configured.':null,coverage:check.scope,remediation:check.fix,evidence:{status_code:200,is_https:true,is_html:true,csp_present:false,hsts_present:true,cookies:[]}}}))}},
};
