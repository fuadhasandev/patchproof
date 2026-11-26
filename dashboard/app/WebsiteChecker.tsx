'use client';
import {useRef,useState} from 'react';
import type {Job} from '@/lib/types';
import {checks,outcome,results,sampleJob} from '@/lib/check-report';

type Project={id:string;name:string};
type Target={id:string;hostname:string;verified_until:number;revoked:boolean};
type Challenge={id:string;record:string;value:string;expires_at:number};
type Submission={target_url:string;session_cookies:string[];ai:boolean;browser:boolean;project_id?:string;target_id?:string};
export default function WebsiteChecker({hosted}:{hosted:boolean}) {
 const [url,setUrl]=useState('');const [job,setJob]=useState<Job|null>(null);const [previous,setPrevious]=useState<Job|null>(null);
 const [busy,setBusy]=useState(false);const [error,setError]=useState('');const [sample,setSample]=useState(false);
 const [submission,setSubmission]=useState<Submission|null>(null);const [challenge,setChallenge]=useState<Challenge|null>(null);
 const [pending,setPending]=useState<Submission|null>(null);const [progress,setProgress]=useState('');
 const keys=useRef(new Map<string,string>());
 async function request<T>(path:string,body?:unknown):Promise<T>{
  const signature=path+JSON.stringify(body);let key=keys.current.get(signature);
  if(body!==undefined&&!key){key=crypto.randomUUID();keys.current.set(signature,key);}
  const response=await fetch('/api/'+(hosted?'hosted/':'')+path,body===undefined?{cache:'no-store'}:{method:'POST',headers:{'Content-Type':'application/json',...(hosted?{'Idempotency-Key':key!}:{})},body:JSON.stringify(body)});
  const data=await response.json();if(!response.ok)throw new Error(data.detail||'Request failed.');keys.current.delete(signature);return data;
 }
 async function all<T>(path:string):Promise<T[]>{
  const items:T[]=[];let cursor:string|null=null;
  do {const page: {items:T[];next_cursor:string|null}=await request(path+(cursor?'?before='+cursor:''));items.push(...page.items);cursor=page.next_cursor;}while(cursor);
  return items;
 }
 async function run(input:Submission,baseline:Job|null){
  setProgress('Checking website…');
  const created=await request<{id:string}>('scans',input);
  setSubmission(input);setPrevious(baseline);setSample(false);setChallenge(null);setPending(null);setJob(null);
  const deadline=Date.now()+180000;
  while(Date.now()<deadline){
   const next=await request<Job>('jobs/'+created.id);
   if(!['queued','running'].includes(next.state)){setJob(next);return;}
   await new Promise(resolve=>setTimeout(resolve,700));
  }
  throw new Error('The check has not finished. Open Advanced to view its saved progress.');
 }
 async function perform(action:()=>Promise<void>){setBusy(true);setError('');try{await action();}catch(e){setError('Could not verify. '+(e as Error).message);}finally{setBusy(false);setProgress('');}}
 async function start(){
  await perform(async()=>{
   const parsed=new URL(url);if(!['http:','https:'].includes(parsed.protocol))throw new Error('Enter an HTTP or HTTPS website URL.');
   const input:Submission={target_url:url,session_cookies:[],ai:false,browser:false};
   if(hosted){
    setProgress('Checking domain verification…');
    const projects=await all<Project>('projects');
    // Reuse an existing verified exact hostname, including paginated projects/targets.
    for(const project of projects){
     const targets=await all<Target>(`projects/${project.id}/targets`);
     const target=targets.find(t=>t.hostname===parsed.hostname&&!t.revoked&&t.verified_until*1000>Date.now());
     if(target){await run({...input,project_id:project.id,target_id:target.id},null);return;}
    }
    const project=projects[0]||await request<Project>('projects',{name:'Website checks'});
    const created=await request<Challenge>(`projects/${project.id}/targets`,{hostname:parsed.hostname});
    setPending({...input,project_id:project.id,target_id:created.id});setChallenge(created);return;
   }
   await run(input,null);
  });
 }
 function showSample(){setJob(sampleJob);setPrevious(null);setSample(true);setSubmission(null);setChallenge(null);setPending(null);setError('');}
 const current=results(job);const before=results(previous);
 const terminalIncomplete=!!job&&job.state!=='completed';
 const groups=['Needs attention','Passed','Could not verify'];
 return <><header className="topbar"><a className="brand" href="/" aria-label="PatchProof home"><span className="brand-mark">P</span><strong>PatchProof</strong></a><a href="/advanced">Advanced</a></header>
 <main className="checker"><section className="checker-intro"><p className="eyebrow">Website configuration checks</p><h1>Check your website’s security configuration.</h1><p>See what needs attention, make a change, then check again.</p></section>
 <section className="panel"><form onSubmit={e=>{e.preventDefault();void start();}}><label htmlFor="website">Website URL</label><div className="url-row"><input id="website" type="url" required maxLength={2048} placeholder="https://your-website.com" value={url} disabled={busy} onChange={e=>setUrl(e.target.value)}/><button className="button" disabled={busy}>Check website</button></div></form><div className="checker-help"><p>Check a website you own or have permission to test.</p><button className="text-button" disabled={busy} onClick={showSample}>Try sample report</button></div>{hosted&&<p>Live checks require sign-in and verification of the exact domain. <a href="/oauth2/sign_in?rd=/">Sign in</a></p>}</section>
 <details className="panel check-scope"><summary>What gets checked?</summary><p>One bounded HTTP GET to the exact URL, with DNS resolution and normal TLS certificate verification. No redirects, crawling, sign-in, or response body analysis.</p>{checks.map(c=><p key={c.id}><strong>{c.title}.</strong> {c.scope}</p>)}<p>The optional static mixed-content browser check is not run here. Configure cookie names, browser checks, and AI in <a href="/advanced">Advanced</a>. These checks do not cover all vulnerabilities.</p></details>
 {busy&&<p className="notice" role="status">{progress||'Preparing check…'}</p>}
 {error&&<p className="notice error" role="alert">{error}</p>}
 {challenge&&pending&&<section className="panel"><h2>Verify your domain before checking</h2><p>Add this DNS TXT record for <strong>{new URL(pending.target_url).hostname}</strong>, then verify it. No website check has run yet.</p><dl><dt>TXT record name</dt><dd><code>{challenge.record}</code></dd><dt>TXT record value</dt><dd><code>{challenge.value}</code></dd></dl><p>Challenge expires {new Date(challenge.expires_at*1000).toLocaleString()}. Subdomains need their own verification.</p><button className="button" disabled={busy} onClick={()=>perform(async()=>{await request(`targets/${challenge.id}/verify`,{});await run(pending,null);})}>Verify domain and check website</button></section>}
 {job&&<section aria-label="Website security configuration report" className="configuration-report"><div className="report-heading"><div><p className="eyebrow">{sample?'Sample report · preloaded example':'Check report'}</p><h2>Website security configuration report</h2><p className="report-url">{job.target_url}</p></div><button className="button secondary" disabled={busy} onClick={()=>sample?(setPrevious(job),setJob({...sampleJob})):submission&&perform(()=>run(submission,job))}>Check again</button></div>
 {sample?<p className="notice">Illustrative example data. No request is made to example.com. Check again reloads the same sample checks; live checks use the URL above.</p>:<p className="muted">Checked {new Date(job.created_at*1000).toLocaleString()}</p>}
 {terminalIncomplete&&<p className="notice error">Could not verify. The check {job.state}. {job.error} Any available results below are partial.</p>}
 {previous&&<section className="panel changes"><h3>What changed</h3><p>Compared with the previous {sample?'sample report':'check of the same URL'}. An unavailable result does not prove a fix.</p>{checks.map(c=>{const old=before.find(r=>r.run.rule_id===c.id);const now=current.find(r=>r.run.rule_id===c.id);const a=outcome(old),b=outcome(now);return <p key={c.id}><strong>{c.title}:</strong> {a===b?`No status change — ${b}`:`${a} → ${b}`}</p>;})}</section>}
 <section className="panel"><h3>What was checked</h3><p>The exact page’s CSP and HSTS response headers. Cookie checks require explicitly selected names and could not be evaluated here. Browser checks and AI were not run.</p><p>These are configuration observations, not an overall security rating.</p></section>
 <div className="summary-strip">{groups.map(group=><div key={group}><strong>{checks.filter(c=>outcome(current.find(r=>r.run.rule_id===c.id))===group).length}</strong><span>{group}</span></div>)}</div>
 {groups.map(group=><section className="result-group" key={group}><h3>{group}</h3>{checks.filter(c=>outcome(current.find(r=>r.run.rule_id===c.id))===group).length===0&&<p className="muted">No checks in this category.</p>}{checks.filter(c=>outcome(current.find(r=>r.run.rule_id===c.id))===group).map(c=>{const result=current.find(r=>r.run.rule_id===c.id);return <article className="panel check-card" key={c.id}><div className="check-card-heading"><h4>{c.title}</h4><span className={'badge '+(group==='Passed'?'resolved':group==='Needs attention'?'still_present':'unverified')}>{group}</span></div><p>{group==='Passed'?c.pass:group==='Needs attention'?c.fail:(result?.run.reason||'The check did not return enough evidence to evaluate this condition.')}</p><p><strong>{group==='Passed'?'Suggested follow-up':'Suggested fix'}:</strong> {group==='Passed'?'Keep this header configured and review its settings; presence alone does not establish an effective policy.':group==='Could not verify'&&c.id!=='http.session-cookie.secure'?'Ensure the exact URL is reachable and returns a successful response. CSP needs an HTML page; HSTS needs HTTPS. Then check again.':c.fix}</p><details><summary>Exact check and evidence</summary><p>{c.scope}</p><code>{c.id}</code>{result&&<p>HTTP status: {result.run.evidence.status_code??'unavailable'} · {result.run.applicability==='evaluated'?'Evaluated':'Not evaluated'}{result.run.reason?' · '+result.run.reason:''}</p>}</details></article>;})}</section>)}
 </section>}
 <footer>PatchProof · Focused checks, explained plainly.<span>{hosted?'Domain verification required for live checks.':'Local checker'}</span></footer></main></>;
}
