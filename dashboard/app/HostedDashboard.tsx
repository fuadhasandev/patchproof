'use client';
import {useCallback,useEffect,useRef,useState} from 'react';
type Page<T>={items:T[];next_cursor:string|null};
type Project={id:string;name:string};
type Target={id:string;hostname:string;verified_until:number;revoked:boolean};
type Finding={id:string;title:string;run:unknown;suggested_fix:string;latest_recheck:Job|null};
type Job={id:string;kind:string;state:string;progress:string;target_url:string;error:string|null;target_calls:number;model_calls:number;report:{baseline?:{status:string};result?:{status:string;run:unknown};browser_result?:{status:string;run:{reason:string}};investigation?:{ai_status:string}}|null;findings?:Finding[]};
const terminal=(state:string)=>['completed','failed','cancelled','interrupted'].includes(state);
async function request<T>(path:string,body?:unknown,key?:string):Promise<T>{
 const response=await fetch('/api/hosted/'+path,body===undefined?{cache:'no-store'}:{method:'POST',headers:{'Content-Type':'application/json',...(key?{'Idempotency-Key':key}:{})},body:JSON.stringify(body)});
 const data=await response.json();if(!response.ok)throw new Error(data.detail+' (request '+(data.request_id||response.headers.get('x-request-id')||'unavailable')+')');return data;
}
function Timeline({id,revision}:{id:string;revision:number}){
 const [page,setPage]=useState<Page<Job>>({items:[],next_cursor:null});const [error,setError]=useState('');
 useEffect(()=>{request<Page<Job>>(`findings/${id}/rechecks`).then(setPage).catch(e=>setError(e.message));},[id,revision]);
 return <section><h4>Recheck history</h4>{error&&<p role="alert">{error}</p>}{page.items.map(j=><p key={j.id}>{j.report?.result?.status.replaceAll('_',' ')||j.state} · {j.error||j.progress}</p>)}{page.next_cursor&&<button onClick={()=>request<Page<Job>>(`findings/${id}/rechecks?before=${page.next_cursor}`).then(p=>setPage({items:[...page.items,...p.items],next_cursor:p.next_cursor})).catch(e=>setError(e.message))}>Older rechecks</button>}</section>;
}
export default function HostedDashboard(){
 const [projects,setProjects]=useState<Page<Project>>({items:[],next_cursor:null});const [project,setProject]=useState('');const [name,setName]=useState('');
 const [targets,setTargets]=useState<Page<Target>>({items:[],next_cursor:null});const [host,setHost]=useState('');const [targetId,setTargetId]=useState('');
 const [challenge,setChallenge]=useState<{id:string;record:string;value:string;expires_at:number}|null>(null);
 const [url,setUrl]=useState('');const [cookies,setCookies]=useState('');const [ai,setAI]=useState(false);const [browser,setBrowser]=useState(false);
 const [history,setHistory]=useState<Page<Job>>({items:[],next_cursor:null});const [job,setJob]=useState<Job|null>(null);const [track,setTrack]=useState<string|null>(null);const [active,setActive]=useState<Job|null>(null);
 const [error,setError]=useState('');const [busy,setBusy]=useState(false);const [revision,setRevision]=useState(0);const [signedIn,setSignedIn]=useState(false);
 const keys=useRef(new Map<string,string>());
 const submit=async<T,>(path:string,body:unknown):Promise<T>=>{const signature=path+JSON.stringify(body);let key=keys.current.get(signature);if(!key){key=crypto.randomUUID();keys.current.set(signature,key);}const result=await request<T>(path,body,key);keys.current.delete(signature);return result;};
 const perform=async(fn:()=>Promise<void>)=>{setBusy(true);setError('');try{await fn();}catch(e){setError((e as Error).message);}finally{setBusy(false);}};
 const refresh=useCallback(async()=>{if(project){setTargets(await request<Page<Target>>(`projects/${project}/targets`));setHistory(await request<Page<Job>>(`projects/${project}/scans`));}},[project]);
 useEffect(()=>{request('me').then(()=>{setSignedIn(true);return request<Page<Project>>('projects');}).then(setProjects).catch(e=>setError(e.message));},[]);
 useEffect(()=>{setJob(null);setTargetId('');setChallenge(null);setTrack(null);setActive(null);refresh().catch(e=>setError(e.message));},[refresh]);
 useEffect(()=>{if(!track)return;let disposed=false;const tick=async()=>{try{const data=await request<Job>('jobs/'+track);if(disposed)return;setActive(data);if(data.kind==='scan')setJob(data);if(terminal(data.state)){setTrack(null);setRevision(r=>r+1);await refresh();if(job && job.id!==track)setJob(await request<Job>('jobs/'+job.id));}}catch(e){if(!disposed)setError((e as Error).message);}};tick();const timer=setInterval(tick,1000);return()=>{disposed=true;clearInterval(timer);};},[track,refresh,job?.id]);
 return <main style={{maxWidth:1100,margin:'auto',padding:32}}>
  <header><h1>PatchProof</h1><p>Verified projects · evidence · replay</p>{signedIn?<a href="/oauth2/sign_out">Sign out</a>:<a href="/oauth2/sign_in?rd=/">Sign in</a>}</header>
  {error&&<p role="alert" className="notice error">{error}</p>}
  <section><h2>Projects</h2><label>Project name<input value={name} onChange={e=>setName(e.target.value)}/></label><button disabled={busy||!name||!signedIn} onClick={()=>perform(async()=>{const p=await request<Project>('projects',{name});setProjects(await request<Page<Project>>('projects'));setProject(p.id);setName('');})}>Create project</button>
   <label>Project<select aria-label="Project" value={project} onChange={e=>setProject(e.target.value)}><option value="">Select project</option>{projects.items.map(p=><option key={p.id} value={p.id}>{p.name}</option>)}</select></label>
   {projects.next_cursor&&<button onClick={()=>perform(async()=>{const p=await request<Page<Project>>('projects?before='+projects.next_cursor);setProjects({items:[...projects.items,...p.items],next_cursor:p.next_cursor});})}>More projects</button>}
  </section>
  {project&&<><section><h2>Target verification</h2><p>Publish a DNS TXT challenge for the exact hostname. Verification expires after 24 hours by default; subdomains require their own challenge.</p>
   <label>Hostname<input value={host} onChange={e=>setHost(e.target.value)} placeholder="app.example.com"/></label><button disabled={busy||!host} onClick={()=>perform(async()=>{setChallenge(await request(`projects/${project}/targets`,{hostname:host}));await refresh();})}>Create DNS challenge</button>
   {challenge&&<div><p>TXT name: <code>{challenge.record}</code></p><p>TXT value: <code>{challenge.value}</code></p><p>Expires: {new Date(challenge.expires_at*1000).toLocaleString()}</p><button disabled={busy} onClick={()=>perform(async()=>{await request(`targets/${challenge.id}/verify`,{});setTargetId(challenge.id);await refresh();})}>Verify DNS</button></div>}
   {targets.items.map(t=><p key={t.id}>{t.hostname} · {t.revoked?'revoked':t.verified_until*1000>Date.now()?'verified':'unverified / expired'} <button disabled={busy} onClick={()=>perform(async()=>{await request(`targets/${t.id}/revoke`,{});await refresh();})}>Revoke {t.hostname}</button></p>)}
   {targets.next_cursor&&<button onClick={()=>perform(async()=>{const p=await request<Page<Target>>(`projects/${project}/targets?before=${targets.next_cursor}`);setTargets({items:[...targets.items,...p.items],next_cursor:p.next_cursor});})}>More targets</button>}
  </section>
  <section><h2>Scan</h2><label>Verified target<select aria-label="Verified target" value={targetId} onChange={e=>setTargetId(e.target.value)}><option value="">Select hostname</option>{targets.items.map(t=><option key={t.id} value={t.id}>{t.hostname}</option>)}</select></label>
   <label>Target URL<input value={url} onChange={e=>setUrl(e.target.value)} placeholder="https://app.example.com/"/></label>
   <label>Session cookie names<input value={cookies} onChange={e=>setCookies(e.target.value)} placeholder="sid, session"/></label>
   <label><input type="checkbox" checked={ai} onChange={e=>setAI(e.target.checked)}/>AI investigation</label>
   <label><input type="checkbox" checked={browser} onChange={e=>setBrowser(e.target.checked)}/>Browser check</label><p>Hosted browser scanning is unavailable until egress isolation is verified; HTTP results remain available.</p>
   <button disabled={busy||!targetId||!url||!!track} onClick={()=>perform(async()=>{const result=await submit<Job>('scans',{project_id:project,target_id:targetId,target_url:url,session_cookies:cookies.split(',').map(x=>x.trim()).filter(Boolean),ai,browser});setJob(null);setTrack(result.id);})}>Run security scan</button>
   {active&&<p role="status">{active.state} · {active.progress} · target attempts {active.target_calls} · model attempts {active.model_calls}</p>}
   {track&&<button disabled={busy} onClick={()=>perform(async()=>{await request(`jobs/${track}/cancel`,{});})}>Cancel job</button>}
  </section>
  <section><h2>Scan history</h2>{history.items.map(j=><p key={j.id}>{j.target_url} · {j.state} <button onClick={()=>perform(async()=>{const saved=await request<Job>('jobs/'+j.id);setJob(saved);setActive(saved);if(!terminal(saved.state))setTrack(saved.id);})}>Open report</button></p>)}{history.next_cursor&&<button onClick={()=>perform(async()=>{const p=await request<Page<Job>>(`projects/${project}/scans?before=${history.next_cursor}`);setHistory({items:[...history.items,...p.items],next_cursor:p.next_cursor});})}>Older scans</button>}</section>
  {job&&<section><h2>Saved report</h2><p>{job.target_url} · {job.state}</p>{job.error&&<p role="alert">{job.error}</p>}<p>HTTP baseline: {job.report?.baseline?.status.replaceAll('_',' ')||'unverified'}</p>
   {job.report?.browser_result&&<p>Browser: {job.report.browser_result.status} · {job.report.browser_result.run.reason}</p>}{job.report?.investigation&&<p>AI: {job.report.investigation.ai_status}</p>}
   {job.findings?.map(f=><article className="finding" key={f.id}><h3>{f.title}</h3><p>Original: still present · Latest: <strong>{f.latest_recheck?.report?.result?.status.replaceAll('_',' ')||f.latest_recheck?.state||'not rechecked'}</strong></p><details><summary>Observed evidence</summary><pre>{JSON.stringify(f.run,null,2)}</pre></details><p>{f.suggested_fix}</p><a href={`/api/hosted/findings/${f.id}/spec`} download>Download CheckSpec</a> <button disabled={busy||!!track} onClick={()=>perform(async()=>{const result=await submit<Job>(`findings/${f.id}/rechecks`,{});setTrack(result.id);})}>Recheck</button><Timeline id={f.id} revision={revision}/></article>)}
  </section>}</>}
 </main>;
}
