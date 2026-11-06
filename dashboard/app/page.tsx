'use client';
import { useEffect, useState } from 'react';
import type {Capabilities, Evidence, Finding, Job, Latest} from '@/lib/types';

async function api<T>(path: string, body?: unknown): Promise<T> {
  const response = await fetch('/api/' + path, body === undefined ? {cache:'no-store'} : {
    method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.detail || 'Request failed.');
  return data;
}
const label = (value:string) => value.replaceAll('_', ' ');
function Badge({value}:{value:string}) { return <span className={'badge ' + value}>{label(value)}</span>; }
function EvidenceView({evidence}:{evidence:Evidence}) {
  const fields = [['HTTP status', evidence.status_code ?? 'Unavailable'], ['HTML', evidence.is_html], ['HTTPS', evidence.is_https], ['CSP present', evidence.csp_present], ['HSTS present', evidence.hsts_present]];
  return <><dl className="evidence">{fields.map(([key,value])=><div key={String(key)}><dt>{key}</dt><dd>{value===null?'Unknown':String(value)}</dd></div>)}</dl>
    {evidence.cookies.map(c=><p className="small" key={c.name}>Cookie <code>{c.name}</code>: {c.instances} issued · {c.missing_secure} without Secure · {c.unparseable} unparseable</p>)}</>;
}
function FindingCard({finding,onRecheck,latest}:{finding:Finding;onRecheck:()=>void;latest:Latest|null}) {
  const busy = latest && ['queued','running'].includes(latest.state);
  return <article className="finding">
    <div className="finding-head"><span className="finding-icon">!</span><div><p className="eyebrow">Configuration observation</p><h3>{finding.title}</h3></div></div>
    <code className="rule">{finding.run.rule_id}{finding.run.cookie_name ? ` · ${finding.run.cookie_name}` : ''}</code>
    <div className="comparison"><div><p className="small">Original scan</p><Badge value="still_present"/></div><span aria-hidden="true">→</span><div><p className="small">Latest recheck</p>{latest ? <Badge value={latest.report?.result.status || latest.state}/> : <span className="muted">Not rechecked</span>}</div></div>
    {latest?.report?.result.run.reason && <p className="notice">{latest.report.result.run.reason}</p>}
    {latest?.error && <p role="alert" className="notice error">{latest.error}</p>}
    <h4>Observed evidence</h4><EvidenceView evidence={finding.run.evidence}/>
    {latest?.report && <details><summary>Latest recheck evidence</summary><EvidenceView evidence={latest.report.result.run.evidence}/></details>}
    <div className="remediation"><h4>Suggested fix</h4><p>{finding.suggested_fix}</p></div>
    <p className="small muted">{finding.run.coverage}</p>
    <div className="actions"><a className="button secondary" href={`/api/findings/${finding.id}/spec`} download="patchproof-check.json">↓ Download CheckSpec</a><button className="button" disabled={!!busy} onClick={onRecheck}>{busy?'Rechecking…':'↻ Recheck'}</button></div>
  </article>;
}
export default function Home() {
  const [caps,setCaps] = useState<Capabilities|null>(null);
  const [target,setTarget] = useState(''); const [cookies,setCookies] = useState(''); const [ai,setAi] = useState(false);
  const [job,setJob] = useState<Job|null>(null); const [jobId,setJobId] = useState<string|null>(null);
  const [latest,setLatest] = useState<Record<string,Latest>>({});
  const [error,setError] = useState(''); const [starting,setStarting] = useState(false);
  useEffect(()=>{api<Capabilities>('capabilities').then(setCaps).catch(e=>setError(e.message));},[]);
  useEffect(()=>{
    if (!jobId) return;
    let cancelled=false; let timer:ReturnType<typeof setTimeout>;
    async function poll() { try {
      const next=await api<Job>('jobs/'+jobId);
      if(cancelled)return; setJob(next);
      if(['queued','running'].includes(next.state)) timer=setTimeout(poll,700);
    } catch(e) {if(!cancelled){setError((e as Error).message);setJobId(null);}} }
    poll(); return ()=>{cancelled=true;clearTimeout(timer);};
  },[jobId]);
  const busy=starting || !!(jobId && (!job || ['queued','running'].includes(job.state)));
  async function start(event:React.FormEvent) {
    event.preventDefault(); setError(''); setStarting(true);setJob(null);setJobId(null);setLatest({});
    try {const next=await api<{id:string}>('scans',{target_url:target,session_cookies:cookies.split(/[\s,]+/).filter(Boolean),ai});setJobId(next.id);}
    catch(e){setError((e as Error).message);}finally{setStarting(false);}
  }
  async function recheck(finding:Finding) {
    setError(''); setLatest(prev=>({...prev,[finding.id]:{id:'',state:'queued',report:null,error:null}}));
    try {
      const created=await api<{id:string}>(`findings/${finding.id}/rechecks`,{});
      while(true) {
        const next=await api<Job>('jobs/'+created.id);
        setLatest(prev=>({...prev,[finding.id]:{id:next.id,state:next.state,report:next.report?.result ? {result:next.report.result}:null,error:next.error}}));
        if(!['queued','running'].includes(next.state))break;
        await new Promise(resolve=>setTimeout(resolve,700));
      }
    }catch(e){setLatest(prev=>({...prev,[finding.id]:{id:'',state:'failed',report:null,error:(e as Error).message}}));}
  }
  const baseline=job?.report?.baseline; const investigation=job?.report?.investigation;
  const blocked=baseline?.checks.some(c=>c.run.reason?.startsWith('Destination blocked'));
  return <><header className="topbar"><div className="brand"><span className="brand-mark">P</span><strong>PatchProof</strong><span className="version">LOCAL WORKBENCH</span></div><span className="connection"><i className={caps?'dot':'dot offline'}/>{caps?'API connected':'API unavailable'}</span></header>
    <main><div className="page-heading"><div><p className="eyebrow">Website security / Verification</p><h1>Evidence first. <span>Verify every fix.</span></h1><p className="intro">Run focused checks, inspect the evidence, and prove what changed.</p></div><span className="local-pill">⌂ Runs on your machine</span></div>
      <div className="workspace"><aside><section className="panel scan-panel"><div className="section-title"><span className="step">01</span><h2>Start a scan</h2></div>
        <form onSubmit={start}><label htmlFor="target">Target URL</label><input id="target" type="url" required maxLength={2048} placeholder="https://your-website.com" value={target} onChange={e=>setTarget(e.target.value)}/><p className="hint">An exact page on a website you own or have permission to test.</p>
          <label htmlFor="cookies">Session cookie names <span className="optional">optional</span></label><input id="cookies" placeholder="sid, session" value={cookies} onChange={e=>setCookies(e.target.value)}/><p className="hint">Case-sensitive names, separated by commas or spaces. Values are never collected.</p>
          {caps?.investigation && <div className="ai-option"><label className="toggle"><input type="checkbox" checked={ai} onChange={e=>setAi(e.target.checked)}/><span>AI investigation <small>Optional · OpenRouter</small></span></label><p className="hint">{caps.ai_configured?'Sends allowlisted observations, never target URLs, cookie names, values, or bodies.':'AI is not configured on the backend. Baseline checks still run.'}</p></div>}
          <button className="button primary" disabled={busy || !caps}>{busy?'Scanning…':'Run security scan →'}</button>
        </form></section>
        <section className="scope"><h3>Small scope. Clear evidence.</h3><ul><li>CSP header presence</li><li>HSTS on HTTPS responses</li><li>Secure on named session cookies</li></ul><p>One request for the baseline. No crawling, redirects, or response-body inspection.</p>{caps?.fixture_origin && <p className="fixture">Fixture enabled: <code>{caps.fixture_origin}</code></p>}<p>Local history expires after 30 minutes and clears on API restart.</p></section></aside>
        <div className="results"><div className="results-heading"><div className="section-title"><span className="step">02</span><h2>Scan results</h2></div>{job && <Badge value={job.state}/>}</div>
          {error && <div className="notice error" role="alert">{error}</div>}
          {busy && <section className="panel progress" role="status"><span className="spinner"/><div><h3>{job?.state==='running'?'Checking your target':'Waiting for a worker'}</h3><p>Collecting sanitized evidence{ai?' and running bounded investigation':''}. This view updates automatically.</p></div></section>}
          {!job && !busy && <section className="panel empty"><div className="empty-icon">⌕</div><h2>Your next fix starts with evidence.</h2><p>Enter a target to see check coverage and configuration findings. Export a check, apply a fix, then recheck the same page.</p><div className="workflow"><span>Scan</span><b>→</b><span>Inspect</span><b>→</b><span>Fix & recheck</span></div></section>}
          {job?.state==='failed' && <div className="notice error" role="alert">Scan failed. {job.error}</div>}
          {baseline && <>
            <div className="summary-strip"><div><strong>{job?.findings.length}</strong><span>observations</span></div><div><strong>{baseline.checks.filter(c=>c.run.applicability==='evaluated').length}</strong><span>checks evaluated</span></div><div><strong>{baseline.checks.filter(c=>c.run.applicability!=='evaluated').length}</strong><span>skipped / unverified</span></div></div>
            {blocked && <div className="notice error">Target blocked by network policy. Local targets require an exact fixture origin configured on the server.</div>}
            {baseline.status==='unverified' && !blocked && <div className="notice">Some checks are unverified. No response or insufficient evidence is not proof of a fix.</div>}
            <section className="panel coverage"><h3>Check coverage</h3>{baseline.checks.map((c,i)=><div className="coverage-row" key={i}><div><code>{c.run.rule_id}</code>{c.run.cookie_name && <span className="small"> · {c.run.cookie_name}</span>}<p>{c.run.reason || c.run.coverage}</p></div><Badge value={c.status}/></div>)}</section>
            {investigation && <section className="panel ai-report"><h3>AI investigation <Badge value={investigation.ai_status}/></h3><p>{investigation.ai_reason}</p><p className="small">{investigation.model_turns} model turns · {investigation.followup_requests} follow-up attempts. Model explanations are advisory.</p>{investigation.tool_events.map((e,i)=><p className="small" key={i}>{e.tool}: {label(e.outcome)}</p>)}{investigation.explanation?.claims.map((c,i)=><blockquote key={i}>{c.explanation}<small>{c.outcome} · {c.evidence_ids.join(', ')}</small></blockquote>)}</section>}
            {job?.findings.map(f=><FindingCard key={f.id} finding={f} latest={latest[f.id] || f.latest_recheck} onRecheck={()=>recheck(f)}/>)}
            {job?.findings.length===0 && <section className="panel"><h3>No configuration findings</h3><p>Review coverage above. Skipped and unverified checks do not establish that a target is secure.</p></section>}
          </>}
        </div>
      </div><footer>PatchProof · Deterministic findings. Reproducible checks. <span>Local preview — not for public hosting.</span></footer>
    </main></>;
}
