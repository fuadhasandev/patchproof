'use client';
import {useEffect, useState} from 'react';
import {api} from '@/lib/client';
import type {HistoryItem, HistoryPage, TimelineEntry} from '@/lib/types';
const date = (value:number) => new Date(value*1000).toLocaleString();
export function History({onOpen}:{onOpen:(id:string)=>void}) {
  const [items,setItems]=useState<HistoryItem[]>([]);
  const [cursor,setCursor]=useState<string|null>(null);
  const [busy,setBusy]=useState(true); const [error,setError]=useState('');
  async function load(before?:string) {
    setBusy(true);setError('');
    try {
      const page=await api<HistoryPage>('scans?limit=20'+(before?'&before='+before:''));
      setItems(old=>before?[...old,...page.items]:page.items);setCursor(page.next_cursor);
    } catch(e){setError((e as Error).message);}finally{setBusy(false);}
  }
  useEffect(()=>{load();},[]);
  return <section className="panel history"><div className="results-heading"><div><p className="eyebrow">Saved on this machine</p><h2>Scan History</h2></div><button className="button secondary" onClick={()=>load()} disabled={busy}>Refresh history</button></div>
    <p className="muted small">Original reports stay unchanged. Open any scan to inspect its findings and recheck timeline.</p>
    {error && <p role="alert" className="notice error">{error}</p>}
    {!busy && !items.length && !error && <div className="empty"><h3>No scans saved yet</h3><p>Run your first scan. Its report and CheckSpecs will be available here after restarting the API.</p></div>}
    {!!items.length && <div className="history-table"><table><thead><tr><th>Target</th><th>Date</th><th>Status</th><th>Findings</th><th><span className="sr-only">Action</span></th></tr></thead><tbody>{items.map(item=><tr key={item.id}><td><span className="history-target">{item.target_url}</span>{item.retry_of && <small>Explicit retry</small>}</td><td>{date(item.created_at)}</td><td><span className={'badge '+item.state}>{item.state}</span></td><td>{item.finding_count}</td><td><button className="button secondary" onClick={()=>onOpen(item.id)}>Open report</button></td></tr>)}</tbody></table></div>}
    {busy && <p role="status">Loading history…</p>}
    {cursor && <button className="button secondary" disabled={busy} onClick={()=>load(cursor)}>Older scans</button>}
  </section>;
}
export function Timeline({findingId,revision,onRetry}:{findingId:string;revision:number;onRetry:(id:string)=>void}) {
  const [items,setItems]=useState<TimelineEntry[]>([]);const [cursor,setCursor]=useState<string|null>(null);
  const [busy,setBusy]=useState(true);const [error,setError]=useState('');
  async function load(before?:string) {
    setBusy(true);setError('');
    try {
      const page=await api<{items:TimelineEntry[];next_cursor:string|null}>(`findings/${findingId}/rechecks?limit=20`+(before?'&before='+before:''));
      setItems(old=>before?[...old,...page.items]:page.items);setCursor(page.next_cursor);
    }catch(e){setError((e as Error).message);}finally{setBusy(false);}
  }
  useEffect(()=>{load();},[findingId,revision]);
  return <section className="timeline"><h4>Recheck timeline</h4>{error && <p role="alert">{error}</p>}
    {!busy && !items.length && !error && <p className="small muted">No rechecks yet. The original finding is preserved above.</p>}
    <ol>{items.map(item=><li key={item.id}><div><time>{date(item.created_at)}</time><span className={'badge '+(item.state==='completed'?item.report?.result.status:item.state)}>{item.state==='completed'?item.report?.result.status.replaceAll('_',' '):item.state}</span></div>
      <p>{item.state==='completed'?item.report?.result.run.reason || 'Deterministic replay evaluated this check.':item.error || 'Waiting for replay.'}</p>
      {['interrupted','failed'].includes(item.state) && <><p>No replay outcome was established. This does not mark the original finding resolved.</p><button className="button secondary" disabled={busy} onClick={()=>onRetry(item.id)}>Retry this recheck</button></>}
    </li>)}</ol>
    {busy && <p className="small" role="status">Loading timeline…</p>}
    {cursor && <button className="button secondary" disabled={busy} onClick={()=>load(cursor)}>Older rechecks</button>}
  </section>;
}
