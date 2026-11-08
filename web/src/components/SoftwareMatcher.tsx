import { useRef, useState } from 'react';
import type { Data } from '../types';
import { confidenceLabel, decodeSoftwareIndex, matchInventory, parseInventory } from '../software';
import type { Inventory, SoftwareIndex, SoftwareMatch } from '../software';
import { downloadFile, queueCsv, ticketDrafts } from '../exports';
import { number } from '../lib';
import '../software.css';

export function SoftwareMatcher({data}: {data: Data}) {
  const [source,setSource] = useState('');
  const [inventory,setInventory] = useState<Inventory | null>(null);
  const [matches,setMatches] = useState<SoftwareMatch[]>([]);
  const [error,setError] = useState('');
  const [busy,setBusy] = useState(false);
  const [label,setLabel] = useState('');
  const [page,setPage] = useState(0);
  const [drag,setDrag] = useState(false);
  const [notice,setNotice] = useState('');
  const index = useRef<SoftwareIndex | null>(null);
  const attempt = useRef(0);
  const input = useRef<HTMLInputElement>(null);
  const file = data.lazy?.software_index?.file;
  const size = 5;
  async function inspect(content: string, filename = 'Pasted inventory', current = ++attempt.current) {
    setBusy(true); setError(''); setNotice(''); setInventory(null); setMatches([]); setPage(0);
    try {
      const parsed = parseInventory(content);
      if (!index.current) {
        if (!file) throw new Error('Software matching data is unavailable.');
        const response = await fetch(`${import.meta.env.BASE_URL}data/${file}`);
        if (!response.ok) throw new Error('Could not load product data. Try again.');
        index.current = decodeSoftwareIndex(await response.json());
      }
      if (current !== attempt.current) return;
      setMatches(matchInventory(parsed.components,index.current));
      setInventory(parsed); setLabel(filename);
    } catch (err) {
      if (current === attempt.current) setError(err instanceof Error ? err.message : 'This inventory could not be read.');
    } finally { if (current === attempt.current) setBusy(false); }
  }
  async function readFile(upload?: File) {
    if (!upload) return;
    const current = ++attempt.current;
    setInventory(null); setMatches([]); setNotice(''); setError('');
    if (upload.size > 5_000_000) { setBusy(false); setError('Use a file smaller than 5 MB.'); return; }
    setBusy(true);
    try {
      const content = await upload.text();
      if (current !== attempt.current) return;
      setSource(content); await inspect(content,upload.name,current);
    } catch { if (current === attempt.current) {setError('This file could not be read.');setBusy(false);} }
    if (input.current) input.current.value = '';
  }
  async function sample(name: string) {
    const current = ++attempt.current;
    setBusy(true); setError('');
    try {
      const response = await fetch(`${import.meta.env.BASE_URL}samples/${name}`);
      if (!response.ok) throw new Error();
      const content = await response.text();
      if (current !== attempt.current) return;
      setSource(content); await inspect(content,name,current);
    } catch { if (current === attempt.current) {setError('Could not load the sample. Try again.');setBusy(false);} }
  }
  function clear() {
    ++attempt.current; setSource(''); setInventory(null); setMatches([]); setError(''); setBusy(false); setNotice('');
  }
  function exportMatches(format: 'csv' | 'json') {
    const rows = matches.map(row=>({...data.scores?.find(score=>score.cve_id === row.cve_id),...row}));
    downloadFile(`slow-burn-software.${format}`, format === 'csv' ? queueCsv(rows,data.runs ?? []) : JSON.stringify(ticketDrafts(rows,data.runs ?? []),null,2)+'\n',format === 'csv' ? 'text/csv;charset=utf-8' : 'application/json;charset=utf-8');
    setNotice(`Prepared ${number(rows.length)} matches. Exporting does not file or approve a ticket.`);
  }
  const matched = new Set(matches.flatMap(row=>row.software_matches.map(m=>`${m.component}\t${m.version}\t${m.ecosystem}`)));
  const unmatched = inventory?.components.filter(c=>!matched.has(`${c.name}\t${c.version}\t${c.ecosystem}`)) ?? [];
  return <div className="software-matcher" aria-label="Match my software">
    <div className={`software-drop ${drag ? 'is-dragging' : ''}`}
      onDragOver={event=>{event.preventDefault();setDrag(true);}}
      onDragLeave={()=>setDrag(false)}
      onDrop={event=>{event.preventDefault();setDrag(false);void readFile(event.dataTransfer.files[0]);}}>
      <label htmlFor="software-input"><strong>Match a software inventory</strong><span>CycloneDX or SPDX JSON, npm package-lock.json, or Python requirements.txt</span></label>
      <textarea id="software-input" value={source} onChange={event=>setSource(event.target.value)} placeholder="Paste an inventory here, or drop a file" spellCheck={false} maxLength={5_000_000} aria-describedby="software-privacy" />
      <div className="software-actions">
        <button className="button primary" onClick={()=>void inspect(source)} disabled={busy || !source.trim()}>{busy ? 'Matching…' : 'Match software'}</button>
        <button className="button secondary" onClick={()=>input.current?.click()} disabled={busy}>Choose file</button>
        <input ref={input} type="file" accept=".json,.txt,application/json,text/plain" onChange={event=>void readFile(event.target.files?.[0])} className="sr-only" tabIndex={-1} aria-label="Choose software inventory" />
        {!!source && <button className="software-clear" onClick={clear}>Clear inventory</button>}
      </div>
      <p id="software-privacy">Files stay in this browser. Nothing is uploaded or saved.</p>
    </div>
    <div className="software-samples"><span>Try a sample</span><button disabled={busy} onClick={()=>void sample('python-sbom.json')}>Python SBOM <span aria-hidden="true">↗</span></button><button disabled={busy} onClick={()=>void sample('package-lock.json')}>npm lockfile <span aria-hidden="true">↗</span></button></div>
    {error && <p className="software-error" role="alert">{error}</p>}
    {inventory && <div className="software-results" aria-live="polite">
      <div className="software-result-heading"><div><h4>{number(matches.length)} matching CVEs</h4><p>{label} · {inventory.format} · {inventory.components.length - unmatched.length} of {inventory.components.length} components matched</p></div>
        <div className="software-downloads"><button disabled={!matches.length} onClick={()=>exportMatches('csv')}>CSV</button><button disabled={!matches.length} onClick={()=>exportMatches('json')}>Ticket JSON</button></div></div>
      <p className="software-order">Slow Burn rank order. Name-only matches need vendor and ecosystem confirmation.</p>
      <ol className="software-list">
        {matches.slice(page*size,(page+1)*size).map(row=><li key={row.cve_id}>
          <div className="software-cve"><span>Rank {number(row.rank)}</span><strong>{row.cve_id}</strong><small>{row.snapshot_month}</small></div>
          {row.software_matches.map((m,i)=><div className="software-evidence" key={i}>
            <p><strong>{m.component}{m.version ? ` ${m.version}` : ' · version unknown'}</strong><span className={`match-confidence ${m.confidence}`}>{confidenceLabel[m.confidence]}</span></p>
            <span>{m.evidence}</span>
          </div>)}
        </li>)}
      </ol>
      {!matches.length && <p>No matches in the supplied product index. This does not establish that the software is safe.</p>}
      {matches.length > size && <div className="software-pagination"><span>{page*size+1}–{Math.min((page+1)*size,matches.length)} of {number(matches.length)}</span><button disabled={!page} onClick={()=>setPage(page-1)}>Previous</button><button disabled={(page+1)*size>=matches.length} onClick={()=>setPage(page+1)}>Next</button></div>}
      {unmatched.length > 0 && <p className="software-unmatched">No match: {unmatched.map(c=>`${c.name}${c.version ? ` ${c.version}` : ''}`).join(', ')}. Missing matches do not establish safety.</p>}
      {!!inventory.warnings.length && <p>{inventory.warnings.length} entries skipped. External files and requirement options are not followed.</p>}
      <p className="software-caveat">Current product metadata covers {number(index.current?.coverage.identity_cves)} of {number(index.current?.coverage.benchmark_cves)} benchmark CVEs. It is used for this review only. Qualified versions and updates need confirmation. The submitted ranking is unchanged.</p>
    </div>}
    {notice && <p role="status" className="export-notice">{notice}</p>}
  </div>;
}
