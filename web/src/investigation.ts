import type { Investigation, LiveClaim, LiveEvent, Run } from './types';

export const LIVE_API = 'http://127.0.0.1:8765';
export const localViewer = (hostname: string) => ['localhost', '127.0.0.1', '[::1]'].includes(hostname);
export const validCve = (value: string) => /^CVE-2026-\d{4,}$/.test(value);
const names = ['start', 'state', 'tool_call', 'tool_result', 'claim', 'briefing', 'error', 'done'];
type Source = Pick<EventSource, 'addEventListener' | 'close'>;

export function connectInvestigation(cve: string, receive: (event: LiveEvent) => void, fail: (message: string) => void, create: (url: string) => Source = url => new EventSource(url)) {
  const source = create(`${LIVE_API}/live/${encodeURIComponent(cve)}`);
  let closed = false, runId: string | undefined, briefing = false;
  let timer: ReturnType<typeof setTimeout>;
  const close = () => { closed = true; clearTimeout(timer); source.close(); };
  const stop = (message: string) => { if (!closed) { close(); fail(message); } };
  const timeout = () => { clearTimeout(timer); timer = setTimeout(() => stop('The stream stopped responding. No approval is available; retry the investigation.'), 120_000); };
  timeout();
  for (const name of names) source.addEventListener(name, raw => {
    if (closed) return;
    if (!('data' in raw) || typeof raw.data !== 'string') { stop('The live connection was interrupted. Retry to start a fresh investigation.'); return; }
    try {
      const data = JSON.parse(raw.data);
      if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Invalid event');
      if (name === 'error') { stop(typeof data.message === 'string' ? data.message : 'Investigation failed.'); return; }
      if (name === 'start') {
        if (data.cve_id !== cve || typeof data.run_id !== 'string') throw new Error('Run identity mismatch');
        runId = data.run_id;
      }
      if (name === 'tool_call' && (typeof data.call_id !== 'string' || typeof data.tool !== 'string')) throw new Error('Invalid tool call');
      if (name === 'tool_result' && (typeof data.call_id !== 'string' || typeof data.ms !== 'number')) throw new Error('Invalid tool result');
      if (name === 'claim' && (typeof data.id !== 'string' || typeof data.verified !== 'boolean' || (data.evidence != null && !Array.isArray(data.evidence)))) throw new Error('Invalid claim');
      if (name === 'briefing') {
        if (!runId || data.run?.run_id !== runId || data.run?.cve_id !== cve || !data.run?.briefing || !['WAITING_APPROVAL', 'FAILED', 'REJECTED', 'TICKET_FILED'].includes(data.run.state)) throw new Error('Briefing identity or state mismatch');
        briefing = true;
      }
      if (name === 'done' && (!briefing || data.run_id !== runId)) throw new Error('Stream ended without a matching briefing');
      timeout();
      receive({ event: name, data, t_ms: 0 });
      if (name === 'done') close();
    } catch { stop('The service returned an invalid or mismatched event. No approval is available.'); }
  });
  return close;
}

export function applyLiveEvent(previous: Investigation, event: LiveEvent): Investigation {
  const d = event.data;
  if (event.event === 'start') return { ...previous, run_id: String(d.run_id), cve_id: String(d.cve_id), model: String(d.model ?? ''), state: 'RECEIVED' };
  if (event.event === 'state') return { ...previous, state: String(d.state) };
  if (event.event === 'tool_call' || event.event === 'recorded_activity') return { ...previous, tools: [...previous.tools.filter(tool => tool.call_id !== d.call_id), { call_id: String(d.call_id), tool: String(d.tool), args: d.args, kind: String(d.kind ?? 'tool'), working: true }] };
  if (event.event === 'tool_result') return { ...previous, tools: previous.tools.map(tool => tool.call_id === d.call_id ? { ...tool, working: false, ms: typeof d.ms === 'number' ? d.ms : undefined, preview: d.preview } : tool) };
  if (event.event === 'claim') return { ...previous, claims: [...previous.claims.filter(claim => claim.id !== d.id), d as unknown as LiveClaim] };
  if (event.event === 'briefing') return { ...previous, run: d.run as Run, state: (d.run as Run).state };
  if (event.event === 'done') return { ...previous, status: 'complete', duration_ms: typeof d.duration_ms === 'number' ? d.duration_ms : undefined };
  return previous;
}

export function recordedEvents(run: Run): LiveEvent[] {
  const events: LiveEvent[] = [
    { event: 'start', t_ms: 0, data: { run_id: run.run_id, cve_id: run.cve_id, model: run.model, started_at: run.started_at } },
    { event: 'state', t_ms: 0, data: { state: 'INVESTIGATING' } },
  ];
  let end = run.duration_ms ?? 0;
  for (const [index, entry] of (run.trace ?? []).entries()) {
    const start = entry.t_ms ?? 0;
    const finish = start + (entry.duration_ms ?? 0);
    end = Math.max(end, finish);
    events.push({ event: entry.kind === 'tool' ? 'tool_call' : 'recorded_activity', t_ms: start, data: { call_id: `trace-${index}`, tool: entry.name ?? 'Recorded event', kind: entry.kind, args: entry.input } });
    events.push({ event: 'tool_result', t_ms: finish, data: { call_id: `trace-${index}`, tool: entry.name, ms: entry.duration_ms, preview: entry.output_summary } });
  }
  const verification = run.trace?.find(entry => entry.kind === 'verifier');
  const verifiedAt = verification ? (verification.t_ms ?? 0) + (verification.duration_ms ?? 0) : end;
  for (const claim of run.briefing?.claims ?? []) events.push({ event: 'claim', t_ms: verifiedAt, data: { ...claim } });
  for (const claim of run.verifier?.dropped ?? []) events.push({ event: 'claim', t_ms: verifiedAt, data: { ...claim, verified: false, reason: claim.why } });
  events.push({ event: 'briefing', t_ms: end, data: { run } });
  events.push({ event: 'done', t_ms: end, data: { run_id: run.run_id, duration_ms: run.duration_ms } });
  return events.sort((a, b) => a.t_ms - b.t_ms);
}

export function replayEvents(events: LiveEvent[], receive: (event: LiveEvent) => void, schedule = setTimeout, unschedule = clearTimeout) {
  const timers = events.map(event => schedule(() => receive(event), Math.max(0, event.t_ms)));
  return () => timers.forEach(timer => unschedule(timer));
}
