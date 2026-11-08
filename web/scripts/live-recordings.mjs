export function normalizeRecording(value) {
  const source = Array.isArray(value) ? value : value?.events;
  if (!Array.isArray(source) || !source.length) return null;
  const events = source.map(entry => ({ event: entry.event ?? entry.type, data: entry.data, t_ms: entry.t_ms ?? entry.at_ms ?? entry.elapsed_ms }));
  if (events.some(entry => typeof entry.event !== 'string' || !entry.data || typeof entry.data !== 'object' || !Number.isFinite(entry.t_ms) || entry.t_ms < 0)) return null;
  const start = events.find(entry => entry.event === 'start')?.data;
  const run = events.find(entry => entry.event === 'briefing')?.data?.run;
  const done = events.find(entry => entry.event === 'done')?.data;
  if (!start?.cve_id || !run?.briefing || run.run_id !== start.run_id || run.cve_id !== start.cve_id || done?.run_id !== run.run_id) return null;
  return { cve_id: run.cve_id, events: events.sort((a,b) => a.t_ms - b.t_ms) };
}
