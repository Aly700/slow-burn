import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { MutableRefObject } from 'react';
import type { ReplayData, ReplayItem, ReplayPositive } from '../types';
import { isIgnited, missedItems, replayBounds, replayDate, replayTime, REPLAY_DURATION_MS, snapshotEnd } from '../replay';
import { number } from '../lib';
import '../replay.css';

const dateLabel = (value?: string | null) => value ? new Date(replayDate(value)).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' }) : 'pending';
type Inspect = (item: ReplayItem, x: number, y: number) => void;

function DotField({ items, clock, tray = false, onInspect }: { items: ReplayItem[]; clock: MutableRefObject<number>; tray?: boolean; onInspect: Inspect }) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const points = useRef<{ x: number; y: number; item: ReplayItem }[]>([]);
  useEffect(() => {
    const node = canvas.current;
    const ctx = node?.getContext('2d');
    if (!node || !ctx) return;
    let frame = 0, width = 0, height = 0, previous = -1, lastChange = 0;
    const resize = () => {
      const box = node.getBoundingClientRect();
      width = box.width; height = box.height;
      const scale = window.devicePixelRatio || 1;
      node.width = Math.round(width * scale); node.height = Math.round(height * scale);
      ctx.setTransform(scale, 0, 0, scale, 0, 0);
      const columns = tray ? Math.max(1, Math.min(items.length, Math.floor(width / 19))) : 25;
      const rows = Math.max(1, Math.ceil(items.length / columns));
      points.current = items.map((item, index) => ({ item, x: 12 + (index % columns + .5) * (width - 24) / columns, y: 12 + (Math.floor(index / columns) + .5) * (height - 24) / rows }));
      previous = -1;
    };
    const observer = new ResizeObserver(resize); observer.observe(node); resize();
    const draw = (now: number) => {
      const time = clock.current;
      if (time !== previous) lastChange = now;
      if (time !== previous || now - lastChange < 650) {
        previous = time;
        ctx.clearRect(0, 0, width, height);
        const radius = tray ? 2.3 : Math.max(1.25, Math.min(2, width / 160));
        for (const point of points.current) {
          const { item, x, y } = point;
          const known = snapshotEnd(item.snapshot_month);
          const age = (time - replayDate(item.kev_date)) / 86_400_000;
          if (isIgnited(item, time)) {
            const flare = window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 0 : Math.max(0, 1 - age / 14 - (now - lastChange) / 600);
            ctx.globalAlpha = 1;
            ctx.shadowColor = '#ed914e'; ctx.shadowBlur = 10 + flare * 15;
            ctx.fillStyle = flare > .4 ? '#fff1ce' : '#f5b474';
            ctx.beginPath(); ctx.arc(x, y, radius + .7 + flare * 1.5, 0, Math.PI * 2); ctx.fill();
            ctx.shadowBlur = 0;
            if (flare > 0) {
              ctx.globalAlpha = flare * .55;
              ctx.strokeStyle = '#f5b474'; ctx.lineWidth = .8;
              ctx.beginPath(); ctx.arc(x, y, radius + 3 + (1 - flare) * 9, 0, Math.PI * 2); ctx.stroke();
            }
          } else {
            const fade = time >= known ? .6 + .4 * Math.min(1, (time - known) / (86_400_000 * 8)) : 0;
            ctx.globalAlpha = .24 + fade * .6;
            ctx.fillStyle = '#72817f';
            ctx.beginPath(); ctx.arc(x, y, radius, 0, Math.PI * 2); ctx.fill();
          }
        }
        ctx.globalAlpha = 1;
      }
      frame = requestAnimationFrame(draw);
    };
    frame = requestAnimationFrame(draw);
    return () => { cancelAnimationFrame(frame); observer.disconnect(); };
  }, [items, clock, tray]);
  return <canvas ref={canvas} className={tray ? 'missed-dots' : 'replay-dots'} aria-hidden="true" onPointerMove={event => {
    const bounds = event.currentTarget.getBoundingClientRect();
    const nearest = points.current.find(point => Math.hypot(point.x - (event.clientX - bounds.left), point.y - (event.clientY - bounds.top)) < 9 && isIgnited(point.item, clock.current));
    event.currentTarget.style.cursor = nearest ? 'pointer' : 'default';
    if (nearest) onInspect(nearest.item, event.clientX, event.clientY);
  }} onClick={event => {
    const bounds = event.currentTarget.getBoundingClientRect();
    const nearest = points.current.find(point => Math.hypot(point.x - (event.clientX - bounds.left), point.y - (event.clientY - bounds.top)) < 12 && isIgnited(point.item, clock.current));
    if (nearest) onInspect(nearest.item, event.clientX, event.clientY);
  }} />;
}

export function Replay({ data, presentation = false }: { data?: ReplayData | null; presentation?: boolean }) {
  const root = useRef<HTMLDivElement>(null);
  const reduced = useRef(window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  const [progress, setProgress] = useState(reduced.current ? 1 : 0);
  const fraction = useRef(progress);
  const clock = useRef(data ? replayTime(data, progress) : 0);
  const [playing, setPlaying] = useState(false);
  const [playback, setPlayback] = useState(0);
  const [inspected, setInspected] = useState<{ item: ReplayPositive; x: number; y: number } | null>(null);
  const [showList, setShowList] = useState(false);
  const methods = useMemo(() => (data?.methods ?? []).filter(method => Array.isArray(method.items)), [data]);
  const missed = useMemo(() => data ? missedItems(data) : [], [data]);
  const metadata = useMemo(() => new Map((data?.later_exploited ?? []).map(item => [item.cve_id, item])), [data]);
  const seek = useCallback((value: number) => {
    fraction.current = value; setProgress(value);
    clock.current = data ? replayTime(data, value) : 0;
    setInspected(null);
  }, [data]);
  const restart = useCallback(() => { seek(reduced.current ? 1 : 0); setPlaying(!reduced.current); setPlayback(value => value + 1); }, [seek]);
  useEffect(() => {
    const node = root.current;
    if (!node || !data) return;
    if (reduced.current) { seek(1); return; }
    const observer = new IntersectionObserver(entries => {
      if (entries.some(entry => entry.isIntersecting)) { setPlaying(true); observer.disconnect(); }
    }, { threshold: .3 });
    observer.observe(node);
    return () => observer.disconnect();
  }, [data, seek]);
  useEffect(() => {
    if (!playing || !data) return;
    let frame = 0, lastPaint = 0;
    const started = performance.now() - fraction.current * REPLAY_DURATION_MS;
    const tick = (now: number) => {
      const next = Math.min(1, (now - started) / REPLAY_DURATION_MS);
      fraction.current = next; clock.current = replayTime(data, next);
      if (now - lastPaint >= 48 || next === 1) { setProgress(next); lastPaint = now; }
      if (next < 1) frame = requestAnimationFrame(tick); else setPlaying(false);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [playing, data, playback]);
  useEffect(() => {
    const key = (event: KeyboardEvent) => {
      if (event.key.toLowerCase() !== 'r' || event.metaKey || event.ctrlKey || event.altKey || /INPUT|TEXTAREA|SELECT/.test((event.target as HTMLElement).tagName)) return;
      if (!presentation && document.querySelector('.presentation')) return;
      const bounds = root.current?.getBoundingClientRect();
      if (bounds && bounds.top < window.innerHeight && bounds.bottom > 0) { event.preventDefault(); restart(); }
    };
    const media = window.matchMedia('(prefers-reduced-motion: reduce)');
    const change = () => { reduced.current = media.matches; if (media.matches) { setPlaying(false); seek(1); } };
    window.addEventListener('keydown', key); media.addEventListener('change', change);
    return () => { window.removeEventListener('keydown', key); media.removeEventListener('change', change); };
  }, [restart, seek, presentation]);
  const inspect: Inspect = (item, x, y) => setInspected({ item: metadata.get(item.cve_id) ?? item, x, y });
  if (!data || !methods.length || !Number.isFinite(replayBounds(data).start)) return <div className="replay-empty"><strong>Replay pending</strong><p>The historical ranking artifact is not available yet.</p></div>;
  const time = replayTime(data, progress);
  const confirmed = (data.later_exploited ?? []).filter(item => isIgnited(item, time));
  const noSignal = (data.later_exploited ?? []).filter(item => item.public_exploit_signal === false).length;
  const missedCount = missed.filter(item => isIgnited(item, time)).length;
  const month = new Date(time).toLocaleDateString('en-GB', { month: 'short', timeZone: 'UTC' });
  return <div className="replay" ref={root} data-progress={progress.toFixed(3)}>
    <div className="replay-legend"><span><i /> Known at snapshot month end</span><span><i className="ember" /> Later confirmed exploited · KEV date</span><span className="replay-year">2025 DEVELOPMENT BACKTEST</span></div>
    <div className="replay-lanes">
      {methods.map(method => <div className={`replay-lane ${method.key === 'ours' ? 'our-lane' : ''}`} key={method.key}>
        <div className="lane-heading"><div><h3>{method.name}</h3><span>{number(method.items?.length)} ranked CVEs</span></div><strong aria-label={`${method.name}: ${method.items?.filter(item => isIgnited(item, time)).length} later KEV entries`}>{number(method.items?.filter(item => isIgnited(item, time)).length)}<small>caught</small></strong></div>
        <DotField items={method.items!} clock={clock} onInspect={inspect} />
      </div>)}
    </div>
    <div className="replay-transport">
      <button className="replay-play" onClick={() => progress >= 1 ? restart() : setPlaying(value => !value)} aria-label={progress >= 1 ? 'Replay 2025' : playing ? 'Pause replay' : 'Play replay'}>{progress >= 1 ? '↻ Replay' : playing ? 'Ⅱ Pause' : '▷ Play'}<kbd>R</kbd></button>
      <div className="replay-timeline"><label className="sr-only" htmlFor={presentation ? 'deck-replay-time' : 'page-replay-time'}>Replay date</label><input id={presentation ? 'deck-replay-time' : 'page-replay-time'} type="range" min="0" max="1000" value={Math.round(progress * 1000)} onChange={event => { setPlaying(false); seek(Number(event.target.value) / 1000); }} aria-valuetext={new Date(time).toLocaleDateString('en-GB', { timeZone: 'UTC' })} style={{ '--replay-progress': `${progress * 100}%` } as React.CSSProperties} /><div className="month-ticks">{Array.from({ length: 12 }, (_, index) => <span key={index} className={index === new Date(time).getUTCMonth() ? 'current-month' : ''}>{new Date(Date.UTC(new Date(replayBounds(data).start).getUTCFullYear(), index)).toLocaleDateString('en-GB', { month: 'short', timeZone: 'UTC' })}</span>)}</div></div>
      <span className="replay-date">{month}<small>{progress >= 1 ? 'Year complete' : playing ? 'Replaying 2025' : 'Paused'}</small></span>
    </div>
    <div className="missed-tray"><div><strong>{missedCount}<span> / {number(missed.length)}</span></strong><p>Missed by every ranking</p></div><DotField items={missed} clock={clock} tray onInspect={inspect} /><p className="missed-note">The blind spot persists.<br /><strong>{number(noSignal)} of {number(data.positives)}</strong> later cases had no public exploit signal.</p></div>
    <div className="replay-footnote"><span>Fixed top-ranked sets · model selected on this development data. 2026 result pending judging.</span><button onClick={() => setShowList(value => !value)} aria-expanded={showList}>{showList ? 'Hide' : 'Inspect'} confirmed CVEs</button></div>
    {showList && <div className="replay-accessible-list">{confirmed.length ? confirmed.map(item => <button key={item.cve_id} onClick={event => { const bounds = event.currentTarget.getBoundingClientRect(); inspect(item, bounds.left, bounds.top); }}>{item.cve_id}<span>{item.vendor}</span></button>) : <p>No later KEV entries yet. Advance the timeline to inspect them.</p>}</div>}
    {inspected && <aside className="ember-tooltip" role="status" style={{ left: Math.max(12, Math.min(window.innerWidth - 316, inspected.x + 12)), top: Math.max(12, Math.min(window.innerHeight - 228, inspected.y + 16)) }}><button aria-label="Close CVE detail" onClick={() => setInspected(null)}>×</button><span>LATER CONFIRMED EXPLOITED</span><strong>{inspected.item.cve_id}</strong><p>{inspected.item.vendor || 'Vendor pending'} · {inspected.item.product || 'Product pending'}</p><dl><div><dt>Published</dt><dd>{dateLabel(inspected.item.published)}</dd></div><div><dt>KEV inclusion</dt><dd>{dateLabel(inspected.item.kev_date)}</dd></div></dl></aside>}
  </div>;
}
