import { useState } from 'react';
import type { RaceData, RaceMethod } from '../race';
import { capacityResult, comparisonText, stepPath } from '../race';
import { SectionHeading } from './SectionHeading';
import { ReadingDetails } from './ReadingDetails';
import '../race.css';

const share = (n: number) => `${(n * 100).toFixed(1)}%`;
const monthName = (m: string) => new Date(`${m}-01T00:00:00Z`).toLocaleDateString('en', { month: 'short', timeZone: 'UTC' });

function RacePanel({ method, positives }: { method: RaceMethod; positives: number }) {
  const rows = method.end.monthly;
  return <figure className={`race-panel ${method.key === 'ours' ? 'race-ours' : ''}`}>
    <figcaption><h3>{method.name}</h3><strong>{method.end.before}<small>before listing</small></strong></figcaption>
    <svg viewBox="0 0 280 188" role="img" aria-label={`${method.name}: ${method.end.before} fixes before listing; ${positives} confirmed exploitations by December. Monthly values in the table below.`}>
      {[0, 25, positives].map(n => <g key={n}>
        <line x1="27" x2="264" y1={154 - n / positives * 134} y2={154 - n / positives * 134} className="race-grid" />
        <text x="18" y={158 - n / positives * 134} textAnchor="end">{n}</text>
      </g>)}
      <path d={stepPath(rows.map(r => r.confirmed), 27, 154, 237, 134, positives)} className="race-confirmed" />
      <path d={stepPath(rows.map(r => r.before), 27, 154, 237, 134, positives)} className="race-before" />
      {rows.map((r, i) => <circle key={r.month} cx={27 + i * 237 / 11} cy={154 - r.before / positives * 134} r="2.4" className="race-point"><title>{monthName(r.month)}: {r.before} fixed before listing, {r.confirmed} confirmed</title></circle>)}
      {[0, 5, 11].map(i => <text key={i} x={27 + i * 237 / 11} y="179" textAnchor={i === 0 ? 'start' : i === 11 ? 'end' : 'middle'}>{monthName(rows[i].month)}</text>)}
    </svg>
  </figure>;
}

export function Race({ data }: { data?: RaceData | null }) {
  const [timing, setTiming] = useState<'end' | 'start'>('end');
  if (!data) return null;
  const focus = capacityResult(data, 42);
  if (!focus) return null;
  const bootstrap = focus.bootstrap.end;
  return <section id="race" className="story-section race-section">
    <SectionHeading index="01b" label="Monthly capacity" title="Fixes made before the listing date" detail={`2025 · ${data.positives} later-listed vulnerabilities`} />
    <div className="race-intro">
      <p>At <strong>42 fixes a month</strong>, {comparisonText(focus).replace(/\.$/, '')}.</p>
      <p className="caption">Fixes complete at month end. Each CVE enters at its snapshot month end and can first be fixed the following month.</p>
    </div>
    <div className="race-chart-heading">
      <h3>42 fixes/month <span>≈ yearly 500 benchmark budget</span></h3>
      <div className="race-legend"><span><i className="race-key-before" />Fixed before listing</span><span><i className="race-key-confirmed" />Confirmed exploited</span></div>
    </div>
    <div className="race-panels">{focus.methods.map(m => <RacePanel key={m.key} method={m} positives={data.positives} />)}</div>
    <p className="caption race-chart-note">Cumulative counts: amber follows fixes of later-listed CVEs; grey repeats the same 55 KEV dates. January starts empty: 462 of 504 annual slots are used.</p>
    <table className="race-capacities">
      <caption>Completed before listing, by monthly capacity <span>out of {data.positives}</span></caption>
      <thead><tr><th scope="col">Ranking</th>{data.capacities.map(c => <th key={c.capacity} scope="col" className={c.capacity === 42 ? 'race-focus' : ''}>{c.capacity}<small>/mo</small></th>)}</tr></thead>
      <tbody>{focus.methods.map(method => <tr key={method.key} className={method.key === 'ours' ? 'race-table-ours' : ''}>
        <th scope="row">{method.name}</th>{data.capacities.map(c => <td key={c.capacity} className={c.capacity === 42 ? 'race-focus' : ''}>{c.methods.find(m => m.key === method.key)!.end.before}</td>)}
      </tr>)}</tbody>
    </table>
    <p className="race-bootstrap">At 42/month, Slow Burn is ahead in {share(bootstrap.ahead)} of month-block draws, tied in {share(bootstrap.tied)}, behind in {share(bootstrap.behind)}. Only 55 positives; this is noisy.</p>
    <p className="caption race-sensitivity">If the same fixes complete at month start: Slow Burn {focus.methods[3].start.before}, exploit-first {focus.methods[2].start.before} before listing.</p>
    <p className="caption race-limits">KEV dates can lag real attacks · equal effort per fix assumed · 2025 development data.</p>
    <ReadingDetails label="Full outcomes and timing sensitivity">
      <p>All {data.pool.toLocaleString('en-US')} CVEs join once with a frozen score; unused capacity expires and unfinished work carries over. The {data.excluded_first_month} listed within their publication month are outside this pool. “After” includes fixes on the listing date. Listed CVEs stay in the queue; their outcomes never affect priority. Days ahead is the median among fixes completed in time. CVSS is a retrospective reference.</p>
      <div className="identity-tabs race-timing" aria-label="Completion timing">
        <button aria-pressed={timing === 'end'} onClick={() => setTiming('end')}>Month end</button>
        <button aria-pressed={timing === 'start'} onClick={() => setTiming('start')}>Month start</button>
      </div>
      <div className="race-outcome-grid">{data.capacities.map(c => <div key={c.capacity}>
        <h3>{c.capacity} fixes/month</h3>
        <table className="race-outcomes"><caption className="sr-only">{c.capacity} monthly fixes, completed at month {timing}</caption>
          <thead><tr><th>Ranking</th><th>Before</th><th>After</th><th>Never</th><th>Days ahead<small>median</small></th></tr></thead>
          <tbody>{c.methods.map(m => <tr key={m.key}><th scope="row">{m.name}</th><td data-label="Before">{m[timing].before}</td><td data-label="After">{m[timing].after}</td><td data-label="Never">{m[timing].never}</td><td data-label="Median days">{m[timing].median_days_ahead ?? '—'}</td></tr>)}</tbody>
        </table>
        <p className="caption">{comparisonText(c, timing)} Bootstrap: {share(c.bootstrap[timing].ahead)} ahead, {share(c.bootstrap[timing].tied)} tied, {share(c.bootstrap[timing].behind)} behind.</p>
      </div>)}</div>
      <p className="caption">{data.uncertainty.iterations.toLocaleString('en-US')} paired draws of 12 snapshot months with replacement, seed {data.uncertainty.seed}. Dates stay fixed; repeated cohorts consume repeated capacity. Each draw reruns the backlog and compares with its best baseline. This excludes model-selection uncertainty.</p>
      <a className="text-link" href={`${import.meta.env.BASE_URL}data/race_2025.json`} download>Download all outcomes and assumptions</a>
    </ReadingDetails>
    <ReadingDetails label="Monthly chart values">
      <table className="race-monthly"><thead><tr><th>2025</th><th>Confirmed</th>{focus.methods.map(m => <th key={m.key}>{m.name}</th>)}</tr></thead>
        <tbody>{focus.methods[0].end.monthly.map((r, i) => <tr key={r.month}><th scope="row">{monthName(r.month)}</th><td>{r.confirmed}</td>{focus.methods.map(m => <td key={m.key}>{m.end.monthly[i].before}</td>)}</tr>)}</tbody>
      </table>
    </ReadingDetails>
  </section>;
}
