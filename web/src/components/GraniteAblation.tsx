import type { Data } from '../types';
import { number } from '../lib';
import '../graniteAblation.css';
interface Method {key: string; name: string; hits: number[]; seed_range: [number,number][]}
interface Split {split: string; pool: number; positives: number; methods: Method[]}
export interface GraniteAblationData {budgets: number[]; design_commit: string; splits: Split[]}
export function smallBudgetLine(data?: GraniteAblationData) {
  const methods = data?.splits[0]?.methods;
  if (!methods) return '';
  const hits = (key: string) => methods.find(m=>m.key === key)?.hits[0];
  return `In the first 50 picks: Slow Burn ${hits('ours')}, exploit-first ${hits('rule')}, EPSS ${hits('epss')}, CVSS ${hits('cvss')}`;
}
export function graniteResult(data?: GraniteAblationData) {
  if (!data) return '';
  const hits = (split: number,key: string) => data.splits[split].methods.find(m=>m.key === key)!.hits[3];
  return `At 500 picks, Granite on / off found ${hits(0,'ours')} / ${hits(0,'without_granite')} in full-year 2025 and ${hits(1,'ours')} / ${hits(1,'without_granite')} in the second split. No consistent gain across budgets and splits.`;
}
export function graniteMapLine(data?: GraniteAblationData) {
  if (!data) return '';
  const count = (split: number, key: string) => data.splits[split].methods.find(m=>m.key === key)!.hits[3];
  return `Granite on/off: ${count(0,'ours')}/${count(0,'without_granite')} hits at 500 in full-year 2025; ${count(1,'ours')}/${count(1,'without_granite')} in the second split.`;
}
export function GraniteAblation({data}: {data: Data}) {
  const study = data.granite_ablation_2025;
  if (!study) return null;
  const names: Record<string,string> = {ours:'Slow Burn',without_granite:'Without Granite',rule:'Exploit-first',epss:'EPSS',cvss:'CVSS'};
  function table(split: Split) {
    return <table className="ablation-table">
      <caption>{split.split === '2024_to_2025' ? 'Full-year 2025' : 'July–September 2025'} · {number(split.pool)} CVEs · {split.positives} later KEV entries</caption>
      <thead><tr><th scope="col">Ranking</th>{study!.budgets.map(k=><th scope="col" key={k}>{k}</th>)}</tr></thead>
      <tbody>{split.methods.map(method=><tr key={method.key} className={method.key === 'ours' ? 'ablation-selected' : ''}>
        <th scope="row">{names[method.key]}</th>{method.hits.map((hits,i)=><td key={i}><strong>{hits}</strong>{['ours','without_granite'].includes(method.key) && <small>{method.seed_range[i][0]}–{method.seed_range[i][1]}</small>}</td>)}
      </tr>)}</tbody>
    </table>;
  }
  return <div className="granite-ablation" id="granite-ablation">
    <span className="eyebrow">POST-EVENT COMPARISON</span>
    <h3>Granite on and off</h3>
    <p>{graniteResult(study)}</p>
    {table(study.splits[0])}
    <p className="ablation-key">Hits at each review budget, seed 2026. Smaller figures show the five-seed range (2026–2030). Baselines are fixed.</p>
    <details className="reading-details"><summary>Second forward split</summary>{table(study.splits[1])}</details>
    <p className="ablation-limits">Same selected LightGBM configuration, cutoffs and splits; only the 24 Granite embedding features removed. Keywords and history stay. These are development comparisons with overlapping test periods, current description revision risk and late-year censoring. Seed ranges measure fitting variability, not confidence intervals. The submission is unchanged.</p>
    <p className="ablation-provenance">Design fixed before the run: <code>{study.design_commit.slice(0,7)}</code>. <a href={`${import.meta.env.BASE_URL}data/granite_ablation_2025.json`} download>Download results</a></p>
  </div>;
}
