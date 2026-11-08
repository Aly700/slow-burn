import { useState } from "react";
import type { BlindSpotStudyData } from "../types";
import type { ProductWatchRow } from "../productWatch";
import { matchSupport } from "../productWatch";
import { number, percent } from "../lib";
import "../productWatch.css";
export function ProductWatch({ rows, choices, loading, error, retry, loose, onLoose, study }: {
  rows: ProductWatchRow[]; choices: number; loading: boolean; error: boolean; retry: () => void;
  loose: boolean; onLoose: (value: boolean) => void; study?: BlindSpotStudyData | null;
}) {
  const [page, setPage] = useState(0);
  const size = 4, pages = Math.ceil(rows.length / size), current = Math.min(page, Math.max(0, pages - 1));
  const history = study?.product_watch?.historical_2025;
  return <section className="product-watch" aria-label="Previously attacked products, no public exploit yet">
    <div className="watch-heading"><div><span className="eyebrow">A SECOND LOOK / PRODUCT HISTORY</span><h4>Previously attacked products,<br className="watch-break" /> no public exploit yet</h4></div><div className="watch-count"><strong>{choices ? loading ? "…" : error ? "—" : number(rows.length) : "—"}</strong><span>matching review candidates</span></div></div>
    <p className="watch-context">In 2025, this kind of list held <strong>{number(history?.positives)} of {number(history?.no_signal_positives)}</strong> later-exploited bugs with no public exploit signal — about <strong>{number(history?.lift, 1)}×</strong> the base rate. A review list for products you run, not a prediction.</p>
    <label className="watch-toggle"><input type="checkbox" checked={loose} onChange={event => { onLoose(event.target.checked); setPage(0); }} /> Include looser name matches <span>Product name alone; vendor may be wrong.</span></label>
    {!choices ? <p className="watch-empty">Choose your stack above to find products worth a closer look.</p> : loading ? <p className="watch-empty" role="status">Loading the product review list…</p> : error ? <p className="watch-empty" role="status">The review list could not load. <button onClick={retry}>Try again</button></p> : !rows.length ? <p className="watch-empty">No supported product matches for this stack. This does not establish that your products are safe.</p> : <>
      <div className="watch-rows">{rows.slice(current * size, (current + 1) * size).map(row => <article className="watch-row" key={row.cve_id}>
        <div className="watch-identity"><strong>{row.vendor} <span>· {row.product}</span></strong><span className="mono">{row.cve_id}</span><small className={row.match_confidence === "product_alias_only" ? "loose" : ""}>{matchSupport[row.match_confidence] ?? "Match support unavailable"}</small></div>
        <div className="watch-history"><span><b>{number(row.prior_kev_count)}</b> prior KEV entries</span><small>Latest prior: <span className="mono">{row.latest_prior_kev_cve || "pending"}</span><br />{row.latest_prior_kev_date || "pending"}</small></div>
        <div className="watch-epss"><span>EPSS <b>{percent(row.epss, 2)}</b></span><small>{row.snapshot_month || "Snapshot pending"}</small></div>
        <p className="watch-description">{row.description || "Description pending"}</p>
      </article>)}</div>
      <div className="watch-footer"><span>{number(current * size + 1)}–{number(Math.min((current + 1) * size, rows.length))} of {number(rows.length)} · prior KEV count, then EPSS · all matches included in Export below</span><div><button disabled={!current} onClick={() => setPage(current - 1)}>Previous</button><button disabled={current + 1 >= pages} onClick={() => setPage(current + 1)}>Next →</button></div></div>
    </>}
    <p className="watch-note">Names are heuristic matches; confirm assets and affected versions. History ends at the snapshot or the end of 2025, whichever is earlier. “No public exploit” includes missing snapshot observations.</p>
  </section>;
}
