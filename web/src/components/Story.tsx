import type { Data, Findings } from "../types";
import { list, number, percent } from "../lib";
import { Icon } from "./Icon";

export function SectionHeading({
  index,
  title,
  detail,
}: {
  index: string;
  title: string;
  detail?: string;
}) {
  return (
    <div className="section-heading">
      <div className="section-title">
        <span className="section-index">{index}</span>
        <h2>{title}</h2>
      </div>
      {detail && <p>{detail}</p>}
    </div>
  );
}

export function Hero({ data }: { data: Data }) {
  const findings = data.findings;
  const ours = findings?.headline?.ours_hits_top500_2025_backtest;
  const baseline = list(data.backtest?.methods);
  const max = Math.max(
    1,
    ...baseline.map((item) => item.hits_at_500 ?? 0),
    ours ?? 0,
  );
  const seed = /seed/i.test(
    `${findings?._status ?? ""} ${data.backtest?._status ?? ""}`,
  );
  const benchmark = findings?.headline?.benchmark_2026_reference;
  const referenceHits = Object.values(benchmark ?? {}).filter(
    (n): n is number => typeof n === "number" && Number.isFinite(n),
  );
  const benchmarkRange = referenceHits.length
    ? `${Math.min(...referenceHits)}–${Math.max(...referenceHits)}`
    : "6–8";
  const first = findings?.two_clocks?.first_month;
  const total = findings?.two_clocks?.kev_2025_total;
  const firstPercent =
    first != null && total ? Math.round((first / total) * 100) : null;
  const lag = findings?.two_clocks?.later_lag_days?.median;
  return (
    <section id="overview" className="hero">
      <div className="hero-main">
        <div className="hero-copy">
          <h1>
            Severity isn’t
            <br />a forecast.
          </h1>
          <p className="hero-lead">
            It tells you how bad an attack could be.
            <br />
            <strong>We ask what attackers will target next.</strong>
          </p>
          <p className="hero-description">
            {firstPercent != null && lag != null ? (
              <>
                In the 2025 exploited cohort, <strong>{firstPercent}%</strong>{" "}
                enter KEV in their publication month. Later cases have a{" "}
                <strong>{number(lag)}-day</strong> median lag. That’s the window
                we prioritise.
              </>
            ) : (
              <>
                A fix-first queue built around the signals that precede
                exploitation, with evidence you can inspect before you act.
              </>
            )}
          </p>
          <a className="button primary" href="#queue">
            Explore the fix-first queue <Icon name="arrow" />
          </a>
          <a className="text-link" href="#timing">
            Start with the discovery <Icon name="down" size={15} />
          </a>
        </div>
        <div className="backtest-panel">
          <div className="panel-label">
            <span>2025 BACKTEST</span>
            <span className="badge">
              {!baseline.length && ours == null
                ? "Awaiting results"
                : seed
                  ? "Preliminary findings"
                  : "Historical validation"}
            </span>
          </div>
          <h2>
            Same 500 fixes.
            <br />
            Different outcomes.
          </h2>
          <div className="result-feature">
            <div className={`result-number ${ours == null ? "pending" : ""}`}>
              {number(ours)}
            </div>
            <div>
              <strong>Before the Breach</strong>
              <span>later KEV entries in the top 500</span>
            </div>
          </div>
          <div
            className="comparison"
            aria-label="2025 backtest hits in the top 500"
          >
            {baseline.length ? (
              baseline.map((method, i) => (
                <div className="comparison-row" key={`${method.name}-${i}`}>
                  <span>{method.name}</span>
                  <div className="bar-track">
                    <div
                      style={{
                        width: `${((method.hits_at_500 ?? 0) / max) * 100}%`,
                      }}
                    />
                  </div>
                  <strong>{number(method.hits_at_500)}</strong>
                </div>
              ))
            ) : (
              <p className="empty-inline">Baseline validation pending.</p>
            )}
          </div>
          <p className="caption">
            {findings?.headline?.positives_2025 != null &&
            findings?.headline?.pool_2025 != null
              ? `${number(findings.headline.positives_2025)} later KEV entries among ${number(findings.headline.pool_2025)} eligible CVEs.`
              : "Cohort counts pending."}{" "}
            Outcome cutoff: 31 Dec 2025.
          </p>
        </div>
      </div>
      <div className="benchmark-strip">
        <div>
          <span className="status-dot" />
          <strong>2026 benchmark</strong>
          <span>Result pending judging</span>
        </div>
        <p>
          Standard rankings find <strong>{benchmarkRange}</strong>{" "}
          later-exploited CVEs in their top 500.
        </p>
        <span className="mono">72,670 candidates</span>
      </div>
    </section>
  );
}

export function Timing({ findings }: { findings?: Findings | null }) {
  const clock = findings?.two_clocks;
  const first = clock?.first_month;
  const later = clock?.later;
  const total = clock?.kev_2025_total;
  const fraction = first != null && total ? first / total : null;
  const laterFraction = later != null && total ? later / total : null;
  const histogram = list(clock?.lag_hist);
  const histMax = Math.max(1, ...histogram.map((bin) => bin.n));
  return (
    <section id="timing" className="story-section timing">
      <SectionHeading
        index="01"
        title="Two clocks. Two defences."
        detail="2025 discovery · time to KEV inclusion"
      />
      <div className="timing-layout">
        <div className="timing-copy">
          <h3>
            The first month is a race.
            <br />
            The next is a window.
          </h3>
          <p>
            Most confirmed cases arrive in the publication month. For the rest,
            prioritisation can buy a security team time to act.
          </p>
          <p className="caption">
            KEV inclusion is an observed proxy, not the date of the first
            attack. A calendar-month boundary can be just a few days away.
          </p>
        </div>
        <div className="timing-chart">
          <div className="clock-numbers">
            <div>
              <span
                className={`metric accent ${fraction == null ? "metric-pending" : ""}`}
              >
                {fraction == null
                  ? "pending"
                  : `${Math.round(fraction * 100)}%`}
              </span>
              <strong>In the first month</strong>
              <span>
                {first != null && total != null
                  ? `${number(first)} of ${number(total)} KEV entries`
                  : "Cohort counts pending"}
              </span>
            </div>
            <div>
              <span
                className={`metric ${clock?.later_lag_days?.median == null ? "metric-pending" : ""}`}
              >
                {number(clock?.later_lag_days?.median)}
                {clock?.later_lag_days?.median != null && <small> days</small>}
              </span>
              <strong>Median lag for later entries</strong>
              <span>
                {later != null
                  ? `${number(later)} vulnerabilities · ${percent(laterFraction, 0)} of cases`
                  : "Later-entry analysis pending"}
              </span>
            </div>
          </div>
          {fraction != null ? (
            <svg
              className="clock-bar"
              viewBox="0 0 600 52"
              role="img"
              aria-label={`${Math.round(fraction * 100)} percent first month, ${number(later)} later entries`}
            >
              <rect width="600" height="52" fill="var(--line-bright)" />
              <rect width={600 * fraction} height="52" fill="var(--accent)" />
              {Array.from({ length: 29 }, (_, i) => (
                <line
                  key={i}
                  x1={(i + 1) * 20}
                  x2={(i + 1) * 20}
                  y1="0"
                  y2="52"
                  stroke="var(--bg)"
                  strokeWidth="3"
                />
              ))}
            </svg>
          ) : (
            <p className="empty-inline">Timing analysis pending.</p>
          )}
          <div className="clock-actions">
            <span>
              <span className="legend-square accent-bg" />
              Patch speed is critical
            </span>
            <span>
              <span className="legend-square" />
              Prioritisation buys a window
            </span>
          </div>
          {histogram.length > 0 && (
            <div className="histogram" aria-label="KEV lag distribution">
              {histogram.map((bin) => (
                <div key={bin.bucket}>
                  <span>{number(bin.n)}</span>
                  <div
                    style={{
                      height: `${Math.max(2, (bin.n / histMax) * 56)}px`,
                    }}
                  />
                  <small>{bin.bucket}</small>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
      <div className="section-takeaway">
        <Icon name="arrow" />
        <p>
          Prediction has a job to do:{" "}
          <strong>use the window before the breach.</strong>
        </p>
      </div>
    </section>
  );
}

export function Signals({ findings }: { findings?: Findings | null }) {
  const signals = list(findings?.signals);
  const lowMax = Math.max(
    1,
    ...signals.filter((s) => s.leak_risk === "low").map((s) => s.lift ?? 0),
  );
  return (
    <section id="signals" className="story-section signals-section">
      <SectionHeading
        index="02"
        title="Find the signal. Question the shortcut."
        detail="2025 cohort · association, not causation"
      />
      <div className="signals-layout">
        <div className="signals-chart">
          <div className="chart-head">
            <span>Signal in the supplied record</span>
            <span>Lift over base rate</span>
            <span>Later KEV / CVEs</span>
          </div>
          {signals.length ? (
            signals.map((signal, index) => {
              const risky = signal.leak_risk !== "low";
              return (
                <div
                  className={`signal-row ${risky ? "risk-row" : ""}`}
                  key={index}
                >
                  <div>
                    <strong>{signal.name ?? "Unnamed signal"}</strong>
                    <span className={`risk-label ${risky ? "risk" : ""}`}>
                      {risky && <Icon name="warning" size={12} />}{" "}
                      {signal.leak_risk ?? "unknown"} leak risk
                    </span>
                  </div>
                  <div className="signal-bar-cell">
                    <div className="signal-bar-track">
                      <div
                        className={risky ? "risk-bar" : ""}
                        style={{
                          width: `${Math.min(100, ((signal.lift ?? 0) / lowMax) * 100)}%`,
                        }}
                      />
                    </div>
                    <strong>
                      {number(signal.lift, 1)}
                      <small>×</small>
                    </strong>
                  </div>
                  <span className="mono signal-count">
                    {number(signal.hits)} <span>/ {number(signal.n)}</span>
                  </span>
                </div>
              );
            })
          ) : (
            <p className="empty-inline">Signal analysis pending.</p>
          )}
          <p className="caption">
            Base rate: {percent(findings?.base_rate_2025, 3)}. Bars scaled to
            low-risk signals; hatched bars exceed that scale. Description
            wording can be updated after an attack.
          </p>
        </div>
        <aside className="deprioritize">
          <span className="eyebrow">ALSO KNOW WHAT TO DEPRIORITISE</span>
          {list(findings?.deprioritize).length ? (
            list(findings?.deprioritize).map((item, i) => (
              <div key={i}>
                <h3>{item.name}</h3>
                <div className="deprioritize-number">
                  {number(item.hits)}
                  <span>later KEV entries</span>
                </div>
                <p>
                  Across <strong>{number(item.n)}</strong> vulnerabilities in
                  the eligible 2025 cohort
                  {item.share_of_pool != null
                    ? ` — ${percent(item.share_of_pool)} of the queue`
                    : ""}
                  .
                </p>
              </div>
            ))
          ) : (
            <p>Deprioritisation analysis pending.</p>
          )}
          <p className="caption">
            No observed KEV entry does not mean no attacks. Reduce queue noise;
            retain an exposure check.
          </p>
          <div className="aside-bottom">
            <Icon name="shield" />
            <span>
              Fewer distractions.
              <br />
              <strong>More attention where it counts.</strong>
            </span>
          </div>
        </aside>
      </div>
    </section>
  );
}

export function Methods({ data }: { data: Data }) {
  const card = data.model_card;
  return (
    <section id="methods" className="story-section methods">
      <SectionHeading
        index="04"
        title="The boundary is part of the model."
        detail="Reproducible decisions · explicit limits"
      />
      <div className="methods-grid">
        <div>
          <span className="eyebrow">USED BY THE CURRENT MODEL</span>
          <h3>{card?.model ?? "Model pending"}</h3>
          {card?.trained_on && <p>{card.trained_on}</p>}
          <div className="feature-list">
            {list(card?.features_used).map((feature) => (
              <span className="chip" key={feature}>
                {feature}
              </span>
            ))}
          </div>
          {!list(card?.features_used).length && (
            <p className="caption">
              Feature inventory pending the final model card.
            </p>
          )}
        </div>
        <div>
          <span className="eyebrow">EXCLUDED & WHY</span>
          {list(card?.features_excluded).length ? (
            list(card?.features_excluded).map((item) => (
              <p className="excluded-feature" key={item.name}>
                <code>{item.name}</code>
                <span>{item.why}</span>
              </p>
            ))
          ) : (
            <p>
              Final exclusions pending. The benchmark rules identify NVD status,
              enrichment counts, missing severity, and retrospective references
              as leakage risks.
            </p>
          )}
        </div>
        <div className="ibm-method">
          <span className="eyebrow">BUILT AROUND IBM GRANITE</span>
          <h3>
            Language into signals.
            <br />
            Evidence into action.
          </h3>
          <p>
            Granite embeddings for prioritisation.
            <br />
            Granite language model for briefings.
          </p>
          {list(card?.ibm_technology).length ? (
            <div className="feature-list">
              {list(card?.ibm_technology).map((tech) => (
                <span className="chip" key={tech}>
                  {tech}
                </span>
              ))}
            </div>
          ) : (
            <span className="badge">Model integration pending</span>
          )}
          <p className="caption">
            {data.meta?.runs_source === "fixtures"
              ? "Briefings currently use illustrative fixtures. No model inference is claimed for these runs."
              : "Recorded briefings identify their inference model in the review panel."}
          </p>
        </div>
      </div>
      <div className="method-footnote">
        <Icon name="shield" size={17} />
        <p>
          2026 rankings use each row’s snapshot month. Historical KEV labels
          stop at 31 Dec 2025. No post-snapshot exploitation feed is used.
        </p>
        <span className="mono">2026 outcome: pending</span>
      </div>
      {data.backtest?.pool && (
        <details className="validation-details">
          <summary>Validation cohort and limitations</summary>
          <p>{data.backtest.pool}</p>
          {data.backtest.label && <p>{data.backtest.label}</p>}
          <p>
            EPSS changed its model in March 2025. February 2025 signal coverage
            is incomplete. NVD descriptions and severity may be revised after
            publication. Missing evidence is not a negative label.
          </p>
          {list(data.backtest?.ablations).map((item) => (
            <p key={item.name}>
              {item.name}: <strong>{number(item.hits_at_500)}</strong> hits at
              500
            </p>
          ))}
        </details>
      )}
    </section>
  );
}
