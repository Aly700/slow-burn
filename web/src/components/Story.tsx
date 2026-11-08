import { ReadingDetails } from "./ReadingDetails";
import { SectionHeading } from "./SectionHeading";
import { AttackResults } from "./AttackResults";
import type { Data, Findings } from "../types";
import { list, number, percent } from "../lib";
import { Replay } from "./Replay";
import { Icon } from "./Icon";

export function Hero({ data }: { data: Data }) {
  return (
    <section id="overview" className="hero replay-hero">
      <div className="replay-intro">
        <h1>Severity isn’t a forecast.</h1>
        <p>
          Same fix budget. A year of consequences.
          <br />
          <strong>Watch what each ranking catches.</strong>
        </p>
      </div>
      <Replay data={data.replay_2025} />
      <div className="benchmark-strip">
        <div>
          <span className="status-dot" />
          <strong>2026 benchmark</strong>
          <span>Result pending judging</span>
        </div>
        <a className="text-link" href="#queue">
          Explore your fix-first queue <Icon name="arrow" size={16} />
        </a>
        <span className="mono">Snapshot-bound ranking</span>
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
        index="01" label="Timing"
        title="Two clocks. Two defences."
        detail="2025 discovery · time to KEV inclusion"
      />
      <div className="timing-layout">
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
              preserveAspectRatio="none"
              viewBox="0 0 600 52"
              role="img"
              aria-label={`${Math.round(fraction * 100)} percent first month, ${number(later)} later entries`}
            >
              <rect width="600" height="52" fill="var(--accent-dim)" />
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
      <p className="caption reading-caution">KEV inclusion is an observed proxy, not the date of the first attack.</p>
      <ReadingDetails label="How we measured">
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
            A calendar-month boundary can be just a few days away.
          </p>
        </div>
      </ReadingDetails>
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
  const signalRow = (signal: (typeof signals)[number], index: number) => {
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
            };
  const featuredSignals = signals.filter(signal => /^(any[_ ]exploit|exploitdb|metasploit|nuclei|poc_github)|^Vendor has earlier|^Current description mentions|^WordPress wording/i.test(signal.name ?? ""));
  return (
    <section id="signals" className="story-section signals-section">
      <SectionHeading
        index="02" label="Signals"
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
            featuredSignals.map(signalRow)
          ) : (
            <p className="empty-inline">Signal analysis pending.</p>
          )}
          <ReadingDetails label={`All ${signals.length} signals`}>
            {signals.map(signalRow)}
          </ReadingDetails>
          <p className="caption">
            Base rate: {percent(findings?.base_rate_2025, 3)}. Bars scaled to
            low-risk signals; hatching marks revision risk. Description wording
            can be updated after an attack.
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
                <ReadingDetails label="WordPress context and limits">
                <p>
                  Across <strong>{number(item.n)}</strong> vulnerabilities in
                  the eligible 2025 cohort
                  {item.share_of_pool != null
                    ? `, ${percent(item.share_of_pool)} of the queue`
                    : ""}
                  .
                </p>
                  <p>Reduce queue noise; retain an exposure check.</p>
                  <div className="aside-bottom"><Icon name="shield" /><span>Fewer distractions.<br /><strong>More attention where it counts.</strong></span></div>
                </ReadingDetails>
              </div>
            ))
          ) : (
            <p>Deprioritisation analysis pending.</p>
          )}
          <p className="caption">
            No observed KEV entry does not mean no attacks.
          </p>

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
        index="08" label="Methods"
        title="The boundary is part of the model."
        detail="Reproducible decisions · explicit limits"
      />
      <AttackResults evaluation={data.redteam_eval} reading />
      <ReadingDetails label="Model, features and exclusions">
      <div className="methods-grid">
        <div>
          <span className="eyebrow">USED BY THE CURRENT MODEL</span>
          <h3>{card?.model ?? "Model pending"}</h3>
          {card?.trained_on && <p>{card.trained_on}</p>}
          <div className="feature-list">
            {list(card?.features_used)
              .slice(0, 14)
              .map((feature) => (
                <span className="chip" key={feature}>
                  {feature}
                </span>
              ))}
          </div>
          {list(card?.features_used).length > 14 && (
            <details className="method-inventory">
              <summary>
                All {number(list(card?.features_used).length)} model features
              </summary>
              <div className="feature-list">
                {list(card?.features_used)
                  .slice(14)
                  .map((feature) => (
                    <span className="chip" key={feature}>
                      {feature}
                    </span>
                  ))}
              </div>
            </details>
          )}
          {!list(card?.features_used).length && (
            <p className="caption">
              Feature inventory pending the final model card.
            </p>
          )}
        </div>
        <div>
          <span className="eyebrow">EXCLUDED & WHY</span>
          {list(card?.features_excluded).length ? (
            list(card?.features_excluded)
              .slice(0, 4)
              .map((item) => (
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
          {list(card?.features_excluded).length > 4 && (
            <details className="method-inventory">
              <summary>
                All {number(list(card?.features_excluded).length)} exclusions
                and reasons
              </summary>
              {list(card?.features_excluded)
                .slice(4)
                .map((item) => (
                  <p className="excluded-feature" key={item.name}>
                    <code>{item.name}</code>
                    <span>{item.why}</span>
                  </p>
                ))}
            </details>
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
            {data.agent_eval?.model ?? "Briefing model pending"}
            <br />
            Model technologies are listed from the current model card.
          </p>
          {list(card?.ibm_technology).length ? (
            <div className="feature-list">
              {list(card?.ibm_technology).map((tech) => (
                <p className="technology-detail" key={tech}>
                  {tech}
                </p>
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
      </ReadingDetails>
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
          <summary>Development cohort and limitations</summary>
          {list(card?.limitations).map((limit, i) => (
            <p key={i}>{limit}</p>
          ))}
          <p>{data.backtest.pool}</p>
          {data.backtest.label && <p>{data.backtest.label}</p>}
          {card?.score_interpretation && <p>{card.score_interpretation}</p>}
          {card?.description_policy?.sanitization && (
            <p>{card.description_policy.sanitization}</p>
          )}
          {card?.description_policy?.residual_risk && (
            <p>{card.description_policy.residual_risk}</p>
          )}
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
