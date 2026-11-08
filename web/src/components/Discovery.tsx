import { ReadingDetails } from "./ReadingDetails";
import { useState } from "react";
import type { Data, Findings, Run } from "../types";
import { list, number, percent } from "../lib";
import { evaluationArms } from "../storyData";
import { SectionHeading } from "./SectionHeading";
import { Icon } from "./Icon";
import { blindSpotSummary } from "../blindSpot";
import { BlindSpotStudy, WatchMethods } from "./BlindSpotStudy";

export function BlindSpot({ findings }: { findings?: Findings | null }) {
  const headline = findings?.headline;
  const study = blindSpotSummary(findings?.blind_spot);
  const unseen = findings?.blind_spot
    ? study.unseen
    : headline?.later_kev_without_public_signal;
  const seen = findings?.blind_spot
    ? study.seen
    : headline?.later_kev_with_public_signal;
  const total = findings?.blind_spot
    ? study.total
    : unseen != null && seen != null
      ? unseen + seen
      : headline?.positives_2025;
  return (
    <div className="blind-spot">
      <div className={`blind-number ${unseen == null ? "is-pending" : ""}`}>
        <strong>{number(unseen)}</strong>
        <span>of {number(total)}</span>
      </div>
      <h3>
        Later-exploited CVEs had
        <br />
        no public exploit signal.
      </h3>
      <p>
        At their snapshot, exploit feeds gave no warning. A missing exploit flag
        is not evidence of safety.
      </p>
      <div className="blind-legend">
        <span className="legend-square accent-bg" />
        No public signal: {number(unseen)}
        <span className="legend-square" />
        Public signal: {number(seen)}
      </div>
      {unseen != null && total != null && total > 0 && (
        <div
          className="blind-bar"
          role="img"
          aria-label={`${number(unseen)} of ${number(total)} had no public exploit signal`}
        >
          <span style={{ width: `${(unseen / total) * 100}%` }} />
        </div>
      )}
      <p className="caption">
        Eligible {study.year ?? "historical"} cohort · signals measured at the
        snapshot. Missing observations also count as no signal.
      </p>
    </div>
  );
}

export function VendorHistory({ findings }: { findings?: Findings | null }) {
  const cohort = findings?.vendor_history_within_poc;
  const allBuckets = list(cohort?.buckets);
  const identities = [
    ...new Set(allBuckets.map((bucket) => bucket.identity ?? "vendor")),
  ];
  const [selectedIdentity, setSelectedIdentity] = useState("vendor");
  const identity = identities.includes(selectedIdentity)
    ? selectedIdentity
    : identities[0];
  const buckets = allBuckets.filter(
    (bucket) => (bucket.identity ?? "vendor") === identity,
  );
  const max = Math.max(0.001, ...buckets.map((bucket) => bucket.rate ?? 0));
  return (
    <div className="vendor-history">
      {identities.length > 1 && (
        <div className="identity-tabs" aria-label="History identity">
          {identities.map((item) => (
            <button
              key={item}
              aria-pressed={identity === item}
              onClick={() => setSelectedIdentity(item)}
            >
              {item} history
            </button>
          ))}
        </div>
      )}
      <div className="chart-head">
        <span>Earlier KEV entries</span>
        <span>Later KEV rate</span>
        <span>Hits / CVEs</span>
      </div>
      {buckets.length ? (
        buckets.map((bucket, index) => (
          <div className="vendor-row" key={`${bucket.identity}-${index}`}>
            <div>
              <strong>{bucket.earlier_kev_bucket ?? "pending"}</strong>
              {bucket.identity && <small>{bucket.identity}</small>}
            </div>
            <div className="vendor-bar">
              <span
                style={{
                  width: `${Math.max(0, ((bucket.rate ?? 0) / max) * 100)}%`,
                }}
              />
              <strong>{percent(bucket.rate, 1)}</strong>
            </div>
            <span className="mono">
              {number(bucket.hits)} / {number(bucket.n)}
            </span>
          </div>
        ))
      ) : (
        <div className="analysis-pending">
          <span className="eyebrow">
            VENDOR HISTORY WITHIN PUBLIC-EXPLOIT TIER
          </span>
          <strong>pending</strong>
          <p>Rates will appear when the cohort analysis is ready.</p>
        </div>
      )}
      <p className="caption">
        Within the public-exploit tier: {number(cohort?.positives)} later KEV
        entries / {number(cohort?.pool)} CVEs. Base rate{" "}
        {percent(cohort?.base_rate, 2)}. Description-based identity carries
        revision and matching risk.
      </p>
    </div>
  );
}
export function WordPress({ findings }: { findings?: Findings | null }) {
  const item = list(findings?.deprioritize).find((item) =>
    /wordpress/i.test(item.name ?? ""),
  );
  return (
    <div className="wordpress-finding">
      <div>
        <strong>{number(item?.hits)}</strong>
        <span>later KEV entries</span>
      </div>
      <p>
        <b>{number(item?.n)} WordPress CVEs.</b>
        <br />A large queue does not imply a high observed attack rate.
      </p>
      <small>No observed KEV entry does not mean no attacks.</small>
    </div>
  );
}
export function LagHistogram({ findings }: { findings?: Findings | null }) {
  const bins = list(findings?.two_clocks?.lag_hist);
  const max = Math.max(1, ...bins.map((bin) => bin.n ?? 0));
  return (
    <div className="lag-chart">
      <span className="eyebrow">
        LATER ENTRIES · DAYS FROM PUBLICATION TO KEV
      </span>
      {bins.length ? (
        <div className="lag-bars">
          {bins.map((bin, i) => (
            <div key={i}>
              <strong>{number(bin.n)}</strong>
              <div className="lag-track">
                <span style={{ height: `${((bin.n ?? 0) / max) * 100}%` }} />
              </div>
              <span>{bin.bucket}</span>
            </div>
          ))}
        </div>
      ) : (
        <div className="lag-pending">
          Lag histogram <strong>pending</strong>
        </div>
      )}
    </div>
  );
}
export function Discovery({ findings }: { findings?: Findings | null }) {
  return (
    <section id="discovery" className="story-section deeper-discovery">
      <SectionHeading
        index="03" label="Blind spot"
        title="The blind spot. And the repeat offenders."
        detail="What an exploit feed alone misses"
      />
      <div className="discovery-blind-grid">
        <BlindSpot findings={findings} />
        <BlindSpotStudy findings={findings} reading />
      </div>
      <ReadingDetails label="How we measured the blind spot">
        <WatchMethods findings={findings} />
      </ReadingDetails>
      <ReadingDetails label="Vendor history inside the exploit tier">
      <div className="discovery-vendor-block">
        <div>
          <span className="eyebrow">AFTER PUBLIC EXPLOIT CODE APPEARS</span>
          <h3>Vendor history helps inside the exploit tier.</h3>
          <VendorHistory findings={findings} />
        </div>
      </div>
      </ReadingDetails>
      {list(findings?.story).length > 0 && (
        <ReadingDetails label="Five findings and supporting counts">
        <div className="finding-stories">
          {list(findings?.story).map((story, i) => (
            <article key={i}>
              <h3>{story.title}</h3>
              <p>{story.sentence?.replaceAll("—", ", ")}</p>
              {story.numbers && (
                <details className="story-counts">
                  <summary>Inspect supporting counts</summary>
                  <dl>
                    {Object.entries(story.numbers).map(([key, value]) => (
                      <div key={key}>
                        <dt>{key.replaceAll("_", " ")}</dt>
                        <dd>
                          {typeof value === "number"
                            ? number(value, 2)
                            : value == null
                              ? "pending"
                              : String(value)}
                        </dd>
                      </div>
                    ))}
                  </dl>
                </details>
              )}
            </article>
          ))}
        </div>
        </ReadingDetails>
      )}
    </section>
  );
}
export function EvalComparison({ data, reading = false }: { data: Data; reading?: boolean }) {
  const evaluation = data.agent_eval;
  return (
    <div className="eval-comparison">
      <div className="eval-label">
        <span className="eyebrow">THREE-ARM BRIEFING EVALUATION</span>
        <span>{number(evaluation?.cases)} cases</span>
      </div>
      <div className="eval-arms">
        {evaluationArms(data).map((arm) => (
          <div
            key={arm.id}
            className={arm.id === evaluation?.active_arm ? "active-arm" : ""}
          >
            <span className="eval-arm-label">
              {arm.id === "template"
                ? "Reasons-only template"
                : arm.id === "granite_decides"
                  ? "Granite decides"
                  : arm.id === "policy_granite"
                    ? "Policy decides + Granite briefs"
                    : arm.name}
            </span>
            <strong>{percent(arm.observed_outcome_accuracy, 0)}</strong>
            <span>observed-outcome accuracy</span>
            <b>{percent(arm.history_or_analogy_coverage, 0)}</b>
            <span>history / analogy coverage</span>
            {arm.id === evaluation?.active_arm && (
              <small>ACTIVE APPROACH</small>
            )}
          </div>
        ))}
      </div>
      {reading && <p className="caption reading-caution">Small, balanced historical evaluation.</p>}
      <ReadingDetails label="Evaluation limits" collapsed={reading}>
      <p className="caption">
        {!reading && <>Small, balanced historical evaluation. </>}The revision reuses the same
        cases after earlier results were known; this is not an unseen validation
        or the ranking backtest.
      </p>
      </ReadingDetails>
    </div>
  );
}
export function AgentSection({
  data,
  run,
  onOpen,
}: {
  data: Data;
  run?: Run;
  onOpen: () => void;
}) {
  return (
    <section id="agent" className="story-section agent-section">
      <SectionHeading
        index="07" label="Briefing"
        title="Let policy decide. Let Granite explain."
        detail="Evidence checked before a human acts"
      />
      <div className="agent-section-grid">
        <div>
          <span className="eyebrow">IBM GRANITE · RECORDED INVESTIGATION</span>
          <h3>{run?.briefing?.headline ?? "Briefing pending"}</h3>
          <p>
            Every delivered claim links to a tool result. The final action waits
            for your approval.
          </p>
          <p className="caption mono">
            {run?.cve_id ?? "pending"} ·{" "}
            {number(run?.verifier?.claims_verified)} verified claims
          </p>
          <button className="button primary" onClick={onOpen} disabled={!run}>
            Inspect the briefing <Icon name="arrow" />
          </button>
        </div>
        <EvalComparison data={data} reading />
      </div>
      {!!list(data.agent_eval?.limitations).length && (
        <details className="validation-details">
          <summary>Evaluation methods and limitations</summary>
          <p>
            Snapshot: {data.agent_eval?.snapshot_end ?? "pending"} · outcome
            cutoff: {data.agent_eval?.outcome_end ?? "pending"}
          </p>
          {list(data.agent_eval?.limitations).map((limitation, i) => (
            <p key={i}>{limitation}</p>
          ))}
        </details>
      )}
    </section>
  );
}
