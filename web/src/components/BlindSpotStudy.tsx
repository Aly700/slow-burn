import { ReadingDetails } from "./ReadingDetails";
import type { Findings } from "../types";
import { blindSpotSummary } from "../blindSpot";
import { number, percent, list } from "../lib";
import "../blind-spot.css";

const plan =
  "https://github.com/Aly700/slow-burn/blob/main/pipeline/WATCH_PLAN.md";
const known = (value: unknown): value is number =>
  typeof value === "number" && Number.isFinite(value);
const lift = (value: unknown) =>
  typeof value === "number" && Number.isFinite(value)
    ? `${value.toFixed(1)}×`
    : "pending";

export function BlindSpotStudy({ findings, reading = false }: { findings?: Findings | null; reading?: boolean }) {
  const s = blindSpotSummary(findings?.blind_spot);
  const noGain = s.result?.hits === 0 && s.epss?.hits === 0;
  if (!s.result && !s.epss && !s.product)
    return (
      <div className="blind-study analysis-pending">
        <span className="eyebrow">NO-SIGNAL STUDY</span>
        <strong>pending</strong>
        <p>
          The model test and product-history comparison will appear when the
          study results are available.
        </p>
      </div>
    );
  const experiment = (
      <div className="watch-experiment">
        <span className="eyebrow">
          {s.registered
            ? "PRE-REGISTERED WATCH MODEL"
            : "WATCH MODEL · REGISTRATION PENDING"}
          {" · "}
          {s.year ?? "pending"} TEST
        </span>
        <div className="watch-results" aria-label="Watch model test results">
          <div>
            <span>Dedicated model</span>
            <strong className={known(s.result?.hits) ? "" : "is-pending"}>
              {number(s.result?.hits)}
              {known(s.result?.hits) && <small> / {number(s.positives)}</small>}
            </strong>
            <span>later cases found</span>
          </div>
          <div>
            <span>EPSS first</span>
            <strong className={known(s.epss?.hits) ? "" : "is-pending"}>
              {number(s.epss?.hits)}
              {known(s.epss?.hits) && <small> / {number(s.positives)}</small>}
            </strong>
            <span>later cases found</span>
          </div>
          <div>
            <span>Chance</span>
            <strong
              className={
                known(s.result?.random_expected_hits) ? "" : "is-pending"
              }
            >
              {number(s.result?.random_expected_hits, 2)}
            </strong>
            <span>expected hits</span>
          </div>
        </div>
        <p className="watch-test-note">
          {number(s.budget)} reviewed in the same no-signal pool.{" "}
          {noGain
            ? "No demonstrated gain."
            : "Compare observed hits with chance."}
        </p>
      </div>
  );
  return (
    <div className="blind-study">
      {!reading && experiment}
      <div className="product-contrast">
        <div className="contrast-heading">
          <h3>
            {known(s.product?.lift) && s.product.lift > 1
              ? "Previously attacked product matches"
              : "Product-history comparison."}
          </h3>
          <strong className={known(s.product?.lift) ? "" : "is-pending"}>
            {lift(s.product?.lift)}
            <small>base rate</small>
          </strong>
        </div>
        <p className="contrast-count">
          <b>
            {number(s.product?.no_signal_positives)} of {number(s.unseen)}
          </b>{" "}
          later cases matched a previously attacked product.
        </p>
        <div
          className="history-shares"
          aria-label="Previously attacked product share"
        >
          {[
            { label: "Among later cases", share: s.product?.positive_share },
            {
              label: "Across the no-signal pool",
              share: s.product?.pool_share,
            },
          ].map(({ label, share }) => (
            <div className="history-share" key={label}>
              <span>{label}</span>
              <div className="history-share-track" aria-hidden="true">
                <span
                  style={{
                    width:
                      typeof share === "number" && Number.isFinite(share)
                        ? `${Math.max(0, Math.min(1, share)) * 100}%`
                        : "0%",
                  }}
                />
              </div>
              <strong className={known(share) ? "" : "is-pending"}>
                {percent(share, 0)}
              </strong>
            </div>
          ))}
        </div>
        <p className="vendor-null">
          Vendor-wide history ({s.vendorThreshold ?? "pending"}+ earlier KEVs):{" "}
          <b>{lift(s.vendor?.lift)} lift</b> in this pool.
        </p>
      </div>
      {reading && <ReadingDetails label="Watch model test: no demonstrated gain">{experiment}</ReadingDetails>}
      <p className="watch-takeaway">
        Review previously attacked products against your asset inventory.
      </p>
      <p className="watch-caution">
        Exploratory association, not a validated predictor. Product matching
        carries revision risk.
      </p>
    </div>
  );
}

export function WatchMethods({
  findings,
  compact = false,
}: {
  findings?: Findings | null;
  compact?: boolean;
}) {
  const s = blindSpotSummary(findings?.blind_spot);
  if (!s.year && !s.registered)
    return (
      <div className={`watch-methods ${compact ? "compact" : ""}`}>
        <p>
          Study methods pending.{" "}
          <a href={plan} target="_blank" rel="noreferrer">
            Read the registered plan <span aria-hidden="true">↗</span>
          </a>
        </p>
      </div>
    );
  return (
    <div className={`watch-methods ${compact ? "compact" : ""}`}>
      <p>
        {s.registered ? "Pre-registered recipes" : "Registration pending"} ·{" "}
        {typeof s.selectionYear === "number"
          ? String(s.selectionYear)
          : "pending"}
        -only selection{s.selectionFrozen ? "" : " pending"} · one primary{" "}
        {s.year ?? "pending"} test.{" "}
        <a href={plan} target="_blank" rel="noreferrer">
          Read the registered plan <span aria-hidden="true">↗</span>
        </a>
      </p>
      <p className="watch-feature-boundary">
        {list(findings?.blind_spot?.limitations).some((item) =>
          item.includes("shared feature family"),
        ) ? (
          <>
            The watch model’s features came from the main model, which was
            developed with {s.year ?? "test-year"} results in view.
          </>
        ) : (
          "Feature-development boundary pending."
        )}
      </p>
      <p className="watch-allocation">
        <b>
          {s.mixedAdopted === false
            ? "Submission unchanged."
            : "Allocation comparison pending."}
        </b>{" "}
        {number(s.mixed?.exploit_tier_rows)} exploit +{" "}
        {number(s.mixed?.watch_rows)} watch found {number(s.mixed?.hits)} vs{" "}
        {number(s.frozen?.hits)} hits.{" "}
        {s.mixedAdopted === false
          ? "The submission stays"
          : "Recorded submission:"}{" "}
        <b>{percent(s.exploitShare, 0)} exploit tier.</b>
      </p>
      {!compact && (
        <details className="watch-limitations">
          <summary>Study boundaries and uncertainty</summary>
          {list(findings?.blind_spot?.limitations).map((item, i) => (
            <p key={i}>{item}</p>
          ))}
          {list(findings?.blind_spot?.profile?.limitations).map((item, i) => (
            <p key={i}>{item}</p>
          ))}
          <p>
            Product history is a prompt for asset review. Confirm the affected
            versions and exposure before changing a patch decision.
          </p>
        </details>
      )}
    </div>
  );
}
