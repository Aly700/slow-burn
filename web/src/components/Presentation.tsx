import { useEffect, useRef, useState } from "react";
import type { Data, Run } from "../types";
import { displayValue, list, number, percent } from "../lib";
import { strongestRun } from "../storyData";
import { blindSpotSummary } from "../blindSpot";
import { useApproval } from "../useApproval";
import {
  BlindSpot,
  EvalComparison,
  LagHistogram,
  VendorHistory,
  WordPress,
} from "./Discovery";
import { Icon } from "./Icon";
import { AttackResults } from "./AttackResults";
import { GraniteMap } from "./GraniteMap";
import { Replay } from "./Replay";
import { BlindSpotStudy, WatchMethods } from "./BlindSpotStudy";
import { useInvestigation } from "../useInvestigation";
import { LiveControls, LiveTrace } from "./LiveInvestigation";

const chapters = [
  "Ranking results",
  "Listing delays",
  "No public exploit signal",
  "Vendor history",
  "Briefing",
  "Ticket approval",
];
const stages = ["RECEIVED", "INVESTIGATING", "VERIFIED", "WAITING_APPROVAL"];

export function Presentation({
  data,
  initialNotice = "",
  onClose,
  onAsk,
  onUpdate,
}: {
  data: Data;
  initialNotice?: string;
  onClose: () => void;
  onAsk?: () => void;
  onUpdate: (run: Run, notice: string) => void;
}) {
  const [step, setStep] = useState(0);
  const [appendix, setAppendix] = useState(false);
  const appendixRef = useRef(false);
  appendixRef.current = appendix;
  const container = useRef<HTMLDivElement>(null);
  const selected = strongestRun(data);
  const {
    currentRun: run,
    notice,
    busy,
    decide,
    replaceRun,
  } = useApproval(
    selected,
    data.meta?.runs_source === "fixtures",
    initialNotice,
    onUpdate,
  );
  const live = useInvestigation(
    data,
    selected?.cve_id ?? "",
    () => replaceRun(undefined),
    replaceRun,
  );
  const showingStream = ["running", "error", "cancelled"].includes(
    live.session.status,
  );
  const advance = (delta: number) =>
    setStep((previous) =>
      Math.max(0, Math.min(chapters.length - 1, previous + delta)),
    );
  useEffect(() => {
    const previous = document.activeElement as HTMLElement;
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    container.current?.focus();
    const key = (event: KeyboardEvent) => {
      if (event.metaKey || event.ctrlKey || event.altKey) return;
      if (event.key === "Escape") {
        event.preventDefault();
        if (appendixRef.current) setAppendix(false);
        else onClose();
        return;
      }
      const target = event.target as HTMLElement;
      if (/INPUT|SELECT|TEXTAREA/.test(target.tagName)) return;
      if (event.key.toLowerCase() === "m") {
        event.preventDefault();
        setAppendix((value) => !value);
        return;
      }
      if (
        !appendixRef.current &&
        (["ArrowRight", "ArrowDown", "PageDown"].includes(event.key) ||
          (event.key === " " && !/BUTTON|SUMMARY/.test(target.tagName)))
      ) {
        event.preventDefault();
        advance(1);
      }
      if (
        !appendixRef.current &&
        ["ArrowLeft", "ArrowUp", "PageUp"].includes(event.key)
      ) {
        event.preventDefault();
        advance(-1);
      }
      if (event.key === "Tab") {
        const nodes = Array.from(
          container.current?.querySelectorAll<HTMLElement>(
            'button:not(:disabled), input, select, summary, a[href], canvas[tabindex="0"]',
          ) ?? [],
        );
        const first = nodes[0],
          last = nodes.at(-1);
        if (
          event.shiftKey &&
          (document.activeElement === first ||
            document.activeElement === container.current)
        ) {
          event.preventDefault();
          last?.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first?.focus();
        }
      }
    };
    window.addEventListener("keydown", key);
    return () => {
      document.body.style.overflow = overflow;
      window.removeEventListener("keydown", key);
      previous?.focus();
    };
  }, [onClose]);
  useEffect(() => {
    container.current?.focus({ preventScroll: true });
  }, [step, appendix]);
  const findings = data.findings;
  const clock = findings?.two_clocks;
  const total = clock?.kev_2025_total;
  const firstShare =
    clock?.first_month != null && total ? clock.first_month / total : null;
  const laterShare = clock?.later != null && total ? clock.later / total : null;
  const droppedRun = list(run?.verifier?.dropped).length
    ? run
    : (data.verifier_example ??
      list(data.runs).find((item) => list(item.verifier?.dropped).length > 0));
  const dropped = list(droppedRun?.verifier?.dropped)[0];
  const state = run?.state ?? "RECEIVED";
  const pending = state === "WAITING_APPROVAL";
  return (
    <div
      className="presentation"
      ref={container}
      tabIndex={-1}
      role="dialog"
      aria-modal="true"
      aria-label="Slow Burn presentation"
    >
      <header className="present-header">
        <strong>
          Slow Burn<span> / </span>
        </strong>
        <span>IBM Before the Breach track · Sheridan Datathon 2026</span>
        <button
          className="map-appendix-button"
          onClick={() => setAppendix((value) => !value)}
          aria-pressed={appendix}
        >
          {appendix ? "Back to story" : "Explore map"} <kbd>M</kbd>
        </button>
        <button
          className="icon-button"
          onClick={onClose}
          aria-label="Exit presentation"
        >
          <Icon name="close" size={24} />
        </button>
      </header>
      {appendix ? (
        <section
          className="present-map"
          aria-label="Appendix: What Granite reads"
        >
          <GraniteMap data={data} appendix />
        </section>
      ) : (
        <section
          className={`present-slide slide-${step + 1}`}
          aria-label={`Slide ${step + 1}: ${chapters[step]}`}
          key={step}
        >
          <div className="slide-kicker">
            <span>
              {String(step + 1).padStart(2, "0")} / {chapters[step]}
            </span>
            <span>
              {step === 2
                ? `${blindSpotSummary(findings?.blind_spot).year ?? "pending"} no-signal study`
                : step < 4
                  ? "2025 historical evidence · development analysis"
                  : data.meta?.runs_source === "fixtures"
                    ? "Illustrative fixture"
                    : live.session.status !== "idle"
                      ? live.session.mode === "live"
                        ? "Live IBM Granite investigation"
                        : "Replay of a recorded run"
                      : "Recorded IBM Granite run"}
            </span>
          </div>
          {step === 0 && (
            <>
              <h1>2025 ranking results</h1>
              <p className="slide-lead">
                Later-exploited CVEs in each top-500 ranking.
              </p>
              <Replay data={data.replay_2025} presentation />
            </>
          )}
          {step === 1 && (
            <>
              <h1>When exploited CVEs get listed</h1>
              <div
                className={`present-clocks ${firstShare == null ? "clocks-pending" : ""}`}
              >
                <div>
                  <strong className="accent">{percent(firstShare, 0)}</strong>
                  <h2>Listed in the first month</h2>
                  <p>110 of 165 vulnerabilities</p>
                </div>
                <div>
                  <strong>{percent(laterShare, 0)}</strong>
                  <h2>Listed after the first month</h2>
                  <p>55 of 165 vulnerabilities</p>
                </div>
                <div className="median-stat">
                  <strong>
                    {number(clock?.later_lag_days?.median)}
                    <small> days</small>
                  </strong>
                  <h2>Median lag for later entries</h2>
                </div>
              </div>
              <LagHistogram findings={findings} />
              <p className="slide-caveat">
                KEV inclusion is a proxy for observed exploitation, not the date
                of the first attack.
              </p>
            </>
          )}
          {step === 2 && (
            <>
              <h1>31 of 55 had no public exploit signal</h1>
              <div className="present-blind">
                <div className="blind-overview">
                  <BlindSpot findings={findings} />
                  <WatchMethods findings={findings} compact />
                </div>
                <BlindSpotStudy findings={findings} />
              </div>
            </>
          )}
          {step === 3 && (
            <>
              <h1>Earlier exploitation by vendor</h1>
              <p className="slide-lead">
                Later KEV rates by earlier vendor exploitation, within the public-exploit tier.
              </p>
              <div className="present-vendors">
                <VendorHistory findings={findings} />
                <WordPress findings={findings} />
              </div>
              <p className="slide-caveat">
                Historical associations guide investigation. They do not
                establish that a particular installation is exposed.
              </p>
            </>
          )}
          {step === 4 && (
            <>
              <h1>How a briefing is made</h1>
              <LiveControls live={live} disabled={busy} />
              {onAsk && (
                <div className="present-ask-link">
                  <button onClick={onAsk}>
                    Ask a question about the ranking ↗
                  </button>
                </div>
              )}
              <div className="present-investigation">
                <div className="present-briefing">
                  <LiveTrace live={live} />
                  {!showingStream && (
                    <>
                      <div className="present-run-title">
                        <span className="verdict urgent">
                          {run?.briefing?.verdict?.replaceAll("_", " ") ??
                            "pending"}
                        </span>
                        <span>{run?.cve_id ?? "pending"}</span>
                        <strong>
                          {number(run?.verifier?.claims_verified)} verified
                        </strong>
                      </div>
                      <h2>{run?.briefing?.headline ?? "Briefing pending"}</h2>
                      <div className="present-claims">
                        {list(run?.briefing?.claims).map((claim) => (
                          <article key={claim.id}>
                            <Icon
                              name={claim.verified ? "check" : "warning"}
                              size={18}
                            />
                            <div>
                              {(claim.text?.length ?? 0) > 260 ? (
                                <details className="long-claim">
                                  <summary>
                                    <p>{claim.text}</p>
                                    <span>Expand claim</span>
                                  </summary>
                                </details>
                              ) : (
                                <p>{claim.text ?? "pending"}</p>
                              )}
                              <div className="present-evidence">
                                {list(claim.evidence).map((evidence, index) => (
                                  <details key={index}>
                                    <summary>{evidence.field}</summary>
                                    <p>
                                      <code>{evidence.tool}</code>
                                      <br />
                                      {displayValue(evidence.value)}
                                    </p>
                                  </details>
                                ))}
                              </div>
                            </div>
                          </article>
                        ))}
                      </div>
                      {dropped ? (
                        <div className="present-dropped">
                          <span>
                            REMOVED BY THE VERIFIER
                            {droppedRun?.cve_id !== run?.cve_id
                              ? ` · ${droppedRun?.cve_id}`
                              : ""}
                          </span>
                          <p>
                            <s>
                              {dropped.text ??
                                `Unsupported claim ${dropped.id}`}
                            </s>
                          </p>
                          <small>{dropped.why}</small>
                        </div>
                      ) : null}
                      {run?.injection?.detected && (
                        <p className="injection-warning">
                          Instruction injection detected. Human approval is
                          still required.
                        </p>
                      )}
                    </>
                  )}
                </div>
                <EvalComparison data={data} />
              </div>
            </>
          )}
          {step === 5 && (
            <>
              <h1>Ticket approval and injection tests</h1>
              <div className="present-gate">
                <div>
                  <AttackResults evaluation={data.redteam_eval} compact />
                  <div
                    className="gate-states"
                    aria-label="Approval state machine"
                  >
                    {[
                      ...stages,
                      pending ? "TICKET_FILED / REJECTED" : state,
                    ].map((stage, i) => (
                      <div
                        key={`${stage}-${i}`}
                        className={
                          stage === state
                            ? "current"
                            : list(run?.states_seen).includes(stage)
                              ? "seen"
                              : ""
                        }
                      >
                        <span>
                          {list(run?.states_seen).includes(stage) &&
                          stage !== state ? (
                            <Icon name="check" size={15} />
                          ) : (
                            i + 1
                          )}
                        </span>
                        {stage.replaceAll("_", " ")}
                      </div>
                    ))}
                  </div>
                </div>
                <div className="gate-control">
                  <div className="gate-control-heading">
                    <Icon name="shield" size={24} />
                    <span className="eyebrow">HUMAN APPROVAL GATE</span>
                  </div>
                  <h2>
                    {pending
                      ? "Ticket awaiting approval"
                      : `${notice.startsWith("Simulated") ? "Simulated: " : ""}${state.toLowerCase().replaceAll("_", " ")}`}
                  </h2>
                  <div className="gate-proposal">
                    <span className="mono">
                      {run?.cve_id ?? "BRIEFING PENDING"}
                    </span>
                    <h3>{run?.briefing?.headline ?? "Briefing pending"}</h3>
                    <details>
                      <summary>Review proposed action</summary>
                      <p className="gate-action">
                        {run?.briefing?.action ??
                          "The proposed action will appear after investigation."}
                      </p>
                    </details>
                  </div>
                  <p>
                    {pending
                      ? "Review the proposed action before approving or rejecting the ticket."
                      : "The decision is retained for this session."}
                  </p>
                  {pending && (
                    <div className="approval-buttons">
                      <button
                        className="button secondary"
                        disabled={busy}
                        onClick={() => void decide(false)}
                      >
                        Reject
                      </button>
                      <button
                        className="button primary"
                        disabled={busy}
                        onClick={() => void decide(true)}
                      >
                        {busy ? "Submitting…" : "Approve ticket"}
                        <Icon name="arrow" />
                      </button>
                    </div>
                  )}
                  <p className="approval-note" role="status">
                    {notice ||
                      (data.meta?.runs_source === "fixtures"
                        ? "Fixture mode. Approval is simulated locally; no ticket will be created."
                        : "Uses localhost:8765. If unreachable, a labelled local simulation is shown.")}
                  </p>
                </div>
              </div>
            </>
          )}
        </section>
      )}
      <footer className="present-footer">
        <span className="present-counter" aria-live="polite">
          {String(step + 1).padStart(2, "0")}{" "}
          <span>/ {String(chapters.length).padStart(2, "0")}</span>
        </span>
        <div className="present-progress">
          {chapters.map((chapter, i) => (
            <button
              key={chapter}
              aria-label={`Go to slide ${i + 1}: ${chapter}`}
              aria-current={step === i ? "step" : undefined}
              onClick={() => {
                setAppendix(false);
                setStep(i);
              }}
            />
          ))}
        </div>
        <span className="present-key-hint">
          {appendix
            ? "Appendix · esc / M returns to story"
            : "← → / space to advance · M map · esc to exit"}
        </span>
        <button
          onClick={() => advance(-1)}
          disabled={appendix || step === 0}
          aria-label="Previous slide"
        >
          ←
        </button>
        <button
          onClick={() => advance(1)}
          disabled={appendix || step === chapters.length - 1}
          aria-label="Next slide"
        >
          →
        </button>
      </footer>
    </div>
  );
}
