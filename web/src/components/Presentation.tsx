import { useEffect, useRef, useState } from "react";
import type { Data, Run } from "../types";
import { displayValue, list, number, percent } from "../lib";
import { standardRankings, strongestRun } from "../storyData";
import { useApproval } from "../useApproval";
import {
  BlindSpot,
  EvalComparison,
  LagHistogram,
  VendorHistory,
  WordPress,
} from "./Discovery";
import { Icon } from "./Icon";

const chapters = [
  "The result",
  "The window",
  "The blind spot",
  "The repeat offenders",
  "The briefing",
  "The decision",
];
const stages = ["RECEIVED", "INVESTIGATING", "VERIFIED", "WAITING_APPROVAL"];

export function Presentation({
  data,
  initialNotice = "",
  onClose,
  onUpdate,
}: {
  data: Data;
  initialNotice?: string;
  onClose: () => void;
  onUpdate: (run: Run, notice: string) => void;
}) {
  const [step, setStep] = useState(0);
  const container = useRef<HTMLDivElement>(null);
  const selected = strongestRun(data);
  const {
    currentRun: run,
    notice,
    busy,
    decide,
  } = useApproval(
    selected,
    data.meta?.runs_source === "fixtures",
    initialNotice,
    onUpdate,
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
        onClose();
      }
      const target = event.target as HTMLElement;
      if (/INPUT|SELECT|TEXTAREA/.test(target.tagName)) return;
      if (
        ["ArrowRight", "ArrowDown", "PageDown"].includes(event.key) ||
        (event.key === " " && !/BUTTON|SUMMARY/.test(target.tagName))
      ) {
        event.preventDefault();
        advance(1);
      }
      if (["ArrowLeft", "ArrowUp", "PageUp"].includes(event.key)) {
        event.preventDefault();
        advance(-1);
      }
      if (event.key === "Tab") {
        const nodes = Array.from(
          container.current?.querySelectorAll<HTMLElement>(
            "button:not(:disabled), summary, a[href]",
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
  }, [step]);
  const findings = data.findings;
  const clock = findings?.two_clocks;
  const total = clock?.kev_2025_total;
  const firstShare =
    clock?.first_month != null && total ? clock.first_month / total : null;
  const laterShare = clock?.later != null && total ? clock.later / total : null;
  const ours = findings?.headline?.ours_hits_top500_2025_backtest;
  const methods = standardRankings(data);
  const maxHits = Math.max(
    1,
    ours ?? 0,
    ...methods.map((method) => method.hits_at_500 ?? 0),
  );
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
          className="icon-button"
          onClick={onClose}
          aria-label="Exit presentation"
        >
          <Icon name="close" size={24} />
        </button>
      </header>
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
            {step < 4
              ? "2025 historical evidence · development analysis"
              : data.meta?.runs_source === "fixtures"
                ? "Illustrative fixture"
                : "Recorded IBM Granite run"}
          </span>
        </div>
        {step === 0 && (
          <>
            <h1>Severity isn’t a forecast.</h1>
            <p className="slide-lead">
              Same top-500 budget. How many later-exploited CVEs did we find?
            </p>
            <div className="present-results">
              <div className="present-ours">
                <span>Slow Burn</span>
                <strong className={ours == null ? "is-pending" : ""}>
                  {number(ours)}
                </strong>
                <p>
                  later KEV entries caught
                  <br />
                  in the top 500
                </p>
              </div>
              <div className="present-baselines">
                {methods.map((method) => (
                  <div key={method.name}>
                    <span>{method.name}</span>
                    <div>
                      <i
                        style={{
                          width: `${((method.hits_at_500 ?? 0) / maxHits) * 100}%`,
                        }}
                      />
                    </div>
                    <strong
                      className={method.hits_at_500 == null ? "is-pending" : ""}
                    >
                      {number(method.hits_at_500)}
                    </strong>
                  </div>
                ))}
              </div>
            </div>
            <div className="slide-bottom-note">
              <strong>2025 DEVELOPMENT BACKTEST</strong>
              <span>
                {number(findings?.headline?.positives_2025)} later KEV entries ·{" "}
                {number(findings?.headline?.pool_2025)} eligible CVEs · outcome
                cutoff 31 Dec 2025
              </span>
              <span>2026 result: pending judging</span>
            </div>
          </>
        )}
        {step === 1 && (
          <>
            <h1>Two clocks. Two defences.</h1>
            <div
              className={`present-clocks ${firstShare == null ? "clocks-pending" : ""}`}
            >
              <div>
                <strong className="accent">{percent(firstShare, 0)}</strong>
                <h2>In the publication month.</h2>
                <p>Patch speed is critical.</p>
              </div>
              <div>
                <strong>{percent(laterShare, 0)}</strong>
                <h2>Arrive later.</h2>
                <p>Prioritisation buys a window.</p>
              </div>
              <div className="median-stat">
                <strong>
                  {number(clock?.later_lag_days?.median)}
                  <small> days</small>
                </strong>
                <h2>Median lag, later entries.</h2>
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
            <h1>Exploit feeds have a blind spot.</h1>
            <div className="present-blind">
              <BlindSpot findings={findings} />
              <aside>
                <span className="eyebrow">THE OPERATIONAL CONSEQUENCE</span>
                <h2>
                  No public exploit.
                  <br />
                  Still worth fixing.
                </h2>
                <p>
                  Rankings built only on exploit signals cannot see the warning
                  that is missing.
                </p>
                <p>We need another way to decide what deserves attention.</p>
              </aside>
            </div>
          </>
        )}
        {step === 3 && (
          <>
            <h1>Look for repeat offenders.</h1>
            <p className="slide-lead">
              Inside the public-exploit tier, does earlier vendor exploitation
              separate risk?
            </p>
            <div className="present-vendors">
              <VendorHistory findings={findings} />
              <WordPress findings={findings} />
            </div>
            <p className="slide-caveat">
              Historical associations guide investigation. They do not establish
              that a particular installation is exposed.
            </p>
          </>
        )}
        {step === 4 && (
          <>
            <h1>Policy decides. Granite briefs.</h1>
            <div className="present-investigation">
              <div className="present-briefing">
                <div className="present-run-title">
                  <span className="verdict urgent">
                    {run?.briefing?.verdict?.replaceAll("_", " ") ?? "pending"}
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
                      <s>{dropped.text ?? `Unsupported claim ${dropped.id}`}</s>
                    </p>
                    <small>{dropped.why}</small>
                  </div>
                ) : (
                  <p className="caption">
                    No dropped claims in the available recorded runs.
                  </p>
                )}
                {run?.injection?.detected && (
                  <p className="injection-warning">
                    Instruction injection detected. Human approval is still
                    required.
                  </p>
                )}
              </div>
              <EvalComparison data={data} />
            </div>
          </>
        )}
        {step === 5 && (
          <>
            <h1>The last step is yours.</h1>
            <div className="present-gate">
              <div>
                <span className="eyebrow">
                  {run?.cve_id ?? "BRIEFING PENDING"}
                </span>
                <h2>{run?.briefing?.headline ?? "Briefing pending"}</h2>
                <p className="gate-action">
                  {run?.briefing?.action ??
                    "The proposed action will appear after investigation."}
                </p>
                <div
                  className="gate-states"
                  aria-label="Approval state machine"
                >
                  {[...stages, pending ? "TICKET_FILED / REJECTED" : state].map(
                    (stage, i) => (
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
                    ),
                  )}
                </div>
              </div>
              <div className="gate-control">
                <Icon name="shield" size={30} />
                <span className="eyebrow">HUMAN APPROVAL GATE</span>
                <h2>
                  {pending
                    ? "Ready for your decision."
                    : `${notice.startsWith("Simulated") ? "Simulated: " : ""}${state.toLowerCase().replaceAll("_", " ")}`}
                </h2>
                <p>
                  {pending
                    ? "Review the evidence. Authorise the ticket."
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
            <blockquote>
              IBM Concert proves what is exploitable in your environment.
              <br />
              <strong>We tell you what to prove first.</strong>
            </blockquote>
          </>
        )}
      </section>
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
              onClick={() => setStep(i)}
            />
          ))}
        </div>
        <span className="present-key-hint">
          ← → / space to advance · esc to exit
        </span>
        <button
          onClick={() => advance(-1)}
          disabled={step === 0}
          aria-label="Previous slide"
        >
          ←
        </button>
        <button
          onClick={() => advance(1)}
          disabled={step === chapters.length - 1}
          aria-label="Next slide"
        >
          →
        </button>
      </footer>
    </div>
  );
}
