import { useEffect, useRef, useState } from "react";
import type { Run, Score } from "../types";
import { displayValue, list, number, percent, reasonLabel } from "../lib";
import { Icon } from "./Icon";
import { useApproval } from "../useApproval";

const stages = ["RECEIVED", "INVESTIGATING", "VERIFIED", "WAITING_APPROVAL"];
const stageLabel = (state: string) => state.toLowerCase().replaceAll("_", " ");

export function Briefing({
  score,
  run,
  fixture,
  initialNotice = "",
  onUpdate,
  onClose,
}: {
  score: Score;
  run?: Run;
  fixture: boolean;
  initialNotice?: string;
  onUpdate: (run: Run, notice: string) => void;
  onClose: () => void;
}) {
  const { currentRun, notice, busy, decide } = useApproval(
    run,
    fixture,
    initialNotice,
    onUpdate,
  );
  const [tab, setTab] = useState("evidence");
  const panel = useRef<HTMLElement>(null);
  const closeButton = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    const previous = document.activeElement as HTMLElement;
    closeButton.current?.focus();
    const priorOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const handler = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
      if (event.key === "Tab") {
        const focusable = Array.from(
          panel.current?.querySelectorAll<HTMLElement>(
            'button:not(:disabled), a[href], input, select, summary, [tabindex="0"]',
          ) ?? [],
        );
        const first = focusable[0],
          last = focusable.at(-1);
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last?.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first?.focus();
        }
      }
    };
    document.addEventListener("keydown", handler);
    return () => {
      document.body.style.overflow = priorOverflow;
      document.removeEventListener("keydown", handler);
      previous?.focus();
    };
  }, [onClose]);
  const briefing = currentRun?.briefing;
  const state = currentRun?.state ?? "RECEIVED";
  const pending = state === "WAITING_APPROVAL";
  const terminal = ["TICKET_FILED", "REJECTED", "FAILED"].includes(state);
  const steps = [...stages, terminal ? state : "TICKET_FILED / REJECTED"];

  return (
    <div className="drawer-layer">
      <div className="drawer-scrim" onClick={onClose} />
      <aside
        className="briefing-panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby="briefing-title"
        ref={panel}
      >
        <header className="drawer-header">
          <div>
            <span className="eyebrow">EVIDENCE → DECISION</span>
            <h2 id="briefing-title">{score.cve_id}</h2>
          </div>
          <button
            ref={closeButton}
            className="icon-button"
            onClick={onClose}
            aria-label="Close briefing"
          >
            <Icon name="close" size={23} />
          </button>
        </header>
        <div className="drawer-context">
          <span>
            {fixture && currentRun
              ? "Illustrative fixture · simulated workflow"
              : currentRun
                ? "Recorded investigation"
                : "Snapshot record"}
          </span>
          <span className="mono">
            Snapshot {score.snapshot_month ?? "unknown"}
          </span>
        </div>
        <div className="drawer-scroll">
          {currentRun ? (
            <>
              <div className="verdict-line">
                <span
                  className={`verdict ${briefing?.verdict === "fix_now" ? "urgent" : ""}`}
                >
                  {briefing?.verdict?.replaceAll("_", " ") ?? "Verdict pending"}
                </span>
                <span className="confidence">
                  Briefing confidence {percent(briefing?.confidence, 0)}
                </span>
              </div>
              <h3 className="briefing-headline">
                {briefing?.headline ?? "Briefing is being prepared."}
              </h3>
              <div className="state-machine" aria-label="Run state machine">
                {steps.map((step, index) => (
                  <div
                    key={step}
                    className={`${list(currentRun.states_seen).includes(step) ? "seen" : ""} ${step === state ? "current" : ""}`}
                  >
                    <span className="state-node">
                      {list(currentRun.states_seen).includes(step) &&
                      step !== state ? (
                        <Icon name="check" size={10} />
                      ) : (
                        index + 1
                      )}
                    </span>
                    <span>{stageLabel(step)}</span>
                  </div>
                ))}
              </div>
              {currentRun.injection?.detected && (
                <div className="injection-warning">
                  <Icon name="warning" />
                  <div>
                    <strong>Instruction injection detected</strong>
                    <p>
                      Untrusted content attempted to change the workflow. Human
                      approval remains required.
                    </p>
                    <details>
                      <summary>Inspect quarantined text</summary>
                      {list(currentRun.injection.spans).map((span, i) => (
                        <code key={i}>{displayValue(span)}</code>
                      ))}
                    </details>
                  </div>
                </div>
              )}
              <div
                className="briefing-tabs"
                role="tablist"
                aria-label="Briefing details"
              >
                <button
                  role="tab"
                  id="evidence-tab"
                  aria-controls="evidence-content"
                  aria-selected={tab === "evidence"}
                  onClick={() => setTab("evidence")}
                >
                  Evidence{" "}
                  <span>
                    {number(currentRun.verifier?.claims_verified)} verified ·{" "}
                    {list(currentRun.verifier?.dropped).length} dropped
                  </span>
                </button>
                <button
                  role="tab"
                  id="trace-tab"
                  aria-controls="trace-content"
                  aria-selected={tab === "trace"}
                  onClick={() => setTab("trace")}
                >
                  Trace <span>{list(currentRun.trace).length} steps</span>
                </button>
              </div>
              {tab === "evidence" ? (
                <div
                  role="tabpanel"
                  id="evidence-content"
                  aria-labelledby="evidence-tab"
                >
                  <div className="claim-list">
                    {list(briefing?.claims).map((claim) => (
                      <article className="claim" key={claim.id}>
                        <div
                          className={`verification-mark ${claim.verified ? "verified" : ""}`}
                        >
                          {claim.verified ? (
                            <Icon name="check" size={16} />
                          ) : (
                            "?"
                          )}
                        </div>
                        <div>
                          <p>{claim.text ?? "Claim text unavailable"}</p>
                          <div className="evidence-chips">
                            {list(claim.evidence).map((evidence, index) => (
                              <details key={index} className="evidence-chip">
                                <summary>
                                  {evidence.field}{" "}
                                  <span>
                                    {typeof evidence.value === "number"
                                      ? String(evidence.value)
                                      : "source"}
                                  </span>
                                </summary>
                                <div>
                                  <code>{evidence.tool}</code>
                                  <p>{displayValue(evidence.value)}</p>
                                </div>
                              </details>
                            ))}
                          </div>
                          <span className="sr-only">
                            {claim.verified
                              ? "Verified against tool output"
                              : "Not verified"}
                          </span>
                        </div>
                      </article>
                    ))}
                  </div>
                  {list(currentRun.verifier?.dropped).length > 0 && (
                    <div className="dropped-claims">
                      <span className="eyebrow">REMOVED BY THE VERIFIER</span>
                      {list(currentRun.verifier?.dropped).map((claim) => (
                        <div key={claim.id}>
                          <p>
                            <Icon name="close" size={14} />
                            <s>
                              {claim.text ?? `Unsupported claim ${claim.id}`}
                            </s>
                          </p>
                          <span>{claim.why}</span>
                        </div>
                      ))}
                    </div>
                  )}
                  <div className="proposed-action">
                    <span className="eyebrow">PROPOSED ACTION</span>
                    <p>{briefing?.action ?? "No action proposed yet."}</p>
                  </div>
                </div>
              ) : (
                <div
                  id="trace-content"
                  role="tabpanel"
                  aria-labelledby="trace-tab"
                  className="trace-timeline"
                >
                  {list(currentRun.trace).map((event, index) => (
                    <div className="trace-event" key={index}>
                      <span className="trace-time">
                        {((event.t_ms ?? 0) / 1000).toFixed(2)}s
                      </span>
                      <div>
                        <div className="trace-label">
                          <strong>
                            {event.name?.replaceAll("_", " ") ?? "Event"}
                          </strong>
                          <span className="badge">{event.kind}</span>
                        </div>
                        <p>
                          {event.output_summary ??
                            "No event summary available."}
                        </p>
                        <details>
                          <summary>
                            Input · {number(event.duration_ms)} ms
                          </summary>
                          <pre>
                            {JSON.stringify(event.input ?? {}, null, 2)}
                          </pre>
                        </details>
                      </div>
                    </div>
                  ))}
                </div>
              )}
              {!!list(score.reasons).length && (
                <details className="run-metadata">
                  <summary>Ranking signals at the snapshot</summary>
                  {list(score.reasons).map((reason, i) => (
                    <p key={i}>{reasonLabel(reason)}</p>
                  ))}
                </details>
              )}
              <details className="run-metadata">
                <summary>Run provenance</summary>
                <dl>
                  <dt>Model</dt>
                  <dd>{currentRun.model ?? "Not supplied"}</dd>
                  <dt>Run</dt>
                  <dd>{currentRun.run_id}</dd>
                  <dt>Duration</dt>
                  <dd>
                    {currentRun.duration_ms == null
                      ? "Unknown"
                      : `${(currentRun.duration_ms / 1000).toFixed(2)} s`}
                  </dd>
                  <dt>Write policy</dt>
                  <dd>{currentRun.policy?.reason ?? "Not supplied"}</dd>
                </dl>
                {fixture && (
                  <p>
                    Hand-authored demonstration using supplied snapshot records.
                    Timings, verification, and model identity are illustrative.
                  </p>
                )}
              </details>
            </>
          ) : (
            <div className="no-run">
              <span className="badge">Briefing pending</span>
              <h3>
                The record is ready.
                <br />
                The investigation is next.
              </h3>
              <p>
                No recorded briefing is available for this CVE. The snapshot
                evidence is shown below.
              </p>
              <div className="snapshot-summary">
                <span>Snapshot EPSS</span>
                <strong>{percent(score.epss, 2)}</strong>
                <span>Public exploit flag</span>
                <strong>
                  {score.any_exploit == null
                    ? "Unknown"
                    : score.any_exploit === 1
                      ? "Present"
                      : "Not present"}
                </strong>
                <span>Assigner</span>
                <strong>{score.assigner || "Unknown"}</strong>
              </div>
              <p className="record-description">
                {score.description || "Description unavailable."}
              </p>
              <div className="feature-list">
                {list(score.reasons).map((reason, i) => (
                  <span className="chip" key={i}>
                    {reasonLabel(reason)}
                  </span>
                ))}
              </div>
              <p className="caption">
                Use “Briefing available” in the queue to inspect a completed
                demonstration.
              </p>
            </div>
          )}
        </div>
        <footer className="approval-footer">
          {currentRun ? (
            <>
              <div className="approval-status">
                <Icon name="shield" size={18} />
                <strong>
                  {pending
                    ? "Human approval required"
                    : `${notice.startsWith("Simulated") ? "Simulated: " : ""}${stageLabel(state)}`}
                </strong>
                {pending && <span>No ticket filed</span>}
              </div>
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
              <p
                className={`approval-note ${notice ? "has-notice" : ""}`}
                role="status"
              >
                {notice ||
                  (fixture
                    ? "Demo mode. Approval is simulated locally; no ticket will be created."
                    : "Uses the local approval service. If unreachable, a local simulation is labelled here.")}
              </p>
            </>
          ) : (
            <p>Approval becomes available after a verified briefing.</p>
          )}
        </footer>
      </aside>
    </div>
  );
}
