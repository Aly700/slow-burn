import { previewOnly } from "../api";
import type { Run } from "../types";
import { displayValue, list } from "../lib";
import { Icon } from "./Icon";

export function VerifiedClaims({ briefing }: { briefing: Run["briefing"] }) {
  return (
    <div className="claim-list">
      {list(briefing?.claims).map((claim) => (
        <article className="claim" key={claim.id}>
          <div className={`verification-mark ${claim.verified ? "verified" : ""}`}>
            {claim.verified ? <Icon name="check" size={16} /> : "?"}
          </div>
          <div>
            <p>{claim.text ?? "Claim text unavailable"}</p>
            <div className="evidence-chips">
              {list(claim.evidence).map((evidence, index) => (
                <details key={index} className="evidence-chip">
                  <summary title={`${evidence.tool} · ${evidence.field}`}>
                    {evidence.field}{" "}
                    <span>
                      {typeof evidence.value === "number" ? String(evidence.value) : "source"}
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
              {claim.verified ? "Verified against tool output" : "Not verified"}
            </span>
          </div>
        </article>
      ))}
    </div>
  );
}

export function ProposedAction({ briefing }: { briefing: Run["briefing"] }) {
  return (
    <div className="proposed-action">
      <span className="eyebrow">PROPOSED ACTION</span>
      <p>{briefing?.action ?? "No action proposed yet."}</p>
    </div>
  );
}

export function ApprovalFooter({ run, notice = "", fixture = false, busy = false, noteId, onDecide }: {
  run?: Run;
  notice?: string;
  fixture?: boolean;
  busy?: boolean;
  noteId?: string;
  onDecide: (approved: boolean) => void | Promise<void>;
}) {
  const state = run?.state ?? "RECEIVED";
  const pending = state === "WAITING_APPROVAL";
  const preview = previewOnly(run);
  const stageLabel = (value: string) => value.toLowerCase().replaceAll("_", " ");
  return (
    <footer className="approval-footer">
      {run ? (
        <>
          <div className="approval-status">
            <Icon name="shield" size={18} />
            <strong>
              {preview ? "Approval preview only" : pending
                ? "Human approval required"
                : `${notice.startsWith("Simulated") ? "Simulated: " : ""}${stageLabel(state)}`}
            </strong>
            {pending && <span>No ticket filed</span>}
          </div>
          {pending && !preview && (
            <div className="approval-buttons">
              <button className="button secondary" disabled={busy} aria-describedby={noteId} onClick={() => void onDecide(false)}>
                Reject
              </button>
              <button className="button primary" disabled={busy} aria-describedby={noteId} onClick={() => void onDecide(true)}>
                {busy ? "Submitting…" : "Approve ticket"}
                <Icon name="arrow" />
              </button>
            </div>
          )}
          <p id={noteId} className={`approval-note ${notice ? "has-notice" : ""}`} role="status">
            {preview ? "Public mode is read-only. This proposed ticket is a preview; no ticket can be filed." : notice || (fixture
              ? "Demo mode. Approval is simulated locally; no ticket will be created."
              : "Uses the local approval service. If unreachable, a local simulation is labelled here.")}
          </p>
        </>
      ) : (
        <p>Approval becomes available after a verified briefing.</p>
      )}
    </footer>
  );
}
