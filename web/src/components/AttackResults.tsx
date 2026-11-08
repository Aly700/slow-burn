import type { RedTeamEvaluation } from "../types";
import { list, number } from "../lib";
import "../attack-results.css";

export function AttackResults({
  evaluation,
  compact = false,
}: {
  evaluation?: RedTeamEvaluation | null;
  compact?: boolean;
}) {
  const families = evaluation?.groups ? Object.keys(evaluation.groups) : null;
  return (
    <div className={`attack-results ${compact ? "compact" : ""}`}>
      {!compact && <h3>The approval gate has a reason.</h3>}
      <p className="attack-suite">
        <strong>{number(evaluation?.cases)}</strong> injection attempts ·{" "}
        <strong>{number(families?.length)}</strong> families{" "}
        <span>Fixed development suite</span>
      </p>
      <div className="attack-boundaries">
        <div>
          <strong
            className={
              evaluation?.tickets_filed_without_approval == null
                ? "is-pending"
                : ""
            }
          >
            {number(evaluation?.tickets_filed_without_approval)}
          </strong>
          <span>
            tickets filed
            <br />
            without approval
          </span>
        </div>
        <div>
          <strong
            className={evaluation?.verdict_changes == null ? "is-pending" : ""}
          >
            {number(evaluation?.verdict_changes)}
          </strong>
          <span>
            verdict
            <br />
            changes
          </span>
        </div>
      </div>
      <div className="attack-survival">
        <strong
          className={
            evaluation?.injected_content_survived_runs == null
              ? "is-pending"
              : ""
          }
        >
          {number(evaluation?.injected_content_survived_runs)}
          <small> / {number(evaluation?.cases)}</small>
        </strong>
        <p>
          Planted wording survived
          <br />
          into briefing text.
        </p>
      </div>
      <p className="attack-reason">
        That is why a person approves,
        <br className="desktop-break" /> and the server enforces the gate.
      </p>
      {!compact && (
        <>
          <div className="attack-families" aria-label="Injection test families">
            {families?.length ? (
              families.map((family) => (
                <span key={family}>{family.replaceAll("_", " ")}</span>
              ))
            ) : (
              <span>Family names pending</span>
            )}
          </div>
          <p className="attack-scope">
            Source checks establish consistency with supplied evidence, not its
            truth. These results describe the fixed suite; they do not establish
            universal injection resistance.
          </p>
          <details className="attack-methods">
            <summary>How the attacks were measured</summary>
            <p>{evaluation?.method ?? "Evaluation methods pending."}</p>
            <p>
              {evaluation?.survival_measure ?? "Survival measurement pending."}
            </p>
            {list(evaluation?.limitations).map((limit, i) => (
              <p key={i}>{limit}</p>
            ))}
          </details>
        </>
      )}
    </div>
  );
}
