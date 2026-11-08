import type { AttackEvaluation, RedTeamEvaluation } from "../types";
import { list, number, percent } from "../lib";
import { attackSummary } from "../attackResults";
import "../attack-results.css";

function Families({
  evaluation,
  label,
}: {
  evaluation?: AttackEvaluation | null;
  label: string;
}) {
  const families = evaluation?.groups ? Object.keys(evaluation.groups) : [];
  return (
    <div className="attack-family-group">
      <h4>{label}</h4>
      <div className="attack-families" aria-label={label}>
        {families.length ? (
          families.map((family) => (
            <span key={family}>{family.replaceAll("_", " ")}</span>
          ))
        ) : (
          <span>Family names pending</span>
        )}
      </div>
    </div>
  );
}

export function AttackResults({
  evaluation,
  compact = false,
}: {
  evaluation?: RedTeamEvaluation | null;
  compact?: boolean;
}) {
  const summary = attackSummary(evaluation);
  const { before, development, heldOut } = summary;
  const boundaries = [
    {
      value: summary.tickets,
      label: (
        <>
          tickets filed
          <br />
          without approval
        </>
      ),
    },
    {
      value: summary.verdictChanges,
      label: (
        <>
          verdict
          <br />
          changes
        </>
      ),
    },
    {
      value: summary.falsePositives,
      label: (
        <>
          false positives on
          <br />
          {number(summary.cleanDescriptions)} clean descriptions
        </>
      ),
    },
  ];
  return (
    <div className={`attack-results ${compact ? "compact" : ""}`}>
      {!compact && <h3>The approval gate has a reason.</h3>}
      <p className="attack-kicker">HELD OUT · FRESH ATTACKS</p>
      <div className="attack-evidence">
        <div>
          <div className="attack-survival">
            <strong
              className={
                heldOut?.injected_content_survived_runs == null
                  ? "is-pending"
                  : ""
              }
            >
              {number(heldOut?.injected_content_survived_runs)}
              <small> of {number(heldOut?.cases)}</small>
            </strong>
            <p>
              {heldOut?.injected_content_survived_runs == null
                ? "Fresh-attack results are pending."
                : "fresh attacks still planted wording in briefing text."}
            </p>
          </div>
          <p className="attack-heldout-note">
            {heldOut
              ? "Written and frozen before the fix. Tested once."
              : "Held-out evaluation pending."}
          </p>
        </div>
        <div className="attack-comparison" aria-label="Development results">
          <div>
            <span>Before the fix</span>
            <strong>
              {number(before?.injected_content_survived_runs)}{" "}
              <small>of {number(before?.cases)}</small>
            </strong>
          </div>
          <div>
            <span>After the fix</span>
            <strong>
              {number(development?.injected_content_survived_runs)}{" "}
              <small>of {number(development?.cases)}</small>
            </strong>
            <span className="attack-tuned">tuned on these</span>
          </div>
        </div>
      </div>
      <p className="attack-reason">
        {heldOut?.injected_content_survived_runs == null
          ? "A person approves,"
          : "That is why a person approves,"}
        <br className="desktop-break" /> and the server enforces the gate.
      </p>
      <p className="attack-suite">
        Across <strong>{number(summary.distinctAttacks)}</strong> distinct
        attacks
        <span>Before, tuned and held out</span>
      </p>
      <div className="attack-boundaries">
        {boundaries.map((boundary, index) => (
          <div key={index}>
            <strong className={boundary.value == null ? "is-pending" : ""}>
              {number(boundary.value)}
            </strong>
            <span>{boundary.label}</span>
          </div>
        ))}
      </div>
      {!compact && (
        <>
          <p className="attack-detector">
            Held-out detector recall:{" "}
            <strong>{percent(heldOut?.detector_recall)}</strong>. Detection is
            advisory; it cannot authorize a write.
          </p>
          <div className="attack-family-groups">
            <Families evaluation={heldOut} label="Fresh held-out families" />
            <Families
              evaluation={development}
              label="Development families · tuned on these"
            />
          </div>
          <p className="attack-scope">
            These are observed results on the recorded tests, not a guarantee of
            universal injection resistance. Source checks establish consistency
            with supplied evidence, not its truth.
          </p>
          <details className="attack-methods">
            <summary>How the attacks were measured</summary>
            <p>
              The original development attacks were run before and after
              hardening; they count once in the distinct-attack total. Repeated
              clean descriptions also count once, and a detection in any run is
              a false positive.
            </p>
            {[
              ["Held out", heldOut],
              ["Before the fix", before],
              ["Development · tuned on these", development],
            ].map(([label, set]) => (
              <p key={String(label)}>
                <strong>{String(label)}: </strong>
                {(set as AttackEvaluation | undefined | null)?.method ??
                  "Evaluation methods pending."}
              </p>
            ))}
            <p>
              {heldOut?.survival_measure ?? "Survival measurement pending."}
            </p>
            {[
              ...new Set(
                [before, development, heldOut].flatMap((set) =>
                  list(set?.limitations),
                ),
              ),
            ].map((limit, i) => (
              <p key={i}>{limit}</p>
            ))}
          </details>
        </>
      )}
    </div>
  );
}
