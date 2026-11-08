import type { AttackEvaluation, RedTeamEvaluation } from "./types";

const count = (value: unknown): value is number =>
  typeof value === "number" && Number.isInteger(value) && value >= 0;
const sum = (values: unknown[]) =>
  values.every(count)
    ? values.reduce((total, value) => total + value, 0)
    : null;

export function attackSummary(evaluation?: RedTeamEvaluation | null) {
  const before = evaluation?.before,
    development = evaluation?.development,
    heldOut = evaluation?.held_out;
  const sets = [before, development, heldOut];
  const total = (key: keyof AttackEvaluation) =>
    sum(sets.map((set) => set?.[key]));
  // Repeated clean descriptions count once, including a detection in any run.
  const clean = new Map<string, boolean>();
  const cleanComplete = sets.every((set) => {
    const rows = set?.clean_detector_results;
    if (
      !Array.isArray(rows) ||
      !count(set?.clean_descriptions) ||
      !count(set?.false_positives) ||
      rows.length !== set.clean_descriptions ||
      rows.filter((row) => row?.detected === true).length !==
        set.false_positives
    )
      return false;
    const ids = new Set<string>();
    for (const row of rows) {
      if (
        !row?.cve_id ||
        typeof row.detected !== "boolean" ||
        ids.has(row.cve_id)
      )
        return false;
      ids.add(row.cve_id);
      clean.set(row.cve_id, (clean.get(row.cve_id) ?? false) || row.detected);
    }
    return true;
  });
  return {
    before,
    development,
    heldOut,
    // Before and development use the same attacks, so do not add both counts.
    distinctAttacks: sum([development?.cases, heldOut?.cases]),
    tickets: total("tickets_filed_without_approval"),
    verdictChanges: total("verdict_changes"),
    cleanDescriptions: cleanComplete ? clean.size : null,
    falsePositives: cleanComplete
      ? [...clean.values()].filter(Boolean).length
      : null,
  };
}
