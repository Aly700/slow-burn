import type { Data, Run, EvalArm } from "./types";
import { list } from "./lib";

export function standardRankings(data: Data) {
  const methods = list(data.backtest?.methods).filter(
    (item) =>
      /cvss|epss|exploit/i.test(item.name) &&
      !/slow burn|ours/i.test(item.name),
  );
  if (methods.length) return methods.slice(0, 3);
  return [
    ["cvss_first", "CVSS first"],
    ["epss_first", "EPSS first"],
    ["exploit_then_epss", "Exploit → EPSS"],
  ].map(([key, name]) => ({
    name,
    hits_at_500: data.findings?.headline?.baselines_2025_backtest?.[key],
  }));
}
export function strongestRun(data: Data): Run | undefined {
  const evidenceBreadth = (run: Run) =>
    new Set(
      list(run.briefing?.claims).flatMap((claim) =>
        list(claim.evidence).map((evidence) => evidence.field),
      ),
    ).size;
  const runs = list(data.runs);
  const candidates = runs.filter(
    (run) =>
      run.briefing?.verdict === "fix_now" &&
      (run.verifier?.claims_verified ?? 0) >= 4,
  );
  return (
    candidates.find((run) => run.cve_id === "CVE-2026-10523") ??
    candidates.sort(
      (a, b) =>
        (b.verifier?.claims_verified ?? 0) -
          (a.verifier?.claims_verified ?? 0) ||
        evidenceBreadth(b) - evidenceBreadth(a),
    )[0] ??
    runs[0]
  );
}
export function evaluationArms(data: Data): EvalArm[] {
  const evaluation = data.agent_eval;
  if (list(evaluation?.arms).length) return list(evaluation?.arms);
  return [
    { id: "template", name: "Reasons-only template", ...evaluation?.baseline },
    {
      id: "granite_decides",
      name: "Granite decides",
      ...evaluation?.granite_decides,
    },
    {
      id: "policy_granite",
      name: "Policy + Granite",
      ...evaluation?.policy_granite,
    },
  ];
}
