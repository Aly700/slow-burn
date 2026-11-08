import type { Run, Score } from "./types";
export function ticketDrafts(rows: Score[], runs: Run[]) {
  const byCve = new Map(runs.map((run) => [run.cve_id, run]));
  return rows.map((row) => {
    const run = byCve.get(row.cve_id);
    const verified =
      run?.briefing?.claims?.filter((claim) => claim.verified) ?? [];
    const evidence = verified
      .map(
        (claim) =>
          `${claim.text ?? claim.id} [${(claim.evidence ?? []).map((item) => `${item.tool}.${item.field}=${typeof item.value === "string" ? item.value : JSON.stringify(item.value)}`).join("; ")}]`,
      )
      .join("\n");
    const reasons = row.reasons
      ?.map((reason) => reason.label ?? reason.feature ?? "")
      .filter(Boolean)
      .join("; ");
    return {
      cve_id: row.cve_id,
      rank: row.rank,
      verdict: run?.briefing?.verdict ?? "pending",
      headline: run?.briefing?.headline ?? `Investigate ${row.cve_id}`,
      proposed_action:
        run?.briefing?.action ??
        "Briefing pending. Review snapshot evidence and confirm affected versions before choosing a remediation.",
      evidence_summary: evidence
        ? `Verified briefing claims:\n${evidence}`
        : reasons
          ? `Ranking signals; briefing verification pending: ${reasons}`
          : "Evidence pending.",
    };
  });
}
export function csvCell(value: unknown) {
  let text = value == null ? "" : String(value);
  // Prevent spreadsheet software from interpreting untrusted text as a formula.
  if (
    typeof value === "string" &&
    (/^[\s]*[=+@-]/.test(text) || /^[\t\r\n]/.test(text))
  )
    text = `'${text}`;
  return `"${text.replaceAll('"', '""')}"`;
}
export function queueCsv(rows: Score[], runs: Run[]) {
  const drafts = ticketDrafts(rows, runs);
  const headers = [
    "cve_id",
    "rank",
    "vendor",
    "product",
    "snapshot_month",
    "score",
    "epss",
    "cvss3_score",
    "verdict",
    "headline",
    "proposed_action",
    "evidence_summary",
  ];
  const body = rows.map((row, index) => {
    const ticket = drafts[index];
    return [
      row.cve_id,
      row.rank,
      row.vendor_identity,
      row.product_identity,
      row.snapshot_month,
      row.score,
      row.epss,
      row.cvss3_score,
      ticket.verdict,
      ticket.headline,
      ticket.proposed_action,
      ticket.evidence_summary,
    ]
      .map(csvCell)
      .join(",");
  });
  return [headers.join(","), ...body].join("\r\n") + "\r\n";
}
export function downloadFile(name: string, text: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
