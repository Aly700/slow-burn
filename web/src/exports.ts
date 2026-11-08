import { watchTickets } from "./productWatch.ts";
import type { ProductWatchRow } from "./productWatch";
import type { Run, Score } from "./types";
export function ticketDrafts(rows: Score[], runs: Run[], review: ProductWatchRow[] = []) {
  const byCve = new Map(runs.map((run) => [run.cve_id, run]));
  const ranked = rows.map((row) => {
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
      ...(row.software_matches ? { software_matches: row.software_matches } : {}),
      source_list: "fix_first",
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
  return [...ranked, ...watchTickets(review)];
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
export function queueCsv(rows: Score[], runs: Run[], review: ProductWatchRow[] = []) {
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
    "source_list",
    "match_confidence",
    "prior_kev_count",
    "latest_prior_kev_cve",
    "latest_prior_kev_date",
    "description",
    "software_matches",
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
      "fix_first", row.software_matches?.map(match => match.confidence).join("; ") ?? "", "", "", "", row.description,
      row.software_matches ? JSON.stringify(row.software_matches) : "",
    ]
      .map(csvCell)
      .join(",");
  });
  const reviewDrafts = watchTickets(review);
  for (let index = 0; index < review.length; index++) {
    const row = review[index], ticket = reviewDrafts[index];
    body.push([row.cve_id, null, row.vendor, row.product, row.snapshot_month, null, row.epss, null, ticket.verdict, ticket.headline, ticket.proposed_action, ticket.evidence_summary, ticket.source_list, row.match_confidence, row.prior_kev_count, row.latest_prior_kev_cve, row.latest_prior_kev_date, row.description, ""].map(csvCell).join(","));
  }
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
