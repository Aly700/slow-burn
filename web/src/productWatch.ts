import { matchesStack } from "./stack.ts";
import type { StackChoice } from "./stack";
export interface ProductWatchRow {
  cve_id: string;
  vendor: string;
  product: string;
  match_confidence: string;
  prior_kev_count: number | null;
  latest_prior_kev_cve: string;
  latest_prior_kev_date: string;
  epss: number | null;
  description: string;
  snapshot_month: string;
}
export function decodeWatch(value: { columns: string[]; rows: unknown[][] }): ProductWatchRow[] {
  if (!Array.isArray(value?.columns) || !Array.isArray(value?.rows)) throw new Error("Invalid review list");
  return value.rows.map(row => Object.fromEntries(value.columns.map((key, index) => [key, row[index]])) as unknown as ProductWatchRow);
}
export function filterWatch(rows: ProductWatchRow[], choices: StackChoice[], loose = false) {
  if (!choices.length) return [];
  return rows.filter(row => (loose || ["psirt_supported", "vendor_text_supported"].includes(row.match_confidence)) && matchesStack({
    rank: 0, cve_id: row.cve_id, vendor_identity: row.vendor, product_identity: row.product, description: row.description,
  }, choices));
}
export const matchSupport: Record<string, string> = {
  psirt_supported: "Vendor PSIRT + product name",
  vendor_text_supported: "Vendor wording + product name",
  product_alias_only: "Looser match · product name only",
};
export function watchTickets(rows: ProductWatchRow[]) {
  return rows.map(row => ({
    cve_id: row.cve_id, rank: null, verdict: "review", source_list: "product_review",
    headline: `Review ${row.vendor} · ${row.product}`,
    proposed_action: "Confirm the product match and affected versions in your inventory, then review snapshot evidence. This list is not a prediction or a patch priority.",
    evidence_summary: `${row.prior_kev_count ?? "pending"} earlier KEV entries for the matched product; latest ${row.latest_prior_kev_cve || "pending"} (${row.latest_prior_kev_date || "pending"}). Match support: ${matchSupport[row.match_confidence] ?? row.match_confidence}. EPSS: ${row.epss ?? "pending"} at ${row.snapshot_month || "pending"}. No public exploit flag at the snapshot; missing observations may also produce a zero flag. ${row.description}`,
  }));
}
