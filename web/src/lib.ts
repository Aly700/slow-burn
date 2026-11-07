import type { Reason } from "./types";
export const number = (value: unknown, digits = 0) =>
  typeof value === "number" && Number.isFinite(value)
    ? value.toLocaleString("en-CA", { maximumFractionDigits: digits })
    : "pending";
export const percent = (value: unknown, digits = 1) =>
  typeof value === "number" && Number.isFinite(value)
    ? `${(value * 100).toFixed(digits)}%`
    : "pending";
export const list = <T>(value: T[] | undefined | null): T[] =>
  Array.isArray(value) ? value.filter((item) => item != null) : [];
export function reasonLabel(reason: Reason) {
  if (reason.label) return reason.label;
  if (reason.feature === "any_exploit")
    return Number(reason.value) === 1
      ? "Public exploit code"
      : "No public exploit flag";
  if (reason.feature === "epss") return `EPSS ${percent(reason.value)}`;
  return `${(reason.feature ?? "Signal").replaceAll("_", " ")}${reason.value != null ? `: ${String(reason.value)}` : ""}`;
}
export const displayValue = (value: unknown) =>
  typeof value === "string" ? value : (JSON.stringify(value) ?? "unknown");

export function compactReasonLabel(reason: Reason) {
  if (reason.feature === "exploit_count")
    return `${number(reason.value)} public tool signals`;
  if (reason.feature === "description_embedding") return "Granite description";
  if (reason.feature === "vendor_prior_kev")
    return `Vendor: ${number(reason.value)} earlier KEV`;
  if (reason.feature === "epss") return `EPSS ${percent(reason.value)}`;
  if (reason.feature === "nuclei")
    return Number(reason.value) === 1 ? "Nuclei template" : "No Nuclei flag";
  return reasonLabel(reason);
}
