import type { Score } from "./types";
export interface StackChoice {
  kind: "vendor" | "product" | "text";
  value: string;
  vendor?: string;
}
export interface StackSuggestion extends StackChoice {
  matches: number;
  top500: number;
}
export const STACK_KEY = "slow-burn.stack.v1";
export const normalizeIdentity = (value = "") =>
  value
    .normalize("NFKC")
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, " ")
    .trim();
const usable = (value?: string) =>
  !!value?.trim() &&
  !["unmapped", "unknown", "none", "n a"].includes(normalizeIdentity(value));
export const choiceKey = (choice: StackChoice) =>
  `${choice.kind}:${normalizeIdentity(choice.vendor)}:${normalizeIdentity(choice.value)}`;
export const choiceLabel = (choice: StackChoice) =>
  choice.kind === "product" && choice.vendor
    ? `${choice.vendor} · ${choice.value}`
    : choice.value;
export function matchesStack(row: Score, choices: StackChoice[]) {
  return (
    !choices.length ||
    choices.some((choice) => {
      const value = normalizeIdentity(choice.value);
      if (!value) return false;
      if (choice.kind === "vendor")
        return normalizeIdentity(row.vendor_identity) === value;
      if (choice.kind === "product")
        return (
          normalizeIdentity(row.product_identity) === value &&
          (!choice.vendor ||
            normalizeIdentity(row.vendor_identity) ===
              normalizeIdentity(choice.vendor))
        );
      const text = normalizeIdentity(
        `${row.vendor_identity ?? ""} ${row.product_identity ?? ""} ${row.assigner ?? ""} ${row.description ?? ""}`,
      );
      return ` ${text} `.includes(` ${value} `);
    })
  );
}
export function stackSuggestions(scores: Score[]) {
  const choices = new Map<string, StackSuggestion>();
  for (const row of scores) {
    const values: StackChoice[] = [];
    if (usable(row.vendor_identity))
      values.push({ kind: "vendor", value: row.vendor_identity! });
    if (usable(row.product_identity))
      values.push({
        kind: "product",
        value: row.product_identity!,
        ...(usable(row.vendor_identity) ? { vendor: row.vendor_identity } : {}),
      });
    for (const choice of values) {
      const key = choiceKey(choice),
        item = choices.get(key) ?? { ...choice, matches: 0, top500: 0 };
      item.matches++;
      if (row.rank <= 500) item.top500++;
      choices.set(key, item);
    }
  }
  return [...choices.values()].sort(
    (a, b) =>
      b.top500 - a.top500 ||
      b.matches - a.matches ||
      choiceLabel(a).localeCompare(choiceLabel(b)),
  );
}
export function parseStack(value: string | null): StackChoice[] {
  try {
    const parsed: unknown = JSON.parse(value ?? "[]");
    if (!Array.isArray(parsed)) return [];
    const unique = new Map<string, StackChoice>();
    for (const item of parsed.slice(0, 50)) {
      if (
        !item ||
        !["vendor", "product", "text"].includes(item.kind) ||
        typeof item.value !== "string" ||
        !item.value.trim() ||
        item.value.length > 100 ||
        (item.vendor != null && typeof item.vendor !== "string")
      )
        continue;
      const choice: StackChoice = {
        kind: item.kind,
        value: item.value.trim(),
        ...(item.vendor ? { vendor: item.vendor.slice(0, 100) } : {}),
      };
      unique.set(choiceKey(choice), choice);
    }
    return [...unique.values()];
  } catch {
    return [];
  }
}
export function loadStack(
  storage: () => Pick<Storage, "getItem"> = () => localStorage,
) {
  try {
    return parseStack(storage().getItem(STACK_KEY));
  } catch {
    return [];
  }
}
export function saveStack(
  choices: StackChoice[],
  storage: () => Pick<Storage, "setItem"> = () => localStorage,
) {
  try {
    storage().setItem(STACK_KEY, JSON.stringify(choices));
    return true;
  } catch {
    return false;
  }
}
