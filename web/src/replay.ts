import type { ReplayData, ReplayItem } from "./types";

export const REPLAY_DURATION_MS = 12_000;
export const replayDate = (date?: string | null) =>
  date ? Date.parse(`${date.slice(0, 10)}T00:00:00Z`) : Infinity;
export function snapshotEnd(month?: string) {
  if (!month) return Infinity;
  const [year, index] = month.split("-").map(Number);
  return Date.UTC(year, index, 1) - 1;
}
export function replayBounds(data: ReplayData) {
  return {
    start: replayDate(data.start),
    end: replayDate(data.end) + 86_400_000 - 1,
  };
}
export function replayTime(data: ReplayData, progress: number) {
  const { start, end } = replayBounds(data);
  return start + Math.max(0, Math.min(1, progress)) * (end - start);
}
export const isIgnited = (item: ReplayItem, time: number) =>
  snapshotEnd(item.snapshot_month) <= time && replayDate(item.kev_date) <= time;
export function missedItems(data: ReplayData) {
  const caught = new Set(
    (data.methods ?? []).flatMap((method) =>
      (method.items ?? []).map((item) => item.cve_id),
    ),
  );
  return (data.later_exploited ?? []).filter(
    (item) => !caught.has(item.cve_id),
  );
}
