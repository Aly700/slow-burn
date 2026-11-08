import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  snapshotEnd,
  replayDate,
  replayTime,
  isIgnited,
  missedItems,
} from "../src/replay.ts";
const data = JSON.parse(
  await readFile(
    new URL("../../artifacts/replay_2025.json", import.meta.url),
    "utf8",
  ),
);
test("replay reveals snapshots only at month end and ignites on the recorded KEV date", () => {
  const item = { snapshot_month: "2025-01", kev_date: "2025-02-06" };
  assert.equal(snapshotEnd(item.snapshot_month), Date.UTC(2025, 1, 1) - 1);
  assert.equal(isIgnited(item, replayDate("2025-02-05")), false);
  assert.equal(isIgnited(item, replayDate("2025-02-06")), true);
  assert.equal(
    isIgnited({ ...item, kev_date: null }, replayTime(data, 1)),
    false,
  );
});
test("replay final counters agree with every artifact method; missed tray is the complement", () => {
  for (const method of data.methods)
    assert.equal(
      method.items.filter((item) => isIgnited(item, replayTime(data, 1)))
        .length,
      method.hits,
      method.key,
    );
  const missed = missedItems(data);
  const caught = new Set(
    data.methods.flatMap((method) =>
      method.items.filter((item) => item.kev_date).map((item) => item.cve_id),
    ),
  );
  assert.equal(missed.length + caught.size, data.positives);
  assert.ok(
    missed.every((item) =>
      Object.values(item.rank_in).every((rank) => rank == null),
    ),
  );
});
