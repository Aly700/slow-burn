import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { blindSpotSummary } from "../src/blindSpot.ts";
const study = JSON.parse(
  await readFile(
    new URL("../../artifacts/findings.json", import.meta.url),
    "utf8",
  ),
).blind_spot;

test("watch summary uses the registered recipe and primary split, not the overlapping secondary", () => {
  const data = structuredClone(study);
  data.splits.reverse();
  data.mixed_allocations.reverse();
  const result = blindSpotSummary(data);
  assert.equal(result.year, "2025");
  assert.equal(result.selectionYear, 2024);
  assert.equal(result.selectionFrozen, true);
  assert.equal(result.result.hits, 0);
  assert.equal(result.epss.hits, 0);
  assert.equal(result.positives, 31);
  assert.equal(result.budget, 500);
  assert.equal(result.total, 55);
  assert.equal(result.product.no_signal_positives, 15);
  assert.equal(result.mixed.delta_vs_frozen, -1);
  assert.equal(result.mixed.watch_rows, 50);
  assert.equal(result.exploitShare, 1);
});

test("watch numbers and budget come from the artifact, including changed or zero observations", () => {
  const data = structuredClone(study);
  const primary = data.splits.find((s) => s.name === "2024_to_2025");
  const allocations = data.mixed_allocations.find(
    (s) => s.split === primary.name,
  );
  allocations.allocations.find(
    (a) => a.name === "frozen submitted model",
  ).budget = 250;
  allocations.allocations.find(
    (a) => a.name === "frozen submitted model",
  ).exploit_tier_rows = 200;
  primary.methods
    .find((m) => m.name === data.selected_recipe)
    .budgets.find((b) => b.budget === 250).hits = 3;
  data.profile.no_signal_positives = 0;
  data.profile.with_signal_positives = 10;
  const result = blindSpotSummary(data);
  assert.equal(result.result.hits, 3);
  assert.equal(result.result.random_expected_hits, 0.1650516451922053);
  assert.equal(result.total, 10);
  assert.equal(result.exploitShare, 0.8);
});

test("missing study, null measurements and missing selected recipe stay unknown", () => {
  for (const data of [
    undefined,
    null,
    {},
    { splits: null, profile: null, mixed_allocations: null },
  ]) {
    const result = blindSpotSummary(data);
    assert.equal(result.result, undefined);
    assert.equal(result.total, undefined);
    assert.equal(result.exploitShare, undefined);
    assert.equal(result.registered, false);
  }
  const data = structuredClone(study);
  data.selected_recipe = null;
  data.profile.no_signal_positives = null;
  assert.equal(blindSpotSummary(data).result, undefined);
  assert.equal(blindSpotSummary(data).total, undefined);
});
