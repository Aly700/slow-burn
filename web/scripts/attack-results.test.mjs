import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { attackSummary } from "../src/attackResults.ts";
const evaluation = JSON.parse(
  await readFile(
    new URL("../../artifacts/redteam_eval.json", import.meta.url),
    "utf8",
  ),
);

test("held-out evidence leads and repeated development attacks and clean descriptions count once", () => {
  const summary = attackSummary(evaluation);
  assert.equal(summary.heldOut.injected_content_survived_runs, 4);
  assert.equal(summary.heldOut.cases, 32);
  assert.equal(summary.before.injected_content_survived_runs, 7);
  assert.equal(summary.development.injected_content_survived_runs, 0);
  assert.equal(summary.distinctAttacks, 80);
  assert.equal(summary.tickets, 0);
  assert.equal(summary.verdictChanges, 0);
  assert.equal(summary.cleanDescriptions, 100);
  assert.equal(summary.falsePositives, 0);
  assert.equal(
    summary.heldOut.detector_recall,
    evaluation.held_out.detector_recall,
  );
});

test("root development aliases cannot replace any named evaluation section", () => {
  const changed = {
    ...evaluation,
    cases: 999,
    injected_content_survived_runs: 888,
    tickets_filed_without_approval: 777,
  };
  assert.deepEqual(attackSummary(changed), attackSummary(evaluation));
  const rootOnly = {
    ...changed,
    before: undefined,
    development: undefined,
    held_out: undefined,
  };
  const summary = attackSummary(rootOnly);
  assert.equal(summary.heldOut, undefined);
  assert.equal(summary.development, undefined);
  assert.equal(summary.distinctAttacks, null);
  assert.equal(summary.tickets, null);
  assert.equal(summary.falsePositives, null);
});

test("a failed boundary in any run is visible and repeated clean detections are deduplicated", () => {
  const changed = structuredClone(evaluation);
  changed.before.tickets_filed_without_approval = 2;
  changed.development.verdict_changes = 3;
  changed.held_out.verdict_changes = 1;
  changed.development.cases = 12;
  changed.held_out.cases = 6;
  for (const [key, index] of [
    ["before", 0],
    ["development", 1],
    ["held_out", 0],
  ]) {
    changed[key].clean_detector_results[index].detected = true;
    changed[key].false_positives = 1;
  }
  const summary = attackSummary(changed);
  assert.equal(summary.distinctAttacks, 18);
  assert.equal(summary.tickets, 2);
  assert.equal(summary.verdictChanges, 4);
  assert.equal(summary.cleanDescriptions, 100);
  assert.equal(summary.falsePositives, 2);
});

test("missing sections and unknown measurements cannot produce a zero guarantee", () => {
  for (const missing of ["before", "development", "held_out"]) {
    const summary = attackSummary({ ...evaluation, [missing]: null });
    assert.equal(summary.tickets, null);
    assert.equal(summary.verdictChanges, null);
    assert.equal(summary.cleanDescriptions, null);
    assert.equal(summary.falsePositives, null);
    if (missing !== "before") assert.equal(summary.distinctAttacks, null);
  }
  const changed = structuredClone(evaluation);
  changed.held_out.cases = null;
  changed.before.tickets_filed_without_approval = null;
  changed.development.verdict_changes = Number.NaN;
  const summary = attackSummary(changed);
  assert.equal(summary.distinctAttacks, null);
  assert.equal(summary.tickets, null);
  assert.equal(summary.verdictChanges, null);
});

test("incomplete or contradictory clean samples stay pending instead of claiming perfect precision", () => {
  for (const mutate of [
    (d) => {
      d.held_out.clean_detector_results = null;
    },
    (d) => {
      d.before.clean_descriptions = null;
    },
    (d) => {
      d.development.clean_detector_results[0].detected = true;
    },
    (d) => {
      d.before.clean_detector_results[1].cve_id =
        d.before.clean_detector_results[0].cve_id;
    },
  ]) {
    const changed = structuredClone(evaluation);
    mutate(changed);
    assert.equal(attackSummary(changed).falsePositives, null);
    assert.equal(attackSummary(changed).cleanDescriptions, null);
  }
});
