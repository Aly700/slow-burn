import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  connectAnalyst,
  applyAskEvent,
  newQuestion,
  recordedAnswer,
  suggestions,
} from "../src/analyst.ts";
const evaluation = JSON.parse(
  await readFile(
    new URL("../../agent/evals/analyst_eval.json", import.meta.url),
    "utf8",
  ),
);
function harness(q = "test question") {
  const listeners = {};
  let closed = false,
    session = newQuestion(q, "live"),
    error,
    url;
  const stop = connectAnalyst(
    q,
    (e) => {
      session = applyAskEvent(session, e);
    },
    (message) => {
      error = message;
    },
    (u) => {
      url = u;
      return {
        addEventListener(n, f) {
          listeners[n] = f;
        },
        close() {
          closed = true;
        },
      };
    },
  );
  return {
    emit: (n, d) => listeners[n]({ data: JSON.stringify(d) }),
    disconnect: () => listeners.error({}),
    stop,
    read: () => ({ session, error, url, closed }),
  };
}
test("analyst stream retains query, results and dropped claims and ends on its matching answer", () => {
  const h = harness("vendor & product?");
  h.emit("start", { run_id: "ask-1", question: "vendor & product?" });
  h.emit("tool_call", {
    call_id: "t1",
    tool: "search_ranked",
    args: { filters: { vendor: "Fortinet" }, limit: 3 },
  });
  h.emit("tool_result", {
    call_id: "t1",
    ms: 9,
    preview: { matched_count: 23 },
  });
  const c = {
    id: "a1",
    text: "23 matches.",
    verified: true,
    evidence: [{ tool: "search_ranked", field: "matched_count", value: 23 }],
  };
  h.emit("claim", c);
  h.emit("claim", {
    id: "drop",
    text: "Unproven claim.",
    verified: false,
    reason: "No source",
  });
  h.emit("answer", { text: c.text, claims: [c] });
  h.emit("done", { run_id: "ask-1", duration_ms: 5000 });
  const r = h.read();
  assert.equal(r.closed, true);
  assert.equal(r.error, undefined);
  assert.match(r.url, /vendor%20%26%20product%3F/);
  assert.equal(r.session.status, "complete");
  assert.equal(r.session.query.filters.vendor, "Fortinet");
  assert.equal(r.session.tools[0].working, false);
  assert.equal(r.session.claims[1].verified, false);
});
test("unsupported answers can complete empty, while mismatched and interrupted streams cannot succeed", () => {
  const empty = harness();
  empty.emit("start", { run_id: "a", question: "test question" });
  empty.emit("answer", { text: "Unsupported question.", claims: [] });
  empty.emit("done", { run_id: "a", duration_ms: 2 });
  assert.equal(empty.read().session.status, "complete");
  assert.equal(empty.read().session.claims.length, 0);
  for (const events of [
    [["start", { run_id: "a", question: "another" }]],
    [
      ["start", { run_id: "a", question: "test question" }],
      ["done", { run_id: "b", duration_ms: 1 }],
    ],
    [
      ["start", { run_id: "a", question: "test question" }],
      [
        "claim",
        { id: "a1", text: "Unsupported", verified: true, evidence: [] },
      ],
    ],
    [
      ["start", { run_id: "a", question: "test question" }],
      ["tool_call", { tool: "file_fix_ticket", call_id: "x", args: {} }],
    ],
  ]) {
    const h = harness();
    for (const [n, d] of events) h.emit(n, d);
    assert.ok(h.read().error);
    assert.equal(h.read().closed, true);
  }
  const h = harness();
  h.disconnect();
  assert.ok(h.read().error);
  assert.equal(h.read().closed, true);
});
test("only fully answered recorded questions become suggestions and recordings keep source identity", () => {
  const rows = suggestions(evaluation);
  assert.equal(rows.length, evaluation.fully);
  assert.ok(rows.every((r) => r.grade === "fully"));
  assert.equal(suggestions(null).length, 0);
  const original = rows[0],
    session = recordedAnswer(original);
  assert.equal(session.mode, "recorded");
  assert.equal(session.run_id, original.run_id);
  assert.deepEqual(session.query, original.query);
  assert.deepEqual(session.answer, original.answer);
  assert.equal(session.duration_ms, original.duration_ms);
});
