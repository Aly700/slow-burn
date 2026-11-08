import { test } from "node:test";
import assert from "node:assert/strict";
import {
  applyLiveEvent,
  connectInvestigation,
  recordedEvents,
  replayEvents,
  localViewer,
  validCve,
} from "../src/investigation.ts";
import { normalizeRecording } from "./live-recordings.mjs";
class MockSource {
  listeners = new Map();
  closed = false;
  addEventListener(name, fn) {
    this.listeners.set(name, fn);
  }
  close() {
    this.closed = true;
  }
  emit(name, data) {
    this.listeners.get(name)?.(
      data === undefined
        ? {}
        : { data: typeof data === "string" ? data : JSON.stringify(data) },
    );
  }
}
const run = {
  run_id: "live-test",
  cve_id: "CVE-2026-12345",
  state: "WAITING_APPROVAL",
  list: "live",
  duration_ms: 246,
  briefing: {
    claims: [{ id: "c1", text: "Supported", verified: true, evidence: [] }],
  },
  verifier: { dropped: [{ id: "c2", why: "No evidence" }] },
  trace: [
    {
      t_ms: 12,
      kind: "tool",
      name: "get_cve",
      duration_ms: 34,
      output_summary: "Snapshot record",
    },
    { t_ms: 240, kind: "verifier", name: "check", duration_ms: 2 },
  ],
};
function stream() {
  const source = new MockSource(),
    messages = [],
    errors = [];
  const close = connectInvestigation(
    run.cve_id,
    (event) => messages.push(event),
    (message) => errors.push(message),
    (url) => {
      assert.match(url, /127\.0\.0\.1:8765\/live\/CVE-2026-12345$/);
      return source;
    },
  );
  return { source, messages, errors, close };
}
test("mock EventSource streams tools and verified/dropped claims, then closes without reconnecting", () => {
  const { source, messages, errors } = stream();
  source.emit("start", { run_id: run.run_id, cve_id: run.cve_id });
  source.emit("tool_call", {
    call_id: "t1",
    tool: "get_cve",
    args: { cve_id: run.cve_id },
  });
  source.emit("tool_result", {
    call_id: "t1",
    tool: "get_cve",
    ms: 34,
    preview: { published: "snapshot" },
  });
  source.emit("claim", {
    id: "c1",
    text: "Supported",
    evidence: [],
    verified: true,
  });
  source.emit("claim", {
    id: "c2",
    text: "Unsupported",
    verified: false,
    reason: "No evidence",
  });
  source.emit("briefing", { run });
  source.emit("done", { run_id: run.run_id, duration_ms: 246 });
  assert.ok(source.closed);
  assert.deepEqual(errors, []);
  const state = messages.reduce(applyLiveEvent, {
    mode: "live",
    status: "running",
    cve_id: run.cve_id,
    tools: [],
    claims: [],
  });
  assert.equal(state.status, "complete");
  assert.equal(state.run.run_id, run.run_id);
  assert.equal(state.tools[0].working, false);
  assert.equal(state.tools[0].ms, 34);
  assert.equal(state.claims[1].verified, false);
  source.emit("error");
  assert.deepEqual(errors, []);
});
test("stream interruption, malformed data, missing briefing and mismatched identity fail closed", () => {
  for (const scenario of [
    "disconnect",
    "invalid",
    "identity",
    "briefing",
    "premature",
  ]) {
    const { source, errors, close } = stream();
    source.emit("start", { run_id: run.run_id, cve_id: run.cve_id });
    if (scenario === "disconnect") source.emit("error");
    if (scenario === "invalid") source.emit("claim", "not-json");
    if (scenario === "identity")
      source.emit("start", { run_id: "x", cve_id: "CVE-2026-0000" });
    if (scenario === "briefing")
      source.emit("briefing", { run: { ...run, run_id: "wrong" } });
    if (scenario === "premature") source.emit("done", { run_id: run.run_id });
    assert.equal(errors.length, 1, scenario);
    assert.ok(source.closed);
    close();
  }
});
test("recorded trace retains real call, result, verification and completion timings", () => {
  const events = recordedEvents(run);
  assert.equal(events.find((e) => e.event === "tool_call").t_ms, 12);
  assert.equal(events.find((e) => e.event === "tool_result").t_ms, 46);
  assert.equal(events.find((e) => e.event === "claim").t_ms, 242);
  assert.equal(events.at(-1).t_ms, 246);
  const scheduled = [],
    cancelled = [];
  const stop = replayEvents(
    events,
    () => {},
    (fn, time) => {
      scheduled.push(time);
      return time;
    },
    (id) => cancelled.push(id),
  );
  assert.deepEqual(
    scheduled,
    events.map((e) => e.t_ms),
  );
  stop();
  assert.deepEqual(cancelled, scheduled);
});
test("complete recorded event journals are accepted; missing real timings or identity are rejected", () => {
  const events = recordedEvents(run);
  assert.equal(normalizeRecording({ events }).cve_id, run.cve_id);
  assert.equal(
    normalizeRecording({ events, fixture: "injection-direct" }).fixture,
    "injection-direct",
  );
  assert.equal(
    normalizeRecording(events.map(({ t_ms, ...event }) => event)),
    null,
  );
  assert.equal(
    normalizeRecording(events.filter((event) => event.event !== "briefing")),
    null,
  );
});
test("hosted pages stay offline and only 2026 identifiers can launch", () => {
  assert.equal(localViewer("aly700.github.io"), false);
  assert.equal(localViewer("127.0.0.1"), true);
  assert.equal(validCve("CVE-2026-10523"), true);
  assert.equal(validCve("CVE-2025-10523"), false);
  assert.equal(validCve("../live/health"), false);
});
