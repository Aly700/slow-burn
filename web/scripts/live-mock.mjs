// A controllable EventSource for local browser checks; no inference server required.
export async function installLiveMock(page) {
  await page.route("http://127.0.0.1:8765/live/health", (route) =>
    route.fulfill({
      json: { ready: true, model: "recorded-test-model", loaded_at: null },
    }),
  );
  await page.addInitScript(() => {
    window.__streams = [];
    class ControlledEventSource extends EventTarget {
      constructor(url) {
        super();
        this.url = url;
        this.closed = false;
        window.__streams.push(this);
      }
      close() {
        this.closed = true;
      }
      emit(event, data) {
        if (!this.closed)
          this.dispatchEvent(
            new MessageEvent(event, { data: JSON.stringify(data) }),
          );
      }
    }
    window.EventSource = ControlledEventSource;
  });
}
export async function emit(page, event, data) {
  await page.evaluate(
    ({ event, data }) => window.__streams.at(-1).emit(event, data),
    { event, data },
  );
}
export async function startLiveMock(page, run) {
  const live = {
    ...run,
    run_id: "browser-live-run",
    list: "live",
    state: "WAITING_APPROVAL",
  };
  await page
    .getByRole("button", { name: "Run live with Granite", exact: true })
    .click();
  await emit(page, "start", {
    run_id: live.run_id,
    cve_id: live.cve_id,
    model: live.model,
    started_at: live.started_at,
  });
  await emit(page, "state", { state: "INVESTIGATING" });
  await emit(page, "tool_call", {
    call_id: "lookup",
    tool: "get_cve",
    args: { cve_id: live.cve_id },
  });
  await emit(page, "tool_result", {
    call_id: "lookup",
    tool: "get_cve",
    ms: 9,
    preview: { cve_id: live.cve_id, snapshot_month: live.snapshot_month },
  });
  await emit(page, "tool_call", {
    call_id: "history",
    tool: "vendor_history",
    args: { cve_id: live.cve_id },
  });
  return live;
}
export async function finishLiveMock(page, run) {
  await emit(page, "tool_result", {
    call_id: "history",
    tool: "vendor_history",
    ms: 41,
    preview: { summary: "Historical snapshot evidence returned" },
  });
  for (const claim of run.briefing?.claims ?? [])
    await emit(page, "claim", claim);
  await emit(page, "claim", {
    id: "unsupported-test",
    text: "Every installation is confirmed compromised.",
    verified: false,
    reason: "No environment evidence supports this claim.",
  });
  await emit(page, "state", { state: "VERIFIED" });
  await emit(page, "briefing", { run });
  await emit(page, "state", { state: "WAITING_APPROVAL" });
  await emit(page, "done", {
    run_id: run.run_id,
    duration_ms: run.duration_ms,
  });
}
