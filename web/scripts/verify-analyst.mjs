import { createRequire } from "node:module";
import path from "node:path";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
const require = createRequire(
  path.resolve(process.env.PLAYWRIGHT_ROOT ?? process.cwd(), "package.json"),
);
const { chromium } = require("playwright-core");
const bundle = JSON.parse(
  await readFile(
    new URL("../public/data/bundle.json", import.meta.url),
    "utf8",
  ),
);
const record = bundle.analyst_eval.results.find((r) => r.grade === "fully");
const browser = await chromium.launch({ channel: "chromium" });
const errors = [],
  passed = [];
const base = process.env.PREVIEW_URL ?? "http://localhost:4317";
try {
  const page = await browser.newPage({
    viewport: { width: 1440, height: 900 },
  });
  page.on("pageerror", (e) => errors.push(e.message));
  await page.route("http://127.0.0.1:8765/live/health", (r) =>
    r.fulfill({ json: { ready: true } }),
  );
  await page.addInitScript(() => {
    window.__asks = [];
    window.EventSource = class {
      listeners = {};
      closed = false;
      constructor(url) {
        this.url = url;
        window.__asks.push(this);
      }
      addEventListener(name, fn) {
        this.listeners[name] = fn;
      }
      close() {
        this.closed = true;
      }
    };
  });
  const emit = async (name, data) =>
    page.evaluate(
      ({ name, data }) =>
        window.__asks.at(-1).listeners[name]?.({ data: JSON.stringify(data) }),
      { name, data },
    );
  await page.goto(base);
  await page.locator(".analyst-health.ready").waitFor();
  await page.locator(".question-chips button").first().click();
  assert.equal(
    await page.evaluate(() =>
      new URL(window.__asks.at(-1).url).searchParams.get("q"),
    ),
    record.question,
  );
  await emit("start", { run_id: "mock-ask", question: record.question });
  await emit("state", { state: "INVESTIGATING", queued: true, position: 2 });
  assert.match(
    await page.locator(".analyst-result-head").textContent(),
    /Queued.*2/,
  );
  await emit("tool_call", {
    call_id: "t1",
    tool: "search_ranked",
    args: { filters: { vendor: "Fortinet" }, limit: 3 },
  });
  assert.match(await page.locator(".analyst-tools").textContent(), /working/);
  await emit("claim", {
    id: "drop",
    text: "An unsupported statement.",
    verified: false,
    reason: "No matching source evidence.",
  });
  assert.equal(
    await page.locator(".answer-claim.dropped s").textContent(),
    "An unsupported statement.",
  );
  await emit("tool_result", {
    call_id: "t1",
    tool: "search_ranked",
    ms: 9,
    preview: { matched_count: 23 },
  });
  await emit("answer", record.answer);
  await emit("done", { run_id: "mock-ask", duration_ms: 5000 });
  assert.equal(
    await page.locator(".answer-claim.verified").count(),
    record.answer.claims.length,
  );
  assert.equal(await page.evaluate(() => window.__asks.at(-1).closed), true);
  await page.locator(".answer-sentence a").first().click();
  await page.getByRole("dialog").waitFor();
  await page.keyboard.press("Escape");
  passed.push(
    "mock stream renders query, queue status, working tool, verified and dropped claims, then opens a CVE briefing",
  );
  await page.locator(".question-chips button").first().click();
  await page.getByRole("button", { name: "Stop question" }).click();
  assert.equal(await page.evaluate(() => window.__asks.at(-1).closed), true);
  assert.match(
    await page.locator(".analyst-no-answer").textContent(),
    /No verified answer/,
  );
  passed.push("stop closes the connection and offers tested suggestions");
  await page.route("http://127.0.0.1:8765/**", (r) => r.abort());
  await page.locator(".analyst-health button").click();
  await page.locator(".analyst-health.offline").waitFor();
  await page.locator(".question-chips button").first().click();
  assert.match(
    await page.locator(".analyst-result-head").textContent(),
    /Recorded answer/,
  );
  assert.equal(
    await page.locator(".answer-claim.verified").count(),
    record.answer.claims.length,
  );
  await page
    .locator("#analyst-question")
    .fill("a question without a saved answer");
  await page.locator(".analyst-form .button").click();
  assert.equal(await page.locator(".answer-claim").count(), 0);
  assert.match(
    await page.locator(".analyst-no-answer").textContent(),
    /No recorded answer for this question/,
  );
  passed.push(
    "offline suggestions retain their recorded answers; arbitrary questions never borrow another answer",
  );
  await page.locator("#analyst-question").blur();
  await page.keyboard.press("p");
  for (let i = 0; i < 4; i++) await page.keyboard.press("ArrowRight");
  await page
    .getByRole("button", { name: "Ask a question about the ranking ↗" })
    .click();
  await page.waitForFunction(
    () => document.activeElement?.id === "analyst-question",
  );
  passed.push("slide five entry exits presentation and focuses the question");
  assert.deepEqual(errors, []);
  console.log(JSON.stringify({ passed, errors }, null, 2));
} finally {
  await browser.close();
}
