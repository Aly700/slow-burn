import { createRequire } from "node:module";
import path from "node:path";
import { readFile } from "node:fs/promises";
import assert from "node:assert/strict";
import { decodeWatch, filterWatch } from "../src/productWatch.ts";
import { parseCsv } from "./csv.mjs";
import {
  installLiveMock,
  startLiveMock,
  finishLiveMock,
  emit,
} from "./live-mock.mjs";
const require = createRequire(
  path.resolve(process.env.PLAYWRIGHT_ROOT ?? process.cwd(), "package.json"),
);
const { chromium } = require("playwright-core");
const base = process.env.PREVIEW_URL ?? "http://localhost:4317";
const bundle = JSON.parse(
  await readFile(
    new URL("../public/data/bundle.json", import.meta.url),
    "utf8",
  ),
);
const browser = await chromium.launch({ channel: "chromium" }),
  passed = [],
  errors = [];
async function load(page, url = base) {
  page.on("pageerror", (error) => errors.push(error.message));
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.goto(url);
  await page.waitForFunction(
    () => document.querySelector("main")?.getAttribute("aria-busy") === "false",
  );
}
async function deck(page) {
  await page.keyboard.press("p");
  for (let i = 0; i < 4; i++) await page.keyboard.press("ArrowRight");
}
async function check(name, fn) {
  const page = await browser.newPage({
    viewport: { width: 1440, height: 900 },
    deviceScaleFactor: 2,
  });
  try {
    await fn(page);
    passed.push(name);
  } finally {
    await page.close();
  }
}
try {
  await check(
    "live stream finishes into the exact run approval, with evidence and dropped claims",
    async (page) => {
      await installLiveMock(page);
      await load(page);
      await deck(page);
      const cve = await page
        .getByRole("textbox", { name: "2026 CVE to investigate" })
        .inputValue();
      const run = await startLiveMock(
        page,
        bundle.runs.find((run) => run.cve_id === cve),
      );
      assert.equal(
        await page.getByRole("button", { name: "Approve ticket" }).count(),
        0,
      );
      assert.match(await page.locator(".live-trace").textContent(), /working/);
      await emit(page, "claim", {
        id: "drop",
        text: "Unsupported claim",
        verified: false,
        reason: "No evidence",
      });
      assert.equal(
        await page.locator(".live-claims s").textContent(),
        "Unsupported claim",
      );
      await finishLiveMock(page, run);
      assert.ok(
        await page
          .locator(".present-slide")
          .evaluate((node) => node.scrollHeight <= node.clientHeight + 2),
        "Completed live briefing must fit the slide",
      );
      await page.keyboard.press("ArrowRight");
      let sent;
      await page.route(
        "http://localhost:8765/runs/**/approval",
        async (route) => {
          sent = {
            url: route.request().url(),
            body: route.request().postDataJSON(),
          };
          await route.fulfill({
            json: { run: { ...run, state: "TICKET_FILED" } },
          });
        },
      );
      await page.getByRole("button", { name: "Approve ticket" }).click();
      await page.getByText("Service response: ticket filed.").waitFor();
      assert.match(sent.url, /browser-live-run\/approval$/);
      assert.equal(sent.body.briefing_hash, run.briefing_hash);
    },
  );
  await check(
    "offline replay retains the original identity and never sends an approval request",
    async (page) => {
      await page.route("http://127.0.0.1:8765/**", (route) => route.abort());
      let writes = 0;
      await page.route("http://localhost:8765/**", (route) => {
        writes++;
        return route.abort();
      });
      await load(page);
      await deck(page);
      await page
        .getByRole("textbox", { name: "2026 CVE to investigate" })
        .fill("CVE-2026-99999999");
      await page.getByRole("button", { name: "Run live with Granite" }).click();
      await page.locator(".live-complete").waitFor();
      assert.match(
        await page.locator(".live-message").textContent(),
        /No recording.*Replaying CVE-/,
      );
      await page.keyboard.press("ArrowRight");
      await page.getByRole("button", { name: "Approve ticket" }).click();
      await page.getByText(/Simulated approval only/).waitFor();
      assert.equal(writes, 0);
    },
  );
  await check(
    "cancel and stream errors cannot leave a stale approval behind",
    async (page) => {
      await installLiveMock(page);
      await load(page);
      await deck(page);
      const cve = await page
        .getByRole("textbox", { name: "2026 CVE to investigate" })
        .inputValue();
      await startLiveMock(
        page,
        bundle.runs.find((run) => run.cve_id === cve),
      );
      await page.getByRole("button", { name: "Stop", exact: true }).click();
      assert.equal(
        await page.evaluate(() => window.__streams.at(-1).closed),
        true,
      );
      await page.keyboard.press("ArrowRight");
      assert.equal(
        await page.getByRole("button", { name: "Approve ticket" }).count(),
        0,
      );
      await page.keyboard.press("ArrowLeft");
      await startLiveMock(
        page,
        bundle.runs.find((run) => run.cve_id === cve),
      );
      await emit(page, "error", {
        message: "CVE not present in the scoreboard.",
      });
      await page.getByText("CVE not present in the scoreboard.").waitFor();
      await page.keyboard.press("ArrowRight");
      assert.equal(
        await page.getByRole("button", { name: "Approve ticket" }).count(),
        0,
      );
    },
  );
  await check(
    "closing the briefing drawer cancels its active EventSource",
    async (page) => {
      await installLiveMock(page);
      await load(page);
      await page.getByRole("button", { name: "Inspect the briefing" }).click();
      const cve = await page
        .getByRole("textbox", { name: "2026 CVE to investigate" })
        .inputValue();
      await startLiveMock(
        page,
        bundle.runs.find((run) => run.cve_id === cve),
      );
      await page.getByRole("button", { name: "Close briefing" }).click();
      assert.equal(
        await page.evaluate(() => window.__streams.at(-1).closed),
        true,
      );
    },
  );
  await check(
    "replay end state and scrubber stay accurate with reduced motion",
    async (page) => {
      await load(page);
      const counts = await page
        .locator(".lane-heading>strong")
        .allTextContents();
      assert.deepEqual(
        counts,
        bundle.replay_2025.methods.map((method) => `${method.hits}caught`),
      );
      const range = page.getByRole("slider", { name: "Replay date" });
      await range.fill("0");
      assert.ok(
        (await page.locator(".lane-heading>strong").allTextContents()).every(
          (count) => count === "0caught",
        ),
      );
      await range.fill("1000");
      await page
        .getByRole("button", { name: "Inspect confirmed CVEs" })
        .click();
      await page.locator(".replay-accessible-list button").first().click();
      assert.match(
        await page.locator(".ember-tooltip").textContent(),
        /Published.*KEV inclusion/,
      );
    },
  );
  await check(
    "stack persists per viewer and exports all filtered rows in both formats",
    async (page) => {
      await load(page);
      await page
        .getByRole("textbox", { name: "Add vendor or product" })
        .fill("Adobe");
      await page.getByRole("button", { name: "Add to stack" }).click();
      const rows = bundle.scores.filter(
        (row) => row.vendor_identity === "Adobe",
      );
      const top = rows.filter((row) => row.rank <= 500).length;
      assert.match(
        await page.locator(".stack-impact>strong").textContent(),
        new RegExp(`^${top} /`),
      );
      await page.reload();
      await page.waitForFunction(
        () =>
          document.querySelector("main")?.getAttribute("aria-busy") === "false",
      );
      assert.match(
        await page.locator(".stack-selected").textContent(),
        /Adobe/,
      );
      for (const format of ["CSV", "JSON tickets"]) {
        await page.getByLabel("Export filtered queue").click();
        const pending = page.waitForEvent("download");
        await page
          .getByRole("button", { name: new RegExp(`^Download ${format}`) })
          .click();
        const download = await pending;
        const content = await readFile(await download.path(), "utf8");
        if (format === "JSON tickets") {
          const payload = JSON.parse(content);
          const review = bundle.lazy?.product_watch
            ? filterWatch(
                decodeWatch(
                  JSON.parse(
                    await readFile(
                      new URL(
                        `../public/data/${bundle.lazy.product_watch.file}`,
                        import.meta.url,
                      ),
                      "utf8",
                    ),
                  ),
                ),
                [{ kind: "vendor", value: "Adobe" }],
              )
            : [];
          assert.deepEqual(
            payload
              .filter((row) => row.source_list === "product_review")
              .map((row) => row.cve_id),
            review.map((row) => row.cve_id),
          );
          assert.ok(
            payload
              .filter((row) => row.source_list === "product_review")
              .every((row) => row.rank === null && row.verdict === "review"),
          );
          assert.deepEqual(
            payload
              .filter((row) => row.source_list === "fix_first")
              .map((row) => row.cve_id),
            rows.map((row) => row.cve_id),
          );
          assert.ok(
            payload.every(
              (row) => "proposed_action" in row && "evidence_summary" in row,
            ),
          );
        } else {
          assert.ok(content.includes("proposed_action"));
          const parsed = parseCsv(content),
            sourceIndex = parsed[0].indexOf("source_list");
          assert.equal(
            parsed.slice(1).filter((row) => row[sourceIndex] === "fix_first")
              .length,
            rows.length,
          );
          if (bundle.lazy?.product_watch)
            assert.ok(
              parsed
                .slice(1)
                .some((row) => row[sourceIndex] === "product_review"),
            );
          for (const row of rows) assert.ok(content.includes(row.cve_id));
        }
      }
      await page
        .getByRole("textbox", { name: "Search queue" })
        .fill("no-match");
      assert.equal(await page.locator("tbody tr").count(), 0);
      await page
        .getByRole("button", { name: "Clear filters", exact: true })
        .click();
      assert.equal(await page.locator(".stack-selected").count(), 0);
    },
  );
  await check(
    "blocked localStorage leaves working stack filters and downloads",
    async (page) => {
      await page.addInitScript(() =>
        Object.defineProperty(window, "localStorage", {
          get() {
            throw new DOMException("blocked", "SecurityError");
          },
        }),
      );
      await load(page);
      await page
        .getByRole("textbox", { name: "Add vendor or product" })
        .fill("ColdFusion");
      await page.getByRole("button", { name: "Add to stack" }).click();
      assert.match(
        await page.locator(".stack-save").textContent(),
        /Kept for this visit/,
      );
      assert.ok((await page.locator("tbody tr").count()) > 0);
      assert.match(
        await page.locator(".stack-selected").textContent(),
        /Adobe.*coldfusion/i,
      );
    },
  );
  await check(
    "static subpath assets load on a hosted origin and use only offline approval",
    async (page) => {
      const dist = new URL("../dist/", import.meta.url).pathname;
      let localRequests = 0;
      page.on("request", (request) => {
        if (request.url().includes(":8765")) localRequests++;
      });
      await page.route("https://aly700.github.io/slow-burn/**", (route) => {
        const relative =
          new URL(route.request().url()).pathname.slice("/slow-burn/".length) ||
          "index.html";
        return route.fulfill({ path: path.join(dist, relative) });
      });
      await load(page, "https://aly700.github.io/slow-burn/");
      await deck(page);
      await page
        .getByText("Granite offline · recorded replay available")
        .waitFor();
      await page.getByRole("button", { name: "Run live with Granite" }).click();
      await page.locator(".live-complete").waitFor();
      await page.keyboard.press("ArrowRight");
      await page.getByRole("button", { name: "Approve ticket" }).click();
      await page.getByText(/Simulated approval only/).waitFor();
      assert.equal(localRequests, 0);
    },
  );
  await check(
    "changing the investigated CVE replaces the drawer ranking evidence too",
    async (page) => {
      await installLiveMock(page);
      await load(page);
      await page.getByRole("button", { name: "Inspect the briefing" }).click();
      const original = await page
        .getByRole("textbox", { name: "2026 CVE to investigate" })
        .inputValue();
      const other = bundle.runs.find(
        (run) =>
          run.cve_id !== original &&
          bundle.scores.some((row) => row.cve_id === run.cve_id),
      );
      const row = bundle.scores.find((row) => row.cve_id === other.cve_id);
      await page
        .getByRole("textbox", { name: "2026 CVE to investigate" })
        .fill(other.cve_id);
      const live = await startLiveMock(page, other);
      await finishLiveMock(page, live);
      assert.equal(
        await page.locator("#briefing-title").textContent(),
        other.cve_id,
      );
      const evidence = page.locator("details.run-metadata").filter({
        has: page.getByText("Ranking signals at the snapshot", {
          exact: true,
        }),
      });
      assert.deepEqual(
        await evidence.locator("p").allTextContents(),
        row.reasons.map((reason) => reason.label ?? reason.feature),
      );
    },
  );
  assert.deepEqual(errors, []);
  console.log(JSON.stringify({ passed, errors }, null, 2));
} finally {
  await browser.close();
}
