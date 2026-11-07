import { createRequire } from "node:module";
import path from "node:path";
import { readFile, mkdir } from "node:fs/promises";
import assert from "node:assert/strict";
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
const shots = new URL("../../shots/checks/", import.meta.url);
await mkdir(shots, { recursive: true });
const browser = await chromium.launch({ channel: "chromium" });
const errors = [],
  passed = [];
async function check(name, fn) {
  const page = await browser.newPage({
    viewport: { width: 1440, height: 900 },
    deviceScaleFactor: 2,
  });
  page.on("pageerror", (e) => errors.push(`${name}: ${e.message}`));
  await page.emulateMedia({ reducedMotion: "reduce" });
  try {
    await fn(page);
    passed.push(name);
  } finally {
    await page.close();
  }
}
async function load(page, data) {
  if (data !== undefined)
    await page.route("**/data/bundle.json", (r) => r.fulfill({ json: data }));
  await page.goto(base);
  await page.waitForFunction(
    () => document.querySelector("main")?.getAttribute("aria-busy") === "false",
  );
  await page.evaluate(() => document.fonts.ready);
}
async function queue(page) {
  await page
    .locator("#queue")
    .evaluate((node) =>
      window.scrollTo({ top: node.offsetTop - 90, behavior: "instant" }),
    );
}
const open = (page, id = "CVE-2026-8037") =>
  page.getByRole("button", { name: id, exact: true }).click();
try {
  await check(
    "search, empty state, filters, pagination, keyboard",
    async (page) => {
      await load(page);
      await queue(page);
      assert.equal(await page.locator("tbody tr").count(), 10);
      await page
        .getByRole("textbox", { name: "Search queue" })
        .fill("no-such-record");
      assert.equal(await page.locator("tbody tr").count(), 0);
      await page.screenshot({
        path: new URL("empty-search.png", shots).pathname,
      });
      await page.getByRole("button", { name: "Clear filters" }).click();
      await page
        .getByRole("button", { name: /2 illustrative briefings/ })
        .click();
      assert.equal(await page.locator("tbody tr").count(), 2);
      await page
        .getByRole("combobox", { name: "Snapshot month" })
        .selectOption("2026-01");
      assert.equal(await page.locator("tbody tr").count(), 0);
      await page.getByRole("button", { name: "Clear filters" }).click();
      await page.getByRole("button", { name: "Next", exact: true }).click();
      assert.match(await page.locator("tbody tr").first().innerText(), /^011/);
      await page.getByRole("button", { name: "Previous", exact: true }).click();
      await queue(page);
      await page
        .getByRole("button", { name: "CVE-2026-8037", exact: true })
        .focus();
      await page.keyboard.press("j");
      await page.waitForFunction(
        () => document.activeElement?.textContent === "CVE-2022-25369",
      );
      await page.keyboard.press("Enter");
      assert.match(
        await page.getByRole("dialog").innerText(),
        /No recorded briefing/,
      );
      await page.keyboard.press("Escape");
      await page.keyboard.press("k");
      await page.keyboard.press("Enter");
      assert.match(
        await page.getByRole("dialog").innerText(),
        /Illustrative fixture/,
      );
    },
  );
  await check(
    "evidence, trace, focus trap, approval persistence",
    async (page) => {
      await load(page);
      await queue(page);
      await open(page);
      await page.keyboard.press("Shift+Tab");
      assert.equal(
        await page.evaluate(() =>
          document.activeElement?.textContent?.includes("Approve ticket"),
        ),
        true,
      );
      await page.keyboard.press("Tab");
      assert.equal(
        await page.evaluate(() =>
          document.activeElement?.getAttribute("aria-label"),
        ),
        "Close briefing",
      );
      await page.locator(".evidence-chip summary").first().click();
      assert.match(
        await page.locator(".evidence-chip[open]").innerText(),
        /cve_lookup/,
      );
      assert.equal(await page.locator(".dropped-claims s").count(), 1);
      await page.getByRole("tab", { name: /Trace/ }).click();
      assert.equal(await page.locator(".trace-event").count(), 6);
      await page.getByRole("button", { name: "Approve ticket" }).click();
      assert.match(
        await page.getByRole("status").innerText(),
        /Simulated approval/,
      );
      await page.screenshot({ path: new URL("approved.png", shots).pathname });
      await page.getByRole("button", { name: "Close briefing" }).click();
      await open(page);
      assert.equal(
        await page.getByRole("button", { name: "Approve ticket" }).count(),
        0,
      );
    },
  );
  await check("injection and rejection", async (page) => {
    await load(page);
    await queue(page);
    await open(page, "CVE-2026-10523");
    assert.match(
      await page.locator(".injection-warning").innerText(),
      /Human approval remains required/,
    );
    await page.locator(".injection-warning summary").click();
    assert.match(
      await page.locator(".injection-warning code").innerText(),
      /Ignore previous instructions/,
    );
    await page.getByRole("button", { name: "Reject", exact: true }).click();
    assert.match(
      await page.getByRole("status").innerText(),
      /Simulated rejection/,
    );
    assert.match(
      await page.locator(".state-machine .current").innerText(),
      /rejected/i,
    );
  });
  await check("missing bundle and null nested fields", async (page) => {
    await page.route("**/data/bundle.json", (r) =>
      r.fulfill({ status: 404, body: "missing" }),
    );
    await load(page);
    assert.match(await page.locator(".data-banner").innerText(), /unavailable/);
    assert.equal(await page.locator(".result-number").innerText(), "pending");
    await page.unroute("**/data/bundle.json");
    await page.route("**/data/bundle.json", (r) =>
      r.fulfill({
        json: {
          findings: {
            headline: { benchmark_2026_reference: { cvss_first: null } },
            two_clocks: null,
            signals: null,
            deprioritize: null,
          },
          backtest: { methods: null },
          model_card: {
            features_used: null,
            features_excluded: null,
            ibm_technology: null,
          },
          scores: null,
          runs: null,
          meta: null,
        },
      }),
    );
    await page.reload();
    await page.waitForFunction(
      () =>
        document.querySelector("main")?.getAttribute("aria-busy") === "false",
    );
    assert.doesNotMatch(
      await page.locator("body").innerText(),
      /Infinity|NaN|undefined/,
    );
    await page.screenshot({
      path: new URL("missing-data.png", shots).pathname,
    });
  });
  await check("live approval request contract", async (page) => {
    const live = structuredClone(bundle);
    live.meta.runs_source = "recorded";
    let posted;
    await page.route("http://localhost:8765/**", async (route) => {
      posted = route.request().postDataJSON();
      await route.fulfill({
        json: {
          state: "TICKET_FILED",
          states_seen: [
            "RECEIVED",
            "INVESTIGATING",
            "VERIFIED",
            "WAITING_APPROVAL",
            "TICKET_FILED",
          ],
        },
      });
    });
    await load(page, live);
    await queue(page);
    await open(page);
    await page.getByRole("button", { name: "Approve ticket" }).click();
    await page.waitForFunction(() =>
      document
        .querySelector(".approval-note")
        ?.textContent?.includes("Service response"),
    );
    assert.deepEqual(posted, { approved: true });
  });
  await check("service rejection stays pending", async (page) => {
    const live = structuredClone(bundle);
    live.meta.runs_source = "recorded";
    await page.route("http://localhost:8765/**", (route) =>
      route.fulfill({ status: 409, json: { detail: "Briefing changed" } }),
    );
    await load(page, live);
    await queue(page);
    await open(page);
    await page.getByRole("button", { name: "Approve ticket" }).click();
    await page.waitForFunction(() =>
      document.querySelector(".approval-note")?.textContent?.includes("409"),
    );
    assert.equal(
      await page.getByRole("button", { name: "Approve ticket" }).count(),
      1,
    );
  });
  await check("mobile layout and briefing", async (page) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await load(page);
    assert.equal(
      await page.evaluate(
        () => document.documentElement.scrollWidth > innerWidth,
      ),
      false,
    );
    await page.screenshot({ path: new URL("mobile-hero.png", shots).pathname });
    await queue(page);
    await open(page);
    assert.equal(
      await page.evaluate(
        () => document.documentElement.scrollWidth > innerWidth,
      ),
      false,
    );
    await page.screenshot({
      path: new URL("mobile-briefing.png", shots).pathname,
    });
  });
  assert.deepEqual(errors, []);
  console.log(JSON.stringify({ passed, errors }, null, 2));
} finally {
  await browser.close();
}
