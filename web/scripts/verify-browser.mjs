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
const evidenceBreadth = (run) =>
  new Set(
    (run.briefing?.claims ?? []).flatMap((claim) =>
      (claim.evidence ?? []).map((evidence) => evidence.field),
    ),
  ).size;
const candidates = bundle.runs.filter(
  (run) =>
    run.briefing?.verdict === "fix_now" && run.verifier?.claims_verified >= 4,
);
const featured =
  candidates.find((run) => run.cve_id === "CVE-2026-10523") ??
  candidates.sort(
    (a, b) =>
      b.verifier.claims_verified - a.verifier.claims_verified ||
      evidenceBreadth(b) - evidenceBreadth(a),
  )[0] ??
  bundle.runs[0];
const rejectRun = bundle.runs.find(
  (run) =>
    run.run_id !== featured.run_id &&
    bundle.scores.some((score) => score.cve_id === run.cve_id),
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
  page.on("pageerror", (error) => errors.push(`${name}: ${error.message}`));
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
    await page.route("**/data/bundle.json", (route) =>
      route.fulfill({ json: data }),
    );
  await page.goto(base);
  await page.waitForFunction(
    () => document.querySelector("main")?.getAttribute("aria-busy") === "false",
  );
  await page.evaluate(() => document.fonts.ready);
}
async function present(page, slide = 1) {
  await page.keyboard.press("p");
  for (let index = 1; index < slide; index++)
    await page.keyboard.press("ArrowRight");
}
const visibleSlide = (page) => page.getByRole("region", { name: /^Slide/ });
const openFeatured = (page) =>
  page.getByRole("button", { name: "Inspect the briefing" }).click();
try {
  await check(
    "presentation keyboard, focus and all six viewport slides",
    async (page) => {
      await load(page);
      assert.match(await page.title(), /Slow Burn/);
      await page.getByRole("button", { name: /Present P/ }).focus();
      await present(page);
      for (let slide = 1; slide <= 6; slide++) {
        assert.match(
          await visibleSlide(page).getAttribute("aria-label"),
          new RegExp(`^Slide ${slide}:`),
        );
        const box = await page.locator(".present-slide").evaluate((node) => ({
          width: node.scrollWidth <= node.clientWidth + 2,
          height: node.scrollHeight <= node.clientHeight + 2,
        }));
        assert.deepEqual(
          box,
          { width: true, height: true },
          `Slide ${slide} must fit the viewport`,
        );
        if (slide < 6) await page.keyboard.press("Space");
      }
      await page.keyboard.press("ArrowLeft");
      assert.match(
        await visibleSlide(page).getAttribute("aria-label"),
        /^Slide 5:/,
      );
      await page.keyboard.press("Escape");
      assert.equal(await page.getByRole("dialog").count(), 0);
      assert.match(
        await page.evaluate(() => document.activeElement.textContent),
        /Present/,
      );
      assert.equal(await page.evaluate(() => document.body.style.overflow), "");
    },
  );
  await check(
    "queue search, pagination, filters and j/k navigation",
    async (page) => {
      await load(page);
      await page.locator("#queue").scrollIntoViewIfNeeded();
      const search = page.getByRole("textbox", { name: "Search queue" });
      await search.fill("no-such-record");
      assert.equal(await page.locator("tbody tr").count(), 0);
      await page.getByRole("button", { name: "Clear filters" }).click();
      await page.getByRole("button", { name: "Next", exact: true }).click();
      assert.equal(await page.locator("tbody tr").count(), 10);
      await page.getByRole("button", { name: "Previous", exact: true }).click();
      const first = page.locator("tbody .cve-button").first();
      const initial = await first.textContent();
      await first.focus();
      await page.keyboard.press("j");
      await page.waitForFunction(
        (id) => document.activeElement?.textContent !== id,
        initial,
      );
      await page.keyboard.press("k");
      await page.waitForFunction(
        (id) => document.activeElement?.textContent === id,
        initial,
      );
      await page.keyboard.press("Enter");
      assert.equal(await page.getByRole("dialog").count(), 1);
      await page.keyboard.press("Escape");
      await search.fill("p");
      assert.equal(await page.locator(".presentation").count(), 0);
    },
  );
  await check(
    "recorded briefing evidence, trace and live hash payload",
    async (page) => {
      let posted;
      await page.route("http://localhost:8765/**", async (route) => {
        posted = route.request().postDataJSON();
        await route.fulfill({ json: { state: "TICKET_FILED" } });
      });
      await load(page);
      await openFeatured(page);
      assert.match(
        await page.getByRole("dialog").innerText(),
        /Recorded investigation/,
      );
      await page.locator(".evidence-chip summary").first().click();
      assert.match(
        await page.locator(".evidence-chip[open]").innerText(),
        /get_cve/,
      );
      await page.getByRole("tab", { name: /Trace/ }).click();
      assert.ok((await page.locator(".trace-event").count()) > 0);
      await page.getByRole("button", { name: "Approve ticket" }).click();
      await page.waitForFunction(() =>
        document
          .querySelector(".approval-note")
          ?.textContent?.includes("Service response"),
      );
      assert.deepEqual(posted, {
        approved: true,
        briefing_hash: featured.briefing_hash,
      });
      await page.keyboard.press("Escape");
      await present(page, 6);
      assert.match(await visibleSlide(page).innerText(), /ticket filed/);
      assert.equal(
        await page.getByRole("button", { name: "Approve ticket" }).count(),
        0,
      );
    },
  );
  await check(
    "offline decisions are labelled simulations and persist",
    async (page) => {
      await page.route("http://localhost:8765/**", (route) =>
        route.abort("connectionrefused"),
      );
      await load(page);
      await present(page, 6);
      await page.getByRole("button", { name: "Reject", exact: true }).click();
      await page.waitForFunction(() =>
        document
          .querySelector(".approval-note")
          ?.textContent?.includes("Simulated rejection"),
      );
      assert.match(
        await page.locator(".gate-control h2").innerText(),
        /Simulated: rejected/,
      );
      await page.keyboard.press("Escape");
      await openFeatured(page);
      assert.match(
        await page.locator(".approval-note").innerText(),
        /Simulated rejection/,
      );
      assert.equal(
        await page.getByRole("button", { name: "Approve ticket" }).count(),
        0,
      );
    },
  );
  await check(
    "HTTP conflict cannot fall back to a simulated success",
    async (page) => {
      await page.route("http://localhost:8765/**", (route) =>
        route.fulfill({ status: 409, json: { detail: "briefing changed" } }),
      );
      await load(page);
      await present(page, 6);
      await page.getByRole("button", { name: "Approve ticket" }).click();
      await page.waitForFunction(() =>
        document.querySelector(".approval-note")?.textContent?.includes("409"),
      );
      assert.match(await page.locator(".gate-control h2").innerText(), /Ready/);
    },
  );
  await check(
    "blind-spot study separates the primary test, exploratory contrast and patch allocation",
    async (page) => {
      await load(page);
      const study = page.locator("#discovery .blind-study");
      assert.deepEqual(
        await study.locator(".watch-results strong").allTextContents(),
        ["0 / 31", "0 / 31", "0.33"],
      );
      assert.match(
        await study.locator(".contrast-count").innerText(),
        /15 of 31/,
      );
      assert.deepEqual(
        await study.locator(".history-share > strong").allTextContents(),
        ["48%", "16%"],
      );
      assert.match(
        await study.locator(".vendor-null").innerText(),
        /1.0× lift/,
      );
      assert.match(
        await page.locator("#discovery .watch-allocation").innerText(),
        /450 exploit \+ 50 watch found 21 vs 22 hits.*100% exploit tier/s,
      );
      assert.equal(
        await page.locator("#discovery .watch-methods a").getAttribute("href"),
        "https://github.com/Aly700/slow-burn/blob/main/pipeline/WATCH_PLAN.md",
      );
      await page.locator("#discovery .watch-limitations summary").click();
      assert.match(
        await page.locator("#discovery .watch-limitations").innerText(),
        /exploratory contrasts, not preregistered causal tests/,
      );
      assert.equal(
        await page
          .getByText("Previously attacked products, no public exploit yet", {
            exact: true,
          })
          .count(),
        0,
      );
      await present(page, 3);
      assert.match(
        await page.locator(".presentation .watch-feature-boundary").innerText(),
        /earlier 2025 exposure/,
      );
      assert.match(
        await page.locator(".presentation .watch-takeaway").innerText(),
        /check whether you run a product that has been attacked before/,
      );
    },
  );
  await check(
    "optional findings, histogram, vendor buckets and dropped claim",
    async (page) => {
      const data = structuredClone(bundle);
      data.findings.blind_spot = null;
      Object.assign(data.findings.headline, {
        later_kev_without_public_signal: 20,
        later_kev_with_public_signal: 10,
      });
      data.findings.two_clocks.lag_hist = [
        { bucket: "1–30", n: 8 },
        { bucket: "31–60", n: 5 },
        { bucket: "61–90", n: 2 },
      ];
      data.findings.vendor_history_within_poc = {
        pool: 100,
        positives: 10,
        base_rate: 0.1,
        buckets: [
          {
            identity: "assigner",
            earlier_kev_bucket: "0",
            n: 50,
            hits: 1,
            rate: 0.02,
            lift_within_poc: 0.2,
          },
          {
            identity: "assigner",
            earlier_kev_bucket: "1–4",
            n: 30,
            hits: 3,
            rate: 0.1,
            lift_within_poc: 1,
          },
          {
            identity: "assigner",
            earlier_kev_bucket: "5+",
            n: 20,
            hits: 6,
            rate: 0.3,
            lift_within_poc: 3,
          },
        ],
      };
      data.findings.story = [
        {
          title: "Test finding",
          sentence: "Synthetic rendering check, not a research result.",
          numbers: { test_count: 10 },
        },
      ];
      data.runs[0].verifier.dropped = [
        {
          id: "test-drop",
          text: "Unsupported test claim",
          why: "No matching tool evidence",
        },
      ];
      await load(page, data);
      assert.match(
        await page.locator(".blind-number").innerText(),
        /20.*of 30/s,
      );
      assert.equal(await page.locator(".vendor-row").count(), 3);
      await present(page, 2);
      assert.equal(await page.locator(".lag-bars > div").count(), 3);
      await page.keyboard.press("ArrowRight");
      await page.keyboard.press("ArrowRight");
      assert.equal(await page.locator(".vendor-row:visible").count(), 6);
      await page.screenshot({
        path: new URL("optional-vendors.png", shots).pathname,
      });
      await page.keyboard.press("ArrowRight");
      assert.match(
        await page.locator(".present-dropped s").innerText(),
        /Unsupported test claim/,
      );
      await page.screenshot({
        path: new URL("optional-dropped.png", shots).pathname,
      });
    },
  );
  await check(
    "missing and null data render all six slides without invented values",
    async (page) => {
      await load(page, {
        findings: {
          headline: null,
          two_clocks: null,
          vendor_history_within_poc: null,
          signals: null,
          story: null,
        },
        agent_eval: { arms: null },
        model_card: {
          features_used: null,
          features_excluded: null,
          ibm_technology: null,
        },
        scores: null,
        runs: null,
        meta: null,
      });
      await present(page);
      for (let slide = 1; slide <= 6; slide++) {
        const text = await visibleSlide(page).innerText();
        assert.doesNotMatch(text, /NaN|Infinity|undefined/);
        assert.match(text, /pending/i);
        assert.equal(
          await page
            .locator(".present-slide")
            .evaluate((node) => node.scrollWidth <= node.clientWidth + 2),
          true,
          `Missing-data slide ${slide} overflows`,
        );
        if (slide < 6) await page.keyboard.press("ArrowRight");
      }
      await page.screenshot({
        path: new URL("missing-presentation.png", shots).pathname,
      });
    },
  );
  await check(
    "fixture injection and dropped claims remain available",
    async (page) => {
      const fixture = JSON.parse(
        await readFile(
          new URL("../fixtures/CVE-2026-10523.json", import.meta.url),
          "utf8",
        ),
      );
      await load(page, {
        ...bundle,
        runs: [fixture],
        meta: { ...bundle.meta, runs_source: "fixtures" },
      });
      await openFeatured(page);
      assert.equal(await page.locator(".dropped-claims s").count(), 1);
      assert.match(
        await page.locator(".injection-warning").innerText(),
        /injection detected/,
      );
      await page.getByRole("button", { name: "Reject", exact: true }).click();
      assert.match(
        await page.locator(".approval-note").innerText(),
        /Simulated rejection/,
      );
    },
  );
  if (process.env.LIVE_APPROVAL === "1")
    await check(
      "real API approval and rejection with durable local ticket",
      async (page) => {
        await load(page);
        await present(page, 6);
        await page.getByRole("button", { name: "Approve ticket" }).click();
        await page.waitForFunction(() =>
          document
            .querySelector(".approval-note")
            ?.textContent?.includes("Service response: ticket filed"),
        );
        await page.screenshot({
          path: new URL("real-approved.png", shots).pathname,
        });
        const tickets = (
          await readFile(
            new URL("../.runtime/demo/tickets.jsonl", import.meta.url),
            "utf8",
          )
        )
          .trim()
          .split("\n")
          .map(JSON.parse);
        assert.ok(tickets.some((ticket) => ticket.cve_id === featured.cve_id));
        await page.keyboard.press("Escape");
        await page.locator("#queue").scrollIntoViewIfNeeded();
        await page
          .getByRole("textbox", { name: "Search queue" })
          .fill(rejectRun.cve_id);
        await page
          .getByRole("button", { name: rejectRun.cve_id, exact: true })
          .click();
        await page.getByRole("button", { name: "Reject", exact: true }).click();
        await page.waitForFunction(() =>
          document
            .querySelector(".approval-note")
            ?.textContent?.includes("Service response: rejected"),
        );
        assert.equal(
          (
            await readFile(
              new URL("../.runtime/demo/tickets.jsonl", import.meta.url),
              "utf8",
            )
          )
            .trim()
            .split("\n").length,
          tickets.length,
        );
      },
    );
  assert.deepEqual(errors, []);
  console.log(JSON.stringify({ passed, errors }, null, 2));
} finally {
  await browser.close();
}
