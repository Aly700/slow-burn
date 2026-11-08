import { createRequire } from "node:module";
import path from "node:path";
import { readFile } from "node:fs/promises";
import assert from "node:assert/strict";
const { chromium } = createRequire(
  path.resolve(process.env.PLAYWRIGHT_ROOT ?? process.cwd(), "package.json"),
)("playwright-core");
const base = process.env.PREVIEW_URL ?? "http://127.0.0.1:5173";
const bundle = JSON.parse(
  await readFile(
    new URL("../public/data/bundle.json", import.meta.url),
    "utf8",
  ),
);
const browser = await chromium.launch({ channel: "chromium" });
const passed = [];
async function check(name, run) {
  const page = await browser.newPage({
    viewport: { width: 1440, height: 900 },
    deviceScaleFactor: 2,
  });
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  try {
    await run(page);
    assert.deepEqual(errors, []);
    passed.push(name);
  } finally {
    await page.close();
  }
}
try {
  await check(
    "subpath loads both lazy datasets, uses primary neighbour evidence, and preserves the six chapters",
    async (page) => {
      const requests = [];
      page.on("request", (request) => requests.push(request.url()));
      await page.route("**/slow-burn/**", async (route) => {
        const url = new URL(route.request().url());
        url.pathname = url.pathname.replace("/slow-burn/", "/");
        await route.fulfill({ response: await route.fetch({ url: url.href }) });
      });
      await page.goto(`${base}/slow-burn/`);
      await page.waitForFunction(
        () =>
          document.querySelector("main")?.getAttribute("aria-busy") === "false",
      );
      assert.ok(
        !requests.some(
          (url) =>
            url.includes("/data/map_2026.json") ||
            url.includes("/data/product_watch_2026.json"),
        ),
      );
      await page.locator(".map-section").scrollIntoViewIfNeeded();
      await page.waitForSelector(
        `canvas[data-points="${bundle.findings.map.rows}"]`,
      );
      const primary = bundle.findings.map.neighbour_check;
      const values = await page
        .locator(".map-evidence strong")
        .allTextContents();
      assert.deepEqual(
        values,
        [
          primary.primary_2025.probability_positive_is_closer,
          primary.primary_2025.permutation.null_mean,
          primary.no_signal_sensitivity.probability_positive_is_closer,
        ].map((value) => `${(value * 100).toFixed(0)}%`),
      );
      await page
        .getByRole("textbox", { name: "Add vendor or product" })
        .fill("Yealink");
      await page.getByRole("button", { name: "Add to stack" }).click();
      await page.waitForFunction(
        () =>
          !document
            .querySelector(".watch-empty")
            ?.textContent?.includes("Loading"),
      );
      await page.getByLabel("Include looser name matches").check();
      await page.waitForSelector(".watch-row");
      assert.ok(
        requests.some((url) =>
          url.includes("/slow-burn/data/product_watch_2026.json"),
        ),
      );
      assert.ok(
        requests.some((url) => url.includes("/slow-burn/data/map_2026.json")),
      );
      await page.locator(".map-field canvas").focus();
      await page.keyboard.press("p");
      await page.keyboard.press("ArrowRight");
      await page.keyboard.press("ArrowRight");
      await page.keyboard.press("ArrowRight");
      await page.keyboard.press("m");
      await page.waitForSelector(".map-appendix canvas[data-points]");
      await page.locator(".map-appendix canvas").focus();
      await page.keyboard.press("ArrowRight");
      assert.equal(await page.locator(".present-map").count(), 1);
      await page.keyboard.press("Escape");
      assert.equal(await page.locator(".slide-4").count(), 1);
      await page.keyboard.press("ArrowRight");
      assert.equal(await page.locator(".slide-5").count(), 1);
    },
  );
  await check(
    "missing map and review artifacts render honest empty states",
    async (page) => {
      await page.route("**/data/bundle.json", (route) =>
        route.fulfill({
          json: { scores: [], findings: { map: { neighbour_check: {} } } },
        }),
      );
      await page.goto(base);
      await page.locator(".map-section").scrollIntoViewIfNeeded();
      assert.match(await page.locator(".map-loading").innerText(), /pending/);
      assert.deepEqual(
        await page.locator(".map-evidence strong").allTextContents(),
        ["pending", "pending", "pending"],
      );
      assert.equal(await page.locator(".product-watch").count(), 0);
    },
  );
  await check(
    "failed map and review downloads can retry without reloading the page",
    async (page) => {
      let mapCalls = 0,
        watchCalls = 0;
      await page.route("**/data/map_2026.json", (route) =>
        ++mapCalls === 1
          ? route.fulfill({ status: 503, body: "Unavailable" })
          : route.continue(),
      );
      await page.route("**/data/product_watch_2026.json", (route) =>
        ++watchCalls === 1
          ? route.fulfill({ status: 503, body: "Unavailable" })
          : route.continue(),
      );
      await page.goto(base);
      await page.locator(".map-section").scrollIntoViewIfNeeded();
      await page.locator(".map-loading button").click();
      await page.waitForSelector("canvas[data-points]");
      await page
        .getByRole("textbox", { name: "Add vendor or product" })
        .fill("Microsoft");
      await page.getByRole("button", { name: "Add to stack" }).click();
      await page.locator(".watch-empty button").click();
      await page.waitForSelector(".watch-row");
      assert.equal(mapCalls, 2);
      assert.equal(watchCalls, 2);
    },
  );
  await check(
    "reduced motion map stays still until an explicit interaction",
    async (page) => {
      await page.emulateMedia({ reducedMotion: "reduce" });
      await page.goto(base);
      await page.locator(".map-section").scrollIntoViewIfNeeded();
      await page.waitForSelector("canvas[data-points]");
      const canvas = page.locator(".map-field canvas");
      await page.waitForFunction(
        () => document.querySelector(".map-field canvas")?.dataset.renderMs,
      );
      await page.evaluate(() => document.fonts.ready);
      await page.evaluate(
        () =>
          new Promise((resolve) =>
            requestAnimationFrame(() => requestAnimationFrame(resolve)),
          ),
      );
      const before = await canvas.evaluate((element) => element.toDataURL());
      await page.waitForTimeout(300);
      assert.ok(
        (await canvas.evaluate((element) => element.toDataURL())) === before,
        "Map should not animate without input",
      );
      await page.getByLabel("Zoom in on map").click();
      await page.waitForFunction(
        () =>
          Number(document.querySelector(".map-field canvas").dataset.zoom) > 1,
      );
    },
  );
  console.log(JSON.stringify({ passed }, null, 2));
} finally {
  await browser.close();
}
