import { createRequire } from "node:module";
import path from "node:path";
const { chromium } = createRequire(
  path.resolve(process.env.PLAYWRIGHT_ROOT ?? process.cwd(), "package.json"),
)("playwright-core");
import fs from "node:fs/promises";
const out = new URL("../../shots/round5", import.meta.url).pathname;
await fs.mkdir(out, { recursive: true });
const browser = await chromium.launch({ channel: "chromium" });
for (const width of [1280, 1440, 1920, 390]) {
  const page = await browser.newPage({
    viewport: {
      width,
      height: width === 1920 ? 1080 : width === 390 ? 844 : 900,
    },
    deviceScaleFactor: 2,
  });
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto(process.env.PREVIEW_URL ?? "http://127.0.0.1:5173");
  await page.waitForSelector(".map-section");
  await page.locator(".map-section").scrollIntoViewIfNeeded();
  await page.waitForSelector('.map-field canvas[data-points="72987"]');
  await page.waitForTimeout(400);
  await page
    .locator(".granite-map")
    .screenshot({
      style: ".site-header,.skip-link{visibility:hidden}",
      path: `${out}/map-full-${width}.png`,
    });
  await page.screenshot({ path: `${out}/map-${width}.png` });
  const initial = await page
    .locator(".map-field canvas")
    .getAttribute("data-render-ms");
  await page.getByLabel("Product review", { exact: false }).check();
  await page.screenshot({ path: `${out}/map-overlay-${width}.png` });
  await page.getByLabel("Explore a map region").selectOption("68");
  await page.waitForTimeout(100);
  await page.screenshot({ path: `${out}/map-region-${width}.png` });
  const c = page.locator(".map-field canvas");
  const box = await c.boundingBox();
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
  await page.waitForTimeout(100);
  await page.screenshot({ path: `${out}/map-hover-${width}.png` });
  await page.getByLabel("Reset map view").click();
  const frames = await c.evaluate(async (canvas) => {
    const samples = [],
      cadence = [];
    let last = performance.now();

    for (let i = 0; i < 120; i++) {
      await new Promise((resolve) => requestAnimationFrame(resolve));
      const now = performance.now();
      if (i > 5) cadence.push(now - last);
      last = now;
      canvas.dispatchEvent(
        new KeyboardEvent("keydown", {
          key: i % 2 ? "ArrowLeft" : "ArrowRight",
          bubbles: true,
        }),
      );
      samples.push(Number(canvas.dataset.renderMs));
    }

    return {
      draw: samples.sort((a, b) => a - b),
      cadence: cadence.sort((a, b) => a - b),
    };
  });
  await c.focus();
  await page.keyboard.press("p");
  await page.getByRole("button", { name: "Explore map M" }).click();
  await page.waitForSelector('.map-appendix canvas[data-points="72987"]');
  await page.waitForTimeout(100);
  await page.screenshot({ path: `${out}/map-appendix-${width}.png` });
  const fit = await page
    .locator(".present-map")
    .evaluate((e) => ({ height: e.clientHeight, scroll: e.scrollHeight }));
  await page.keyboard.press("Escape");
  if (!(await page.locator(".slide-1").isVisible()))
    throw Error("Appendix did not return to chapter");
  await page.keyboard.press("Escape");
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth > innerWidth,
  );
  console.log({
    width,
    initial,
    panMedian: frames.draw[60],
    pan95: frames.draw[114],
    frameMedian: frames.cadence[57],
    frame95: frames.cadence[108],
    fit,
    overflow,
    errors,
  });
  if (overflow || errors.length) throw Error("Browser failure");
  await page.close();
}
await browser.close();
