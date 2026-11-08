import { createRequire } from "node:module";
import path from "node:path";
import fs from "node:fs/promises";
import assert from "node:assert/strict";
import { decodeMap, mapStories } from "../src/graniteMap.ts";
const { chromium } = createRequire(
  path.resolve(process.env.PLAYWRIGHT_ROOT ?? process.cwd(), "package.json"),
)("playwright-core");
const base = process.env.PREVIEW_URL ?? "http://127.0.0.1:5173";
const artifact = JSON.parse(
  await fs.readFile(
    new URL("../../artifacts/map_2026.json", import.meta.url),
    "utf8",
  ),
);
const stories = mapStories(decodeMap(artifact));
const out = new URL("../../shots/round6", import.meta.url).pathname;
await fs.mkdir(out, { recursive: true });
const browser = await chromium.launch({ channel: "chromium" });
const result = [];
async function settled(canvas) {
  await canvas.evaluate(async (element) => {
    await new Promise((resolve) =>
      requestAnimationFrame(() => requestAnimationFrame(resolve)),
    );
    while (
      element.dataset.flying !== "false" ||
      element.dataset.entrance !== "done"
    )
      await new Promise((resolve) => requestAnimationFrame(resolve));
  });
}
async function labelsClear(canvas, requireWordpress = false) {
  const layout = await canvas.evaluate((element) => {
    const b = element.getBoundingClientRect();
    return {
      labels: JSON.parse(element.dataset.labels || "[]"),
      blocks: [
        ...element.parentElement.querySelectorAll(
          ".map-guidance,.map-controls,.map-tooltip",
        ),
      ].map((node) => {
        const a = node.getBoundingClientRect();
        return { x: a.x - b.x, y: a.y - b.y, width: a.width, height: a.height };
      }),
    };
  });
  const overlap = (a, b) =>
    a.x < b.x + b.width &&
    a.x + a.width > b.x &&
    a.y < b.y + b.height &&
    a.y + a.height > b.y;
  for (let i = 0; i < layout.labels.length; i++) {
    for (const block of layout.blocks)
      assert.ok(
        !overlap(layout.labels[i], block),
        "Region label overlaps a caption or control",
      );
    for (const other of layout.labels.slice(i + 1))
      assert.ok(!overlap(layout.labels[i], other), "Region labels overlap");
  }
  if (requireWordpress)
    assert.ok(
      layout.labels.some(
        (item) =>
          item.id ===
          stories.find((story) => story.id === "wordpress").region.id,
      ),
      "WordPress is labelled in the overview",
    );
}
try {
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
    await page.goto(base);
    await page.waitForSelector(".map-section");
    await page.locator(".map-section").scrollIntoViewIfNeeded();
    const canvas = page.locator(".map-section canvas"),
      map = page.locator(".map-section .granite-map");
    await page.waitForFunction(() => {
      const opacity = JSON.parse(
        document.querySelector(".map-section canvas")?.dataset.opacity || "{}",
      );
      return (
        opacity.dust === 1 &&
        opacity.anchors > 0 &&
        opacity.anchors < 0.7 &&
        opacity.top === 0
      );
    });
    await page
      .locator(".map-section .map-field")
      .screenshot({ path: `${out}/entrance-${width}.png` });
    await settled(canvas);
    await labelsClear(canvas, true);
    const initial = JSON.parse(await canvas.getAttribute("data-view"));
    await map.screenshot({
      path: `${out}/default-${width}.png`,
      style: ".site-header,.skip-link{visibility:hidden}",
    });
    for (const story of stories.filter((item) => item.id !== "whole")) {
      const button = map
        .locator(".map-stories button")
        .filter({ hasText: story.title });
      await button.click();
      await page.waitForTimeout(250);
      await labelsClear(canvas);
      assert.equal(
        await canvas.getAttribute("data-flying"),
        "true",
        "Normal-motion guided camera should animate",
      );
      await settled(canvas);
      await labelsClear(canvas, story.id === "wordpress");
      assert.equal(
        await map.locator(".map-guidance p").innerText(),
        story.caption,
      );
      await page
        .locator(".map-section .map-field")
        .screenshot({ path: `${out}/guide-${story.id}-${width}.png` });
    }
    await map.getByLabel("Reset map view").click();
    await settled(canvas);
    assert.deepEqual(
      JSON.parse(await canvas.getAttribute("data-view")),
      initial,
      "Reset restores the robust overview",
    );
    await labelsClear(canvas, true);
    await map
      .locator(".map-stories button")
      .filter({ hasText: "WordPress" })
      .click();
    await page.waitForTimeout(200);
    await canvas.press("ArrowRight");
    await settled(canvas);
    assert.equal(await canvas.getAttribute("data-flying"), "false");
    assert.equal(
      await map.locator(".map-guidance .eyebrow").innerText(),
      "Explore the field",
    );
    const displayedZoom = Number.parseFloat(
      await map.locator(".map-controls span").innerText(),
    );
    assert.ok(
      Math.abs(displayedZoom - Number(await canvas.getAttribute("data-zoom"))) < 0.06,
      "Interrupting a flight keeps the zoom readout aligned with the stopped view",
    );
    await map.getByLabel("Reset map view").click();
    await settled(canvas);
    await page.locator("header.site-header").scrollIntoViewIfNeeded();
    await page.locator(".map-section").scrollIntoViewIfNeeded();
    assert.equal(
      await canvas.getAttribute("data-entrance"),
      "done",
      "Scrolling back must not replay the entrance",
    );
    for (let i = 0; i < 5; i++) await map.getByLabel("Zoom out on map").click();
    const wider = JSON.parse(await canvas.getAttribute("data-view"));
    assert.ok(
      wider.zoom < initial.zoom,
      "Outliers stay reachable below overview zoom",
    );
    await map.getByLabel("Reset map view").click();
    await settled(canvas);
    await map.getByLabel("Product review", { exact: false }).check();
    const perf = await canvas.evaluate(async (element) => {
      const frame = [],
        draw = [];
      let last = performance.now();
      for (let i = 0; i < 150; i++) {
        await new Promise((resolve) => requestAnimationFrame(resolve));
        const now = performance.now();
        if (i > 10) {
          frame.push(now - last);
          draw.push(Number(element.dataset.renderMs));
        }
        last = now;
        element.dispatchEvent(
          new KeyboardEvent("keydown", {
            key: i % 2 ? "ArrowLeft" : "ArrowRight",
            bubbles: true,
          }),
        );
      }
      frame.sort((a, b) => a - b);
      draw.sort((a, b) => a - b);
      return {
        frameMedian: frame[Math.floor(frame.length * 0.5)],
        frameP95: frame[Math.floor(frame.length * 0.95)],
        drawP95: draw[Math.floor(draw.length * 0.95)],
      };
    });
    assert.ok(
      perf.frameP95 < 1000 / 60,
      "Pan frame budget exceeds 60 fps target",
    );
    await canvas.focus();
    await page.keyboard.press("p");
    await page.keyboard.press("m");
    const deck = page.locator(".map-appendix"),
      deckCanvas = deck.locator("canvas");
    await deckCanvas.waitFor();
    await settled(deckCanvas);
    await labelsClear(deckCanvas, true);
    await page.screenshot({ path: `${out}/appendix-default-${width}.png` });
    for (const story of stories.filter((item) => item.id !== "whole")) {
      await deck
        .locator(".map-stories button")
        .filter({ hasText: story.title })
        .click();
      await settled(deckCanvas);
      await labelsClear(deckCanvas, story.id === "wordpress");
      await page.screenshot({
        path: `${out}/appendix-${story.id}-${width}.png`,
      });
    }
    const fit = await page
      .locator(".present-map")
      .evaluate((element) => ({
        height: element.clientHeight,
        scroll: element.scrollHeight,
      }));
    if (width > 700)
      assert.ok(
        fit.scroll <= fit.height + 2,
        "Appendix should fit the desktop viewport",
      );
    await page.emulateMedia({ reducedMotion: "reduce" });
    await deck
      .getByRole("button", { name: "Whole field", exact: false })
      .click();
    await settled(deckCanvas);
    await deck.getByRole("button", { name: "WordPress", exact: false }).click();
    await page.evaluate(
      () =>
        new Promise((resolve) =>
          requestAnimationFrame(() => requestAnimationFrame(resolve)),
        ),
    );
    assert.equal(
      await deckCanvas.getAttribute("data-flying"),
      "false",
      "Reduced-motion camera should jump to its target",
    );
    await page.keyboard.press("Escape");
    assert.equal(await page.locator(".slide-1").count(), 1);
    await page.keyboard.press("Escape");
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth > innerWidth,
    );
    assert.equal(overflow, false);
    assert.deepEqual(errors, []);
    result.push({ width, ...perf, fit, overflow, errors });
    console.log(JSON.stringify(result.at(-1)));
    await page.close();
  }
  await fs.writeFile(`${out}/checks.json`, JSON.stringify(result, null, 2));
} finally {
  await browser.close();
}
