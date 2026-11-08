import { createRequire } from "node:module";
import path from "node:path";
import { readFile, mkdir, writeFile } from "node:fs/promises";
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
const out = new URL("../../shots/round7/", import.meta.url).pathname;
await mkdir(out, { recursive: true });
const browser = await chromium.launch({ channel: "chromium" });
const checks = [];
async function load(page) {
  await page.goto(base);
  await page.waitForFunction(
    () => document.querySelector("main")?.getAttribute("aria-busy") === "false",
  );
  await page.evaluate(() => document.fonts.ready);
}
async function present(page) {
  await page.keyboard.press("p");
  for (let i = 0; i < 5; i++) await page.keyboard.press("ArrowRight");
  await page.locator(".slide-6").waitFor();
}
async function fit(page, width) {
  const box = await page.locator(".present-slide").evaluate((node) => ({
    width: node.clientWidth,
    scrollWidth: node.scrollWidth,
    height: node.clientHeight,
    scrollHeight: node.scrollHeight,
  }));
  if (width > 700 && box.scrollHeight > box.height + 2) {
    await page.screenshot({ path: `${out}/overflow-${width}.png` });
    console.log(JSON.stringify({ width, overflow: box }));
  }
  assert.ok(box.scrollWidth <= box.width + 2, "No horizontal slide overflow");
  if (width > 700)
    assert.ok(
      box.scrollHeight <= box.height + 2,
      "Slide six must fit vertically",
    );
  return box;
}
try {
  for (const width of [1280, 1440, 1920, 390]) {
    const page = await browser.newPage({
      viewport: {
        width,
        height: width === 1920 ? 1080 : width === 390 ? 844 : 900,
      },
      deviceScaleFactor: 2,
      reducedMotion: "reduce",
    });
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    await load(page);
    const methods = page.locator("#methods .attack-results");
    await methods.scrollIntoViewIfNeeded();
    await methods.screenshot({
      path: `${out}/methods-${width}.png`,
      style: ".site-header,.skip-link{visibility:hidden}",
    });
    assert.match(
      await methods.locator(".attack-survival").innerText(),
      /4.*of 32/s,
    );
    assert.match(
      await methods.locator(".attack-detector").innerText(),
      /65\.6%/,
    );
    assert.equal(await methods.locator(".attack-families span").count(), 16);
    await present(page);
    const normal = await fit(page, width);
    const slide = page.locator(".slide-6");
    assert.match(
      await slide.locator(".attack-survival").innerText(),
      /4.*of 32/s,
    );
    assert.match(
      await slide.locator(".attack-comparison").innerText(),
      /Before the fix.*7.*of 48.*After the fix.*0.*of 48.*tuned on these/s,
    );
    assert.equal(await slide.locator(".attack-suite strong").innerText(), "80");
    assert.deepEqual(
      await slide.locator(".attack-boundaries strong").allTextContents(),
      ["0", "0", "0"],
    );
    assert.match(
      await slide.locator(".attack-boundaries").innerText(),
      /100 clean descriptions/,
    );
    await page.screenshot({ path: `${out}/slide6-${width}.png` });
    await page.keyboard.press("Escape");
    await page.route("**/data/bundle.json", (route) =>
      route.fulfill({
        json: {
          ...bundle,
          redteam_eval: { ...bundle.redteam_eval, held_out: null },
        },
      }),
    );
    await load(page);
    await present(page);
    const pending = await fit(page, width);
    assert.match(
      await slide.locator(".attack-survival").innerText(),
      /pending.*of pending/s,
    );
    assert.deepEqual(
      await slide.locator(".attack-boundaries strong").allTextContents(),
      ["pending", "pending", "pending"],
    );
    await page.screenshot({ path: `${out}/pending-${width}.png` });
    assert.deepEqual(errors, []);
    await page.keyboard.press("Escape");
    assert.equal(
      await page.evaluate(
        () => document.documentElement.scrollWidth > innerWidth,
      ),
      false,
    );
    checks.push({ width, normal, pending, errors });
    console.log(JSON.stringify(checks.at(-1)));
    await page.close();
  }
  await writeFile(`${out}/checks.json`, JSON.stringify(checks, null, 2));
} finally {
  await browser.close();
}
