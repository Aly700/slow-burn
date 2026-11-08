import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  decodeMap,
  overlaps,
  zoomAt,
  robustBounds,
  fitBounds,
  mapStories,
  entranceOpacity,
  easeCamera,
} from "../src/graniteMap.ts";
const artifact = JSON.parse(
  await readFile(
    new URL("../../artifacts/map_2026.json", import.meta.url),
    "utf8",
  ),
);
const findings = JSON.parse(
  await readFile(
    new URL("../../artifacts/findings.json", import.meta.url),
    "utf8",
  ),
);
test("binary map keeps every point, dated anchors and complete overlapping cohorts", () => {
  const map = decodeMap(artifact);
  assert.equal(map.n, findings.map.rows);
  for (const [group, flag] of Object.entries({
    dust: "is_2026",
    top: "in_top500",
    anchors: "is_past_exploited",
    watch: "in_product_watch",
    wordpress: "is_wordpress",
  }))
    assert.equal(map.groups[group].length, findings.map.counts[flag]);
  assert.equal(map.groups.dust.length + map.groups.anchors.length, map.n);
  const expected = new Set([
    ...map.groups.top,
    ...map.groups.anchors,
    ...map.groups.watch,
  ]);
  assert.equal(map.ids.size, expected.size);
  for (const index of expected) assert.match(map.ids.get(index), /^CVE-/);
  const bytes = Buffer.from(artifact.coordinates.data, "base64");
  assert.equal(map.coordinates[0], bytes.readUInt16LE(0));
  assert.equal(map.coordinates.at(-1), bytes.readUInt16LE(bytes.length - 2));
  assert.ok(map.clusters.some((value) => value === -1));
});
test("malformed map arrays fail instead of silently shifting identities", () => {
  assert.throws(
    () =>
      decodeMap({
        ...artifact,
        coordinates: { ...artifact.coordinates, data: "AA==" },
      }),
    /Incomplete/,
  );
  assert.throws(
    () => decodeMap({ ...artifact, schema_version: 2 }),
    /Unsupported/,
  );
});
test("zoom preserves the world point under the pointer and stays within limits", () => {
  const view = { x: 20, y: 30, zoom: 2 },
    next = zoomAt(view, 3, 100, 200);
  assert.equal((100 - view.x) / view.zoom, (100 - next.x) / next.zoom);
  assert.equal((200 - view.y) / view.zoom, (200 - next.y) / next.zoom);
  assert.equal(zoomAt(view, 100, 0, 0).zoom, 24);
  assert.equal(zoomAt(view, 0.001, 0, 0).zoom, 0.25);
  assert.equal(
    overlaps(
      { x: 0, y: 0, width: 50, height: 20 },
      { x: 30, y: 10, width: 40, height: 20 },
    ),
    true,
  );
  assert.equal(
    overlaps(
      { x: 0, y: 0, width: 50, height: 20 },
      { x: 70, y: 10, width: 40, height: 20 },
    ),
    false,
  );
});

test("robust framing ignores sparse tails without deleting points", () => {
  const coordinates = [];
  for (let i = 0; i < 1000; i++) coordinates.push(20000 + i, 30000 + i);
  coordinates.push(0, 0, 65535, 65535);
  const bounds = robustBounds(coordinates);
  assert.ok(bounds[0] > 0 && bounds[2] < 65535);
  const viewport = { x: 20, y: 40, width: 1000, height: 400 },
    unit = 400 / 65535;
  const camera = fitBounds(bounds, viewport, unit);
  assert.ok(camera.zoom > 1);
  for (const [x, y] of [
    [bounds[0], bounds[1]],
    [bounds[2], bounds[3]],
  ]) {
    const px = camera.x + x * unit * camera.zoom,
      py = camera.y + y * unit * camera.zoom;
    assert.ok(px >= viewport.x && px <= viewport.x + viewport.width);
    assert.ok(py >= viewport.y && py <= viewport.y + viewport.height);
  }
  assert.equal(coordinates.length, 2004);
});
test("guided captions use region counts and exclude the unassigned cloud", () => {
  const map = decodeMap(artifact),
    stories = mapStories(map);
  assert.equal(stories.length, 4);
  const wordpress = stories.find((story) => story.id === "wordpress");
  assert.match(
    wordpress.caption,
    new RegExp(wordpress.region.counts.is_2026.toLocaleString("en-CA")),
  );
  assert.ok(wordpress.region.id >= 0);
  const changed = structuredClone(artifact);
  const cluster = changed.clusters.find(
    (region) => region.id === wordpress.region.id,
  );
  cluster.counts.is_past_exploited = 4;
  const updated = mapStories(decodeMap(changed)).find(
    (story) => story.id === "wordpress",
  );
  assert.match(updated.caption, /4 past-exploited anchors/);
  assert.doesNotMatch(updated.caption, /stays dark/);
  assert.ok(stories.find((story) => story.id === "dense").region.id >= 0);
});
test("entrance reveals dust, anchors, then picks; reduced motion and camera endpoints are exact", () => {
  assert.equal(entranceOpacity(400).anchors, 0);
  assert.ok(
    entranceOpacity(900).dust === 1 && entranceOpacity(900).anchors > 0,
  );
  assert.equal(entranceOpacity(900).top, 0);
  assert.ok(entranceOpacity(1600).top > 0);
  assert.deepEqual(entranceOpacity(0, true), entranceOpacity(2000));
  const a = { x: 0, y: 20, zoom: 1 },
    b = { x: -200, y: -100, zoom: 5 };
  assert.deepEqual(easeCamera(a, b, 0), a);
  assert.deepEqual(easeCamera(a, b, 1), b);
  assert.ok(easeCamera(a, b, 0.25).zoom > 1 && easeCamera(a, b, 0.25).zoom < 3);
});
