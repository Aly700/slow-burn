import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { decodeMap, overlaps, zoomAt } from "../src/graniteMap.ts";
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
  assert.equal(zoomAt(view, 100, 0, 0).zoom, 18);
  assert.equal(zoomAt(view, 0.001, 0, 0).zoom, 1);
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
