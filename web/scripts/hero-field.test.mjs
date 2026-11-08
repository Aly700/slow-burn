import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fieldPoint, renderField } from '../src/heroField.ts';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

test('live coordinates match the poster cover crop across wide and tall frames', () => {
  for (const [w, h, phone] of [[1920, 1004, false], [1280, 720, false], [768, 948, false], [390, 784, true], [430, 872, true]]) {
    const [bw, bh] = phone ? [390, 784] : [1440, 824];
    const scale = Math.max(w / bw, h / bh);
    const source = fieldPoint(33000, 41000, bw, bh, phone);
    const live = fieldPoint(33000, 41000, w, h, phone);
    assert.ok(Math.abs(live[0] - (source[0] * scale + (w - bw * scale) / 2)) < 1e-8);
    assert.ok(Math.abs(live[1] - (source[1] * scale + (h - bh * scale) / 2)) < 1e-8);
  }
});
test('field raster is deterministic and retains overlapping rows', () => {
  const palette = { bg: [12, 12, 12], ash: [90, 90, 90], ember: [240, 160, 80] };
  const single = { coordinates: [35000, 35000], flags: [1] };
  const twice = { coordinates: [35000, 35000, 35000, 35000], flags: [1, 1] };
  const a = renderField(single, 100, 200, palette);
  assert.deepEqual(a, renderField(single, 100, 200, palette));
  assert.notDeepEqual(a, renderField(twice, 100, 200, palette));
});
test('committed poster variants retain the frozen cohorts and stay within budget', async () => {
  const dir = new URL('../public/hero/', import.meta.url);
  const manifest = JSON.parse(await readFile(new URL('manifest.json', dir)));
  assert.deepEqual([manifest.rows, manifest.benchmark, manifest.picks, manifest.anchors], [72987, 72670, 500, 317]);
  assert.equal(Object.keys(manifest.files).length, 8);
  for (const [file, info] of Object.entries(manifest.files)) {
    const bytes = await readFile(new URL(file, dir));
    assert.equal(bytes.length, info.bytes);
    assert.ok(bytes.length < 450000);
    assert.equal(createHash('sha256').update(bytes).digest('hex'), info.sha256);
  }
});
