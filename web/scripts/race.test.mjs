import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { capacityResult, comparisonText, stepPath } from '../src/race.ts';
const data = JSON.parse(await readFile(new URL('../../artifacts/race_2025.json', import.meta.url), 'utf8'));

test('race comparison states ties and losses without assuming a lead', () => {
  const c = capacityResult(data, 42);
  assert.match(comparisonText(c), /ties/);
  assert.match(comparisonText(capacityResult(data, 10)), /leads/);
  const lower = structuredClone(c);
  lower.methods[3].end.before = 0;
  assert.match(comparisonText(lower), /trails/);
  assert.equal(capacityResult(data, 99), undefined);
});

test('race chart steps at month end without interpolating future counts', () => {
  assert.equal(stepPath([0, 2, 3], 0, 60, 20, 60, 6), 'M0,60 H10 V40 H20 V30');
  assert.equal(stepPath([], 0, 0, 20, 60, 6), '');
});

test('race outcomes partition all positives and curves agree with totals', () => {
  for (const c of data.capacities) {
    for (const method of c.methods) {
      for (const timing of ['end', 'start']) {
        const r = method[timing];
        assert.equal(r.before + r.after + r.never, data.positives);
        assert.equal(r.monthly.length, 12);
        assert.equal(r.monthly[0].fixed_total, 0);
        assert.equal(r.monthly.at(-1).before, r.before);
        assert.equal(r.monthly.at(-1).confirmed, data.positives);
        assert.equal(r.fixed_total, c.capacity * 11);
        assert.equal(r.positive_outcomes.filter(p => p.outcome === 'before').length, r.before);
        assert.ok(r.positive_outcomes.filter(p => p.outcome === 'before').every(p => p.completed < p.kev_date));
      }
      assert.ok(method.start.before >= method.end.before);
      assert.equal(method.end.never, method.start.never);
    }
    for (const timing of ['end', 'start']) {
      const b = c.bootstrap[timing];
      assert.ok(Math.abs(b.ahead + b.tied + b.behind - 1) < 1e-12);
      assert.equal(b.observed_delta, c.methods[3][timing].before - Math.max(...c.methods.slice(0, 3).map(m => m[timing].before)));
    }
  }
});
