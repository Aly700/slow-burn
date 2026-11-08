import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { workflowExample } from '../src/workflow.ts';
import { convertScores } from './csv.mjs';

const run = JSON.parse(readFileSync(new URL('../../artifacts/agent_runs/CVE-2026-39808.json', import.meta.url), 'utf8'));
const scores = convertScores(readFileSync(new URL('../../artifacts/scores_2026_top5000.csv', import.meta.url), 'utf8'));
const data = { runs: [run], scores, meta: { runs_source: 'recorded' } };

test('workflow keeps the recorded run and ranking intact and derives its product from exact evidence', () => {
  const example = workflowExample(data);
  assert.equal(example.run, run);
  assert.equal(example.score, scores.find(row => row.cve_id === run.cve_id));
  assert.equal(example.product, 'FortiSandbox');
  assert.ok(example.score.description.includes(example.product));
  assert.ok(run.briefing.claims.some(claim => claim.evidence.some(evidence => evidence.quote === example.product)));
});

test('workflow never presents fixtures, terminal decisions, or unmatched rows as awaiting approval', () => {
  assert.equal(workflowExample({}), undefined);
  assert.equal(workflowExample({ ...data, meta: { runs_source: 'fixtures' } }), undefined);
  assert.equal(workflowExample({ ...data, scores: [] }), undefined);
  assert.equal(workflowExample({ ...data, runs: [{ ...run, fixture: 'injection-direct' }] }), undefined);
  assert.equal(workflowExample({ ...data, runs: [{ ...run, state: 'TICKET_FILED' }] }), undefined);
});
