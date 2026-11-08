import { test } from 'node:test';
import assert from 'node:assert/strict';
import { apiCandidates, findApi, liveLabel, fallbackQuestion, previewOnly } from '../src/api.ts';
import { connectAnalyst } from '../src/analyst.ts';
import { connectInvestigation } from '../src/investigation.ts';

test('empty hosted setting preserves local-only connections', () => {
  assert.deepEqual(apiCandidates('aly700.github.io', ''), []);
  assert.deepEqual(apiCandidates('localhost', ''), ['http://127.0.0.1:8765']);
});
test('configured hosted service is usable by visitors, local service stays first on localhost', () => {
  assert.deepEqual(apiCandidates('aly700.github.io', 'https://api.example/'), ['https://api.example']);
  assert.deepEqual(apiCandidates('localhost', 'https://api.example'), ['http://127.0.0.1:8765', 'https://api.example']);
  assert.deepEqual(apiCandidates('aly700.github.io', 'http://unsafe.example'), []);
});
test('health selects a ready backend and handles budgets, malformed and failed health', async () => {
  const hosted = 'https://api.example';
  const ready = await findApi('aly700.github.io', hosted, async () => new Response(JSON.stringify({ready:true, backend:'watsonx', model:'ibm/granite-4-h-small', public:true})));
  assert.equal(ready.base, hosted);
  assert.equal(liveLabel(ready), 'Live · IBM Granite on watsonx');
  const spent = await findApi('aly700.github.io', hosted, async () => new Response(JSON.stringify({ready:false, budget:{exhausted:true}})));
  assert.equal(spent.base, null);
  assert.match(spent.message, /Daily limit reached/);
  assert.equal((await findApi('aly700.github.io', hosted, async () => {throw new Error('offline')})).base, null);
  assert.equal((await findApi('aly700.github.io', hosted, async () => new Response('invalid'))).base, null);
});
test('both streams use the selected base and close on the daily-limit SSE event', () => {
  for (const [connect, question] of [[connectAnalyst, 'test'], [connectInvestigation, 'CVE-2026-1000']]) {
    const listeners = {}; let url, error, closed=false;
    connect(question, () => {}, message => error=message, value => {
      url=value; return {addEventListener:(n, f)=>listeners[n]=f, close:()=>closed=true};
    }, 'https://api.example');
    assert.ok(url.startsWith('https://api.example/'));
    listeners.error({data:JSON.stringify({message:'Daily limit reached, showing recorded answers.'})});
    assert.equal(closed, true); assert.match(error,/Daily limit reached/);
  }
});
test('failed questions show a matching recording or an honest missing-recording message', () => {
  const result={question:'Known question',run_id:'saved',answer:{text:'Recorded',claims:[]}};
  const session=fallbackQuestion('known question', {results:[result]}, 'Daily limit reached, showing recorded answers.');
  assert.equal(session.mode,'recorded'); assert.equal(session.run_id,'saved'); assert.match(session.message,/Daily limit/);
  assert.match(fallbackQuestion('new question', {results:[result]}).message,/No recorded answer/);
});
test('public hosted runs have preview-only approvals even when viewed locally', () => {
  assert.equal(previewOnly({public:true},'localhost',''),true);
  assert.equal(previewOnly({},'aly700.github.io','https://api.example'),true);
  assert.equal(previewOnly({},'localhost','https://api.example'),false);
  assert.equal(previewOnly({},'aly700.github.io',''),false);
});
