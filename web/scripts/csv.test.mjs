import { test } from "node:test";
import assert from "node:assert/strict";
import { parseCsv, convertScores } from "./csv.mjs";

test("preserves quoted multiline descriptions and embedded reason JSON", () => {
  const csv =
    'rank,cve_id,description,score,reasons\r\n1,CVE-2026-1,"line one,\nline ""two""",0.3,"[{""feature"":""epss"",""value"":0.4}]"\r\n';
  const result = convertScores(csv);
  assert.equal(result[0].description, 'line one,\nline "two"');
  assert.equal(result[0].score, 0.3);
  assert.deepEqual(result[0].reasons, [{ feature: "epss", value: 0.4 }]);
});
test("blank and invalid numeric values stay unknown, never zero", () => {
  assert.deepEqual(
    convertScores("rank,cve_id,score,epss,reasons\n1,CVE-2026-1,,oops,")[0],
    { rank: 1, cve_id: "CVE-2026-1", score: null, epss: null, reasons: [] },
  );
});
test("empty input and BOM are supported; row limit is respected", () => {
  assert.deepEqual(parseCsv(""), []);
  assert.equal(
    convertScores("\uFEFFrank,cve_id\n1,CVE-2026-1\n2,CVE-2026-2", 1).length,
    1,
  );
});
test("malformed quoting fails explicitly", () => {
  assert.throws(() => parseCsv('a,b\n1,"unclosed'), /Unclosed/);
});
