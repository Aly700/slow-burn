import { test } from "node:test";
import assert from "node:assert/strict";
import {
  matchesStack,
  stackSuggestions,
  loadStack,
  saveStack,
  parseStack,
} from "../src/stack.ts";
import { ticketDrafts, queueCsv } from "../src/exports.ts";
import { parseCsv } from "./csv.mjs";
const rows = [
  {
    cve_id: "CVE-2026-1001",
    rank: 2,
    vendor_identity: "Adobe",
    product_identity: "ColdFusion",
    description: "A quoted, multiline\nrecord",
    score: 0.6,
    reasons: [{ label: "Earlier vendor exploitation" }],
  },
  {
    cve_id: "CVE-2026-1002",
    rank: 600,
    vendor_identity: "Example",
    product_identity: "ColdFusion",
    description: "PHP issue",
  },
  {
    cve_id: "CVE-2026-1003",
    rank: 42,
    vendor_identity: "Microsoft",
    product_identity: "Windows",
    description: "Windows issue",
  },
];
test("stack matches vendor and vendor-qualified product identities, with OR across selections", () => {
  assert.deepEqual(
    rows
      .filter((row) => matchesStack(row, [{ kind: "vendor", value: "adobe" }]))
      .map((r) => r.rank),
    [2],
  );
  assert.deepEqual(
    rows
      .filter((row) =>
        matchesStack(row, [
          { kind: "product", value: "coldfusion", vendor: "Adobe" },
        ]),
      )
      .map((r) => r.rank),
    [2],
  );
  assert.deepEqual(
    rows
      .filter((row) =>
        matchesStack(row, [
          { kind: "vendor", value: "Adobe" },
          { kind: "vendor", value: "Microsoft" },
        ]),
      )
      .map((r) => r.rank),
    [2, 42],
  );
  assert.equal(matchesStack(rows[1], [{ kind: "text", value: "HP" }]), false);
  assert.equal(
    matchesStack(rows[2], [{ kind: "text", value: "windows issue" }]),
    true,
  );
  assert.equal(matchesStack(rows[0], []), true);
  const suggestions = stackSuggestions(rows);
  assert.equal(
    suggestions.find((s) => s.kind === "vendor" && s.value === "Example")
      .top500,
    0,
  );
  assert.equal(
    suggestions.filter(
      (s) => s.kind === "product" && s.value.toLowerCase() === "coldfusion",
    ).length,
    2,
  );
});
test("storage failures and malformed saved choices leave a usable in-memory stack", () => {
  assert.deepEqual(
    loadStack(() => {
      throw new Error("blocked");
    }),
    [],
  );
  assert.equal(
    saveStack([], () => {
      throw new Error("blocked");
    }),
    false,
  );
  assert.deepEqual(parseStack("{bad"), []);
  assert.deepEqual(parseStack('[null,3,{"kind":"vendor"}]'), []);
  assert.equal(
    parseStack(
      '[{"kind":"vendor","value":"Adobe"},{"kind":"vendor","value":"adobe"}]',
    ).length,
    1,
  );
});
test("exports preserve filtered order, quote CSV and exclude dropped or unverified claims", () => {
  const runs = [
    {
      cve_id: rows[0].cve_id,
      briefing: {
        verdict: "fix_now",
        headline: 'Fix "this", safely',
        action: "Confirm\nversions",
        claims: [
          {
            id: "ok",
            text: "Supported evidence",
            verified: true,
            evidence: [{ tool: "get_cve", field: "vendor", value: "Adobe" }],
          },
          { id: "bad", text: "Unsupported claim", verified: false },
        ],
      },
      verifier: { dropped: [{ id: "dropped", text: "Dropped claim" }] },
    },
  ];
  const tickets = ticketDrafts([rows[0], rows[2]], runs);
  assert.equal(tickets[0].verdict, "fix_now");
  assert.match(tickets[0].evidence_summary, /Supported evidence/);
  assert.doesNotMatch(tickets[0].evidence_summary, /Unsupported|Dropped/);
  assert.equal(tickets[1].verdict, "pending");
  const parsed = parseCsv(
    queueCsv(
      [rows[0], { ...rows[2], vendor_identity: '=IMPORTXML("url")' }],
      runs,
    ),
  );
  assert.equal(parsed.length, 3);
  assert.equal(parsed[1][9], 'Fix "this", safely');
  assert.equal(parsed[1][10], "Confirm\nversions");
  assert.ok(parsed[2][2].startsWith("'="));
  assert.equal(parsed[2][5], "");
});
