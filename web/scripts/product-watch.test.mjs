import { test } from "node:test";
import assert from "node:assert/strict";
import { decodeWatch, filterWatch } from "../src/productWatch.ts";
import { queueCsv, ticketDrafts } from "../src/exports.ts";
import { parseCsv } from "./csv.mjs";
const rows = [
 { cve_id:"CVE-2026-1", vendor:"Yealink", product:"router", match_confidence:"product_alias_only", prior_kev_count:9, description:"MitraStar router", epss:null },
 { cve_id:"CVE-2026-2", vendor:"Yealink", product:"router", match_confidence:"psirt_supported", prior_kev_count:8, description:"Text, with a newline\nand quotes \"here\"", epss:.1 },
 { cve_id:"CVE-2026-3", vendor:"Other", product:"router", match_confidence:"vendor_text_supported", prior_kev_count:4 },
];
test("product review preserves file order and excludes unsupported matches by default", () => {
 const stack = [{kind:"vendor", value:"yealink"}];
 assert.deepEqual(filterWatch(rows, []), []);
 assert.deepEqual(filterWatch(rows, stack).map(r => r.cve_id), ["CVE-2026-2"]);
 assert.deepEqual(filterWatch(rows, stack, true).map(r => r.cve_id), ["CVE-2026-1", "CVE-2026-2"]);
 assert.equal(filterWatch(rows, [{kind:"product",value:"router",vendor:"Other"}]).length, 1);
});
test("compact data keeps nulls and export separates review from ranked predictions", () => {
 assert.equal(decodeWatch({columns:["cve_id","epss"],rows:[["CVE-2026-1",null]]})[0].epss, null);
 const tickets = ticketDrafts([], [], rows);
 assert.equal(tickets[0].rank, null);
 assert.equal(tickets[0].verdict, "review");
 assert.equal(tickets[0].source_list, "product_review");
 assert.match(tickets[0].evidence_summary, /product name only/);
 const parsed = parseCsv(queueCsv([], [], rows));
 assert.equal(parsed.length,4);
 assert.equal(parsed[2][17], rows[1].description);
 assert.equal(parsed[1][1], "");
 assert.equal(parsed[1][5], "");
});
