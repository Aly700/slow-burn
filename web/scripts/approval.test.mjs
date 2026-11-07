import { test } from "node:test";
import assert from "node:assert/strict";
import { requestApproval } from "../src/approval.ts";

test("posts the human decision and accepts an explicit service state", async () => {
  let request;
  const result = await requestApproval("run /1", true, async (url, init) => {
    request = { url, init };
    return Response.json({ run: { state: "TICKET_FILED" } });
  });
  assert.equal(result.kind, "confirmed");
  assert.equal(result.run.state, "TICKET_FILED");
  assert.match(request.url, /run%20%2F1\/approval$/);
  assert.deepEqual(JSON.parse(request.init.body), { approved: true });
});
test("null, invalid JSON and unknown states cannot become local success", async () => {
  for (const response of [
    Response.json(null),
    new Response("invalid"),
    Response.json({ state: "UNKNOWN" }),
  ]) {
    assert.equal(
      (await requestApproval("r", true, async () => response)).kind,
      "unconfirmed",
    );
  }
});
test("HTTP errors leave the recorded state unchanged", async () => {
  const result = await requestApproval("r", false, async () =>
    Response.json({}, { status: 409 }),
  );
  assert.equal(result.kind, "unconfirmed");
  assert.match(result.message, /409/);
});
test("only a network failure selects the labelled local fallback", async () => {
  assert.equal(
    (
      await requestApproval("r", true, async () => {
        throw new TypeError("Failed to fetch");
      })
    ).kind,
    "offline",
  );
  assert.equal(
    (
      await requestApproval("r", true, async () => {
        throw new DOMException("Timeout", "TimeoutError");
      })
    ).kind,
    "unconfirmed",
  );
});

test("binds approval to the exact displayed briefing when a hash exists", async () => {
  let body;
  const result = await requestApproval(
    "recorded",
    true,
    async (_url, init) => {
      body = JSON.parse(init.body);
      return Response.json({ state: "TICKET_FILED" });
    },
    "displayed-hash",
  );
  assert.equal(result.kind, "confirmed");
  assert.deepEqual(body, { approved: true, briefing_hash: "displayed-hash" });
});
