import type { Run } from "./types";

type ApprovalResult =
  | { kind: "confirmed"; run: Partial<Run> & { state: string } }
  | { kind: "offline" }
  | { kind: "unconfirmed"; message: string };

export async function requestApproval(
  runId: string,
  approved: boolean,
  request: typeof fetch = fetch,
  briefingHash?: string,
): Promise<ApprovalResult> {
  let response: Response;
  try {
    response = await request(
      `http://localhost:8765/runs/${encodeURIComponent(runId)}/approval`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          approved,
          ...(briefingHash ? { briefing_hash: briefingHash } : {}),
        }),
        signal: AbortSignal.timeout(5000),
      },
    );
  } catch (error) {
    if (error instanceof TypeError) return { kind: "offline" };
    return {
      kind: "unconfirmed",
      message:
        "The service did not confirm the decision. Check the run before retrying.",
    };
  }
  if (!response.ok)
    return {
      kind: "unconfirmed",
      message: `Approval service returned ${response.status}. The run is unchanged; no local decision was substituted.`,
    };
  try {
    const body: unknown = await response.json();
    if (body && typeof body === "object") {
      const payload = "run" in body ? body.run : body;
      if (
        payload &&
        typeof payload === "object" &&
        "state" in payload &&
        typeof payload.state === "string" &&
        ["TICKET_FILED", "REJECTED", "FAILED", "WAITING_APPROVAL"].includes(
          payload.state,
        )
      ) {
        return {
          kind: "confirmed",
          run: payload as Partial<Run> & { state: string },
        };
      }
    }
  } catch {
    /* An unreadable response cannot confirm a write. */
  }
  return {
    kind: "unconfirmed",
    message:
      "The service received the decision but did not return a valid state. Check the recorded run before retrying.",
  };
}
