import type {
  AnalystEvaluation,
  AnalystRecord,
  AnalystSession,
  LiveClaim,
  LiveEvent,
} from "./types";

export const ASK_API = "http://127.0.0.1:8765";
export const localAnalyst = (host: string) =>
  ["localhost", "127.0.0.1", "[::1]"].includes(host);
export const questionKey = (q: string) =>
  q.trim().replace(/\s+/g, " ").toLowerCase();
export const suggestions = (evaluation?: AnalystEvaluation | null) =>
  (evaluation?.results ?? []).filter(
    (r) =>
      r?.grade === "fully" &&
      r.question &&
      r.answer?.claims?.some((c) => c.verified === true),
  );
export const newQuestion = (
  question: string,
  mode: "live" | "recorded",
): AnalystSession => ({
  question,
  mode,
  status: "running",
  tools: [],
  claims: [],
});

export function recordedAnswer(record: AnalystRecord): AnalystSession {
  return {
    ...newQuestion(record.question, "recorded"),
    status: "complete",
    run_id: record.run_id,
    duration_ms: record.duration_ms,
    query: record.query,
    claims: [
      ...(record.answer?.claims ?? []),
      ...(record.verifier?.dropped ?? []).map((c) => ({
        ...c,
        verified: false,
        reason: c.why,
      })),
    ],
    answer: record.answer,
  };
}
export function applyAskEvent(
  previous: AnalystSession,
  event: LiveEvent,
): AnalystSession {
  const d = event.data;
  if (event.event === "start")
    return {
      ...previous,
      run_id: String(d.run_id),
      model: String(d.model ?? ""),
    };
  if (event.event === "state")
    return {
      ...previous,
      state: String(d.state),
      queued: d.queued === true,
      position: typeof d.position === "number" ? d.position : undefined,
    };
  if (event.event === "tool_call")
    return {
      ...previous,
      query: d.args as Record<string, unknown>,
      tools: [
        ...previous.tools.filter((t) => t.call_id !== d.call_id),
        {
          call_id: String(d.call_id),
          tool: String(d.tool),
          args: d.args,
          working: true,
        },
      ],
    };
  if (event.event === "tool_result")
    return {
      ...previous,
      tools: previous.tools.map((t) =>
        t.call_id === d.call_id
          ? { ...t, working: false, ms: Number(d.ms), preview: d.preview }
          : t,
      ),
    };
  if (event.event === "claim")
    return {
      ...previous,
      claims: [
        ...previous.claims.filter((c) => c.id !== d.id),
        d as unknown as LiveClaim,
      ],
    };
  if (event.event === "answer") {
    const claims = d.claims as LiveClaim[];
    return {
      ...previous,
      answer: { text: String(d.text ?? ""), claims },
      claims: [
        ...claims,
        ...previous.claims
          .filter((c) => !c.verified || !claims.some((a) => a.id === c.id))
          .map((c) =>
            c.verified
              ? {
                  ...c,
                  verified: false,
                  reason: "Not retained in the final answer.",
                }
              : c,
          ),
      ],
    };
  }
  if (event.event === "done")
    return {
      ...previous,
      status: "complete",
      duration_ms: Number(d.duration_ms),
    };
  return previous;
}
const validClaim = (c: unknown): c is LiveClaim => {
  if (!c || typeof c !== "object") return false;
  const v = c as LiveClaim;
  return (
    typeof v.id === "string" &&
    typeof v.text === "string" &&
    typeof v.verified === "boolean" &&
    (!v.verified || (Array.isArray(v.evidence) && v.evidence.length > 0)) &&
    (v.evidence == null ||
      (Array.isArray(v.evidence) &&
        v.evidence.every(
          (e) => e && typeof e.tool === "string" && typeof e.field === "string",
        )))
  );
};
export function connectAnalyst(
  question: string,
  receive: (event: LiveEvent) => void,
  fail: (message: string) => void,
  create: (url: string) => Pick<EventSource, "addEventListener" | "close"> = (
    url,
  ) => new EventSource(url),
  base = ASK_API,
) {
  const source = create(`${base}/ask?q=${encodeURIComponent(question)}`);
  let closed = false,
    runId: string | undefined,
    answered = false;
  let timer: ReturnType<typeof setTimeout>;
  const close = () => {
    closed = true;
    clearTimeout(timer);
    source.close();
  };
  const stop = (message: string) => {
    if (!closed) {
      close();
      fail(message);
    }
  };
  const arm = () => {
    clearTimeout(timer);
    timer = setTimeout(
      () =>
        stop(
          "The analyst stopped responding. Retry or choose a suggested question.",
        ),
      120_000,
    );
  };
  arm();
  for (const name of [
    "start",
    "state",
    "tool_call",
    "tool_result",
    "claim",
    "answer",
    "error",
    "done",
  ]) {
    source.addEventListener(name, (raw) => {
      if (closed) return;
      if (!("data" in raw) || typeof raw.data !== "string") {
        stop(
          "The live connection was interrupted. No completed answer is available.",
        );
        return;
      }
      try {
        const d = JSON.parse(raw.data);
        if (!d || typeof d !== "object" || Array.isArray(d)) throw Error();
        if (name === "error") {
          stop(
            typeof d.message === "string"
              ? d.message
              : "The question could not be answered.",
          );
          return;
        }
        if (name === "start") {
          if (runId || d.question !== question || typeof d.run_id !== "string")
            throw Error();
          runId = d.run_id;
        } else if (!runId) throw Error();
        if (
          name === "tool_call" &&
          (typeof d.call_id !== "string" ||
            !["search_ranked", "compare_cves", "summarize_ranked"].includes(
              d.tool,
            ) ||
            !d.args ||
            typeof d.args !== "object")
        )
          throw Error();
        if (
          name === "tool_result" &&
          (typeof d.call_id !== "string" ||
            typeof d.ms !== "number" ||
            !Number.isFinite(d.ms))
        )
          throw Error();
        if (name === "claim" && !validClaim(d)) throw Error();
        if (name === "answer") {
          if (
            !Array.isArray(d.claims) ||
            !d.claims.every(validClaim) ||
            typeof d.text !== "string"
          )
            throw Error();
          answered = true;
        }
        if (
          name === "done" &&
          (!answered || d.run_id !== runId || typeof d.duration_ms !== "number")
        )
          throw Error();
        arm();
        receive({
          event: name,
          data: d,
          t_ms: typeof d.t_ms === "number" ? d.t_ms : 0,
        });
        if (name === "done") close();
      } catch {
        stop(
          "The service returned an invalid or mismatched answer. Please retry.",
        );
      }
    });
  }
  return close;
}
