import { useCallback, useEffect, useRef, useState } from "react";
import type { AnalystEvaluation, AnalystSession } from "./types";
import {
  ASK_API,
  applyAskEvent,
  connectAnalyst,
  localAnalyst,
  newQuestion,
  questionKey,
  recordedAnswer,
} from "./analyst";

export function useAnalyst(evaluation?: AnalystEvaluation | null) {
  const [input, setInput] = useState("");
  const [health, setHealth] = useState<"checking" | "ready" | "offline">(
    "checking",
  );
  const [session, setSession] = useState<AnalystSession>({
    ...newQuestion("", "recorded"),
    status: "idle",
  });
  const active = useRef(session),
    generation = useRef(0),
    stop = useRef<(() => void) | null>(null),
    request = useRef<AbortController | null>(null);
  const checkHealth = useCallback(async () => {
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    if (!localAnalyst(location.hostname)) {
      setHealth("offline");
      return;
    }
    try {
      const r = await fetch(`${ASK_API}/live/health`, {
        signal: AbortSignal.any([controller.signal, AbortSignal.timeout(1800)]),
      });
      const d = await r.json();
      if (!controller.signal.aborted)
        setHealth(r.ok && d.ready === true ? "ready" : "offline");
    } catch {
      if (!controller.signal.aborted) setHealth("offline");
    }
  }, []);
  useEffect(() => {
    void checkHealth();
    const timer = setInterval(() => void checkHealth(), 15_000);
    return () => {
      clearInterval(timer);
      request.current?.abort();
      generation.current++;
      stop.current?.();
    };
  }, [checkHealth]);
  const launch = (question = input) => {
    const q = question.trim();
    if (!q || q.length > 1000) return;
    setInput(q);
    stop.current?.();
    const id = ++generation.current;
    if (health !== "ready" || !localAnalyst(location.hostname)) {
      const record = evaluation?.results?.find(
        (r) => questionKey(r.question) === questionKey(q),
      );
      setSession(
        record
          ? recordedAnswer(record)
          : {
              ...newQuestion(q, "recorded"),
              status: "complete",
              message:
                "No recorded answer for this question. Choose a suggestion below.",
            },
      );
      return;
    }
    active.current = newQuestion(q, "live");
    setSession(active.current);
    const fail = (message: string) => {
      if (message.includes("question structured output invalid"))
        message =
          "Granite could not turn this question into a supported query.";
      if (id === generation.current)
        setSession((p) => ({ ...p, status: "error", message }));
    };
    try {
      stop.current = connectAnalyst(
        q,
        (event) => {
          if (id !== generation.current) return;
          active.current = applyAskEvent(active.current, event);
          setSession(active.current);
        },
        fail,
      );
    } catch {
      fail("The local analyst connection could not be opened. Please retry.");
    }
  };
  const cancel = () => {
    generation.current++;
    stop.current?.();
    setSession((p) => ({
      ...p,
      status: "cancelled",
      message: "Question stopped. No completed answer is available.",
    }));
  };
  return { input, setInput, health, session, launch, cancel, checkHealth };
}
