import { useEffect, useRef, useState } from "react";
import type { Data, Investigation, LiveEvent, Run } from "./types";
import {
  applyLiveEvent,
  connectInvestigation,
  recordedEvents,
  replayEvents,
  validCve,
} from "./investigation";
import { useApi } from "./useApi";
import { strongestRun } from "./storyData";

export function useInvestigation(
  data: Data,
  initialCve: string,
  onStart: () => void,
  onComplete: (run: Run, replay: boolean) => void,
) {
  const [input, setInput] = useState(initialCve);
  const { api, health, checkHealth, label } = useApi();
  const [session, setSession] = useState<Investigation>({
    mode: "replay",
    status: "idle",
    cve_id: initialCve,
    tools: [],
    claims: [],
  });
  const [elapsed, setElapsed] = useState(0);
  const stop = useRef<(() => void) | null>(null);
  const state = useRef(session);
  const callbacks = useRef({ onStart, onComplete });
  callbacks.current = { onStart, onComplete };
  const generation = useRef(0);
  useEffect(() => () => { stop.current?.(); generation.current++; }, []);
  useEffect(() => {
    if (session.status !== "running") return;
    const start = performance.now();
    setElapsed(0);
    const timer = setInterval(() => setElapsed(performance.now() - start), 100);
    return () => clearInterval(timer);
  }, [session.status]);
  const cancel = () => {
    generation.current++;
    stop.current?.();
    setSession((previous) => ({
      ...previous,
      status: "cancelled",
      message: "Investigation stopped. No approval was submitted.",
    }));
  };
  const launch = () => {
    const cve = input.trim().toUpperCase();
    if (!validCve(cve)) {
      setSession((previous) => ({
        ...previous,
        message: "Enter a 2026 CVE, for example CVE-2026-10523.",
      }));
      return;
    }
    stop.current?.();
    const id = ++generation.current;
    let mode: "live" | "replay" =
      health === "ready" && api.base
        ? "live"
        : "replay";
    const recording =
      data.live_examples?.find(
        (example) => example.cve_id === cve && !example.fixture,
      ) ??
      data.live_examples?.find((example) => example.cve_id === cve) ??
      (!data.runs?.some((run) => run.cve_id === cve)
        ? data.live_examples?.find((example) => !example.fixture)
        : undefined);
    const record =
      data.runs?.find((run) => run.cve_id === cve) ?? strongestRun(data);
    if (mode === "replay" && !recording && !record) {
      setSession((previous) => ({
        ...previous,
        status: "error",
        message: "Granite is offline and no recorded run is available yet.",
      }));
      return;
    }
    const actualCve =
      mode === "live" ? cve : (recording?.cve_id ?? record!.cve_id);
    state.current = {
      mode,
      illustrative:
        mode === "replay" &&
        !recording &&
        data.meta?.runs_source === "fixtures",
      fixture:
        mode === "replay" ? (recording?.fixture ?? record?.fixture) : undefined,
      status: "running",
      cve_id: actualCve,
      tools: [],
      claims: [],
      message:
        actualCve !== cve
          ? `No recording for ${cve}. Replaying ${actualCve} instead.`
          : api.message,
    };
    setSession(state.current);
    callbacks.current.onStart();
    const receive = (event: LiveEvent) => {
      if (id !== generation.current) return;
      state.current = applyLiveEvent(state.current, event);
      setSession(state.current);
      if (event.event === "done") {
        if (state.current.run)
          callbacks.current.onComplete(state.current.run, mode === "replay");
        else
          setSession((previous) => ({
            ...previous,
            status: "error",
            message: "The recording has no completed briefing.",
          }));
      }
    };
    const replay = (message?: string) => {
      if (id !== generation.current) return;
      stop.current?.();
      if (!recording && !record) {
        setSession(previous => ({ ...previous, status: "error", message: "Live service unavailable and no recorded run is available." }));
        return;
      }
      mode = "replay";
      const recordedCve = recording?.cve_id ?? record!.cve_id;
      state.current = { mode, status: "running", cve_id: recordedCve, tools: [], claims: [],
        illustrative: !recording && data.meta?.runs_source === "fixtures",
        fixture: recording?.fixture ?? record?.fixture,
        message: [message, recordedCve !== cve ? `No recording for ${cve}. Replaying ${recordedCve} instead.` : undefined].filter(Boolean).join(' ') || undefined };
      setSession(state.current);
      stop.current = replayEvents(recording?.events ?? recordedEvents(record!), receive);
    };
    if (mode === "live" && api.base) {
      try {
        stop.current = connectInvestigation(cve, receive, message => replay(
          message.includes('Daily limit reached') ? message : 'Live investigation unavailable, showing a recorded run.'
        ), undefined, api.base);
      } catch { replay('Live investigation unavailable, showing a recorded run.'); }
    } else replay(api.message);

  };
  return {
    input,
    setInput,
    health,
    session,
    elapsed,
    launch,
    cancel,
    checkHealth,
    label,
    recordingAvailable: !!(data.runs?.length || data.live_examples?.length),
  };
}
export type LiveInvestigationState = ReturnType<typeof useInvestigation>;
