import { useState } from "react";
import { requestApproval } from "./approval";
import { list } from "./lib";
import type { Run } from "./types";

export function useApproval(
  run: Run | undefined,
  fixture: boolean,
  initialNotice: string,
  onUpdate: (run: Run, notice: string) => void,
) {
  const [currentRun, setCurrentRun] = useState(run);
  const [notice, setNotice] = useState(initialNotice);
  const [busy, setBusy] = useState(false);
  async function decide(approved: boolean) {
    if (!currentRun || currentRun.state !== "WAITING_APPROVAL" || busy) return;
    setBusy(true);
    setNotice("");
    const commit = (updated: Run, message: string) => {
      setCurrentRun(updated);
      setNotice(message);
      onUpdate(updated, message);
    };
    const local = () => {
      const state = approved ? "TICKET_FILED" : "REJECTED";
      commit(
        {
          ...currentRun,
          state,
          states_seen: [...list(currentRun.states_seen), state],
          trace: [
            ...list(currentRun.trace),
            {
              kind: "policy",
              name: "local_decision_simulated",
              input: { approved },
              output_summary:
                "Local simulation only. No service write confirmed.",
            },
          ],
        },
        `Simulated ${approved ? "approval" : "rejection"} only. No ticket was created by this page.`,
      );
    };
    if (fixture) local();
    else {
      const result = await requestApproval(
        currentRun.run_id,
        approved,
        fetch,
        currentRun.briefing_hash,
      );
      if (result.kind === "confirmed")
        commit(
          { ...currentRun, ...result.run },
          `Service response: ${result.run.state.toLowerCase().replaceAll("_", " ")}.`,
        );
      else if (result.kind === "offline") local();
      else setNotice(result.message);
    }
    setBusy(false);
  }
  return { currentRun, notice, busy, decide };
}
