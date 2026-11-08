import { useEffect, useRef, useState } from "react";
import type { LiveInvestigationState } from "../useInvestigation";
import { displayValue } from "../lib";
import { Icon } from "./Icon";
import "../investigation.css";

export function LiveControls({
  live,
  disabled = false,
}: {
  live: LiveInvestigationState;
  disabled?: boolean;
}) {
  const running = live.session.status === "running";
  return (
    <div className="live-controls">
      <div className={`live-availability ${live.health}`} role="status">
        <i />
        <span>
          {live.health === "ready"
            ? live.label
            : live.health === "checking"
              ? "Checking local Granite…"
              : live.recordingAvailable
                ? "Granite offline · recorded replay available"
                : "Granite offline · recording pending"}
        </span>
        <button
          onClick={() => void live.checkHealth()}
          aria-label="Check Granite connection"
        >
          Check connection
        </button>
      </div>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          if (!running && !disabled) live.launch();
        }}
      >
        <label>
          <span className="sr-only">2026 CVE to investigate</span>
          <input
            value={live.input}
            onChange={(event) =>
              live.setInput(event.target.value.toUpperCase())
            }
            placeholder="CVE-2026-10523"
            spellCheck={false}
            autoComplete="off"
            maxLength={32}
            disabled={running || disabled}
          />
        </label>
        <button
          className="button primary"
          type="submit"
          disabled={running || disabled || live.health === "checking"}
        >
          <span>{running ? "Investigating…" : "Run live with Granite"}</span>
          <Icon name="arrow" size={16} />
        </button>
        {running && (
          <button type="button" className="live-stop" onClick={live.cancel}>
            Stop
          </button>
        )}
      </form>
      {live.session.message && (
        <p className="live-message" role="status">
          {live.session.message}
        </p>
      )}
    </div>
  );
}

export function LiveTrace({ live }: { live: LiveInvestigationState }) {
  const { session, elapsed } = live;
  const [expanded, setExpanded] = useState(false);
  const end = useRef<HTMLDivElement>(null);
  const follow = useRef(true);
  const running = session.status === "running";
  useEffect(() => {
    if (follow.current && running) {
      const scroll = end.current?.parentElement;
      if (scroll) scroll.scrollTop = scroll.scrollHeight;
    }
  }, [session.tools, session.claims, running]);
  if (session.status === "idle") return null;
  const title = session.illustrative
    ? "Illustrative fixture replay"
    : session.fixture
      ? "Replay of a recorded fixture run"
      : session.mode === "replay"
        ? "Replay of a recorded run"
        : live.label;
  if (session.status === "complete" && !expanded)
    return (
      <div className="live-complete">
        <span>
          {title} ·{" "}
          {session.duration_ms == null
            ? "timing pending"
            : `${(session.duration_ms / 1000).toFixed(2)} s`}
        </span>
        <button onClick={() => setExpanded(true)}>
          Inspect streamed trace
        </button>
      </div>
    );
  return (
    <div className={`live-trace ${running ? "running" : ""}`}>
      <header>
        <div>
          <span className="eyebrow">{title}</span>
          <strong>{session.cve_id}</strong>
        </div>
        <span className="live-stage">
          {running && <i className="working-ring" />}
          {session.queued
            ? `QUEUED · ${session.queue_position ?? "pending"}`
            : (session.state?.replaceAll("_", " ") ??
              (running ? "CONNECTING" : session.status.toUpperCase()))}
          <small>
            {((session.duration_ms ?? elapsed) / 1000).toFixed(1)} s
          </small>
        </span>
        {session.status === "complete" && (
          <button
            className="icon-button"
            onClick={() => setExpanded(false)}
            aria-label="Collapse streamed trace"
          >
            ×
          </button>
        )}
      </header>
      <p className="sr-only" role="status">
        {session.state}. {session.tools.filter((tool) => !tool.working).length}{" "}
        results received.{" "}
        {session.claims.filter((claim) => claim.verified).length} claims
        verified.
      </p>
      <div
        className="live-event-scroll"
        tabIndex={0}
        aria-label="Investigation events"
        onScroll={(event) => {
          const n = event.currentTarget;
          follow.current = n.scrollHeight - n.scrollTop - n.clientHeight < 60;
        }}
      >
        {!session.tools.length && (
          <p className="live-waiting">
            {running
              ? session.queued
                ? "Waiting for the local Granite worker…"
                : "Opening the snapshot record…"
              : "No tool results received."}
          </p>
        )}
        {session.tools.map((tool) => (
          <article className="live-tool" key={tool.call_id}>
            <div>
              {tool.working && running ? (
                <i className="working-ring" />
              ) : (
                <Icon name={tool.working ? "warning" : "check"} size={14} />
              )}
              <strong>{tool.tool.replaceAll("_", " ")}</strong>
              <span>
                {tool.kind === "model"
                  ? "Granite"
                  : tool.kind === "policy"
                    ? "Policy"
                    : tool.kind === "verifier"
                      ? "Verifier"
                      : "Tool"}
              </span>
              <small>
                {tool.working
                  ? running
                    ? "working"
                    : "interrupted"
                  : tool.ms == null
                    ? "timing pending"
                    : `${tool.ms} ms`}
              </small>
            </div>
            {!tool.working && <p>{displayValue(tool.preview)}</p>}
            <details>
              <summary>Inputs</summary>
              <pre>{displayValue(tool.args)}</pre>
            </details>
          </article>
        ))}
        {session.claims.length > 0 && (
          <div className="live-claims">
            <span className="eyebrow">CLAIMS CHECKED AGAINST EVIDENCE</span>
            {session.claims.map((claim) => (
              <article
                className={claim.verified ? "verified" : "dropped"}
                key={claim.id}
              >
                <Icon name={claim.verified ? "check" : "close"} size={16} />
                <div>
                  {claim.verified ? (
                    <p>{claim.text}</p>
                  ) : (
                    <>
                      <s>{claim.text ?? claim.id}</s>
                      <small>
                        {claim.reason ?? "Not supported by tool output"}
                      </small>
                    </>
                  )}
                  {claim.verified && (
                    <div className="evidence-chips">
                      {claim.evidence?.map((evidence, index) => (
                        <details className="evidence-chip" key={index}>
                          <summary>{evidence.field}</summary>
                          <div>
                            <code>{evidence.tool}</code>
                            <p>{displayValue(evidence.value)}</p>
                          </div>
                        </details>
                      ))}
                    </div>
                  )}
                </div>
              </article>
            ))}
          </div>
        )}
        <div ref={end} />
      </div>
      <p className="live-trace-note">
        {session.illustrative
          ? "Illustrative timings and evidence. Approval is simulated locally."
          : session.fixture
            ? `Recorded fixture: ${session.fixture}. Approval is simulated locally.`
            : session.mode === "replay"
              ? "Original timings. Replay approval is simulated locally."
              : "Snapshot evidence only. A verified briefing still needs your approval."}
      </p>
    </div>
  );
}
