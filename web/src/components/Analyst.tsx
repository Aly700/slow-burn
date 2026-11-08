import { ReadingDetails } from "./ReadingDetails";
import { useRef } from "react";
import type { AnalystSession, Data, LiveClaim } from "../types";
import { displayValue, number } from "../lib";
import { suggestions } from "../analyst";
import { useAnalyst } from "../useAnalyst";
import { SectionHeading } from "./SectionHeading";
import { Icon } from "./Icon";
import "../analyst.css";

function CveText({
  text,
  onOpen,
}: {
  text: string;
  onOpen: (cve: string) => void;
}) {
  return (
    <>
      {text.split(/(CVE-\d{4}-\d{4,})/g).map((part, i) =>
        /^CVE-\d{4}-\d{4,}$/.test(part) ? (
          <a
            key={i}
            href="#queue"
            onClick={(e) => {
              e.preventDefault();
              onOpen(part);
            }}
            aria-label={`Open briefing for ${part}`}
          >
            {part}
          </a>
        ) : (
          part
        ),
      )}
    </>
  );
}
function AnswerClaim({
  claim,
  onOpen,
}: {
  claim: LiveClaim;
  onOpen: (cve: string) => void;
}) {
  return (
    <article
      className={`answer-claim ${claim.verified ? "verified" : "dropped"}`}
    >
      {claim.verified ? (
        (claim.text ?? "")
          .split(/(?<=[.!?])\s+(?=[A-Z])/)
          .map((sentence, i) => (
            <p className="answer-sentence" key={i}>
              <Icon name="check" size={16} />
              <span>
                <span className="sr-only">Verified: </span>
                <CveText text={sentence} onOpen={onOpen} />
              </span>
            </p>
          ))
      ) : (
        <>
          <p className="answer-sentence">
            <Icon name="close" size={16} />
            <s>{claim.text ?? `Claim ${claim.id}`}</s>
          </p>
          <p className="answer-drop-reason">
            Dropped: {claim.reason ?? "Not supported by the returned evidence."}
          </p>
        </>
      )}
      {!!claim.evidence?.length && (
        <details className="answer-evidence">
          <summary>{number(claim.evidence.length)} evidence references</summary>
          <dl>
            {claim.evidence.map((e, i) => (
              <div key={i}>
                <dt>
                  {e.tool} · {e.field}
                </dt>
                <dd>{displayValue(e.value)}</dd>
              </div>
            ))}
          </dl>
        </details>
      )}
    </article>
  );
}
function InterpretedQuery({ session }: { session: AnalystSession }) {
  const q = session.query;
  const filters =
    q?.filters && typeof q.filters === "object"
      ? (q.filters as Record<string, unknown>)
      : q;
  return (
    <div className="analyst-query">
      <div className="analyst-query-title">
        <span className="eyebrow">
          {session.mode === "recorded"
            ? "RECORDED QUERY"
            : "QUERY CHOSEN BY GRANITE"}
        </span>
        <code>
          {session.tools.at(-1)?.tool ??
            (q
              ? "recorded selection"
              : session.status === "running"
                ? "interpreting…"
                : "no query")}
        </code>
      </div>
      {q ? (
        <>
          <div className="query-filters">
            {Object.entries(filters ?? {}).map(([key, value]) => (
              <span key={key}>
                <b>{key.replaceAll("_", " ")}</b> {displayValue(value)}
              </span>
            ))}
            {q.filters && q.limit != null ? (
              <span>
                <b>return limit</b> {displayValue(q.limit)}
              </span>
            ) : null}
          </div>
          <details className="query-json">
            <summary>Exact query</summary>
            <pre>{JSON.stringify(q, null, 2)}</pre>
          </details>
        </>
      ) : (
        <p>
          {session.status === "running"
            ? "Reading the question and selecting a supported local query."
            : "No structured query was returned."}
        </p>
      )}
    </div>
  );
}
export function Analyst({
  data,
  onOpen,
}: {
  data: Data;
  onOpen: (cve: string) => void;
}) {
  const live = useAnalyst(data.analyst_eval);
  const { session } = live;
  const suggested = suggestions(data.analyst_eval);
  const field = useRef<HTMLTextAreaElement>(null);
  const running = session.status === "running";
  const verified = session.claims.filter((c) => c.verified);
  const noAnswer = session.status !== "idle" && !running && !verified.length;
  function ask(q: string) {
    live.launch(q);
    if (window.matchMedia("(max-width: 700px)").matches)
      requestAnimationFrame(() =>
        field.current
          ?.closest(".analyst-main")
          ?.scrollIntoView({ behavior: "instant", block: "start" }),
      );
  }
  return (
    <section id="analyst" className="story-section analyst-section">
      <SectionHeading
        index="06" label="Ask Slow Burn"
        title="Ask Slow Burn"
        detail="Local ranking · read-only analysis"
      />
      <p className="analyst-lead">
        Start with a tested question. Granite interprets the filters; every
        retained sentence points back to the supplied evidence.
      </p>
      <div className="analyst-workspace">
        <aside className="analyst-suggestions">
          <div className="suggestions-heading">
            <span className="eyebrow">QUESTIONS THAT WORKED</span>
            <span>{number(suggested.length)} answered in evaluation</span>
          </div>
          <p>Choose one to ask it now.</p>
          <div className="question-chips">
            {suggested.slice(0, 4).map((r) => (
              <button
                key={r.id}
                onClick={() => ask(r.question)}
                disabled={running || live.health === "checking"}
                aria-pressed={session.question === r.question}
              >
                <span>{r.question}</span>
                <Icon name="arrow" size={16} />
              </button>
            ))}
          </div>
          {suggested.length > 4 && (
            <ReadingDetails label={`More tested questions (${suggested.length - 4})`}>
              <div className="question-chips">
              {suggested.slice(4).map((r) => (
              <button
                key={r.id}
                onClick={() => ask(r.question)}
                disabled={running || live.health === "checking"}
                aria-pressed={session.question === r.question}
              >
                <span>{r.question}</span>
                <Icon name="arrow" size={16} />
              </button>
              ))}
              </div>
            </ReadingDetails>
          )}
          {!suggested.length && <p>Recorded suggestions pending.</p>}
          <ReadingDetails label="Scope and limits">
          <p className="analyst-scope">
            Vendor matching is exact. Questions are limited to the supplied
            ranking and local metadata. This view cannot create tickets.
          </p>
          </ReadingDetails>
        </aside>
        <div className="analyst-main">
          <div className={`analyst-health ${live.health}`}>
            <span role="status">
              <i />
              {live.health === "ready"
                ? "Local Granite ready"
                : live.health === "checking"
                  ? "Checking local Granite…"
                  : suggested.length
                    ? "Offline · recorded answers available"
                    : "Offline · recordings pending"}
            </span>
            <button onClick={() => void live.checkHealth()}>
              Check connection
            </button>
          </div>
          <form
            className="analyst-form"
            onSubmit={(e) => {
              e.preventDefault();
              if (!running) ask(live.input);
            }}
          >
            <label htmlFor="analyst-question">Your question</label>
            <textarea
              ref={field}
              id="analyst-question"
              rows={2}
              maxLength={1000}
              placeholder="Choose a suggestion, or ask about a vendor, product or CVE…"
              value={live.input}
              onChange={(e) => live.setInput(e.target.value)}
              disabled={running}
            />
            <div className="analyst-form-actions">
              <span>
                {live.health === "ready"
                  ? "Runs on this laptop"
                  : "Suggested questions have recorded answers"}
              </span>
              {running ? (
                <button
                  type="button"
                  className="button secondary"
                  onClick={(event) => {
                    event.preventDefault();
                    live.cancel();
                  }}
                >
                  Stop question
                </button>
              ) : (
                <button
                  className="button primary"
                  disabled={!live.input.trim() || live.health === "checking"}
                >
                  Ask Slow Burn <Icon name="arrow" size={16} />
                </button>
              )}
            </div>
          </form>
          {session.status === "idle" ? (
            <div className="analyst-idle">
              <Icon name="search" size={24} />
              <p>Pick a question to inspect its query and evidence.</p>
            </div>
          ) : (
            <div className="analyst-result" aria-busy={running}>
              <div className="analyst-result-head">
                <span>
                  {session.mode === "live"
                    ? "Live Granite answer"
                    : "Recorded answer · evaluation run"}
                </span>
                <span className="mono" role="status">
                  {running ? (
                    <>
                      {session.queued
                        ? `Queued · position ${number(session.position)}`
                        : "Working…"}
                      <i className="ask-spinner" aria-hidden="true" />
                    </>
                  ) : session.status === "complete" ? (
                    session.duration_ms != null ? (
                      `${number(session.duration_ms / 1000, 2)} s${session.mode === "recorded" ? " original run" : ""}`
                    ) : (
                      "Recorded mode"
                    )
                  ) : (
                    session.status
                  )}
                </span>
              </div>
              <InterpretedQuery session={session} />
              {!!session.tools.length && (
                <div className="analyst-tools">
                  {session.tools.map((t) => (
                    <details key={t.call_id}>
                      <summary>
                        <span>
                          {t.working ? (
                            <i className="ask-spinner" />
                          ) : (
                            <Icon name="check" size={14} />
                          )}
                          <code>{t.tool}</code>
                        </span>
                        <span>
                          {t.working ? "working" : `${number(t.ms)} ms`} ·
                          result
                        </span>
                      </summary>
                      {t.preview != null ? (
                        <pre>{JSON.stringify(t.preview, null, 2)}</pre>
                      ) : (
                        <p>Waiting for tool results.</p>
                      )}
                    </details>
                  ))}
                </div>
              )}
              {session.mode === "recorded" && (
                <p className="analyst-record-note">
                  Saved answer and query, not a new inference. Source values are
                  available under each evidence disclosure.
                </p>
              )}
              {(noAnswer ||
                session.status === "error" ||
                session.status === "cancelled") && (
                <div className="analyst-no-answer" role="status">
                  <h3>
                    {verified.length
                      ? "Answer incomplete."
                      : "No verified answer."}
                  </h3>
                  <p>
                    {session.message ??
                      "The returned text did not produce a verified answer to this question."}
                  </p>
                  {session.answer?.text && !verified.length && (
                    <details>
                      <summary>Returned limitation</summary>
                      <p>{session.answer.text}</p>
                    </details>
                  )}
                  <p>Try one of the questions that worked:</p>
                  <div>
                    {suggested.slice(0, 2).map((r) => (
                      <button key={r.id} onClick={() => ask(r.question)}>
                        {r.question} <span aria-hidden="true">→</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}
              {!!session.claims.length && (
                <div className="analyst-answer">
                  <div className="answer-label">
                    <span className="eyebrow">
                      {session.status === "error" ||
                      session.status === "cancelled"
                        ? "PARTIAL EVIDENCE · ANSWER INCOMPLETE"
                        : "SENTENCES CHECKED AGAINST SOURCE EVIDENCE"}
                    </span>
                    <span>
                      {number(verified.length)} retained ·{" "}
                      {number(session.claims.length - verified.length)} dropped
                      claims
                    </span>
                  </div>
                  {session.claims.map((c) => (
                    <AnswerClaim key={c.id} claim={c} onOpen={onOpen} />
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
