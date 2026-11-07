import { useEffect, useMemo, useRef, useState } from "react";
import type { Data, Score } from "../types";
import { list, number, percent, reasonLabel } from "../lib";
import { Icon } from "./Icon";
import { SectionHeading } from "./Story";

export function Queue({
  data,
  onOpen,
}: {
  data: Data;
  onOpen: (score: Score) => void;
}) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const [month, setMonth] = useState("all");
  const [selected, setSelected] = useState(0);
  const [page, setPage] = useState(0);
  const root = useRef<HTMLElement>(null);
  const keyboardMove = useRef(false);
  const scores = list(data.scores);
  const runIds = useMemo(
    () => new Set(list(data.runs).map((run) => run.cve_id)),
    [data.runs],
  );
  const rows = useMemo(
    () =>
      scores.filter((row) => {
        const text =
          `${row.cve_id} ${row.assigner ?? ""} ${row.description ?? ""} ${list(row.reasons).map(reasonLabel).join(" ")}`.toLowerCase();
        return (
          text.includes(query.toLowerCase()) &&
          (month === "all" || row.snapshot_month === month) &&
          (filter === "all" ||
            (filter === "code"
              ? row.any_exploit === 1
              : filter === "briefings"
                ? runIds.has(row.cve_id)
                : row.rank <= 500))
        );
      }),
    [scores, query, month, filter, runIds],
  );
  const pageSize = 10;
  const pages = Math.ceil(rows.length / pageSize);
  const visible = rows.slice(page * pageSize, (page + 1) * pageSize);
  function reset() {
    setSelected(0);
    setPage(0);
  }
  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (
        document.querySelector('[role="dialog"]') ||
        /INPUT|SELECT|TEXTAREA/.test((event.target as HTMLElement).tagName) ||
        event.metaKey ||
        event.ctrlKey ||
        event.altKey
      )
        return;
      const box = root.current?.getBoundingClientRect();
      if (
        !box ||
        box.top > window.innerHeight * 0.6 ||
        box.bottom < 100 ||
        !rows.length
      )
        return;
      if (event.key === "j" || event.key === "k") {
        event.preventDefault();
        const next = Math.min(
          rows.length - 1,
          Math.max(0, selected + (event.key === "j" ? 1 : -1)),
        );
        keyboardMove.current = true;
        setSelected(next);
        setPage(Math.floor(next / pageSize));
      }
      if (
        event.key === "Enter" &&
        !/BUTTON|A|SUMMARY/.test((event.target as HTMLElement).tagName)
      ) {
        event.preventDefault();
        if (rows[selected]) onOpen(rows[selected]);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [rows, selected, onOpen]);
  useEffect(() => {
    if (keyboardMove.current) {
      root.current
        ?.querySelector("tr.selected")
        ?.scrollIntoView({ block: "nearest", behavior: "instant" });
      root.current
        ?.querySelector<HTMLButtonElement>("tr.selected .cve-button")
        ?.focus({ preventScroll: true });
      keyboardMove.current = false;
    }
  }, [selected, page]);
  const ranking = data.meta?.score_mode === "ranking";
  return (
    <section
      id="queue"
      ref={root}
      className="story-section queue-section"
      aria-label="Fix-first queue"
    >
      <SectionHeading
        index="03"
        title="The fix-first queue."
        detail="2026 candidates · evidence at each snapshot"
      />
      <div className="queue-intro">
        <p>
          Spend the next patch on the right vulnerability.
          <br />
          <span>Select a row to inspect its evidence and proposed action.</span>
        </p>
        <div className="queue-count">
          <strong>{number(scores.length)}</strong>
          <span>ranked candidates shown</span>
        </div>
      </div>
      <div className="queue-toolbar">
        <label className="search">
          <Icon name="search" />
          <input
            aria-label="Search queue"
            placeholder="Search CVE, assigner, or description…"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              reset();
            }}
          />
          {query && (
            <button
              aria-label="Clear search"
              onClick={() => {
                setQuery("");
                reset();
              }}
            >
              <Icon name="close" size={16} />
            </button>
          )}
        </label>
        <label className="filter-select">
          <span className="sr-only">Filter queue</span>
          <select
            aria-label="Filter queue"
            value={filter}
            onChange={(e) => {
              setFilter(e.target.value);
              reset();
            }}
          >
            <option value="all">All candidates</option>
            <option value="top500">Submission · top 500</option>
            <option value="code">Public exploit code</option>
            <option value="briefings">Briefing available</option>
          </select>
        </label>
        <select
          aria-label="Snapshot month"
          value={month}
          onChange={(e) => {
            setMonth(e.target.value);
            reset();
          }}
        >
          <option value="all">All snapshots</option>
          {[...new Set(scores.map((row) => row.snapshot_month).filter(Boolean))]
            .sort()
            .map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
        </select>
        <span className="keyboard-hint">
          <kbd>j</kbd>
          <kbd>k</kbd> move <kbd>↵</kbd> open
        </span>
      </div>
      <div className="queue-meta">
        <span>
          {ranking
            ? "Baseline order · exploit flags, then EPSS · score is not a probability"
            : "Model score · estimated probability of later KEV inclusion"}
        </span>
        <button
          className="briefings-filter"
          onClick={() => {
            setQuery("");
            setMonth("all");
            setFilter(filter === "briefings" ? "all" : "briefings");
            reset();
          }}
          aria-pressed={filter === "briefings"}
        >
          {runIds.size}{" "}
          {data.meta?.runs_source === "fixtures" ? "illustrative" : "recorded"}{" "}
          briefings <Icon name="arrow" size={13} />
        </button>
      </div>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th scope="col">Rank</th>
              <th scope="col">Vulnerability / assigner</th>
              <th scope="col">Snapshot</th>
              <th scope="col" className="score-cell">
                {ranking ? "Rank score" : "Model score"}
              </th>
              <th scope="col">Why it ranks</th>
              <th scope="col">
                <span className="sr-only">Briefing</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {visible.map((row, index) => (
              <tr
                key={row.cve_id}
                className={
                  selected === page * pageSize + index ? "selected" : ""
                }
                onClick={() => {
                  setSelected(page * pageSize + index);
                  onOpen(row);
                }}
              >
                <td className="rank mono">
                  {String(row.rank).padStart(3, "0")}
                </td>
                <td>
                  <button
                    className="cve-button"
                    onClick={(event) => {
                      event.stopPropagation();
                      setSelected(page * pageSize + index);
                      onOpen(row);
                    }}
                  >
                    {row.cve_id}
                  </button>
                  <span className="assigner" title={row.assigner}>
                    {row.assigner || "Assigner unavailable"}
                  </span>
                </td>
                <td className="mono snapshot">{row.snapshot_month || "—"}</td>
                <td className="score-cell mono">
                  {ranking ? number(row.score, 4) : percent(row.score, 2)}
                </td>
                <td>
                  <div className="reason-chips">
                    {list(row.reasons)
                      .slice(0, 2)
                      .map((reason, i) => (
                        <span
                          className="chip"
                          title={reasonLabel(reason)}
                          key={i}
                        >
                          {reasonLabel(reason)}
                        </span>
                      ))}
                    {!list(row.reasons).length && (
                      <span className="muted">Reasons pending</span>
                    )}
                    {list(row.reasons).length > 2 && (
                      <span className="more-reasons">
                        +{list(row.reasons).length - 2}
                      </span>
                    )}
                  </div>
                </td>
                <td className="row-action">
                  {runIds.has(row.cve_id) && (
                    <span className="run-dot" title="Briefing available" />
                  )}
                  <Icon name="arrow" size={17} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!visible.length && (
          <div className="queue-empty">
            <Icon name="search" size={28} />
            <h3>
              {scores.length
                ? "No candidates match these filters."
                : "The ranked queue is pending."}
            </h3>
            <p>
              {scores.length
                ? "Try another CVE, assigner, or snapshot month."
                : "The page will use the ranking artifact after the next data sync."}
            </p>
            {scores.length > 0 && (
              <button
                className="button secondary"
                onClick={() => {
                  setQuery("");
                  setFilter("all");
                  setMonth("all");
                  reset();
                }}
              >
                Clear filters
              </button>
            )}
          </div>
        )}
      </div>
      <div className="queue-footer">
        <span>
          {rows.length
            ? `${page * pageSize + 1}–${Math.min((page + 1) * pageSize, rows.length)} of ${number(rows.length)}`
            : "0 matches"}
          <span className="footer-divider">/</span>Top 500 form the submission
        </span>
        <div>
          <button
            className="page-button"
            disabled={page === 0}
            onClick={() => {
              setPage(page - 1);
              setSelected((page - 1) * pageSize);
            }}
          >
            Previous
          </button>
          <span className="mono">
            {pages ? page + 1 : 0} / {pages}
          </span>
          <button
            className="page-button"
            disabled={page + 1 >= pages}
            onClick={() => {
              setPage(page + 1);
              setSelected((page + 1) * pageSize);
            }}
          >
            Next <Icon name="arrow" size={14} />
          </button>
        </div>
      </div>
    </section>
  );
}
