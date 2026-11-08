import { useEffect, useMemo, useRef, useState } from "react";
import type { Data, Score } from "../types";
import { list, number, percent, reasonLabel } from "../lib";
import { Icon } from "./Icon";
import { SectionHeading } from "./SectionHeading";
import { QueueRow } from "./QueueRow";
import { ProductWatch } from "./ProductWatch";
import { decodeWatch, filterWatch } from "../productWatch";
import type { ProductWatchRow } from "../productWatch";
import { SoftwareMatcher } from "./SoftwareMatcher";
import { StackFilter } from "./StackFilter";
import { loadStack, matchesStack, saveStack } from "../stack";
import type { StackChoice } from "../stack";
import { downloadFile, queueCsv, ticketDrafts } from "../exports";

export function Queue({
  data,
  onOpen,
}: {
  data: Data;
  onOpen: (score: Score) => void;
}) {
  const [query, setQuery] = useState("");
  const [stack, setStack] = useState<StackChoice[]>(loadStack);
  const [watch, setWatch] = useState<ProductWatchRow[] | null>(null);
  const [watchError, setWatchError] = useState(false);
  const [watchLoading, setWatchLoading] = useState(false);
  const [watchAttempt, setWatchAttempt] = useState(0);
  const [loose, setLoose] = useState(false);
  const watchFile = data.lazy?.product_watch?.file;
  const needsWatch = !!stack.length;
  useEffect(() => {
    if (!watchFile || !needsWatch || watch) return;
    const controller = new AbortController();
    setWatchLoading(true); setWatchError(false);
    fetch(`${import.meta.env.BASE_URL}data/${watchFile}`, { signal: controller.signal })
      .then(response => { if (!response.ok) throw new Error("Missing review list"); return response.json(); })
      .then(value => setWatch(decodeWatch(value)))
      .catch(() => { if (!controller.signal.aborted) setWatchError(true); })
      .finally(() => { if (!controller.signal.aborted) setWatchLoading(false); });
    return () => controller.abort();
  }, [watchFile, needsWatch, watch, watchAttempt]);
  const watchRows = useMemo(() => filterWatch(watch ?? [], stack, loose), [watch, stack, loose]);
  const [persisted, setPersisted] = useState(true);
  const [exportNotice, setExportNotice] = useState("");
  const exportMenu = useRef<HTMLDetailsElement>(null);
  const ledger = useRef<HTMLDetailsElement>(null);
  const [exportUp, setExportUp] = useState(false);
  useEffect(() => {
    setPersisted(saveStack(stack));
  }, [stack]);
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
          `${row.cve_id} ${row.assigner ?? ""} ${row.vendor_identity ?? ""} ${row.description ?? ""} ${list(row.reasons).map(reasonLabel).join(" ")}`.toLowerCase();
        return (
          matchesStack(row, stack) &&
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
    [scores, query, month, filter, runIds, stack],
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
      if (ledger.current) ledger.current.open = true;
      root.current
        ?.querySelector("tr.selected")
        ?.scrollIntoView({ block: "nearest", behavior: "instant" });
      root.current
        ?.querySelector<HTMLButtonElement>("tr.selected .cve-button")
        ?.focus({ preventScroll: true });
      keyboardMove.current = false;
    }
  }, [selected, page]);
  function exportRows(format: "csv" | "json") {
    const runs = list(data.runs);
    const contents =
      format === "csv"
        ? queueCsv(rows, runs, watchRows)
        : JSON.stringify(ticketDrafts(rows, runs, watchRows), null, 2) + "\n";
    downloadFile(
      `slow-burn-queue.${format}`,
      contents,
      format === "csv"
        ? "text/csv;charset=utf-8"
        : "application/json;charset=utf-8",
    );
    if (exportMenu.current) exportMenu.current.open = false;
    setExportNotice(
      `Prepared ${number(rows.length)} ranked rows and ${number(watchRows.length)} product review rows. Review rows have no rank or predicted verdict; exporting does not approve a ticket.`,
    );
  }
  const ranking = data.meta?.score_mode === "ranking";
  return (
    <section
      id="queue"
      ref={root}
      className="story-section queue-section"
      aria-label="Fix-first queue"
    >
      <SectionHeading
        index="07" label="Fix-first queue"
        title="Fix-first queue"
        detail="2026 candidates · evidence at each snapshot"
      />
      <div className="queue-intro">
        <p>Select a row to inspect its evidence and proposed action.</p>
        <div className="queue-count">
          <strong>{number(scores.length)}</strong>
          <span>ranked candidates shown</span>
        </div>
      </div>
      <StackFilter
        inventoryInput={<SoftwareMatcher data={data} />}
        scores={scores}
        reviewIdentities={data.lazy?.product_watch?.identities}
        secondaryList={watchFile ? <ProductWatch rows={watchRows} choices={stack.length} loading={watchLoading || (needsWatch && !watch && !watchError)} error={watchError} retry={() => setWatchAttempt(value => value + 1)} loose={loose} onLoose={setLoose} study={data.findings?.blind_spot} /> : undefined}
        choices={stack}
        persisted={persisted}
        onChange={(choices) => {
          setStack(choices);
          reset();
          setExportNotice("");
        }}
      />
      <div className="queue-toolbar">
        <label className="search">
          <Icon name="search" />
          <input
            aria-label="Search queue"
            placeholder="Search CVE, vendor, assigner, or description…"
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
      <div className="queue-export-row">
        <span>
          <strong>{number(rows.length)}</strong> ranked matches · exports include
          every matching page{watchFile && stack.length > 0 ? ` + ${number(watchRows.length)} product review rows from your stack` : ""}
        </span>
        <details
          className={`queue-export ${exportUp ? "opens-up" : ""}`}
          ref={exportMenu}
          onToggle={(event) => {
            if (event.currentTarget.open)
              setExportUp(
                window.innerHeight -
                  event.currentTarget.getBoundingClientRect().bottom <
                  200,
              );
          }}
          onKeyDown={(event) => {
            if (event.key === "Escape") {
              event.currentTarget.open = false;
              event.currentTarget.querySelector("summary")?.focus();
            }
          }}
        >
          <summary aria-label="Export filtered queue">
            Export <Icon name="down" size={14} />
          </summary>
          <div className="export-options">
            <button disabled={(!rows.length && !watchRows.length) || (needsWatch && !!watchFile && (!watch || watchLoading))} onClick={() => exportRows("csv")}>
              Download CSV <span>{number(rows.length + watchRows.length)} rows</span>
            </button>
            <button disabled={(!rows.length && !watchRows.length) || (needsWatch && !!watchFile && (!watch || watchLoading))} onClick={() => exportRows("json")}>
              Download JSON tickets <span>{number(rows.length + watchRows.length)} drafts</span>
            </button>
            <p>
              Product review rows follow the stack and match toggle above; ranked rows follow queue filters. Exporting does not file or
              approve a ticket.
            </p>
          </div>
        </details>
      </div>
      {exportNotice && (
        <p className="export-notice" role="status">
          {exportNotice}
        </p>
      )}
      <div className="queue-preview" aria-label="Leading ranked matches">
        {visible.slice(0, 3).map((row, index) => (
          <button key={row.cve_id} onClick={() => {
            setSelected(page * pageSize + index);
            onOpen(row);
          }}>
            <span className="preview-rank mono">{String(row.rank).padStart(3, "0")}</span>
            <span className="preview-identity"><strong>{row.cve_id}</strong><span>{row.vendor_identity && row.vendor_identity !== "unmapped" ? row.vendor_identity : row.assigner || "Assigner unavailable"}{row.product_identity ? ` · ${row.product_identity}` : ""}</span></span>
            <span className="preview-score mono">{ranking ? number(row.score, 4) : percent(row.score, 2)}<small>{ranking ? "Rank score" : "Model score"}</small></span>
            <Icon name="arrow" size={17} />
          </button>
        ))}
      </div>
      <details className="reading-details queue-ledger" ref={ledger} open={!rows.length}>
        <summary>All {number(rows.length)} ranked matches</summary>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th scope="col">Rank</th>
              <th scope="col">Vulnerability / vendor or assigner</th>
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
              <QueueRow
                key={row.cve_id}
                row={row}
                ranking={ranking}
                selected={selected === page * pageSize + index}
                hasRun={runIds.has(row.cve_id)}
                onOpen={() => {
                  setSelected(page * pageSize + index);
                  onOpen(row);
                }}
              />
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
                ? "Try another stack item, CVE, or snapshot month."
                : "The page will use the ranking artifact after the next data sync."}
            </p>
            {scores.length > 0 && (
              <button
                className="button secondary"
                onClick={() => {
                  setQuery("");
                  setFilter("all");
                  setMonth("all");
                  setStack([]);
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
            ? `${page * pageSize + 1}-${Math.min((page + 1) * pageSize, rows.length)} of ${number(rows.length)}`
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
      </details>
    </section>
  );
}
