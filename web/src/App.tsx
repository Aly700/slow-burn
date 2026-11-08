import { useCallback, useEffect, useRef, useState } from "react";
import type { Data, Score, Run } from "./types";
import { list } from "./lib";
import { Hero, Methods, Signals, Timing } from "./components/Story";
import { GraniteMap } from "./components/GraniteMap";
import { Queue } from "./components/Queue";
import { Analyst } from "./components/Analyst";
import { Briefing } from "./components/Briefing";
import { Discovery, AgentSection } from "./components/Discovery";
import { Presentation } from "./components/Presentation";
import { strongestRun } from "./storyData";
import { Icon } from "./components/Icon";
import { AshHero } from "./components/AshHero";

export default function App() {
  const [data, setData] = useState<Data>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [selected, setSelected] = useState<Score | null>(null);
  const [presenting, setPresenting] = useState(false);
  const [active, setActive] = useState("overview");
  const [decisions, setDecisions] = useState<
    Record<string, { run: Run; notice: string }>
  >({});
  const updateRun = useCallback(
    (run: Run, notice: string) =>
      setDecisions((previous) => ({
        ...previous,
        [run.cve_id]: { run, notice },
      })),
    [],
  );
  useEffect(() => {
    let active = true;
    fetch(`${import.meta.env.BASE_URL}data/bundle.json`)
      .then((response) => {
        if (!response.ok) throw new Error("Missing data");
        return response.json();
      })
      .then((value) => {
        if (active) setData(value ?? {});
      })
      .catch(() => {
        if (active) setError(true);
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries)
          if (entry.isIntersecting) setActive(entry.target.id);
      },
      { rootMargin: "-10% 0px -65% 0px" },
    );
    document
      .querySelectorAll("main section[id]")
      .forEach((section) => observer.observe(section));
    return () => observer.disconnect();
  }, [loading]);
  const closePresentation = useCallback(() => setPresenting(false), []);
  useEffect(() => {
    const key = (event: KeyboardEvent) => {
      if (
        event.key.toLowerCase() === "p" &&
        !event.metaKey &&
        !event.ctrlKey &&
        !event.altKey &&
        !/INPUT|SELECT|TEXTAREA/.test((event.target as HTMLElement).tagName) &&
        !document.querySelector('[role="dialog"]')
      ) {
        event.preventDefault();
        setPresenting(true);
      }
    };
    window.addEventListener("keydown", key);
    return () => window.removeEventListener("keydown", key);
  }, []);
  const featured = strongestRun(data);
  const openFeatured = () => {
    if (!featured) return;
    setSelected(
      list(data.scores).find((score) => score.cve_id === featured.cve_id) ?? {
        rank: 0,
        cve_id: featured.cve_id,
        snapshot_month: featured.snapshot_month,
      },
    );
  };
  const openCve = (cve: string) =>
    setSelected(
      list(data.scores).find((row) => row.cve_id === cve) ?? {
        rank: 0,
        cve_id: cve,
      },
    );
  const askAfterPresentation = useRef(false);
  useEffect(() => {
    if (!presenting && askAfterPresentation.current) {
      askAfterPresentation.current = false;
      document
        .getElementById("analyst")
        ?.scrollIntoView({ behavior: "instant", block: "start" });
      document
        .getElementById("analyst-question")
        ?.focus({ preventScroll: true });
    }
  }, [presenting]);
  const openAnalyst = () => {
    askAfterPresentation.current = true;
    setPresenting(false);
  };
  const close = useCallback(() => setSelected(null), []);
  return (
    <>
      <a className="skip-link" href="#queue">
        Skip to fix-first queue
      </a>
      <header className="site-header">
        <a className="brand" href="#overview" aria-label="Slow Burn overview">
          <span className="brand-mark">
            <span />
            <span />
            <span />
          </span>
          <strong>
            Slow Burn<span> / </span>
          </strong>
        </a>
        <nav aria-label="Main navigation">
          {[
            ["overview", "Overview"],
            ["timing", "Discovery"],
            ["queue", "Fix-first queue"],
            ["analyst", "Ask Slow Burn"],
            ["agent", "Briefing"],
            ["methods", "Methods"],
          ].map(([id, label]) => (
            <a
              key={id}
              className={
                active === id ||
                (id === "timing" && ["signals", "discovery", "granite-map"].includes(active))
                  ? "active"
                  : ""
              }
              href={`#${id}`}
            >
              {label}
            </a>
          ))}
        </nav>
        <div className="header-end">
          <span className="track-subtitle">
            IBM Before the Breach track · Sheridan Datathon 2026
          </span>
          <button
            className="present-button"
            onClick={() => setPresenting(true)}
          >
            Present <kbd>P</kbd>
          </button>
        </div>
      </header>
      {error && (
        <div className="data-banner" role="status">
          Data bundle unavailable. Findings remain pending; run the data sync
          before the demo.
        </div>
      )}
      <main aria-busy={loading}>
        <AshHero />
        <Hero data={data} />
        <Timing findings={data.findings} />
        <Signals findings={data.findings} />
        <Discovery findings={data.findings} />
        <section
          id="granite-map"
          className="story-section map-section"
          aria-label="What Granite reads"
        >
          <GraniteMap data={data} />
        </section>
        <Queue
          data={{
            ...data,
            runs: [
              ...list(data.runs).map(
                (run) => decisions[run.cve_id]?.run ?? run,
              ),
              ...Object.values(decisions)
                .filter(
                  ({ run }) =>
                    !list(data.runs).some(
                      (recorded) => recorded.cve_id === run.cve_id,
                    ),
                )
                .map(({ run }) => run),
            ],
          }}
          onOpen={setSelected}
        />
        <Analyst data={data} onOpen={openCve} />
        <AgentSection data={data} run={featured} onOpen={openFeatured} />
        <Methods data={data} />
      </main>
      <footer className="site-footer">
        <a href="#overview">
          Slow Burn <Icon name="arrow" size={16} />
        </a>
        <span>Know what to fix. Know why.</span>
        <span>Sheridan Datathon · 07–08 Nov 2026</span>
      </footer>
      {presenting && (
        <Presentation
          data={{
            ...data,
            runs: list(data.runs).map(
              (run) => decisions[run.cve_id]?.run ?? run,
            ),
          }}
          initialNotice={featured ? decisions[featured.cve_id]?.notice : ""}
          onClose={closePresentation}
          onAsk={openAnalyst}
          onUpdate={updateRun}
        />
      )}
      {selected && (
        <Briefing
          key={selected.cve_id}
          data={data}
          score={selected}
          run={
            decisions[selected.cve_id]?.run ??
            list(data.runs).find((run) => run.cve_id === selected.cve_id)
          }
          initialNotice={decisions[selected.cve_id]?.notice}
          onUpdate={updateRun}
          fixture={data.meta?.runs_source === "fixtures"}
          onClose={close}
        />
      )}
    </>
  );
}
