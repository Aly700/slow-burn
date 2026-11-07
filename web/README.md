# Before the Breach · web

A static Vite, React and TypeScript interface for the IBM track at Sheridan Datathon 2026. IBM Plex fonts ship locally. Charts use native SVG and CSS; there is no frontend backend or UI kit.

## Run the demo

Use Node 22.18+ and npm. From `web/`:

```sh
npm ci
npm run build
npm run preview
```

Open `http://localhost:4317`. The preview is local only. Stop it with Ctrl+C. For development, run `npm run dev`; it also syncs the data before starting.

## Data handoff

`npm run sync-data` reads `../artifacts/` and writes generated files to `public/data/`. It does not access the `data/` symlink or modify source artifacts. A production build always syncs first.

- All root artifact JSON files are copied and included in `bundle.json`.
- `scores_2026_top5000.csv` becomes JSON with the first 1,000 rows. CSV quoting, embedded newlines, and reasons JSON are preserved. Blank numbers remain null.
- Recorded `agent_runs/CVE-*.json` files take precedence. When the source directory has no run files, the two files in `fixtures/` supply clearly labelled illustrations.
- Every sync replaces the generated run directory so old fixtures cannot linger beside real runs.
- A model identified as a baseline, or a score outside 0–1, is presented as a ranking score rather than probability.
- Missing numbers show pending; missing runs show the available snapshot evidence and no approval controls.

Generated data and `dist/` are ignored. Rebuild after the model and briefing artifacts are integrated. Deploy the resulting `dist/` directory as static files; relative asset paths support a subdirectory deployment.

The 2025 baseline counts (currently 5 / 10 / 18) are separate from the published 2026 benchmark counts (7 / 6 / 8). The 2026 outcome is always pending judging. KEV inclusion is labelled as a proxy, not the date of the first attack. No historical or current exploitation feeds are fetched by this interface.

## Briefing and approval

Fixture runs are hand-authored from the supplied snapshot records. Their timings, confidence, verification outcomes and model identity are illustrative. They are not evidence of model inference. Fixture approval always simulates locally and creates no ticket.

For recorded runs the interface sends:

```http
POST http://localhost:8765/runs/{run_id}/approval
Content-Type: application/json

{"approved": true}
```

Rejection sends `false`. The response can contain the updated run directly or under `run`; a recognized `state` is required. The current repository contract does not specify the request body, so `{approved: boolean}` is an integration assumption to confirm with the service owner. The service must allow the preview origin through CORS. No live service was available during verification.

A network failure uses an explicitly labelled local simulation. HTTP errors, timeouts, malformed JSON, and unknown states leave the recorded state unchanged. Decisions last for the current page session; reload resets the demonstration to the recorded artifact. The browser never performs the server-side evidence verification itself.

## Two-minute route

1. **0:00–0:20 — Overview.** Severity measures potential harm. Point to the honestly labelled 2025 backtest, then distinguish the unjudged 2026 result.
2. **0:20–0:40 — Discovery.** The first month calls for patch speed; later entries have a 45-day median lag in the seed cohort. The exact numbers update with the findings artifact.
3. **0:40–1:00 — Signals.** Explain the low-risk signals and the much larger, suspicious wording lift. Show the WordPress cohort without treating zero KEV as zero risk.
4. **1:00–1:40 — Queue and evidence.** Select “illustrative briefings” or “recorded briefings”, open a row, expand an evidence chip, show the dropped claim and trace, then approve or reject. Label simulation aloud when it is shown.
5. **1:40–2:00 — Methods.** Show feature exclusions, the snapshot boundary, and the IBM technology recorded in the model card and run provenance. Do not claim the pending integrations have completed.

In the queue, `j` and `k` move selection and scroll it into view. Enter opens the selected row. Escape closes the briefing. Search inputs retain normal typing; native controls support Tab and Enter.

## Verification

`npm test` checks CSV conversion, source-safe sync and approval response handling. To run the browser scenarios against a running preview using an existing `playwright-core` install:

```sh
PLAYWRIGHT_ROOT=/path/to/project-with-playwright-core node scripts/verify-browser.mjs
```

Chromium must be installed as the `chromium` channel. The verification script uses the supplied seed fixture IDs and intercepts service responses; rerun or adapt those scenario IDs after replacing the seed artifacts. Screenshots are written to the ignored root `shots/` directory. Four visual rounds covered 1440×900 and 1920×1080 at 2× density, with an additional 390×844 layout check.
