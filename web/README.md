# Slow Burn · web

A static Vite, React and TypeScript interface for the IBM Before the Breach track at Sheridan Datathon 2026. IBM Plex fonts ship locally. Charts use Canvas, SVG and CSS; the frontend has no backend of its own.

## Run the demo

Use Node 22.18+ and npm. From `web/`:

```sh
npm ci
npm run build
npm run preview
```

Open `http://localhost:4317`. Build always runs data sync first. Development uses `npm run dev`. Stop the local preview with Ctrl+C.

The scroll page opens with the description field from `artifacts/map_2026.json`. Its responsive AVIF and WebP posters live in `public/hero/`. `node scripts/render-hero.mjs` verifies their source hashes on every build and regenerates stale files from the same deterministic projection used by the live canvas. Regeneration uses the existing `avifenc` and `cwebp` command-line tools; unchanged builds use the committed posters without these tools. `--force` regenerates every variant; `--check` fails on stale assets. Colours come from the root OKLCH tokens in `src/styles.css`.

The static field loads before the map JSON. The live canvas enhances it after the initial render. Reduced motion keeps the complete poster and disables pointer drift. The 2025 replay follows the opening, and the six presentation layouts remain separate.

Click **Present** or press **p** for the six-step, approximately one-minute walk. Right/left arrows move between slides; space advances when focus is on the slide. Escape exits and restores focus. Buttons and evidence disclosures keep their normal keyboard behaviour. The step counter and progress controls can also navigate directly.

1. A 12-second replay of the **2025 development backtest**. Four fields show each ranking’s selected CVEs; dots become available at snapshot month end and ignite at their recorded KEV dates. The separate tray contains positives missed by all four rankings. Press **r** to replay, pause, or drag the date scrubber. Reduced motion starts at the final state. Hover burning dots or use **Inspect confirmed CVEs** for dates and product details. The 2026 outcome remains pending judging.
2. Publication-month versus later KEV inclusion, with the later-entry lag histogram. KEV inclusion is a catalog clock, not a first-attack timestamp.
3. The later-exploited cohort without a public exploit signal at its snapshot, the pre-registered watch-model test, and the exploratory product-history contrast. All study measurements come from `findings.blind_spot`; the primary split is kept separate from the overlapping later-cutoff analysis. The registered plan and full limitations are linked in Discovery.
4. Vendor history within the public-exploit tier, with separate vendor/product views and the WordPress description cohort.
5. A fix-now briefing, **Run live with Granite**, and the three-arm evaluation. The evaluation reused its cases during revision; it is not an unseen confirmation.
6. The human approval gate and the IBM Concert positioning line.

For the two-minute video, follow the presentation, run an investigation, exit to the queue, choose a stack, and export its fix list. In the queue, `j`/`k` move selection and Enter opens the briefing. Escape closes it. Methods include the current model’s complete feature and exclusion inventory.

## Data handoff

`npm run sync-data` reads `../artifacts/` and writes ignored generated files to `public/data/`. It never writes source artifacts or accesses the `data/` symlink.

- Root artifact JSON files are copied and included in `bundle.json`, including `agent_eval.json` and `replay_2025.json`. Replay counters and dates are derived from the recorded items; no outcome counts are embedded in the component.
- `scores_2026_top5000.csv` becomes JSON with the first 1,000 rows. Quoted newlines and reason JSON are preserved; blank numbers remain null.
- Root `agent_runs/CVE-*.json` recordings take precedence. If none exist, the two clearly labelled illustrative runs in `fixtures/` are used.
- The generated run directory is replaced on every sync. A recursive scan finds a recorded dropped-claim example if one is available; it is attributed separately when it belongs to another CVE.
- The featured run prefers a fix-now Ivanti Sentry recording with at least four verified claims. Otherwise it selects by verified claim count and distinct evidence fields. It does not depend on the baseline ranking’s CVEs remaining present.
- `findings.headline`, `two_clocks.lag_hist`, `vendor_history_within_poc`, and `story` feed both views. Missing measurements show **pending**. Evaluation arms read `observed_outcome_accuracy` and `history_or_analogy_coverage`; the active arm comes from the artifact.
- Model features, exclusions, technologies and limitations come from `model_card.json`. Long inventories remain expandable. Scores are historical catalog-inclusion estimates, not a fixed 30-day attack probability; tier priority can make score order non-monotonic across tiers.

Rebuild after merging new artifacts. Deploy `dist/` as static files. Relative asset paths support a subdirectory deployment. The interface fetches no external exploitation data.

## Your stack and exports

Choose vendor/product suggestions or enter a custom text term above the queue. Selections match **any** chosen item. Vendor matches are exact after normalization; product identities are qualified by vendor. Custom terms match complete normalized phrases in identities, assigners and descriptions. These are candidate matches; installed versions and exposure still need confirmation.

Selections are saved per browser under `slow-burn.stack.v1`. Restricted storage leaves the page functional for the current visit. Clear stack removes the selection; Clear filters also resets search, snapshot and queue filters. The top-500 match count is independent of the additional search/month filters.

**Export** downloads every matching row across pages, from the bundled top 1,000 candidates. CSV includes the ranking, snapshot signals and ticket fields. JSON drafts contain `cve_id`, `rank`, `verdict`, `headline`, `proposed_action`, and `evidence_summary`. Only verified briefing claims enter that summary; rows without a briefing carry `pending` and labelled ranking signals. Exports do not create or approve tickets. The phone queue keeps rank, CVE/product and score visible without horizontal scrolling.

The stack panel exposes an optional `secondaryList` slot. A future artifact-backed list can reuse the selected `StackChoice[]` and `matchesStack` helper. Keep “Previously attacked products, no public exploit yet” separate from the patch ranking and render it only when `product_watch_2026.csv` has been supplied and synced. This revision renders no second list and assumes no future CSV or embedding-map schema.

## Live investigation

Slide 5 and the briefing drawer accept a 2026 CVE identifier. On a local page, `GET http://127.0.0.1:8765/live/health` determines readiness. **Run live with Granite** consumes the named EventSource events in `research/CONTRACTS.md`: tools appear while working, results include recorded milliseconds, and verified/dropped claims appear as they arrive. Completion replaces the briefing and binds approval to that run ID and briefing hash. Closing the drawer or stopping a run closes its stream. Disconnects, malformed events and identity mismatches stop the investigation; they never silently substitute a successful replay.

An unavailable service or a hosted page replays available evidence and labels the source. `agent_runs/live-examples/*.json` stream envelopes use `{schema_version, source, cve_id, fixture, events: [{event, data, t_ms}]}`. Sync normalizes complete journals and preserves fixture labels. Exact non-fixture recordings take precedence over fixture recordings. The fallback replays a recorded run’s trace using its actual start times and durations. When another CVE must be replayed, the page names that substitution. Replay approvals always simulate locally. Hosted pages make no calls to a viewer’s localhost service.

The service allows specific local origins. Use the normal preview on port 4317 or development port 5173; an arbitrary preview port can be rejected even while the API is ready. Keep one inference worker and prepare weights before the table demo.

## Live approval

For a clean worktree, run this in a second terminal from `web/`:

```sh
npm run demo-api
```

This runs the existing `agent` service described in `../agent/README.md`, using `uv` and its pinned dependencies. Granite weights load before the API becomes ready. It imports verified recorded proposals, checks their briefing hashes, and preserves any existing decisions. The service listens on `127.0.0.1:8765` and supports the preview origin through CORS.

The launcher keeps its environment under `web/.runtime/venv` and its state/tickets under `web/.runtime/demo/`. Nothing is written to the shared artifact directory. It is a launcher and store importer, not a second API implementation. A service started directly with the agent README command also works if its database contains the displayed recorded run IDs.

The page sends:

```http
POST http://localhost:8765/runs/{run_id}/approval
Content-Type: application/json

{"approved": true, "briefing_hash": "the displayed record's hash"}
```

Rejection sends `false`. A recognized service state is required before displaying success. The hash prevents approving a different briefing. Network failure uses a labelled local simulation; HTTP errors, timeouts and malformed responses leave the state unchanged. Fixture decisions always simulate. Session decisions are shared between presentation and the drawer. Reload restores the static recording; the API retains its durable decision and handles repeat approvals idempotently.

Dropped claims appear struck out with the verifier’s reason whenever they are supplied. The streamed trace retains rejected claims after completion. Fixtures remain available for explicitly illustrative verifier and injection demonstrations.

## Verification

```sh
npm test
PLAYWRIGHT_ROOT=/path/to/project-with-playwright-core node scripts/verify-browser.mjs
PLAYWRIGHT_ROOT=/path/to/project-with-playwright-core node scripts/verify-workflows.mjs
```

The workflow checks use a controllable EventSource and verify live completion, offline identity, cancellation, exact approval IDs, recorded timing, stack persistence, blocked storage, downloads and a hosted sub-path. They do not require a running model. The other browser scenarios exercise presentation keys and viewport fit, queue navigation, source evidence, trace, hash-bound approval, simulation, HTTP conflicts, optional findings, null values and illustrative injection/dropped claims. Chromium must be installed as the `chromium` channel.

With the demo API running, the following additionally files one real local ticket and rejects a separate recorded run:

```sh
PLAYWRIGHT_ROOT=/path/to/project-with-playwright-core LIVE_APPROVAL=1 node scripts/verify-browser.mjs
```

That live check changes the isolated demo store. Use a fresh store for a fresh table demonstration; retain any decisions you need before doing so. Screenshots are written under the ignored root `shots/` directory. The replay, stream and stack revision was reviewed at 1280×900, 1440×900, 1920×1080 and phone width, device scale 2. A real Granite investigation and its local approval were also checked against the running service.
