# Slow Burn · web

A static Vite, React and TypeScript interface for the IBM Before the Breach track at Sheridan Datathon 2026. IBM Plex fonts ship locally. Charts use SVG and CSS; the frontend has no backend of its own.

## Run the demo

Use Node 22.18+ and npm. From `web/`:

```sh
npm ci
npm run build
npm run preview
```

Open `http://localhost:4317`. Build always runs data sync first. Development uses `npm run dev`. Stop the local preview with Ctrl+C.

Click **Present** or press **p** for the six-step, approximately one-minute walk. Right/left arrows move between slides; space advances when focus is on the slide. Escape exits and restores focus. Buttons and evidence disclosures keep their normal keyboard behaviour. The step counter and progress controls can also navigate directly.

1. The top-500 result, explicitly labelled **2025 development backtest**. The 2026 outcome remains pending judging.
2. Publication-month versus later KEV inclusion, with the later-entry lag histogram. KEV inclusion is a catalog clock, not a first-attack timestamp.
3. The later-exploited cohort without a public exploit signal at its snapshot.
4. Vendor history within the public-exploit tier, with separate vendor/product views and the WordPress description cohort.
5. A recorded fix-now briefing and the three-arm evaluation. The evaluation reused its cases during revision; it is not an unseen confirmation.
6. The human approval gate and the IBM Concert positioning line.

For the two-minute video, follow the presentation, exit to the queue, search for a CVE, expand a source chip and inspect the trace. In the queue, `j`/`k` move selection and Enter opens the briefing. Escape closes it. Methods include the current model’s complete feature and exclusion inventory.

## Data handoff

`npm run sync-data` reads `../artifacts/` and writes ignored generated files to `public/data/`. It never writes source artifacts or accesses the `data/` symlink.

- Root artifact JSON files are copied and included in `bundle.json`, including `agent_eval.json`.
- `scores_2026_top5000.csv` becomes JSON with the first 1,000 rows. Quoted newlines and reason JSON are preserved; blank numbers remain null.
- Root `agent_runs/CVE-*.json` recordings take precedence. If none exist, the two clearly labelled illustrative runs in `fixtures/` are used.
- The generated run directory is replaced on every sync. A recursive scan finds a recorded dropped-claim example if one is available; it is attributed separately when it belongs to another CVE.
- The featured run prefers a fix-now Ivanti Sentry recording with at least four verified claims. Otherwise it selects by verified claim count and distinct evidence fields. It does not depend on the baseline ranking’s CVEs remaining present.
- `findings.headline`, `two_clocks.lag_hist`, `vendor_history_within_poc`, and `story` feed both views. Missing measurements show **pending**. Evaluation arms read `observed_outcome_accuracy` and `history_or_analogy_coverage`; the active arm comes from the artifact.
- Model features, exclusions, technologies and limitations come from `model_card.json`. Long inventories remain expandable. Scores are historical catalog-inclusion estimates, not a fixed 30-day attack probability; tier priority can make score order non-monotonic across tiers.

Rebuild after merging new artifacts. Deploy `dist/` as static files. Relative asset paths support a subdirectory deployment. The interface fetches no external exploitation data.

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

No recorded run currently contains a dropped claim. The page says so, and shows a struck-out claim automatically when one is supplied. Fixtures remain available for explicitly illustrative verifier and injection demonstrations.

## Verification

```sh
npm test
PLAYWRIGHT_ROOT=/path/to/project-with-playwright-core node scripts/verify-browser.mjs
```

The browser scenarios exercise presentation keys and viewport fit, queue navigation, source evidence, trace, hash-bound approval, simulation, HTTP conflicts, optional findings, null values and illustrative injection/dropped claims. Chromium must be installed as the `chromium` channel.

With the demo API running, the following additionally files one real local ticket and rejects a separate recorded run:

```sh
PLAYWRIGHT_ROOT=/path/to/project-with-playwright-core LIVE_APPROVAL=1 node scripts/verify-browser.mjs
```

That live check changes the isolated demo store. Use a fresh store for a fresh table demonstration; retain any decisions you need before doing so. Screenshots are written under the ignored root `shots/` directory. The lead revision has three visual rounds at 1440×900 and 1920×1080, device scale 2, including all six slides in every round.
