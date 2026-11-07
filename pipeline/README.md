# Reproducing the model lane

Run from this worktree with Python managed by `uv`. The `data/` directory is a read-only symlink to the supplied files; it must never be committed. All source code was written during the event.

```sh
uv sync --locked
uv run python -I pipeline/run.py --all
uv run python -I pipeline/checks.py --artifacts
uv run python -I pipeline/report.py
```

The first run downloads the pinned IBM Granite embedding weights. Subsequent runs reuse content-addressed embeddings under the ignored `artifacts/cache/`. MPS is used when available; CPU is a documented fallback. There are no external vulnerability-data requests in the pipeline.

| Artifact or stage | One command |
|---|---|
| Every contract artifact, from the supplied data | `uv run python -I pipeline/run.py --all` |
| Cached cohorts and input hashes | `uv run python -I pipeline/data.py` |
| IBM identity and sanitized-description embeddings | `uv run python -I pipeline/embed.py` |
| Main forward splits and ablations | `uv run python -I pipeline/evaluate.py` |
| Additional exact-calendar analog in `backtest.json` | `uv run python -I pipeline/analog.py` |
| Leak audit cache, used by `model_card.json` | `uv run python -I pipeline/leak_audit.py` |
| `top500.csv`, `scores_2026_top5000.csv`, `model_card.json`, and refreshed findings, using completed evaluation/audit | `uv run python -I pipeline/run.py` |
| `findings.json`, including all narrative counts | `uv run python -I pipeline/findings.py` |
| Local `.lane/model-REPORT.md` | `uv run python -I pipeline/report.py` |
| Baseline metric display | `uv run python -I pipeline/baseline.py` |
| Temporal and artifact gates | `uv run python -I pipeline/checks.py --artifacts` |

`run.py --all` is the authoritative dependency-ordered rebuild. Running `evaluate.py` alone replaces the main backtest, so rerun `analog.py` and `run.py` afterward. Cache files, model weights and the fitted model are local and ignored. Source-file and preprocessing-code SHA-256 fingerprints invalidate derived tabular caches; ordered row identifiers are also checked before history-cache reuse. The checked-in model card records every input hash. The original baseline script now prints reference metrics and cannot overwrite the production rankings.

## Cohorts and labels

Each vulnerability enters once, at publication-month end. The 2026 CSV's supplied `snapshot_month` is authoritative, including June → July. The historical main comparison uses each year's available publication-month signals. An additional January–September analog shifts June to July and ends observation on November 4, exactly matching the benchmark calendar.

Historical eligibility requires both no catalog addition by snapshot end and no `in_kev=1` at that snapshot. Missing snapshot signals mean missing EPSS and zero flags; no later observation is carried backward. One 2025 row is excluded by this conservative dual check, explaining the change from the initial exploration's 48,040-row pool.

The primary model fits 2024-published rows with at least 90 days follow-up, using only additions known by December 31, 2024. Its test is 2025-published rows with additions through December 31, 2025. A second model freezes labels on June 30, 2025 and tests July–September 2025. A third early-2024 → Q4-2024 check evaluates models without embeddings, because the frozen encoder was released in December 2024.

The all-2025 result includes right-censored late rows for comparison with the seed exploration. Separate tables use January–September rows with at least 90 days observation and a fixed 90-day endpoint. Training excludes immature rows regardless of label, avoiding selection based on whether an event happened early. Final training uses mature 2024+2025 rows and outcomes through December 31, 2025. KEV non-membership is an unobserved outcome, not proof of no exploitation.

Top-500 metrics are literal. The equal-workload budget is `round(N * 500 / 72670)`, since the 2026 benchmark selects 0.688% of 72,670 rows. Monthly budgets divide 500 proportionally across cohort sizes, with largest-remainder rounding. All rankings break ties by `cve_id` ascending. The organizer's 2026 counts are context; no 2026 outcome is used or estimated as a measured result.

## Feature provenance

| Feature block | Inputs | Production decision |
|---|---|---|
| Snapshot signals | `epss`, `exploitdb`, `metasploit`, `nuclei`, `poc_github` from the exact monthly snapshot | Eligible; log EPSS, within-month percentile, separate flags/count. Nuclei is detection tooling, not proof of attack. |
| Publication attributes | `cve_id`, `published`, `snapshot_month` | Eligible; reserved-year gap and days available at snapshot. |
| Assigning organization | `assigner`; vendor domain with conservative exclusions for third-party assigners | Eligible under a stated stability assumption; the data has no field-level provenance. |
| KEV history | Local catalog `date_added`, `vendor`, joined historical assigning organization | Eligible only for dates at or before snapshot; 2026 history freezes at December 2025. Counts and recent-year counts. |
| IBM identity embeddings | Fixed template containing only the assigning organization | Eligible candidate; 384 dimensions reduced to 24 by PCA fitted on training rows only. |
| Description keywords and Granite embeddings | Sanitized current `description` | Experimental only. Explicit incident claims, URLs, dates and CVE IDs are removed, but that does not prove historical availability. |
| Description vendor/product history | Catalog names already known at snapshot, matched to current description | Experimental only; excluded from the strict production matrix. |
| First monthly EPSS | Earliest observed value no later than snapshot | Historical audit only; equivalent history is absent from the 2026 scoreboard. |
| Vendor-supplied CVSS/vector | `cvss3_source`, `cvss3_score`, `cvss3_vector` | Audit only; provenance is safer than NIST but lacks a timestamp and masking can reveal coverage. |
| NIST/CISA CVSS, CWE, missing scores | Current severity/vector fields and `cwe_ids` | Excluded; no historical enrichment timestamps. Current CVSS remains a clearly labeled benchmark reference. |
| Status, counts, CPEs, references | `nvd_status`, `n_affected_cpes`, `n_references`, `affected_products.csv`, `references.csv` | Excluded; the audit measures each one's effect on 2025 without promoting it to production. |
| Ransomware | `known_ransomware_use` | Excluded; KEV inclusion date does not date subsequent ransomware annotation. |
| Record updates, target KEV, external feeds | `last_modified`, target `in_kev`, any external outcome/score | Excluded. Target membership is only for cohort eligibility and labels. |

The model card contains the exact selected feature names and signed audit deltas for logistic regression and LightGBM. A suspect feature failing to improve a backtest does not prove it safe. Current description/CVSS/CWE fields in the output CSV serve the display contract only and do not enter the strict model.

## Selection, probabilities and reasons

The candidate family is intentionally small: regularized logistic regression, small LightGBM trees, feature-block ablations, and a 25% log-odds blend with a training-calibrated exploit-first rule. The selection rule averages recall at literal and equal-workload budgets across two forward 2025 evaluations. A one-primary-hit indifference band favors simpler models. These are development comparisons, including overlapping test periods, not an untouched test of the selected recipe. A paired month bootstrap reports variability without claiming to include model-selection uncertainty.

Models optimize unweighted binary log-loss. `score` is the estimated probability of later catalog inclusion under historical, variable follow-up. It is neither EPSS nor a calibrated 30-day attack probability. Brier scores and mean predictions are included in the backtest; scarcity, censoring and temporal drift limit calibration.

Reasons are signed logistic terms or LightGBM `pred_contrib` values in log-odds units. The five largest absolute grouped contributions are shown; embedding dimensions combine into one organization-identity term. Extra CSV columns preserve the base log odds and omitted contribution sum, so the probability can be reconstructed. Reasons describe model associations, not causal explanations.

Before each local milestone commit, regenerate the touched artifacts, run the temporal and contract checks, and verify no input data/cache is staged. Commit subjects start with lowercase `model:`. No push is part of this workflow.
