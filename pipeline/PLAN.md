# Modeling implementation plan

Goal: reproducible, date-safe ranking and research artifacts in the existing model worktree.

1. `checks.py`: temporal boundary tests, future-history invariance, feature allowlists and artifact contract checks.
2. `data.py`: read-only CSV ingestion, immutable cached snapshots, cutoff-specific labels and 90-day maturity, exact scoreboard month handling.
3. `features.py`: strict signals/assigner history and separately gated exploratory text, score and CWE blocks; no CPE inputs in production.
4. `embed.py`: pinned IBM Granite weights, MPS batches, content-hashed local cache, separate identity and sanitized-description representations.
5. `evaluate.py`: baselines, logistic regression, small LightGBM, forward splits, workload scaling, ablations, censoring sensitivity and uncertainty.
6. `leak_audit.py`: historical suspect-column additions and coverage/lift measurements; results embedded in the model card.
7. `run.py`: fit the chosen recipe on mature 2024+2025 cohorts, produce contract CSV/JSON files and validate them.
8. `findings.py` and `report.py`: regenerate counts, lags, signal lifts, selected-list summaries and the final local lane report.

Each milestone runs its artifact-producing command with `uv run python -I`, then temporal/contract checks, then a local lowercase `model:` commit. The first complete artifact milestone is due by 19:30 EST; reporting ends by 22:30 EST. Cache files stay ignored. No writes to `data/`, no changes to other lanes, no push.
