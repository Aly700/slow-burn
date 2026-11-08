# Product watch and semantic map implementation plan

The submitted ranking and model remain frozen. This round adds descriptive capabilities, not candidate rankings. All input records come from the supplied files; external access is limited to package metadata and technical documentation.

## Product watch

- [ ] Reuse the profile's exact no-signal pool and product identity. Reconstruct distinct prior KEV IDs for its chosen alias, capped at both snapshot end and 2025-12-31. Assert that the count equals the profile's feature count.
- [ ] Export the specified twelve columns, ordered by descending prior count, descending EPSS (missing last), then ascending CVE ID. Confidence is categorical evidence strength, not a fabricated probability: `psirt_supported`, `vendor_text_supported`, or `product_alias_only`.
- [ ] Report the complete queue's 2025 size and coverage of the 31 no-signal positives, plus the 2026 size and match-source breakdown. Preserve all earlier findings and the edited README.
- [ ] Test temporal cutoffs, count reconciliation, and ordering; regenerate, check, document the contract, and commit this part.

## Semantic map and predeclared check

Interpret years as publication years. The map contains every 2026 scoreboard row and every CVE published in 2024 or 2025 and listed by 2025-12-31, including first-month additions excluded from ranking backtests. Reuse cached sanitized Granite vectors and encode only missing anchor texts, with the same pinned model revision and 256-token limit.

Use UMAP with cosine distance, 30 neighbours, minimum distance 0.1, spread 1, 500 epochs, spectral initialization, seed 2026 and one worker. Cluster the resulting layout with HDBSCAN (minimum cluster size 150, minimum samples 15); retain noise as unassigned. Name regions from mean TF-IDF terms in sanitized descriptions, without outcomes or explicit exploitation claims. These are visual regions, not verified vulnerability taxonomies. UMAP is preferred to openTSNE for its direct cosine-neighbour formulation and tractable full-cohort fit; neither layout's gaps or density establish risk.

Before measuring the outcome association, freeze this check: use the original normalized 384-dimensional vectors, never map coordinates. Each eligible 2025 row is compared with its closest 2024-published CVE listed by 2024-12-31. Report the probability that a later-listed row is closer than a non-listed row (AUROC, half credit for ties), group distance summaries, and 10,000 fixed-seed label permutations within snapshot months. Repeat the same check in the no-signal pool as a declared sensitivity. Labels stop at 2025-12-31; late-year censoring, non-independent product families, current text revisions, and the previously inspected 2025 cohort limit interpretation. No parameters or ranking change after this check.

Add one map story only if primary AUROC exceeds 0.5 with one-sided permutation p <= 0.01, and the no-signal sensitivity also exceeds 0.5 with p <= 0.05. Otherwise publish the measured result without a new story. This is an association check, not evidence that nearest-neighbour ranking improves top-500 performance.

- [ ] Test typed-array encoding, flag counts, sparse ID membership, and temporal anchor selection before implementation.
- [ ] Pin UMAP and its numerical dependencies without changing existing locked model packages. Cache layout by input vectors, parameters, code and versions.
- [ ] Export interleaved uint16 coordinates, uint8 bit flags, int16 cluster IDs, sparse indexed CVE IDs, and region centroids/terms/counts. JSON must be less than 3,000,000 bytes.
- [ ] Decode and visually inspect the full map locally; test exact membership and counts against source data. Keep any preview under the ignored cache directory.
- [ ] Add contracts, findings, reproduction commands, and dependency-ordered full rebuild while keeping replay last. Run all existing and new checks, confirm protected hashes, commit, and generate `.lane/model-REPORT-4.md`.
