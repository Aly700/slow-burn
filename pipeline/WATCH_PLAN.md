# Blind-spot watch-list registration

This plan and the four recipes in `watch_registry.py` are committed before dedicated watch scores are computed for 2025. The selected submission and its artifacts are frozen by SHA-256. The watch list is a separate review queue, not an alternative submission.

Select a recipe using only 2024 no-signal rows: January–March training with outcomes observable by June 30, followed by July–September validation with outcomes through December 31. This gives 8,433 training rows with 3 positives and 8,305 validation rows with 8 positives. The tiny training event count is a serious limitation; it is not a reason to select on 2025 instead. No 2023 publication snapshot can be reconstructed from the supplied files.

Compare regularized logistic regression and small LightGBM trees, each with and without Granite description embeddings. Use the existing safe feature block, removing constant tool flags. Do not promote current CWE, CVSS/vector parts or missingness into features. Those fields can appear in a clearly marked descriptive profile only. Granite weights were available by the start of the 2025 test; internal 2024 validation is retrospective development with that frozen encoder.

Selection maximizes the sum of validation hits at 100, 250 and 500, then average precision, then simplicity. Freeze that winner before scoring either 2025 split. Fit the primary test on mature 2024 rows, and the secondary on mature rows observed by June 2025. Do not inspect other recipes' 2025 watch results. If LightGBM wins, report five seeds without selecting the best seed. Production always uses seed 2026.

Report EPSS and current-CVSS reference rankings, random expectation, lift, paired month bootstrap, and pool/missing-observation counts. Profile all requested families, with explicit timestamp and matching risks. Vendor-history and product-class contrasts are descriptive and cannot change the chosen recipe. Mixed allocations are report-only at a fixed 500-review budget. A clean negative result is published without trying another model.

Rejected alternative: choosing whichever existing full-pool model happens to rank the 2025 no-signal positives best. That would select using the test outcomes and would not answer whether specialization generalizes.
