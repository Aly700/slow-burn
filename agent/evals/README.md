# Historical triage evaluation

The fixed set has 30 CVEs published in 2025, observed outside KEV at September month-end: 15 subsequently admitted by December 31 and 15 not present in the supplied catalog by that date. These controls are right-censored, not proven unexploited. Selection uses a fixed hash order within each outcome group. Cases are held out from prompt development; this does not claim exclusion from pretrained weights.

`heldout_2025.json` contains outcomes and is read only by the scorer. `heldout_scores_2025.csv` contains snapshot features, no outcomes, and reasons available to both methods. The CSV retains schema-compatible EPSS and case-order placeholders, but the evaluation marker makes the MCP response return rank and score as unavailable. No historical model ranking is supplied. Zero contribution values mean no attribution model was fitted for this reliability evaluation.

The deterministic baseline reads only the reasons column: `fix_now` if EPSS >= 0.1 or any exploit flag is 1; `watch` if EPSS >= 0.01; otherwise `defer`. It renders exact feature/value facts and uses the same action templates and approval boundary as Granite. Thresholds are fixed before inference.

Run `uv run --project agent python -m agent.evaluate`. Metrics report pre-verifier fidelity, delivered fidelity, successful-run rate, unauthorized writes, independent write probes, injection detection, median/p95 latency, evidence categories and an exploratory confusion matrix (`fix_now` versus the observed KEV outcome). The balanced sample is unsuitable for estimating real-world precision or deployment base rates. The baseline has an inherent latency advantage. Canonical evidence rendering makes fidelity a system property rather than a free-text model score.

The two attack fixtures replace a tool-returned description, preserving all real snapshot signals. The detector flags instruction spans before the model reads the content. Every run independently attempts the write with no approval capability. This tests server enforcement even when the model never requests a write. Fixture results distinguish these probes from model-requested writes.

The first evaluation accidentally exposed the arbitrary case order as a rank. `initial_metrics.json` preserves that result. The final evaluation fixes this fixture provenance issue with the same frozen cases, prompts and thresholds; no outcome-driven prompt tuning was performed.
