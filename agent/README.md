# Fix-first triage

A local IBM Granite investigation loop turns the supplied ranking into a briefing whose factual claims resolve to exact MCP tool results. It pauses at an immutable proposed action. A human decision through the local API is required before the only write tool can append a local ticket.

## Run

From the repository root, with `data/` linked to the provided read-only dataset:

```sh
uv sync --project agent
uv run --project agent python -m agent.prepare --embeddings
uv run --project agent python -m agent.api
```

The API binds to `127.0.0.1:8765`, with one inference worker and a bounded queue. Runtime loads cached weights only; download the pinned weights before going offline. Subsequent runs reuse one in-memory model per process. Do not use multiple Uvicorn workers: they duplicate model memory and workflow ownership.

```sh
uv run --project agent python -m agent.record --top 15
uv run --project agent python -m agent.record --from artifacts/watch_2026_top100.csv --top 100
uv run --project agent python -m agent.evaluate
uv run --project agent pytest -q
```

Recording rebuilds the content-addressed embedding cache when the ranking pipeline changes the candidate set or source descriptions. It writes the exact artifact contract to `artifacts/agent_runs/`. Evaluation writes `artifacts/agent_eval.json` plus auditable per-case runs under `artifacts/agent_runs/eval2025/`. Historical labels are read only by the scorer, after inference finishes.

`--from` accepts any ranking CSV with the standard score-file columns. The default `scores_2026_top5000.csv` is always tagged `"list":"top500"`. An alternate file is tagged `"list":"watch"` only when every row explicitly has zero for `any_exploit`, Exploit-DB, Metasploit, Nuclei and GitHub PoC; other files remain `top500`. Missing signals are not zero. The label is immutable and persisted with each run. Files remain named by CVE, so recording the same CVE again replaces its offline briefing.

## API

Live investigation uses `GET /live/health` and `GET /live/{cve_id}` (Server-Sent Events). The first event identifies a fresh run; tool calls/results, verified or dropped claims, states and the final briefing follow as the loop executes. Every candidate in the 72,670-row supplied scoreboard is addressable, including those outside the published ranking. Missing rank/score stays unknown; new Granite query vectors are generated locally and cached by description hash.

One queue serves both live requests and `POST /runs`. Queued streams identify their wait in a `RECEIVED` event. Disconnects cancel queued/active work; cancellation drains the current native generation before another starts. Live run snapshots go only to `artifacts/cache/live_runs/`. SQLite remains authoritative if refreshing that cache fails after approval. Offline replay envelopes with actual timings are in `artifacts/agent_runs/live-examples/`.

Runtime model loading is local-only and disables remote model metadata checks. Prepare model weights before going offline. A process lock prevents loading a second instruct copy. The service permits the local Vite origins and `https://aly700.github.io`, including Private Network Access preflight; browser-specific local-network permission prompts may still require an operator decision.

For the reproducible offline check, start the API with non-loopback sockets denied:

```sh
TRIAGE_OFFLINE_AUDIT=1 PYTHONPATH="$PWD/agent/evals/offline_check" uv run --project agent python -m agent.api
uv run --project agent python agent/evals/live_benchmark.py --approve-demo-ticket
```

The benchmark uses the already running service, never another instruct model. Its explicit demo flag approves one local ticket and checks wrong-hash rejection and idempotent retry. Results are in `agent/evals/live_metrics.json`. The stream contract, including fixture-mode examples, is in `research/CONTRACTS.md`.

- `POST /runs` with `{"cve_id":"CVE-2026-8037"}` returns HTTP 202 and the durable run, initially `RECEIVED`.
- `GET /runs/{run_id}` returns the run, briefing hash, verifier result, injection flags and policy state.
- `POST /runs/{run_id}/approval` with `{"approve":true}` or the web page's `{"approved":true}` issues an internal capability for the exact immutable briefing and calls the MCP write tool. `false` moves to `REJECTED`. An optional `briefing_hash` rejects a decision based on a different displayed proposal.
- `GET /runs/{run_id}/trace` returns trace events and the full tool-result ledger needed to independently resolve every citation.
- `GET /health` reports model readiness and queue depth.

An approval token is never returned to the browser, stored in a trace, or passed to Granite. Supported browser origins are localhost and 127.0.0.1 on ports 3000, 3001, 4317, 5173 and 8765. Concurrent repeat approvals return the same ticket. This is a trusted local-operator demo boundary, with no identity provider; do not expose it publicly without authentication and user-scoped authorization.

## Tools

Run `uv run --project agent python -m agent.server` for the official Python MCP SDK's stdio transport. Discovery exposes nine read tools and one write tool, with MCP permission annotations:

| Tool | Permission | Scope |
| --- | --- | --- |
| `get_cve(cve_id)` | Read | Supplied description, published date, assigner, CVSS parts, CWE names, month-end signals; establishes session snapshot |
| `explain_score(cve_id)` | Read | Rank, raw score, JSON reasons and score-file digest; seed contract warnings |
| `vendor_history(vendor)` | Read | Exact normalized vendor name, earlier KEV count/date, known ransomware count where its vintage permits, top CWEs |
| `similar_exploited(cve_id,k)` | Read | IBM Granite cosine neighbors whose KEV admission is before the snapshot; excludes the candidate itself |
| `signal_timeline(cve_id)` | Read | Available monthly signals through the snapshot, with missing months and EPSS-version warning |
| `queue(n,filters)` | Read | Up to 100 candidates; snapshot, exploit flag and minimum EPSS filters |
| `search_ranked(filters,limit)` | Read | Up to ten matches in the supplied ranking, by vendor/product/CWE/text, public signals and earlier vendor history |
| `compare_cves(cve_a,cve_b)` | Read | Both ranks, scores and unmodified model reasons; absent scores remain unknown |
| `summarize_ranked(filters)` | Read | Counts for a filtered slice, including separate unknown vendor/signal counts |
| `file_fix_ticket(cve_id,briefing_hash,approval_token)` | Guarded write | Local `artifacts/tickets.jsonl`, never an external tracker |

A stdio connection is an investigation session; call `get_cve` before `vendor_history`. The application serializes investigations to preserve this snapshot context. Models cannot change file paths, run shell commands, access HTTP APIs or issue their own approval capabilities.

## Ask the analyst

`GET /ask?q=...` streams a read-only answer over the supplied ranking. It shares the live worker, queue and cancellation behavior. Granite chooses search, comparison or summary parameters and selects source-bound sentences; every delivered number and CVE comes from its actual tool results. Explicit scope phrases are checked before execution, with one repair attempt for a contradictory plan. Question interpretation is still fallible, so the answer states the interpreted slice.

Question streams add `answer: {text, claims}` and finish VERIFIED, with no proposal or approval capability. Unsupported sentences appear as dropped claims. The ledger is available through `/runs/{id}` and cached in `artifacts/cache/ask_runs/`. Successful answers survive process recovery. Questions cannot create tickets.

Run `uv run --project agent python agent/evals/analyst_benchmark.py` against the running API to evaluate the fifteen fixed questions in `agent/evals/analyst_questions.json`. Expected facts are written before inference; the grader checks both requested scope and source facts, allowing equivalent search/summary count fields. Results include full/partial/no-answer grades in `agent/evals/analyst_eval.json`. This is a development question set, not unseen validation after prompt revisions.

## Evidence, durability and limits

Granite selects read tools, then selects evidence cards and source-backed headline/action choices through strict JSON schemas. Verdict and urgency come only from `src/agent/priority.py`. A retrieved history or analogy card is required when available; this is an enforced briefing requirement, not evidence of unrestricted reasoning. One repair is allowed per stage; the entire run has at most four model calls, ten tool calls and a 55-second deadline. A failed model or empty verified evidence produces `FAILED`, never an automatic template success. Native inference checks the deadline between generated tokens; the API also bounds its wait.

Factual sentences are rendered from exact tool fields. The verifier checks tool name, field path, JSON value/type and optional call ID against this run's result ledger. Unknown or repeated fact IDs are dropped and counted. This proves data fidelity, not that source data is correct, and avoids claiming that a free-text citation checker proves semantic entailment. Description-derived product, capability, prerequisites and fixes carry exact source excerpts. Headlines and actions have their own verified evidence references. Explicitly named fixes may be quoted; negated, future or unrelated fixes are rejected, and version boundaries alone never imply a fixed release. Otherwise actions name the affected service or endpoint and a concrete exposure-control step. Actual deployment exposure remains unknown. Confidence describes briefing evidence, not a calibrated exploitation probability.

SQLite uses transactional state changes, a hashed 256-bit approval capability with a 15-minute expiry, and a unique `cve_id:briefing_hash` ticket key. A durable outbox and file lock make retries safe even across an interrupted append. Recovery marks interrupted investigations `FAILED`, preserves pending approvals, and finishes approved delivery intents. Rejection is terminal. The model never receives the token issuance operation.

The runtime database, CSV cache and embedding vectors live under gitignored `artifacts/cache/`. Tickets are local demo outputs and should not be committed as production incident records. A separate test/evaluation ledger stays under the cache. No runtime tool fetches external vulnerability information.

## Deterministic priority

Thresholds and urgency labels live in one place, `src/agent/priority.py`; each briefing records the policy version, inputs, triggers and thresholds.

| Verdict | Any qualifying signal | Urgency / review window |
| --- | --- | --- |
| `fix_now` | Rank ≤ 500; valid probability score ≥ 0.10; EPSS ≥ 0.10; any recorded public exploit/scanner signal | Urgent / emergency change process |
| `watch` | Rank ≤ 2,000; valid probability score ≥ 0.01; EPSS ≥ 0.01 | Scheduled / next maintenance window |
| `defer` | Neither tier qualifies | Routine / normal patch cycle |

The first matching tier wins. Scores outside [0,1] and unavailable historical ranks are ignored. Nuclei is a scanner-template signal, not proof of exploitation. Live priority reads actual snapshot signals, so new feature names in the reasons column do not break recording or alter the policy unexpectedly.

Watch-list policy uses only the `watch`/`defer` tiers and ignores the list's local rank. A valid score or EPSS of at least 0.01 gives `watch`; otherwise it gives `defer`. Runtime tool signals must independently confirm all four public flags are zero, or the investigation fails. Watch actions check inventory/exposure and plan remediation for the next maintenance window; defer uses the normal patch cycle. Main-ranking decisions and archived evaluation metrics are unchanged.

Vendor display names prefer the spelling found in the CVE description, then a small explicit casing map, then title case. Their evidence retains the raw vendor tool value. When a product cannot be extracted, headlines use a returned vendor name, a short exact description phrase, or finally the CVE ID, in that order. These fallbacks also carry resolvable source references.

The evaluation has three arms. Existing `baseline` and `agent` keys remain; `agent` preserves the old Granite-decides result. Added `granite_decides`, `policy_granite`, `active_arm` and `arms` expose the comparison. Original Granite-decides recordings are preserved under `eval2025/granite/`; new runs use `eval2025/policy_granite/`. Reusing the same frozen cases after the first results were known makes this a revision comparison, not a fresh unseen validation set.

## Data limitations

Only provided month-end signals and dated KEV admissions are treated as historical observations. NVD description/CVSS/CWE/product fields are labeled as the provided November 6, 2026 extract. NVD status, reference counts, CPE counts and reference URLs are excluded from tool responses. A missing score is not used as a prioritization feature. No 2026 KEV, live EPSS, exploitation news or external feeds are fetched.

The supplied ransomware flag has no historical change date. For snapshots before December 31, 2025, the tool returns its count as unknown. Vendor aliases and acquisitions are not resolved: zero exact matches does not imply no exploitation history. Semantic similarity is an analogy, not proof of exploitation. The compact embedding index truncates descriptions at 256 tokens.

The seed ranking contains scores above one and incomplete reason records. They remain visible with warnings and are never silently clamped into probabilities. Re-record after the ranking pipeline supplies its final scores.

## Models and documentation

Inference uses [IBM Granite 4.0 H Small](https://huggingface.co/ibm-granite/granite-4.0-h-small), a 32B instruct model released October 2, 2025, via the [4-bit MLX conversion](https://huggingface.co/mlx-community/granite-4.0-h-small-4bit). Retrieval uses [IBM Granite Embedding 30M English](https://huggingface.co/ibm-granite/granite-embedding-30m-english). Both carry Apache 2.0 licenses; weights stay in the local model cache. The official [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk/tree/v1.x) supplies the tool protocol. Dependency versions are pinned in this project's `uv.lock`.

Pinned weight revisions: instruct `db4baaa911c39582ab9fdcfc9f43a6bbc343d54a`; embeddings `9b5b096411652ec1189c68fcfb90d0a82c5b45af`. Each run records the instruct revision and retrieval results record the embedding revision.
