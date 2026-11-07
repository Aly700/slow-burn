# Fix-first triage

A local IBM Granite investigation loop turns the supplied ranking into a briefing whose factual claims resolve to exact MCP tool results. It pauses at an immutable proposed action. A human decision through the local API is required before the only write tool can append a local ticket.

## Run

From the repository root, with `data/` linked to the provided read-only dataset:

```sh
uv sync --project agent
uv run --project agent python -m agent.prepare --embeddings
uv run --project agent python -m agent.api
```

The API binds to `127.0.0.1:8765`, with one inference worker and a bounded queue. The first model load downloads weights if absent; prepare the machine before a demo. Subsequent runs reuse one in-memory model per process. Do not use multiple Uvicorn workers: they duplicate model memory and workflow ownership.

```sh
uv run --project agent python -m agent.record --top 15
uv run --project agent python -m agent.evaluate
uv run --project agent pytest -q
```

Recording rebuilds the content-addressed embedding cache when the model lane changes the candidate set or source descriptions. It writes the exact artifact contract to `artifacts/agent_runs/`. Evaluation writes `artifacts/agent_eval.json` plus auditable per-case runs under `artifacts/agent_runs/eval2025/`. Historical labels are read only by the scorer, after inference finishes.

## API

- `POST /runs` with `{"cve_id":"CVE-2026-8037"}` returns HTTP 202 and the durable run, initially `RECEIVED`.
- `GET /runs/{run_id}` returns the run, briefing hash, verifier result, injection flags and policy state.
- `POST /runs/{run_id}/approval` with `{"approve":true}` issues an internal capability for the exact immutable briefing and calls the MCP write tool. `false` moves to `REJECTED`. An optional `briefing_hash` rejects a decision based on a different displayed proposal.
- `GET /runs/{run_id}/trace` returns trace events and the full tool-result ledger needed to independently resolve every citation.
- `GET /health` reports model readiness and queue depth.

An approval token is never returned to the browser, stored in a trace, or passed to Granite. Supported browser origins are localhost ports 3000, 3001 and 8765. This is a trusted local-operator demo boundary, with no identity provider; do not expose it publicly without authentication and user-scoped authorization.

## Tools

Run `uv run --project agent python -m agent.server` for the official Python MCP SDK's stdio transport. Discovery exposes six read tools and one write tool, with MCP permission annotations:

| Tool | Permission | Scope |
| --- | --- | --- |
| `get_cve(cve_id)` | Read | Supplied description, published date, assigner, CVSS parts, CWE names, month-end signals; establishes session snapshot |
| `explain_score(cve_id)` | Read | Rank, raw score, JSON reasons and score-file digest; seed contract warnings |
| `vendor_history(vendor)` | Read | Exact normalized vendor name, earlier KEV count/date, known ransomware count where its vintage permits, top CWEs |
| `similar_exploited(cve_id,k)` | Read | IBM Granite cosine neighbors whose KEV admission is before the snapshot; excludes the candidate itself |
| `signal_timeline(cve_id)` | Read | Available monthly signals through the snapshot, with missing months and EPSS-version warning |
| `queue(n,filters)` | Read | Up to 100 candidates; snapshot, exploit flag and minimum EPSS filters |
| `file_fix_ticket(cve_id,briefing_hash,approval_token)` | Guarded write | Local `artifacts/tickets.jsonl`, never an external tracker |

A stdio connection is an investigation session; call `get_cve` before `vendor_history`. The application serializes investigations to preserve this snapshot context. Models cannot change file paths, run shell commands, access HTTP APIs or issue their own approval capabilities.

## Evidence, durability and limits

Granite selects read tools, then selects evidence cards and a verdict through strict JSON schemas. One repair is allowed per stage; the entire run has at most four model calls, ten tool calls and a 55-second deadline. A failed model or empty verified evidence produces `FAILED`, never an automatic template success. Native inference checks the deadline between generated tokens; the API also bounds its wait.

Factual sentences are rendered from exact tool fields. The verifier checks tool name, field path, JSON value/type and optional call ID against this run's result ledger. Unknown or repeated fact IDs are dropped and counted. This proves data fidelity, not that source data is correct, and avoids claiming that a free-text citation checker proves semantic entailment. Headlines contain a recommendation and CVE ID; actions are bounded operational recommendations rather than invented patch versions. Confidence is triage judgment, not a calibrated exploitation probability.

SQLite uses transactional state changes, a hashed 256-bit approval capability with a 15-minute expiry, and a unique `cve_id:briefing_hash` ticket key. A durable outbox and file lock make retries safe even across an interrupted append. Recovery marks interrupted investigations `FAILED`, preserves pending approvals, and finishes approved delivery intents. Rejection is terminal. The model never receives the token issuance operation.

The runtime database, CSV cache and embedding vectors live under gitignored `artifacts/cache/`. Tickets are local demo outputs and should not be committed as production incident records. A separate test/evaluation ledger stays under the cache. No runtime tool fetches external vulnerability information.

## Data limitations

Only provided month-end signals and dated KEV admissions are treated as historical observations. NVD description/CVSS/CWE/product fields are labeled as the provided November 6, 2026 extract. NVD status, reference counts, CPE counts and reference URLs are excluded from tool responses. A missing score is not used as a prioritization feature. No 2026 KEV, live EPSS, exploitation news or external feeds are fetched.

The supplied ransomware flag has no historical change date. For snapshots before December 31, 2025, the tool returns its count as unknown. Vendor aliases and acquisitions are not resolved: zero exact matches does not imply no exploitation history. Semantic similarity is an analogy, not proof of exploitation. The compact embedding index truncates descriptions at 256 tokens.

The seed ranking contains scores above one and incomplete reason records. They remain visible with warnings and are never silently clamped into probabilities. Re-record after the model lane supplies its final scores.

## Models and documentation

Inference uses [IBM Granite 4.0 H Small](https://huggingface.co/ibm-granite/granite-4.0-h-small), a 32B instruct model released October 2, 2025, via the [4-bit MLX conversion](https://huggingface.co/mlx-community/granite-4.0-h-small-4bit). Retrieval uses [IBM Granite Embedding 30M English](https://huggingface.co/ibm-granite/granite-embedding-30m-english). Both carry Apache 2.0 licenses; weights stay in the local model cache. The official [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk/tree/v1.x) supplies the tool protocol. Dependency versions are pinned in this project's `uv.lock`.

Pinned weight revisions: instruct `db4baaa911c39582ab9fdcfc9f43a6bbc343d54a`; embeddings `9b5b096411652ec1189c68fcfb90d0a82c5b45af`. Each run records the instruct revision and retrieval results record the embedding revision.
