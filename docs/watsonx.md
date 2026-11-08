# Public Granite runtime

The default remains offline MLX. Set `SLOWBURN_MODEL_BACKEND=watsonx` to use
`ibm/granite-4-h-small` through the IBM us-south chat REST API. Supply
`WATSONX_APIKEY`, `WATSONX_PROJECT_ID`, and `WATSONX_URL` at runtime. No SDK is
required. IAM tokens are held in memory and refreshed before expiry.

Both backends use the same messages, JSON tool plans, evidence selections,
priority policy, and verifier. MLX renders its chat template locally; watsonx
renders the messages on the server. Native function-call responses are rejected.
The model never receives IBM credentials or an approval capability.

## Public mode

`SLOWBURN_PUBLIC=1` disables ticket approval and filing at the HTTP, tool, and
store boundaries. The page displays hosted proposals as previews. Requests are
limited to six inference attempts per IP per 60 seconds by default, 16 KiB of
body/query data, and 1,000 question characters. Only `https://aly700.github.io`
and HTTP localhost origins are accepted. HTTP access logs are disabled.

`SLOWBURN_DAILY_TOKENS` defaults to 100,000, counting input and output together.
Each inference first reserves a conservative UTF-8 byte bound plus chat framing
and its output allowance. Reported usage releases the unused reservation;
unknown usage, cancellation, timeouts, and crashes retain the reservation.
Insufficient headroom closes inference for that UTC day. Health and SSE responses
announce the recorded fallback. This may stop earlier than the billed-token cap.

`SLOWBURN_BUDGET_PATH` selects a SQLite ledger. Mount it persistently for local
containers. For Code Engine, set `SLOWBURN_BUDGET_COS_URL` to
`https://s3.us-south.cloud-object-storage.appdomain.cloud/BUCKET/PREFIX`.
The shared ledger uses conditional object writes (`If-Match` / `If-None-Match`)
and fails closed if storage is unavailable. Its IAM identity needs object read
and write access on that dedicated bucket. A public Code Engine process refuses
an ephemeral-only budget. Never put SQLite on a COS filesystem mount.

Forwarded IP headers are ignored by default. Configure `SLOWBURN_TRUSTED_PROXIES`
only with verified ingress proxy CIDRs. Addresses are walked from the trusted
right edge; arbitrary client-supplied forwarding headers cannot bypass limits.
Until the hosted ingress chain is verified, the shared proxy address receives
one conservative rate limit. No credential or request body is logged.

## Local container

Prepare the bundle using the supplied data and pinned local embedding weights:

```sh
uv run --project agent python -m agent.bundle --output .lane/container-assets
docker build -t slowburn-watsonx:local .
```

The bundle contains the corpus DuckDB, ranking export, the existing Granite
index, and precomputed queries for every scoreboard CVE. It does not contain
raw CSVs, model weights, state databases, tickets, or credentials. Dependencies
are pinned in `agent/requirements-runtime.txt`; there is no MLX, PyTorch, or
sentence-transformers in the image. The local preparation step uses the existing
embedding dependencies only.

Load credentials in the shell without printing them, then pass variable names:

```sh
set -a
source ~/.watsonx_env
set +a
docker run --rm --name slowburn-local -p 127.0.0.1:8876:8080 \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
  -e WATSONX_APIKEY -e WATSONX_PROJECT_ID -e WATSONX_URL \
  -v slowburn-state:/state slowburn-watsonx:local
```

The process runs as UID 10001, listens on `$PORT` (8080 by default), and exposes
`/health` and `/live/health`. Stop only the container you started.
For Code Engine, build `--platform linux/amd64` and use the shared durable budget.

## Page configuration

Build with `VITE_SLOWBURN_API_URL=https://YOUR-API` to enable hosted inference for
visitors. Leave it empty to retain the existing local/recorded behavior. Local
viewers try MLX at `127.0.0.1:8765` first; hosted viewers use the configured URL.
A healthy watsonx service displays “Live · IBM Granite on watsonx.” Any failed
stream uses recorded answers; absent recordings are stated explicitly.

Hosted health is checked on mount and with Check connection, without idle
polling. This permits scale-to-zero. An 8-second hosted health timeout falls back
to recordings; a later connection check can pick up a completed cold start.
`VITE_SLOWBURN_LOCAL_API_URL` can isolate local browser tests on another port;
leave it unset for the normal MLX behavior. It is not a credential setting.

## Reproducible measurements

The existing benchmark scripts accept `SLOWBURN_EVAL_URL` and
`SLOWBURN_EVAL_OUTPUT` to target an isolated server and preserve the recorded
MLX artifacts. Run them with the container interpreter and runtime data mounted.
The held-out red-team evaluator also accepts `SLOWBURN_EVAL_REVISION` for images
without Git; supply the committed source revision and verify the image matches.
Its exclusive first-attempt receipt prevents accidentally overwriting a run.

Evaluations retain prompt/output token counts, rejected structured responses,
claim counts, source checks, and per-request timings. Red-team prose survival is
a lexical test, not a proof of semantic safety. Exact evidence verification
establishes source consistency, not source truth.
