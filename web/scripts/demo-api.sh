#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
export UV_PROJECT_ENVIRONMENT="$PWD/.runtime/venv"
export TRIAGE_STATE_DB="$PWD/.runtime/demo/triage.sqlite"
export TRIAGE_TICKETS="$PWD/.runtime/demo/tickets.jsonl"
uv run --frozen --project ../agent python scripts/prepare-demo-api.py
exec uv run --frozen --project ../agent python -m agent.api
