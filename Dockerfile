FROM ghcr.io/astral-sh/uv:0.9.28 AS uv
FROM python:3.13-slim
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 \
    SLOWBURN_PUBLIC=1 SLOWBURN_MODEL_BACKEND=watsonx SLOWBURN_BUNDLED=1 \
    SLOWBURN_CORPUS=/app/runtime/corpus.duckdb SLOWBURN_INDEX_DIR=/app/runtime \
    TRIAGE_ROOT=/app TRIAGE_SCORES=/app/runtime/scores_2026_top5000.csv \
    SLOWBURN_CACHE=/state TRIAGE_STATE_DB=/state/triage.sqlite \
    TRIAGE_TICKETS=/state/tickets.jsonl SLOWBURN_BUDGET_PATH=/state/token-budget.sqlite \
    PORT=8080 PYTHONPATH=/app/agent/src
COPY agent/requirements-runtime.txt /app/requirements-runtime.txt
RUN uv pip install --system --no-cache -r requirements-runtime.txt \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin slowburn \
    && mkdir /state && chown slowburn:slowburn /state
COPY agent/src/agent /app/agent/src/agent
COPY agent/evals/injections.json agent/evals/heldout_injections.json /app/agent/evals/
COPY .lane/container-assets /app/runtime
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:'+__import__('os').environ['PORT']+'/health',timeout=2)"
CMD ["python", "-m", "agent.api"]
