import asyncio
from contextlib import asynccontextmanager
import os

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator

from .client import ToolClient
from .config import IBM_MODEL, Settings
from .model import Granite
from .runtime import Runner
from .store import Store

ORIGINS = ["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:3001", "http://127.0.0.1:3001", "http://localhost:8765", "http://127.0.0.1:8765"]
ORIGINS += [f"http://{host}:{port}" for host in ("localhost", "127.0.0.1") for port in (4317, 5173)]


class StartRun(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,10}$")


class Approval(BaseModel):
    model_config = ConfigDict(extra="forbid")
    approve: StrictBool
    briefing_hash: str | None = None

    @model_validator(mode="before")
    @classmethod
    def accept_web_alias(cls, value):
        if isinstance(value, dict) and "approved" in value:
            value = dict(value)
            if "approve" in value and value["approve"] != value["approved"]:
                raise ValueError("conflicting approval decisions")
            value["approve"] = value.pop("approved")
        return value


def create_app(settings=None, model=None):
    settings = settings or Settings()
    model = model or Granite(settings.model)
    store = Store(settings.state, settings.tickets)
    queue = asyncio.Queue(maxsize=16)
    approval_lock = asyncio.Lock()

    @asynccontextmanager
    async def lifespan(app):
        store.recover()
        ready = asyncio.get_running_loop().create_future()

        async def worker():
            try:
                await asyncio.to_thread(model.warmup)
                async with ToolClient(settings) as client:
                    app.state.client = client
                    runner = Runner(settings, store, model)
                    ready.set_result(True)
                    while True:
                        rid = await queue.get()
                        try:
                            if rid is None:
                                return
                            await runner.run(rid, client)
                        finally:
                            queue.task_done()
            except BaseException as exc:
                if not ready.done():
                    ready.set_exception(exc)
                else:
                    app.state.worker_error = type(exc).__name__
                raise

        task = asyncio.create_task(worker())
        app.state.worker_error = None
        await ready
        try:
            yield
        finally:
            await queue.put(None)
            await task

    app = FastAPI(title="Fix-first triage", version="0.1.0", lifespan=lifespan)
    app.add_middleware(CORSMiddleware, allow_origins=ORIGINS, allow_methods=["GET", "POST"], allow_headers=["Content-Type"])

    @app.middleware("http")
    async def local_mutation_boundary(request: Request, call_next):
        if request.method == "POST":
            origin = request.headers.get("origin")
            if origin and origin not in ORIGINS:
                from fastapi.responses import JSONResponse
                return JSONResponse({"detail": "untrusted approval origin"}, status_code=403)
        return await call_next(request)

    def get_run(run_id):
        try:
            return store.get(run_id)
        except KeyError:
            raise HTTPException(404, "run not found") from None

    @app.get("/health")
    async def health():
        return {"ready": app.state.worker_error is None, "model": model.name, "queue_depth": queue.qsize(), "ticket_destination": "local artifacts/tickets.jsonl"}

    @app.post("/runs", status_code=202)
    async def start_run(body: StartRun):
        if app.state.worker_error:
            raise HTTPException(503, "investigation worker unavailable")
        if queue.full():
            raise HTTPException(429, "investigation queue is full")
        source = getattr(model, "source_name", model.name)
        run = store.create(body.cve_id, source)
        queue.put_nowait(run["run_id"])
        return run

    @app.get("/runs/{run_id}")
    async def read_run(run_id: str):
        return get_run(run_id)

    @app.get("/runs/{run_id}/trace")
    async def trace(run_id: str):
        run = get_run(run_id)
        return {"run_id": run_id, "trace": run["trace"], "tool_results": run["tool_results"]}

    async def apply_decision(run_id: str, body: Approval):
        run = get_run(run_id)
        if body.briefing_hash and body.briefing_hash != run.get("briefing_hash"):
            raise HTTPException(409, "approval does not match the displayed briefing hash")
        if run["state"] == "TICKET_FILED" and body.approve:
            return run
        if run["state"] == "REJECTED" and not body.approve:
            return run
        try:
            token = store.approve(run_id, body.approve)
        except (ValueError, PermissionError) as exc:
            raise HTTPException(409, str(exc)) from None
        if body.approve:
            try:
                result = await app.state.client.call("file_fix_ticket", {"cve_id": run["cve_id"], "briefing_hash": run["briefing_hash"], "approval_token": token})
            except Exception:
                raise HTTPException(503, "ticket delivery interrupted; retry this approval to recover the durable action") from None
            if not result.get("allowed"):
                raise HTTPException(409, result.get("reason", "write denied"))
        return get_run(run_id)

    @app.post("/runs/{run_id}/approval")
    async def approval(run_id: str, body: Approval):
        async with approval_lock:
            return await apply_decision(run_id, body)

    return app


app = create_app()


def main():
    import uvicorn
    uvicorn.run("agent.api:app", host="127.0.0.1", port=8765, workers=1)


if __name__ == "__main__":
    main()
