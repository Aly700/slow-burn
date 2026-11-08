import asyncio
from contextlib import asynccontextmanager
import os

from fastapi import FastAPI, HTTPException, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from .live import LiveService
from .data import validate_cve
from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator

from .client import ToolClient
from .config import IBM_MODEL, Settings
from .model import Granite
from .runtime import Runner
from .store import Store
from .record import save_record

ORIGINS = ["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:3001", "http://127.0.0.1:3001", "http://localhost:8765", "http://127.0.0.1:8765"]
ORIGINS += ["https://aly700.github.io"]
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
    service = LiveService(settings,store,model)
    approval_lock = asyncio.Lock()

    @asynccontextmanager
    async def lifespan(app):
        store.recover()
        await service.start()
        app.state.client = service.client
        try:
            yield
        finally:
            await service.close()

    app = FastAPI(title="Fix-first triage", version="0.1.0", lifespan=lifespan)
    app.state.service = service
    app.add_middleware(CORSMiddleware, allow_origins=ORIGINS, allow_private_network=True, allow_methods=["GET", "POST"], allow_headers=["Content-Type"])

    @app.middleware("http")
    async def local_mutation_boundary(request: Request, call_next):
        if request.method == 'OPTIONS':
            response = await call_next(request)
            if response.status_code != 200 and 'Access-Control-Allow-Private-Network' in response.headers:
                del response.headers['Access-Control-Allow-Private-Network']
            return response
        if request.method == "POST" or request.url.path.startswith('/live/') or request.url.path == '/ask':
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
        return {"ready": service.loaded_at is not None and service.error is None, "model": model.name, "queue_depth": service.queue.qsize(), "ticket_destination": "local artifacts/tickets.jsonl"}

    @app.get('/live/health')
    async def live_health():
        return {'ready': service.loaded_at is not None and service.error is None,
                'model':getattr(model,'source_name',model.name), 'loaded_at':service.loaded_at}

    def submit(cve_id, streamed=True, fixture=None):
        try:
            validate_cve(cve_id)
            return service.submit(cve_id,streamed=streamed,fixture=fixture)
        except ValueError as exc:
            raise HTTPException(422,str(exc)) from None
        except asyncio.QueueFull:
            raise HTTPException(429,'investigation queue is full') from None
        except RuntimeError as exc:
            raise HTTPException(503,str(exc)) from None

    @app.get('/live/{cve_id}')
    async def investigate(cve_id: str, fixture: str | None = None):
        if fixture not in {None,'injection-direct','injection-subtle'}:
            raise HTTPException(422,'unknown injection fixture')
        job=submit(cve_id,fixture=fixture)
        return StreamingResponse(job.stream(),media_type='text/event-stream',headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no'})

    @app.post("/runs", status_code=202)
    async def start_run(body: StartRun):
        job=submit(body.cve_id,streamed=False)
        return store.get(job.run_id)

    @app.get('/ask')
    async def ask(q: str = Query(min_length=1,max_length=1000)):
        if not q.strip(): raise HTTPException(422,'question is empty')
        try:
            job=service.submit(question=q.strip())
        except asyncio.QueueFull:
            raise HTTPException(429,'investigation queue is full') from None
        except RuntimeError as exc:
            raise HTTPException(503,str(exc)) from None
        return StreamingResponse(job.stream(),media_type='text/event-stream',headers={'Cache-Control':'no-cache','X-Accel-Buffering':'no'})

    @app.get("/runs/{run_id}")
    async def read_run(run_id: str):
        return get_run(run_id)

    @app.get("/runs/{run_id}/trace")
    async def trace(run_id: str):
        run = get_run(run_id)
        return {"run_id": run_id, "trace": run["trace"], "tool_results": run["tool_results"]}

    def approval_result(run):
        if run.get('list')=='live':
            try:
                save_record(settings.cache/'live_runs'/f"{run['run_id']}.json",run)
            except OSError:
                return {**run,'cache_warning':'Live cache refresh unavailable; SQLite remains authoritative.'}
        return run

    async def apply_decision(run_id: str, body: Approval):
        run = get_run(run_id)
        if body.briefing_hash and body.briefing_hash != run.get("briefing_hash"):
            raise HTTPException(409, "approval does not match the displayed briefing hash")
        if run["state"] == "TICKET_FILED" and body.approve:
            return approval_result(run)
        if run["state"] == "REJECTED" and not body.approve:
            return approval_result(run)
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
        return approval_result(get_run(run_id))

    @app.post("/runs/{run_id}/approval")
    async def approval(run_id: str, body: Approval):
        async with approval_lock:
            return await apply_decision(run_id, body)

    return app


app = create_app()


def main():
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8765, workers=1)


if __name__ == "__main__":
    main()
