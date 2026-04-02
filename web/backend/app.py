"""FastAPI application entry point for the Iterative Research web UI."""
from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from db.database import init_db, get_db, SessionLocal
from db.sync import sync_runs
from api.config import router as config_router
from api.runs import router as runs_router
from api.experiment import router as experiment_router
from api.vulnerabilities import router as vuln_router
from services.websocket import log_stream


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    db = SessionLocal()
    try:
        synced = sync_runs(db, str(_REPO_ROOT / "runs"))
        if synced:
            print(f"[startup] Synced {synced} existing run(s) from filesystem.")
    finally:
        db.close()
    yield


app = FastAPI(
    title="Iterative Research",
    description="Web UI for the iterative LLM vulnerability research framework.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(config_router, prefix="/api")
app.include_router(runs_router, prefix="/api")
app.include_router(experiment_router, prefix="/api")
app.include_router(vuln_router, prefix="/api")


@app.websocket("/ws/logs/{run_id}")
async def ws_logs(websocket: WebSocket, run_id: str):
    await log_stream(websocket, run_id)


@app.get("/api/health")
async def health():
    return {"status": "ok"}
