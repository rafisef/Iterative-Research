"""Action API: start/stop experiments, generation, scanning, analysis."""
from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_PYTHON = sys.executable

if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from db.database import get_db, SessionLocal
from db.models import Run
from db.sync import sync_runs
from services.process_manager import ProcessInfo, process_manager

router = APIRouter(tags=["actions"])


def _make_run_id() -> str:
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def _on_process_exit(info: ProcessInfo) -> None:
    """Update the run status in the DB when a subprocess completes."""
    db = SessionLocal()
    try:
        run = db.query(Run).filter(Run.id == info.run_id).first()
        if run:
            if info.status == "cancelled":
                run.status = "cancelled"
            elif info.exit_code == 0:
                run.status = "complete"
            else:
                run.status = "failed"
            db.commit()
        sync_runs(db, str(_REPO_ROOT / "runs"))
    finally:
        db.close()


# ── Experiment (full pipeline) ───────────────────────────────────────────────

class ExperimentBody(BaseModel):
    model: Optional[str] = None
    iterations: Optional[int] = None
    run_id: Optional[str] = None
    snippet: Optional[str] = None
    base_code_dir: Optional[str] = None
    log: Optional[str] = None
    config: str = "config/config.yaml"


@router.post("/experiment")
async def start_experiment(body: ExperimentBody, db: Session = Depends(get_db)):
    run_id = body.run_id or _make_run_id()

    cmd = [_PYTHON, "main.py", "--config", body.config]
    if body.model:
        cmd += ["--model", body.model]
    if body.iterations is not None:
        cmd += ["--iterations", str(body.iterations)]
    if body.run_id:
        cmd += ["--run-id", body.run_id]
    if body.snippet:
        cmd += ["--snippet", body.snippet]
    if body.base_code_dir:
        cmd += ["--base-code-dir", body.base_code_dir]
    if body.log:
        cmd += ["--log", body.log]

    run = Run(id=run_id, status="generating", started_at=datetime.now().isoformat())
    db.merge(run)
    db.commit()

    info = process_manager.spawn(run_id, cmd, on_exit=_on_process_exit)
    return {"run_id": run_id, "pid": info.pid, "status": "started", "command": info.command}


# ── Generate only ────────────────────────────────────────────────────────────

class GenerateBody(BaseModel):
    model: Optional[str] = None
    iterations: Optional[int] = None
    run_id: Optional[str] = None
    snippet: Optional[str] = None
    base_code_dir: Optional[str] = None
    config: str = "config/config.yaml"


@router.post("/runs/generate")
async def start_generate(body: GenerateBody, db: Session = Depends(get_db)):
    run_id = body.run_id or _make_run_id()

    cmd = [_PYTHON, "utils/generate.py", "--config", body.config]
    if body.model:
        cmd += ["--model", body.model]
    if body.iterations is not None:
        cmd += ["--iterations", str(body.iterations)]
    cmd += ["--run-id", run_id]
    if body.snippet:
        cmd += ["--snippet", body.snippet]
    if body.base_code_dir:
        cmd += ["--base-code-dir", body.base_code_dir]

    run = Run(id=run_id, status="generating", started_at=datetime.now().isoformat())
    db.merge(run)
    db.commit()

    info = process_manager.spawn(run_id, cmd, on_exit=_on_process_exit)
    return {"run_id": run_id, "pid": info.pid, "status": "started", "command": info.command}


# ── Analyze (synchronous — fast) ─────────────────────────────────────────────

@router.get("/runs/{run_id}/analysis")
async def get_analysis(run_id: str):
    run_dir = _REPO_ROOT / "runs" / run_id
    if not run_dir.exists():
        raise HTTPException(status_code=404, detail=f"Run directory not found: {run_id}")

    from framework.analyzer import analyze_run_json
    result = analyze_run_json(run_dir)
    return result


# ── Test run ─────────────────────────────────────────────────────────────────

class TestRunBody(BaseModel):
    snippet: Optional[str] = None
    model: Optional[str] = None
    config: str = "config/config.yaml"


@router.post("/test-run")
async def start_test_run(body: TestRunBody, db: Session = Depends(get_db)):
    run_id = f"test-run-{_make_run_id()}"

    cmd = [_PYTHON, "main.py", "--config", body.config]
    if body.snippet:
        cmd += ["--test-run", body.snippet]
    else:
        cmd += ["--test-run"]
    if body.model:
        cmd += ["--model", body.model]
    cmd += ["--run-id", run_id]

    run = Run(id=run_id, status="generating", started_at=datetime.now().isoformat())
    db.merge(run)
    db.commit()

    info = process_manager.spawn(run_id, cmd, on_exit=_on_process_exit)
    return {"run_id": run_id, "pid": info.pid, "status": "started", "command": info.command}


# ── Test LLM connectivity ─────────────────────────────────────────────────────

class TestLLMBody(BaseModel):
    model: Optional[str] = None
    config: str = "config/config.yaml"


@router.post("/test-llm")
async def start_test_llm(body: TestLLMBody):
    run_id = f"test-llm-{_make_run_id()}"

    cmd = [_PYTHON, "utils/test_llm_connectivity.py", "--config", body.config]
    if body.model:
        cmd += ["--model", body.model]

    info = process_manager.spawn(run_id, cmd)
    return {"run_id": run_id, "pid": info.pid, "status": "started", "command": info.command}


# ── Nuclei rescan ─────────────────────────────────────────────────────────────

class NucleiRescanBody(BaseModel):
    run_id: Optional[str] = None
    scan_all: bool = False
    agent: Optional[str] = None
    min_severity: str = "low"
    config: str = "config/config.yaml"


@router.post("/nuclei-rescan")
async def start_nuclei_rescan(body: NucleiRescanBody):
    target_run = body.run_id or "latest"
    ws_id = f"nuclei-{target_run}-{_make_run_id()}"

    cmd = [_PYTHON, "utils/nuclei_rescan.py", "--config", body.config]
    if body.run_id:
        cmd += ["--run", body.run_id]
    if body.scan_all:
        cmd += ["--all"]
    if body.agent:
        cmd += ["--agent", body.agent]
    if body.min_severity:
        cmd += ["--min-severity", body.min_severity]

    info = process_manager.spawn(ws_id, cmd)
    return {"run_id": ws_id, "pid": info.pid, "status": "started", "command": info.command}


# ── Language detection ────────────────────────────────────────────────────────

_LANG_MAP = {
    ".py": "python",
    ".ts": "typescript", ".tsx": "typescript",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".cs": "csharp",
    ".swift": "swift",
    ".kt": "kotlin",
}

_CODE_EXTS = set(_LANG_MAP.keys())


@router.get("/detect-language")
async def detect_language(path: str):
    target = Path(path)
    if not target.exists():
        target = _REPO_ROOT / path
    if not target.exists():
        raise HTTPException(status_code=404, detail=f"Path not found: {path}")

    counts: dict[str, int] = {}
    if target.is_file():
        lang = _LANG_MAP.get(target.suffix.lower(), "unknown")
        counts[lang] = 1
    else:
        for f in target.rglob("*"):
            if f.is_file() and f.suffix.lower() in _CODE_EXTS:
                lang = _LANG_MAP.get(f.suffix.lower(), "unknown")
                counts[lang] = counts.get(lang, 0) + 1

    languages = [
        {"language": lang, "count": count}
        for lang, count in sorted(counts.items(), key=lambda x: -x[1])
    ]
    return {"languages": languages}


# ── Process control ──────────────────────────────────────────────────────────

@router.post("/process/{pid}/kill")
async def kill_process(pid: int):
    success = process_manager.kill(pid)
    if not success:
        raise HTTPException(status_code=404, detail="Process not found or already exited")
    return {"status": "killed", "pid": pid}


@router.get("/process/active")
async def active_processes():
    active = process_manager.active()
    return [
        {
            "pid": p.pid,
            "run_id": p.run_id,
            "command": p.command,
            "started_at": p.started_at,
            "status": p.status,
        }
        for p in active
    ]
