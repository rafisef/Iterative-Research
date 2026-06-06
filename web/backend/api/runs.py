"""Runs CRUD API: list, detail, delete, results, generated code."""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from db.database import get_db
from db.models import GeneratedCode, Result, Run
from db.sync import sync_runs

router = APIRouter(tags=["runs"])


def _run_to_dict(run: Run) -> dict:
    return {
        "id": run.id,
        "started_at": run.started_at,
        "model": run.model,
        "temperature": run.temperature,
        "max_tokens": run.max_tokens,
        "iterations": run.iterations,
        "agents": json.loads(run.agents) if run.agents else [],
        "vulnerabilities": json.loads(run.vulnerabilities) if run.vulnerabilities else [],
        "random_seed": run.random_seed,
        "status": run.status,
        "snippet": run.snippet,
        "base_code_dir": run.base_code_dir,
    }


def _result_to_dict(r: Result) -> dict:
    # Canonical HIGH/MEDIUM/LOW counts. Rows synced before metadata-based
    # severity have these columns defaulted to 0 while the legacy rule-level
    # columns are populated — fall back to them so old runs still render.
    sg_high, sg_med, sg_low = r.semgrep_high or 0, r.semgrep_medium or 0, r.semgrep_low or 0
    if sg_high == sg_med == sg_low == 0 and (r.semgrep_error or r.semgrep_warning or r.semgrep_info):
        sg_high, sg_med, sg_low = r.semgrep_error or 0, r.semgrep_warning or 0, r.semgrep_info or 0
    return {
        "id": r.id,
        "run_id": r.run_id,
        "agent": r.agent,
        # New canonical field: file (basename of the snippet)
        "file": Path(r.snippet_path).name if r.snippet_path else r.vulnerability_id,
        "iteration": r.iteration,
        "prompt": r.prompt,
        "model": r.model,
        "success": r.success,
        "server_started": r.server_started,
        "nuclei_exit_code": r.nuclei_exit_code,
        "snippet_path": r.snippet_path,
        "log_path": r.log_path,
        "bandit_high": r.bandit_high,
        "bandit_medium": r.bandit_medium,
        "bandit_low": r.bandit_low,
        "semgrep_findings": r.semgrep_findings,
        "semgrep_high": sg_high,
        "semgrep_medium": sg_med,
        "semgrep_low": sg_low,
        "semgrep_error": r.semgrep_error,
        "semgrep_warning": r.semgrep_warning,
        "semgrep_info": r.semgrep_info,
        "static_log_path": r.static_log_path,
        "bandit_issues": json.loads(r.bandit_issues) if r.bandit_issues else [],
        "semgrep_issues": json.loads(r.semgrep_issues) if r.semgrep_issues else [],
    }


def _code_to_dict(c: GeneratedCode) -> dict:
    return {
        "id": c.id,
        "run_id": c.run_id,
        "agent": c.agent,
        "vuln_id": c.vuln_id,
        "file": Path(c.file_path).name if c.file_path else c.vuln_id,
        "iteration": c.iteration,
        "language": c.language,
        "file_path": c.file_path,
        "code_content": c.code_content,
        "has_syntax_error": c.has_syntax_error,
    }


# ── List & detail ────────────────────────────────────────────────────────────

@router.get("/runs")
async def list_runs(db: Session = Depends(get_db)):
    runs = db.query(Run).order_by(Run.started_at.desc()).all()
    return [_run_to_dict(r) for r in runs]


@router.get("/runs/{run_id}")
async def get_run(run_id: str, db: Session = Depends(get_db)):
    run = db.query(Run).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    data = _run_to_dict(run)
    data["result_count"] = db.query(Result).filter(Result.run_id == run_id).count()
    data["code_count"] = db.query(GeneratedCode).filter(GeneratedCode.run_id == run_id).count()
    return data


@router.delete("/runs/{run_id}")
async def delete_run(run_id: str, db: Session = Depends(get_db)):
    run = db.query(Run).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    db.delete(run)
    db.commit()

    run_dir = _REPO_ROOT / "runs" / run_id
    if run_dir.exists():
        shutil.rmtree(run_dir, ignore_errors=True)
    return {"status": "deleted", "run_id": run_id}


@router.post("/runs/sync")
async def trigger_sync(db: Session = Depends(get_db)):
    count = sync_runs(db, str(_REPO_ROOT / "runs"))
    return {"synced": count}


# ── Results ──────────────────────────────────────────────────────────────────

@router.get("/runs/{run_id}/results")
async def list_results(
    run_id: str,
    agent: Optional[str] = Query(None),
    vuln: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    q = db.query(Result).filter(Result.run_id == run_id)
    if agent:
        q = q.filter(Result.agent == agent)
    if vuln:
        q = q.filter(Result.vulnerability_id == vuln)
    results = q.order_by(Result.agent, Result.vulnerability_id, Result.iteration).all()
    return [_result_to_dict(r) for r in results]


@router.get("/runs/{run_id}/results/{result_id}")
async def get_result(run_id: str, result_id: int, db: Session = Depends(get_db)):
    r = db.query(Result).filter(Result.id == result_id, Result.run_id == run_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Result not found")
    return _result_to_dict(r)


class ResultUpdateBody(BaseModel):
    bandit_high: Optional[int] = None
    bandit_medium: Optional[int] = None
    bandit_low: Optional[int] = None
    semgrep_findings: Optional[int] = None
    semgrep_high: Optional[int] = None
    semgrep_medium: Optional[int] = None
    semgrep_low: Optional[int] = None
    semgrep_error: Optional[int] = None
    semgrep_warning: Optional[int] = None
    semgrep_info: Optional[int] = None
    prompt: Optional[str] = None


@router.put("/runs/{run_id}/results/{result_id}")
async def update_result(
    run_id: str,
    result_id: int,
    body: ResultUpdateBody,
    db: Session = Depends(get_db),
):
    r = db.query(Result).filter(Result.id == result_id, Result.run_id == run_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Result not found")
    for field, val in body.model_dump(exclude_unset=True).items():
        setattr(r, field, val)
    db.commit()
    db.refresh(r)
    return _result_to_dict(r)


@router.delete("/runs/{run_id}/results/{result_id}")
async def delete_result(run_id: str, result_id: int, db: Session = Depends(get_db)):
    r = db.query(Result).filter(Result.id == result_id, Result.run_id == run_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Result not found")
    db.delete(r)
    db.commit()
    return {"status": "deleted", "result_id": result_id}


# ── Generated code ───────────────────────────────────────────────────────────

@router.get("/runs/{run_id}/code")
async def list_code(
    run_id: str,
    agent: Optional[str] = Query(None),
    vuln: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    q = db.query(GeneratedCode).filter(GeneratedCode.run_id == run_id)
    if agent:
        q = q.filter(GeneratedCode.agent == agent)
    if vuln:
        q = q.filter(GeneratedCode.vuln_id == vuln)
    codes = q.order_by(GeneratedCode.agent, GeneratedCode.vuln_id, GeneratedCode.iteration).all()
    return [_code_to_dict(c) for c in codes]


@router.get("/runs/{run_id}/code/{agent}/{vuln_id}/{iteration}")
async def get_code(
    run_id: str,
    agent: str,
    vuln_id: str,
    iteration: int,
    db: Session = Depends(get_db),
):
    c = (
        db.query(GeneratedCode)
        .filter(
            GeneratedCode.run_id == run_id,
            GeneratedCode.agent == agent,
            GeneratedCode.vuln_id == vuln_id,
            GeneratedCode.iteration == iteration,
        )
        .first()
    )
    if not c:
        raise HTTPException(status_code=404, detail="Generated code not found")
    return _code_to_dict(c)


class CodeUpdateBody(BaseModel):
    code_content: str


@router.put("/runs/{run_id}/code/{agent}/{vuln_id}/{iteration}")
async def update_code(
    run_id: str,
    agent: str,
    vuln_id: str,
    iteration: int,
    body: CodeUpdateBody,
    db: Session = Depends(get_db),
):
    c = (
        db.query(GeneratedCode)
        .filter(
            GeneratedCode.run_id == run_id,
            GeneratedCode.agent == agent,
            GeneratedCode.vuln_id == vuln_id,
            GeneratedCode.iteration == iteration,
        )
        .first()
    )
    if not c:
        raise HTTPException(status_code=404, detail="Generated code not found")
    c.code_content = body.code_content
    if c.language == "python":
        try:
            compile(body.code_content, "<web-edit>", "exec")
            c.has_syntax_error = False
        except SyntaxError:
            c.has_syntax_error = True
    if c.file_path and Path(c.file_path).exists():
        Path(c.file_path).write_text(body.code_content, encoding="utf-8")
    db.commit()
    db.refresh(c)
    return _code_to_dict(c)


@router.delete("/runs/{run_id}/code/{agent}/{vuln_id}/{iteration}")
async def delete_code(
    run_id: str,
    agent: str,
    vuln_id: str,
    iteration: int,
    db: Session = Depends(get_db),
):
    c = (
        db.query(GeneratedCode)
        .filter(
            GeneratedCode.run_id == run_id,
            GeneratedCode.agent == agent,
            GeneratedCode.vuln_id == vuln_id,
            GeneratedCode.iteration == iteration,
        )
        .first()
    )
    if not c:
        raise HTTPException(status_code=404, detail="Generated code not found")
    if c.file_path and Path(c.file_path).exists():
        Path(c.file_path).unlink(missing_ok=True)
    db.delete(c)
    db.commit()
    return {"status": "deleted"}
