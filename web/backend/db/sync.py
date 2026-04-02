"""Sync filesystem run directories into the SQLite database."""
from __future__ import annotations

import json
from pathlib import Path
from typing import List

from sqlalchemy.orm import Session

from .models import GeneratedCode, Result, Run

_SNIPPET_EXTENSIONS = frozenset({".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"})


def _detect_language(path: str) -> str:
    ext = Path(path).suffix.lower()
    if ext == ".py":
        return "python"
    if ext in {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}:
        return "typescript"
    return "unknown"


def sync_runs(db: Session, runs_dir: str = "runs") -> int:
    """
    Scan *runs_dir* for run directories and upsert into the database.

    Returns the number of runs synced (new or updated).
    """
    runs_path = Path(runs_dir)
    if not runs_path.exists():
        return 0

    synced = 0
    for run_dir in sorted(runs_path.iterdir()):
        if not run_dir.is_dir():
            continue
        meta_path = run_dir / "run_metadata.json"
        if not meta_path.exists():
            continue

        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        run_id = meta.get("run_id", run_dir.name)

        existing = db.query(Run).filter(Run.id == run_id).first()
        if existing is None:
            run_obj = Run(
                id=run_id,
                started_at=meta.get("started_at"),
                model=meta.get("model"),
                temperature=meta.get("temperature"),
                max_tokens=meta.get("max_tokens"),
                iterations=meta.get("iterations"),
                agents=json.dumps(meta.get("agents", [])),
                vulnerabilities=json.dumps(meta.get("vulnerabilities", [])),
                random_seed=meta.get("random_seed"),
                status="complete",
                snippet=meta.get("snippet"),
                base_code_dir=meta.get("base_code_dir"),
                config_snapshot=json.dumps(meta),
            )
            db.add(run_obj)
            db.flush()
        else:
            run_obj = existing

        _sync_results(db, run_dir, run_id)
        _sync_generated_code(db, run_dir, run_id, meta)

        synced += 1

    db.commit()
    return synced


def _sync_results(db: Session, run_dir: Path, run_id: str) -> None:
    results_path = run_dir / "results.jsonl"
    if not results_path.exists():
        return

    existing_count = db.query(Result).filter(Result.run_id == run_id).count()
    if existing_count > 0:
        return

    for line in results_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue

        result = Result(
            run_id=run_id,
            agent=rec.get("agent", ""),
            vulnerability_id=rec.get("vulnerability_id", ""),
            iteration=rec.get("iteration", 0),
            prompt=rec.get("prompt", ""),
            model=rec.get("model", ""),
            success=rec.get("success", True),
            server_started=rec.get("server_started", False),
            nuclei_exit_code=rec.get("nuclei_exit_code"),
            snippet_path=rec.get("snippet_path", ""),
            log_path=rec.get("log_path", ""),
            bandit_high=rec.get("bandit_high", 0),
            bandit_medium=rec.get("bandit_medium", 0),
            bandit_low=rec.get("bandit_low", 0),
            semgrep_findings=rec.get("semgrep_findings", 0),
            static_log_path=rec.get("static_log_path", ""),
            bandit_issues=json.dumps(rec.get("bandit_issues", [])),
            semgrep_issues=json.dumps(rec.get("semgrep_issues", [])),
        )
        db.add(result)


def _sync_generated_code(db: Session, run_dir: Path, run_id: str, meta: dict) -> None:
    outputs_dir = run_dir / "outputs"
    if not outputs_dir.exists():
        return

    existing_count = db.query(GeneratedCode).filter(GeneratedCode.run_id == run_id).count()
    if existing_count > 0:
        return

    agents: List[str] = meta.get("agents", [])
    vulns: List[str] = meta.get("vulnerabilities", [])
    iterations: int = meta.get("iterations", 0)

    for agent_id in agents:
        for vuln_id in vulns:
            for it in range(iterations):
                for ext in (".py", ".ts"):
                    fp = outputs_dir / agent_id / vuln_id / f"iteration_{it}{ext}"
                    if fp.exists():
                        code = fp.read_text(encoding="utf-8")
                        lang = _detect_language(str(fp))
                        has_err = False
                        if lang == "python":
                            try:
                                compile(code, str(fp), "exec")
                            except SyntaxError:
                                has_err = True

                        db.add(GeneratedCode(
                            run_id=run_id,
                            agent=agent_id,
                            vuln_id=vuln_id,
                            iteration=it,
                            language=lang,
                            file_path=str(fp),
                            code_content=code,
                            has_syntax_error=has_err,
                        ))
                        break
