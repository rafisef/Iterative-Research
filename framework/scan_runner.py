"""
framework/scan_runner.py
------------------------
Scanning component of the three-component pipeline.

Responsibilities
----------------
- Read run_metadata.json to discover agents / vulnerabilities / iterations
- Load generation_log.jsonl to recover per-iteration prompts (when available)
- For each agent × vulnerability × iteration: locate the output file, call
  run_static_scan(), and append a ResultRecord to results.jsonl
- Use ThreadPoolExecutor for parallelism (same as the original runner)
- Operate on any run directory, including ones generated independently
- Support baseline scanning of arbitrary files/directories

Public API
----------
    run_scans(run_dir, config, max_workers, semgrep_config_override) -> None
    scan_baseline(target, runs_dir, semgrep_config) -> Path
"""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .io_utils import (
    AI_CODE_DIR,
    ResultRecord,
    append_result_record,
    ensure_dir,
    logger,
    resolve_code_dir,
)
from .static_scanner import (
    _ENABLED_SCANNERS,
    detect_language,
    run_static_scan,
)
from .vulnerabilities import get_all_vulnerabilities


def run_scans(
    run_dir: Path,
    config: Dict,
    max_workers: int = 1,
    semgrep_config_override: str = "",
) -> None:
    """
    Run static analysis on all generated output files in an existing run directory.

    Parameters
    ----------
    run_dir:
        Path to the run directory (e.g. runs/2026-04-01_11-34-04).
    config:
        Loaded YAML config dict (used as a model-name fallback in ResultRecord).
    max_workers:
        Thread pool size for parallel scanning.
    semgrep_config_override:
        Space-separated Semgrep rule packs passed from CLI (e.g. "p/xss p/owasp-top-ten").
        Overrides per-vulnerability defaults when non-empty.
    """
    meta_path = run_dir / "run_metadata.json"
    if not meta_path.exists():
        raise FileNotFoundError(
            f"run_metadata.json not found in {run_dir}. "
            f"Run code generation first with: python utils/generate.py --run-id {run_dir.name}"
        )

    metadata = json.loads(meta_path.read_text(encoding="utf-8"))
    agent_ids: List[str] = metadata.get("agents", [])
    vuln_ids: List[str] = metadata.get("vulnerabilities", [])
    iterations: int = int(metadata.get("iterations", 0))
    model: str = metadata.get("model") or config.get("llm", {}).get("model", "unknown")
    run_id: str = metadata.get("run_id", run_dir.name)

    generation_log = _load_generation_log(run_dir)
    all_vulns = get_all_vulnerabilities()

    outputs_dir = resolve_code_dir(run_dir)
    logs_dir = run_dir / "logs"
    results_index = str(run_dir / "results.jsonl")

    ensure_dir(logs_dir)

    max_workers = max(1, max_workers)

    def _scan_single(agent_id: str, vuln_id: str, iteration: int) -> None:
        vuln = all_vulns.get(vuln_id)
        if vuln is None:
            logger.warning(
                "Vulnerability '%s' not found in registry; "
                "attempting scan with .ts extension and no semgrep override.",
                vuln_id,
            )
            ext = ".ts"
            effective_semgrep = semgrep_config_override or ""
        else:
            lang = detect_language(vuln.base_snippet_path)
            ext = ".py" if lang == "python" else ".ts"
            effective_semgrep = semgrep_config_override or vuln.semgrep_config

        snippet_path = outputs_dir / agent_id / vuln_id / f"iteration_{iteration}{ext}"
        if not snippet_path.exists():
            logger.warning("Output file not found, skipping scan: %s", snippet_path)
            return

        prompt = generation_log.get((agent_id, vuln_id, iteration), "")

        static_result = run_static_scan(
            snippet_path=str(snippet_path),
            agent=agent_id,
            vulnerability_id=vuln_id,
            iteration=iteration,
            logs_dir=str(logs_dir),
            semgrep_config_override=effective_semgrep,
        )

        language = detect_language(str(snippet_path))
        scanners_used = _ENABLED_SCANNERS.get(language, ["semgrep"])

        record = ResultRecord(
            agent=agent_id,
            vulnerability_id=vuln_id,
            iteration=iteration,
            prompt=prompt,
            model=model,
            success=True,
            server_started=False,
            nuclei_exit_code=None,
            snippet_path=str(snippet_path),
            log_path="",
            bandit_high=static_result.bandit.high,
            bandit_medium=static_result.bandit.medium,
            bandit_low=static_result.bandit.low,
            semgrep_findings=static_result.semgrep.findings,
            semgrep_error=static_result.semgrep.error,
            semgrep_warning=static_result.semgrep.warning,
            semgrep_info=static_result.semgrep.info,
            static_log_path=static_result.log_path,
            bandit_issues=static_result.bandit.issues,
            semgrep_issues=static_result.semgrep.issues,
            run_id=run_id,
        )
        append_result_record(results_index, record, scanners_used=scanners_used)

    work_items: List[Tuple[str, str, int]] = [
        (agent_id, vuln_id, iteration)
        for vuln_id in vuln_ids
        for iteration in range(iterations)
        for agent_id in agent_ids
    ]

    logger.info(
        "Scanning %d file(s) across %d agent(s), %d vuln(s), %d iteration(s) (max_workers=%d)",
        len(work_items), len(agent_ids), len(vuln_ids), iterations, max_workers,
    )

    if max_workers == 1:
        for agent_id, vuln_id, iteration in work_items:
            _scan_single(agent_id, vuln_id, iteration)
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(_scan_single, agent_id, vuln_id, iteration)
                for agent_id, vuln_id, iteration in work_items
            ]
            for future in as_completed(futures):
                future.result()

    logger.info("Scanning complete. Results: %s", results_index)


def scan_baseline(
    target: str | Path,
    runs_dir: str = "runs",
    semgrep_config: str = "",
) -> Path:
    """
    Scan arbitrary file(s) to establish a baseline of findings.

    Creates a standard run directory (runs/baseline-<timestamp>/) with
    run_metadata.json and results.jsonl so baseline scans appear alongside
    regular experiment runs.

    Parameters
    ----------
    target:
        Path to a single file or directory of code to scan.
    runs_dir:
        Root directory for all runs.
    semgrep_config:
        Optional Semgrep rule packs override (space-separated).

    Returns
    -------
    Path to the created run directory.
    """
    target_path = Path(target).resolve()
    if not target_path.exists():
        raise FileNotFoundError(f"Baseline scan target not found: {target_path}")

    if target_path.is_file():
        files = [target_path]
    else:
        files = sorted(
            f for f in target_path.rglob("*")
            if f.is_file() and f.suffix in {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
        )

    if not files:
        raise ValueError(f"No scannable source files found in {target_path}")

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    run_dir = ensure_dir(Path(runs_dir) / f"baseline-{timestamp}")
    logs_dir = ensure_dir(run_dir / "logs")
    results_index = str(run_dir / "results.jsonl")

    vuln_ids_seen: List[str] = []
    for src_file in files:
        vuln_id = src_file.stem
        if vuln_id not in vuln_ids_seen:
            vuln_ids_seen.append(vuln_id)

    languages_seen = set()
    for src_file in files:
        languages_seen.add(detect_language(str(src_file)))

    metadata = {
        "run_id": run_dir.name,
        "timestamp": timestamp,
        "mode": "baseline",
        "target": str(target_path),
        "agents": ["baseline"],
        "vulnerabilities": vuln_ids_seen,
        "iterations": 1,
        "model": "n/a",
    }
    (run_dir / "run_metadata.json").write_text(
        json.dumps(metadata, indent=2), encoding="utf-8"
    )

    logger.info(
        "Baseline scan: %d file(s) in %s → %s", len(files), target_path, run_dir
    )

    for src_file in files:
        vuln_id = src_file.stem
        language = detect_language(str(src_file))
        scanners_used = _ENABLED_SCANNERS.get(language, ["semgrep"])

        static_result = run_static_scan(
            snippet_path=str(src_file),
            agent="baseline",
            vulnerability_id=vuln_id,
            iteration=0,
            logs_dir=str(logs_dir),
            semgrep_config_override=semgrep_config,
        )

        record = ResultRecord(
            agent="baseline",
            vulnerability_id=vuln_id,
            iteration=0,
            prompt="",
            model="n/a",
            success=True,
            server_started=False,
            nuclei_exit_code=None,
            snippet_path=str(src_file),
            log_path="",
            bandit_high=static_result.bandit.high,
            bandit_medium=static_result.bandit.medium,
            bandit_low=static_result.bandit.low,
            semgrep_findings=static_result.semgrep.findings,
            semgrep_error=static_result.semgrep.error,
            semgrep_warning=static_result.semgrep.warning,
            semgrep_info=static_result.semgrep.info,
            static_log_path=static_result.log_path,
            bandit_issues=static_result.bandit.issues,
            semgrep_issues=static_result.semgrep.issues,
            run_id=run_dir.name,
        )
        append_result_record(results_index, record, scanners_used=scanners_used)

    logger.info("Baseline scan complete. Results: %s", results_index)
    return run_dir


def scan_adhoc(
    target: str | Path,
    runs_dir: str = "runs",
    semgrep_config: str = "",
) -> Path:
    """
    Run semgrep on an arbitrary file or directory (ad-hoc scan).

    Unlike scan_baseline (which tags results as agent="baseline" for
    distinguishing original code), this creates results tagged with
    agent="scan" — used for re-scanning AI-generated output or any
    arbitrary code without the baseline label.

    Creates a standard run directory (runs/scan-<timestamp>/) with
    run_metadata.json and results.jsonl.
    """
    target_path = Path(target).resolve()
    if not target_path.exists():
        raise FileNotFoundError(f"Adhoc scan target not found: {target_path}")

    if target_path.is_file():
        files = [target_path]
    else:
        files = sorted(
            f for f in target_path.rglob("*")
            if f.is_file() and f.suffix in {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}
        )

    if not files:
        raise ValueError(f"No scannable source files found in {target_path}")

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    run_dir = ensure_dir(Path(runs_dir) / f"scan-{timestamp}")
    logs_dir = ensure_dir(run_dir / "logs")
    results_index = str(run_dir / "results.jsonl")

    vuln_ids_seen: List[str] = []
    for src_file in files:
        vuln_id = src_file.stem
        if vuln_id not in vuln_ids_seen:
            vuln_ids_seen.append(vuln_id)

    metadata = {
        "run_id": run_dir.name,
        "timestamp": timestamp,
        "mode": "adhoc",
        "target": str(target_path),
        "agents": ["scan"],
        "vulnerabilities": vuln_ids_seen,
        "iterations": 1,
        "model": "n/a",
    }
    (run_dir / "run_metadata.json").write_text(
        json.dumps(metadata, indent=2), encoding="utf-8"
    )

    logger.info(
        "Adhoc scan: %d file(s) in %s → %s", len(files), target_path, run_dir
    )

    for src_file in files:
        vuln_id = src_file.stem
        language = detect_language(str(src_file))
        scanners_used = _ENABLED_SCANNERS.get(language, ["semgrep"])

        static_result = run_static_scan(
            snippet_path=str(src_file),
            agent="scan",
            vulnerability_id=vuln_id,
            iteration=0,
            logs_dir=str(logs_dir),
            semgrep_config_override=semgrep_config,
        )

        record = ResultRecord(
            agent="scan",
            vulnerability_id=vuln_id,
            iteration=0,
            prompt="",
            model="n/a",
            success=True,
            server_started=False,
            nuclei_exit_code=None,
            snippet_path=str(src_file),
            log_path="",
            bandit_high=static_result.bandit.high,
            bandit_medium=static_result.bandit.medium,
            bandit_low=static_result.bandit.low,
            semgrep_findings=static_result.semgrep.findings,
            semgrep_error=static_result.semgrep.error,
            semgrep_warning=static_result.semgrep.warning,
            semgrep_info=static_result.semgrep.info,
            static_log_path=static_result.log_path,
            bandit_issues=static_result.bandit.issues,
            semgrep_issues=static_result.semgrep.issues,
            run_id=run_dir.name,
        )
        append_result_record(results_index, record, scanners_used=scanners_used)

    logger.info("Adhoc scan complete. Results: %s", results_index)
    return run_dir


def _load_generation_log(run_dir: Path) -> Dict[Tuple[str, str, int], str]:
    """
    Load the generation log written by generate_code().

    Returns a dict mapping (agent_id, vuln_id, iteration) -> prompt string.
    Returns an empty dict if the log does not exist or cannot be parsed.
    """
    log_path = run_dir / "generation_log.jsonl"
    if not log_path.exists():
        return {}

    result: Dict[Tuple[str, str, int], str] = {}
    for line in log_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            key = (entry["agent"], entry["vuln_id"], int(entry["iteration"]))
            result[key] = entry.get("prompt", "")
        except (json.JSONDecodeError, KeyError, ValueError):
            logger.warning("Skipping malformed entry in generation_log.jsonl: %s", line[:80])
    return result
