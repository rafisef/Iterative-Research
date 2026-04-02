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

Public API
----------
    run_scans(run_dir, config, max_workers) -> None
"""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .io_utils import ResultRecord, append_result_record, ensure_dir, logger
from .static_scanner import detect_language, run_static_scan
from .vulnerabilities import get_all_vulnerabilities


def run_scans(
    run_dir: Path,
    config: Dict,
    max_workers: int = 1,
) -> None:
    """
    Run static analysis on all generated output files in an existing run directory.

    Reads run_metadata.json to discover which agents / vulnerabilities /
    iterations were generated, then calls run_static_scan() on each output
    file and appends a ResultRecord to results.jsonl.

    Parameters
    ----------
    run_dir:
        Path to the run directory (e.g. runs/2026-04-01_11-34-04).
    config:
        Loaded YAML config dict (used as a model-name fallback in ResultRecord).
    max_workers:
        Thread pool size for parallel scanning.
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

    outputs_dir = run_dir / "outputs"
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
            semgrep_config_override = ""
        else:
            lang = detect_language(vuln.base_snippet_path)
            ext = ".py" if lang == "python" else ".ts"
            semgrep_config_override = vuln.semgrep_config

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
            semgrep_config_override=semgrep_config_override,
        )

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
            static_log_path=static_result.log_path,
            bandit_issues=static_result.bandit.issues,
            semgrep_issues=static_result.semgrep.issues,
            run_id=run_id,
        )
        append_result_record(results_index, record)

    # Outer loop order: vuln → iteration → agent (matches original runner).
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
