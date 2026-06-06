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
- Stand-alone Semgrep scanning of an arbitrary file or directory (scan_files)

Public API
----------
    run_scans(run_dir, config, max_workers, semgrep_config_override) -> None
    scan_files(target, output_path, semgrep_config) -> Path
"""
from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Tuple

from .io_utils import (
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


# File extensions Semgrep (and Bandit, for .py) can scan.
_SCANNABLE_EXTS = frozenset({
    ".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
    ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp",
    ".java", ".rb", ".php", ".swift", ".kt",
})


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

    outputs_dir = resolve_code_dir(run_dir)
    logs_dir = run_dir / "logs"
    results_index = str(run_dir / "results.jsonl")

    ensure_dir(logs_dir)

    # results.jsonl is written append-only, and run_scans always rescans the
    # full agent × vuln × iteration set from run_metadata.json. Clear any prior
    # results first so re-scanning a run *replaces* its records instead of
    # appending a second copy (which previously produced duplicate rows).
    results_path = Path(results_index)
    if results_path.exists():
        logger.info("Clearing existing results before rescan: %s", results_index)
        results_path.unlink()

    max_workers = max(1, max_workers)

    def _scan_single(agent_id: str, vuln_id: str, iteration: int) -> None:
        # Prefer any generated snippet file's extension if present; otherwise
        # fall back to the vulnerability registry (if it exists) to infer
        # language/semgrep config, and finally default to TypeScript.
        agent_dir = outputs_dir / agent_id / vuln_id
        detected_ext = None
        if agent_dir.exists() and agent_dir.is_dir():
            for suf in (".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"):
                cand = agent_dir / f"iteration_{iteration}{suf}"
                if cand.exists():
                    detected_ext = suf
                    break

        if detected_ext:
            ext = detected_ext
            effective_semgrep = semgrep_config_override or ""
        else:
            # No generated snippet found; default to TypeScript and no per-vuln overrides
            ext = ".ts"
            effective_semgrep = semgrep_config_override or ""

        snippet_path = outputs_dir / agent_id / vuln_id / f"iteration_{iteration}{ext}"
        if not snippet_path.exists():
            logger.warning("Output file not found, skipping scan: %s", snippet_path)
            return

        # Map prompts by filename — generation_log.jsonl uses 'file' as key.
        try:
            file_key = Path(snippet_path).name
        except Exception:
            file_key = vuln_id
        prompt = generation_log.get((agent_id, file_key, iteration), "")

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
            semgrep_high=static_result.semgrep.high,
            semgrep_medium=static_result.semgrep.medium,
            semgrep_low=static_result.semgrep.low,
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
        "Scanning %d file(s) across %d agent(s), %d vulnerabilities, %d iteration(s) (max_workers=%d)",
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


# ---------------------------------------------------------------------------
# Stand-alone Semgrep scanning of an arbitrary file or directory
# ---------------------------------------------------------------------------

_ITERATION_RE = re.compile(r"iteration_(\d+)$")


def _derive_record_keys(file_path: Path, root: Path) -> Tuple[str, str, int]:
    """
    Derive (agent, vulnerability_id, iteration) for a scanned file.

    When the file sits in the generator's conventional layout —
    ``<agent>/<vuln>/iteration_<N>.<ext>`` relative to *root* — those values are
    recovered so the records remain compatible with the per-iteration analysis.
    Otherwise it falls back to agent="scan", vulnerability_id=<file stem>,
    iteration=0.
    """
    try:
        rel = file_path.relative_to(root)
    except ValueError:
        rel = Path(file_path.name)
    parts = rel.parts
    m = _ITERATION_RE.match(file_path.stem)
    if m and len(parts) >= 3:
        return parts[-3], parts[-2], int(m.group(1))
    return "scan", file_path.stem, 0


def scan_files(
    target: str | Path,
    output_path: str | Path,
    *,
    semgrep_config: str = "auto",
    max_workers: int = 1,
) -> Path:
    """
    Scan a single file or a directory (recursively) with the static analysers
    and write a ``results.jsonl`` to *output_path*.

    Parameters
    ----------
    target:
        A single source file, or a directory whose scannable files are scanned
        recursively.
    output_path:
        Destination path for the results.jsonl file. Its parent directory is
        created if needed; a ``logs/`` folder is written alongside it.
    semgrep_config:
        Space-separated Semgrep rule packs (e.g. "p/xss p/owasp-top-ten").
        Defaults to "auto" (Semgrep auto-detection).

    Returns
    -------
    Path to the written results.jsonl file.
    """
    target_path = Path(target).resolve()
    if not target_path.exists():
        raise FileNotFoundError(f"Scan target not found: {target_path}")

    if target_path.is_file():
        files = [target_path]
        root = target_path.parent
    else:
        files = sorted(
            f for f in target_path.rglob("*")
            if f.is_file() and f.suffix.lower() in _SCANNABLE_EXTS
        )
        root = target_path

    if not files:
        raise ValueError(f"No scannable source files found in {target_path}")

    output_path = Path(output_path)
    out_dir = output_path.parent if str(output_path.parent) else Path(".")
    ensure_dir(out_dir)
    logs_dir = ensure_dir(out_dir / "logs")

    # Idempotent: a re-scan replaces results.jsonl rather than appending to it.
    if output_path.exists():
        logger.info("Clearing existing results before scan: %s", output_path)
        output_path.unlink()
    results_index = str(output_path)

    run_id = out_dir.resolve().name or "scan"

    logger.info("Scanning %d file(s) under %s → %s (max_workers=%d)", len(files), target_path, output_path, max_workers)

    max_workers = max(1, int(max_workers))

    def _scan_one(src_file: Path) -> None:
        agent, vuln_id, iteration = _derive_record_keys(src_file, root)
        language = detect_language(str(src_file))
        scanners_used = _ENABLED_SCANNERS.get(language, ["semgrep"])

        static_result = run_static_scan(
            snippet_path=str(src_file),
            agent=agent,
            vulnerability_id=vuln_id,
            iteration=iteration,
            logs_dir=str(logs_dir),
            semgrep_config_override=semgrep_config,
        )

        record = ResultRecord(
            agent=agent,
            vulnerability_id=vuln_id,
            iteration=iteration,
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
            semgrep_high=static_result.semgrep.high,
            semgrep_medium=static_result.semgrep.medium,
            semgrep_low=static_result.semgrep.low,
            semgrep_error=static_result.semgrep.error,
            semgrep_warning=static_result.semgrep.warning,
            semgrep_info=static_result.semgrep.info,
            static_log_path=static_result.log_path,
            bandit_issues=static_result.bandit.issues,
            semgrep_issues=static_result.semgrep.issues,
            run_id=run_id,
        )
        append_result_record(results_index, record, scanners_used=scanners_used)

    if max_workers == 1:
        for src_file in files:
            _scan_one(src_file)
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(_scan_one, f) for f in files]
            for future in as_completed(futures):
                future.result()

    logger.info("Scan complete. Results: %s", results_index)
    return output_path


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
            # generation_log.jsonl uses 1-based iteration numbers for human
            # readability; convert back to a zero-based internal index here.
            key = (entry["agent"], entry.get("file", ""), int(entry["iteration"]) - 1)
            result[key] = entry.get("prompt", "")
        except (json.JSONDecodeError, KeyError, ValueError):
            logger.warning("Skipping malformed entry in generation_log.jsonl: %s", line[:80])
    return result
