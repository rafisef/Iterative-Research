"""
framework/generator.py
-----------------------
Code-generation component of the three-component pipeline.

Responsibilities
----------------
- Seed the RNG (reproducibility)
- For each vulnerability × iteration × agent: call the LLM, save output file
- Python syntax-check warning (preserved from the original runner)
- Previous-iteration fallback logic (preserved)
- Write run_metadata.json
- Write generation_log.jsonl (per-iteration prompt log consumed by scan_runner)

Public API
----------
    generate_code(config, config_path, run_dir, agents, vulns, iterations, **opts) -> Path
    write_run_metadata(run_dir, run_id, config, *, effective_iterations, ...) -> None
    discover_snippets_from_dir(base_dir) -> List[Vulnerability]
"""
from __future__ import annotations

import json
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from .agents import Agent
from .io_utils import AI_CODE_DIR, ensure_dir, logger, read_text, write_text
from .llm_client import get_llm_client
from .static_scanner import detect_language
from dataclasses import dataclass


@dataclass
class Vulnerability:
    id: str
    description: str
    base_snippet_path: str
    semgrep_config: str = ""


# Lock for generation_log.jsonl writes — multiple threads append concurrently.
_GENERATION_LOG_LOCK = threading.Lock()


def generate_code(
    config: Dict,
    config_path: str,
    run_dir: Path,
    agents: List[Agent],
    vulns: List[Vulnerability],
    iterations: int,
    *,
    max_workers: int = 1,
    seed: int | None = None,
    model_override: str | None = None,
    test_run_snippet: str | None = None,
    snippet_path_arg: str | None = None,
    base_code_dir_arg: str | None = None,
) -> Path:
    """
    Generate LLM code iterations for all agent × vulnerability combinations.

    Writes output files to:
        <run_dir>/ai-generated-code-snippets/<agent_id>/<vuln_id>/iteration_N.<ext>

    Writes per-iteration prompt/model info to:
        <run_dir>/generation_log.jsonl
    Each line: {"agent", "vuln_id", "iteration", "prompt", "model"}

    Writes run configuration to:
        <run_dir>/run_metadata.json

    Parameters
    ----------
    config:
        Loaded YAML config dict.
    config_path:
        Path to the YAML config file (forwarded to get_llm_client).
    run_dir:
        Timestamped run directory (already created by caller).
    agents:
        Resolved Agent objects to iterate over.
    vulns:
        Resolved Vulnerability objects to iterate over.
    iterations:
        Number of LLM improvement rounds per agent per vulnerability.
    max_workers:
        Thread pool size for parallel agent processing within each iteration.
    seed:
        Optional RNG seed for reproducible prompt selection.
    model_override:
        LiteLLM model string, overrides config value.
    test_run_snippet:
        Non-None when invoked via --test-run (recorded in metadata only).
    snippet_path_arg:
        Non-None when invoked via --snippet (recorded in metadata only).
    base_code_dir_arg:
        Non-None when invoked via --base-code-dir (recorded in metadata only).

    Returns
    -------
    Path
        The run_dir, for chaining convenience.
    """
    if seed is not None:
        random.seed(int(seed))

    llm_cfg = config.get("llm", {})
    temperature = llm_cfg.get("temperature")
    top_p = llm_cfg.get("top_p")
    max_tokens = llm_cfg.get("max_tokens")
    active_model = model_override or llm_cfg.get("model", "gpt-4o")
    outputs_dir = run_dir / AI_CODE_DIR
    generation_log_path = run_dir / "generation_log.jsonl"

    ensure_dir(outputs_dir)
    write_run_metadata(
        run_dir=run_dir,
        run_id=run_dir.name,
        config=config,
        effective_iterations=iterations,
        effective_agents=[a.id for a in agents],
        effective_vulns=[v.id for v in vulns],
        test_run_snippet=test_run_snippet,
        snippet_path_arg=snippet_path_arg,
        base_code_dir_arg=base_code_dir_arg,
    )

    llm_client = get_llm_client(config_path=config_path, model_override=active_model)

    def _generate_single(
        vuln_id: str,
        vuln_base_snippet: str,
        vuln_base_snippet_path: str,
        agent: Agent,
        iteration: int,
    ) -> None:
        ext = Path(vuln_base_snippet_path).suffix
        vuln_language = detect_language(vuln_base_snippet_path)
        is_python = vuln_language == "python"
        # ext = ".py" if is_python else ".ts"

        if iteration == 0:
            input_code = vuln_base_snippet
        else:
            prev_path = outputs_dir / agent.id / vuln_id / f"iteration_{iteration - 1}{ext}"
            try:
                input_code = read_text(prev_path)
            except FileNotFoundError:
                logger.warning(
                    "Previous snippet not found for agent=%s file=%s iteration=%d at %s; "
                    "falling back to base snippet.",
                    agent.id, Path(vuln_base_snippet_path).name, iteration + 1, prev_path,
                )
                input_code = vuln_base_snippet

        instruction = agent.random_instruction()
        logger.info(
            "Iteration %d for agent=%s file=%s | prompt=%s",
            iteration + 1, agent.id, Path(vuln_base_snippet_path).name, instruction,
        )

        generated_code = llm_client.generate_from_snippet(
            input_code, instruction, language=vuln_language,
        )

        if not generated_code.strip():
            logger.warning(
                "Empty code generated for agent=%s file=%s iteration=%d",
                agent.id, Path(vuln_base_snippet_path).name, iteration + 1,
            )
        else:
            logger.info(
                "LLM response received for agent=%s file=%s iteration=%d (%d chars).",
                agent.id, Path(vuln_base_snippet_path).name, iteration + 1, len(generated_code),
            )

        if is_python:
            try:
                compile(generated_code, "<generated-snippet>", "exec")
            except SyntaxError as exc:
                logger.warning(
                    "Generated code has syntax error for agent=%s file=%s iteration=%d: %s",
                    agent.id, Path(vuln_base_snippet_path).name, iteration + 1, exc,
                )

        agent_dir = outputs_dir / agent.id / vuln_id
        ensure_dir(agent_dir)
        snippet_path = agent_dir / f"iteration_{iteration + 1}{ext}"
        write_text(snippet_path, generated_code)

        log_entry = json.dumps({
            "agent": agent.id,
            # Use explicit filename instead of vulnerability id in logs
            "file": Path(vuln_base_snippet_path).name,
            # Human-facing iteration numbering (1-based)
            "iteration": iteration + 1,
            "prompt": instruction,
            "model": active_model,
            "temperature": temperature,
            "top_p": top_p,
            "max_tokens": max_tokens
        })
        with _GENERATION_LOG_LOCK:
            with open(generation_log_path, "a", encoding="utf-8") as f:
                f.write(log_entry + "\n")

        logger.info("Saved %s", snippet_path)

    max_workers = max(1, max_workers)

    for vuln in vulns:
        vuln_lang = detect_language(vuln.base_snippet_path)
        logger.info(
            "Generating code for vulnerability: %s (language=%s)", vuln.id, vuln_lang,
        )
        base_snippet = read_text(vuln.base_snippet_path)

        for iteration in range(iterations):
            logger.info(
                "Starting generation iteration %d for file=%s across %d agents (max_workers=%d)",
                    iteration + 1, Path(vuln.base_snippet_path).name, len(agents), max_workers,
            )

            if max_workers == 1:
                for agent in agents:
                    _generate_single(
                        vuln_id=vuln.id,
                        vuln_base_snippet=base_snippet,
                        vuln_base_snippet_path=vuln.base_snippet_path,
                        agent=agent,
                        iteration=iteration,
                    )
            else:
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = [
                        executor.submit(
                            _generate_single,
                            vuln.id,
                            base_snippet,
                            vuln.base_snippet_path,
                            agent,
                            iteration,
                        )
                        for agent in agents
                    ]
                    for future in as_completed(futures):
                        future.result()

    logger.info("Code generation complete. Outputs: %s/%s/", run_dir, AI_CODE_DIR)
    return run_dir


def write_run_metadata(
    run_dir: Path,
    run_id: str,
    config: Dict,
    *,
    effective_iterations: int,
    effective_agents: List[str],
    effective_vulns: List[str],
    test_run_snippet: str | None = None,
    snippet_path_arg: str | None = None,
    base_code_dir_arg: str | None = None,
) -> None:
    """
    Persist a JSON snapshot of the run configuration alongside results.

    Uses the resolved runtime values (after CLI overrides) rather than raw
    config values so the metadata accurately reflects what ran.
    """
    llm_cfg = config.get("llm", {})
    experiment_cfg = config.get("experiment", {})

    metadata = {
        "run_id": run_id,
        "started_at": datetime.now().isoformat(),
        "model": llm_cfg.get("model"),
        "temperature": llm_cfg.get("temperature"),
        "max_tokens": llm_cfg.get("max_tokens"),
        "iterations": effective_iterations,
        "agents": effective_agents,
        "vulnerabilities": effective_vulns,
        "random_seed": experiment_cfg.get("random_seed"),
        "test_run": test_run_snippet is not None,
        "test_run_snippet": test_run_snippet,
        "snippet": snippet_path_arg,
        "base_code_dir": base_code_dir_arg,
    }

    meta_path = run_dir / "run_metadata.json"
    meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    logger.info("Run metadata written to %s", meta_path)


# ---------------------------------------------------------------------------
# Directory-based snippet discovery
# ---------------------------------------------------------------------------

#: File extensions recognised as code snippets eligible for generation.
_SNIPPET_EXTENSIONS: frozenset[str] = frozenset(
    {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".java", ".rb", ".php", ".swift", ".kt"}
)


def discover_snippets_from_dir(base_dir: Path) -> List[Vulnerability]:
    """
    Recursively discover all code snippet files under *base_dir* and return
    one ad-hoc ``Vulnerability`` per file.

    Supported extensions: .py, .ts, .tsx, .js, .jsx, .mjs, .cjs

    IDs are derived from each file's path relative to *base_dir* (without the
    extension), with path separators replaced by underscores — e.g.:

        base_dir = snippets/
        file     = snippets/python/injection/xss_base.py
        vuln_id  = python_injection_xss_base

    This ensures uniqueness even when the same stem appears in multiple
    subdirectories.  Files are yielded in sorted order for deterministic runs.

    Parameters
    ----------
    base_dir:
        Root directory to search (searched recursively).

    Returns
    -------
    List[Vulnerability]
        Ad-hoc Vulnerability objects whose ``base_snippet_path`` points to the
        discovered file.  Language is auto-detected by the scanner from the
        file extension — no manual tagging is required.

    Raises
    ------
    FileNotFoundError
        If *base_dir* does not exist or is not a directory.
    """
    base_dir = Path(base_dir)
    if not base_dir.exists():
        raise FileNotFoundError(f"--base-code-dir not found: {base_dir}")
    if not base_dir.is_dir():
        raise NotADirectoryError(f"--base-code-dir is not a directory: {base_dir}")

    found: List[Vulnerability] = []
    seen_ids: dict[str, str] = {}  # id → first path (collision detection)

    for snippet_file in sorted(base_dir.rglob("*")):
        if not snippet_file.is_file():
            continue
        if snippet_file.suffix.lower() not in _SNIPPET_EXTENSIONS:
            continue

        rel = snippet_file.relative_to(base_dir).with_suffix("")
        vuln_id = rel.as_posix().replace("/", "_").replace("-", "_").replace(" ", "_")

        if vuln_id in seen_ids:
            logger.warning(
                "discover_snippets_from_dir: ID collision '%s' for %s "
                "(already used by %s); appending suffix to disambiguate.",
                vuln_id, snippet_file, seen_ids[vuln_id],
            )
            vuln_id = f"{vuln_id}_{snippet_file.suffix.lstrip('.')}"

        seen_ids[vuln_id] = str(snippet_file)
        found.append(
            Vulnerability(
                id=vuln_id,
                description=f"Ad-hoc snippet: {snippet_file.name}",
                base_snippet_path=str(snippet_file),
            )
        )

    logger.info(
        "discover_snippets_from_dir: found %d snippet(s) in %s", len(found), base_dir,
    )
    return found
