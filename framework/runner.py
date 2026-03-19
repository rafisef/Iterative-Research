from __future__ import annotations

import argparse
import json
import logging
import random
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

from .agents import resolve_agents_from_config
from .io_utils import ResultRecord, append_result_record, ensure_dir, load_yaml_config, logger, read_text, write_text
from .llm_client import get_llm_client
from .static_scanner import run_static_scan
from .vulnerabilities import resolve_vulnerabilities_from_config


def _parse_args() -> argparse.Namespace:
  parser = argparse.ArgumentParser(description="Iterative LLM vulnerability experiment runner.")
  parser.add_argument(
    "--config",
    type=str,
    default="config/config.yaml",
    help="Path to YAML configuration file.",
  )
  parser.add_argument(
    "--dry-run",
    action="store_true",
    help="Only generate code snippets; do not run scans.",
  )
  parser.add_argument(
    "--skip-static",
    action="store_true",
    help="Skip static analysis (Bandit/Semgrep) scans.",
  )
  parser.add_argument(
    "--run-id",
    type=str,
    default="",
    help=(
      "Override the auto-generated run ID (YYYY-MM-DD_HH-MM-SS). "
      "Useful for re-running or resuming a named experiment."
    ),
  )
  parser.add_argument(
    "--log",
    type=str,
    help="Base name for a log file; written to <run_dir>/logs/<name>.log.",
  )
  return parser.parse_args()


def _make_run_id() -> str:
  """Return a filesystem-safe timestamp string: YYYY-MM-DD_HH-MM-SS."""
  return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def _write_run_metadata(run_dir: Path, run_id: str, config: Dict) -> None:
  """
  Persist a JSON snapshot of the run configuration alongside results.
  This makes every run self-documenting and reproducible.
  """
  experiment_cfg = config.get("experiment", {})
  llm_cfg = config.get("llm", {})
  scanner_cfg = config.get("scanner", {})

  metadata = {
    "run_id": run_id,
    "started_at": datetime.now().isoformat(),
    "model": llm_cfg.get("model"),
    "temperature": llm_cfg.get("temperature"),
    "max_tokens": llm_cfg.get("max_tokens"),
    "iterations": experiment_cfg.get("iterations"),
    "agents": experiment_cfg.get("agents", []),
    "vulnerabilities": experiment_cfg.get("vulnerabilities", []),
    "random_seed": experiment_cfg.get("random_seed"),
    "dry_run": experiment_cfg.get("dry_run", False),
    "scanner_backends": scanner_cfg.get("backends", []),
    "semgrep_config": scanner_cfg.get("semgrep_config"),
  }

  meta_path = run_dir / "run_metadata.json"
  meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
  logger.info("Run metadata written to %s", meta_path)


def run_experiment(config_path: str | None = None, cli_args: Dict | None = None) -> None:
  """
  Main entrypoint for running the experiment programmatically.

  Each invocation creates a new timestamped run directory:
    runs/<YYYY-MM-DD_HH-MM-SS>/
      outputs/    — LLM-generated code per agent/vuln/iteration
      logs/       — Bandit + Semgrep static scan logs
      results.jsonl
      run_metadata.json

  Nuclei dynamic scanning is handled separately via nuclei_rescan.py after
  the run completes, targeting only iterations where static scans found issues.
  """
  if config_path is None or cli_args is None:
    args = _parse_args()
    config_path = args.config
    dry_run_flag = args.dry_run
    skip_static_flag = args.skip_static
    run_id_override = args.run_id
    log_name = args.log
  else:
    dry_run_flag = bool(cli_args.get("dry_run", False))
    skip_static_flag = bool(cli_args.get("skip_static", False))
    run_id_override = cli_args.get("run_id", "")
    log_name = cli_args.get("log")

  config = load_yaml_config(config_path)
  if dry_run_flag:
    config.setdefault("experiment", {})
    config["experiment"]["dry_run"] = True

  experiment_cfg = config.get("experiment", {})
  iterations = int(experiment_cfg.get("iterations", 10))
  agent_ids = experiment_cfg.get("agents", [])
  vuln_ids = experiment_cfg.get("vulnerabilities", [])
  dry_run = bool(experiment_cfg.get("dry_run", False))

  # Seed the RNG for reproducible prompt selection across runs.
  seed = experiment_cfg.get("random_seed")
  if seed is not None:
    random.seed(int(seed))
    logger.info("Random seed set to %s for reproducible prompt selection.", seed)

  # Static scanner config.
  scanner_cfg = config.get("scanner", {})
  static_backends: List[str] = scanner_cfg.get("backends", [])
  semgrep_config: str = scanner_cfg.get("semgrep_config", "p/xss")
  run_static = bool(static_backends) and not skip_static_flag

  paths_cfg = config.get("paths", {})
  runs_dir = paths_cfg.get("runs_dir", "runs")
  snippets_dir = paths_cfg.get("snippets_dir", "snippets")

  # --- Build the timestamped run directory -----------------------------------
  run_id = run_id_override.strip() or _make_run_id()
  run_dir = Path(runs_dir) / run_id
  ensure_dir(run_dir)

  # All paths for this run live inside run_dir.
  outputs_dir = str(run_dir / "outputs")
  logs_dir = str(run_dir / "logs")
  results_index = str(run_dir / "results.jsonl")

  ensure_dir(outputs_dir)
  ensure_dir(snippets_dir)

  logger.info("=" * 60)
  logger.info("Run ID   : %s", run_id)
  logger.info("Run dir  : %s", run_dir.resolve())
  logger.info("=" * 60)

  _write_run_metadata(run_dir, run_id, config)

  if log_name:
    ensure_dir(logs_dir)
    log_path = Path(logs_dir) / f"{log_name}.log"
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(
      logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
      )
    )
    logger.addHandler(file_handler)
    logger.info("File logging enabled: %s", log_path)

  agents = resolve_agents_from_config(agent_ids)
  vulns = resolve_vulnerabilities_from_config(vuln_ids)
  llm_client = get_llm_client(config_path=config_path)

  max_workers = int(experiment_cfg.get("max_workers", 1))
  if max_workers < 1:
    max_workers = 1

  llm_cfg = config.get("llm", {})
  logger.info(
    "LLM configuration: model=%s temperature=%s top_p=%s max_tokens=%s",
    llm_cfg.get("model"),
    llm_cfg.get("temperature"),
    llm_cfg.get("top_p"),
    llm_cfg.get("max_tokens"),
  )
  logger.info(
    "Scanner configuration: static_backends=%s semgrep_config=%s",
    static_backends,
    semgrep_config,
  )
  logger.info(
    "Starting experiment: iterations=%d agents=%s vulns=%s dry_run=%s",
    iterations,
    [a.id for a in agents],
    [v.id for v in vulns],
    dry_run,
  )

  def _process_single_agent_iteration(
    vuln_id: str,
    vuln_base_snippet: str,
    agent_idx: int,
    agent,
    iteration: int,
  ) -> Tuple[str, int]:
    """
    Runs one full iteration for a single agent: LLM generation, static
    analysis (Bandit + Semgrep), and result recording. All output is written
    inside the current run_dir.

    Nuclei dynamic scanning is intentionally excluded here — run
    nuclei_rescan.py after the experiment to target only the iterations
    where static scans found vulnerabilities.
    """

    # Resolve input code — always within this run's outputs directory.
    if iteration == 0:
      input_code = vuln_base_snippet
    else:
      prev_path = Path(outputs_dir) / agent.id / vuln_id / f"iteration_{iteration - 1}.py"
      try:
        input_code = read_text(prev_path)
      except FileNotFoundError:
        logger.warning(
          "Previous snippet not found for agent=%s vuln=%s iteration=%d at %s; "
          "falling back to base snippet.",
          agent.id,
          vuln_id,
          iteration,
          prev_path,
        )
        input_code = vuln_base_snippet

    # Generate code via LLM.
    instruction = agent.random_instruction()
    logger.info(
      "Iteration %d for agent=%s vuln=%s | prompt=%s",
      iteration,
      agent.id,
      vuln_id,
      instruction,
    )
    generated_code = llm_client.generate_from_snippet(input_code, instruction)
    if not generated_code.strip():
      logger.warning("Empty code generated for agent=%s iteration=%d", agent.id, iteration)

    # Syntax check.
    try:
      compile(generated_code, "<generated-snippet>", "exec")
    except SyntaxError as exc:
      logger.warning(
        "Generated code has syntax error for agent=%s iteration=%d: %s",
        agent.id,
        iteration,
        exc,
      )

    # Save snippet inside run_dir/outputs/<agent>/<vuln>/iteration_N.py
    agent_dir = Path(outputs_dir) / agent.id / vuln_id
    ensure_dir(agent_dir)
    snippet_path = agent_dir / f"iteration_{iteration}.py"
    write_text(snippet_path, generated_code)

    # Initialise static scan result fields.
    bandit_high = 0
    bandit_medium = 0
    bandit_low = 0
    semgrep_count = 0
    static_log_path = ""
    bandit_issues: list = []
    semgrep_issues: list = []

    if dry_run:
      logger.info(
        "Dry-run enabled; skipping all scans for agent=%s iteration=%d.",
        agent.id,
        iteration,
      )
      record = ResultRecord(
        agent=agent.id,
        vulnerability_id=vuln_id,
        iteration=iteration,
        prompt=instruction,
        model=config.get("llm", {}).get("model", "unknown"),
        success=False,
        server_started=False,
        nuclei_exit_code=None,
        snippet_path=str(snippet_path),
        log_path="",
        run_id=run_id,
      )

      append_result_record(results_index, record)
      return agent.id, iteration

    # --- Static analysis (Bandit + Semgrep) — fast, no server required. ---
    if run_static:
      static_result = run_static_scan(
        snippet_path=str(snippet_path),
        backends=static_backends,
        semgrep_config=semgrep_config,
        agent=agent.id,
        vulnerability_id=vuln_id,
        iteration=iteration,
        logs_dir=logs_dir,
      )
      bandit_high = static_result.bandit.high
      bandit_medium = static_result.bandit.medium
      bandit_low = static_result.bandit.low
      semgrep_count = static_result.semgrep.findings
      static_log_path = static_result.log_path
      bandit_issues = static_result.bandit.issues
      semgrep_issues = static_result.semgrep.issues

    success = run_static and not dry_run

    record = ResultRecord(
      agent=agent.id,
      vulnerability_id=vuln_id,
      iteration=iteration,
      prompt=instruction,
      model=config.get("llm", {}).get("model", "unknown"),
      success=success,
      server_started=False,
      nuclei_exit_code=None,
      snippet_path=str(snippet_path),
      log_path="",
      bandit_high=bandit_high,
      bandit_medium=bandit_medium,
      bandit_low=bandit_low,
      semgrep_findings=semgrep_count,
      static_log_path=static_log_path,
      bandit_issues=bandit_issues,
      semgrep_issues=semgrep_issues,
      run_id=run_id,
    )
    append_result_record(results_index, record)
    return agent.id, iteration

  # Main loop.
  for vuln in vulns:
    logger.info("Processing vulnerability: %s", vuln.id)
    base_snippet = read_text(vuln.base_snippet_path)

    for iteration in range(iterations):
      logger.info(
        "Starting iteration %d for vuln=%s across %d agents (max_workers=%d)",
        iteration, vuln.id, len(agents), max_workers,
      )

      if max_workers == 1:
        for agent_idx, agent in enumerate(agents):
          _process_single_agent_iteration(
            vuln_id=vuln.id,
            vuln_base_snippet=base_snippet,
            agent_idx=agent_idx,
            agent=agent,
            iteration=iteration,
          )
      else:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
          futures = [
            executor.submit(
              _process_single_agent_iteration,
              vuln.id,
              base_snippet,
              agent_idx,
              agent,
              iteration,
            )
            for agent_idx, agent in enumerate(agents)
          ]
          for future in as_completed(futures):
            future.result()

  logger.info("Run complete. Results: %s", results_index)


if __name__ == "__main__":
  run_experiment()
