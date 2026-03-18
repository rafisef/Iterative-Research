from __future__ import annotations

import argparse
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, Iterable, Tuple

from .agents import resolve_agents_from_config
from .io_utils import ResultRecord, append_result_record, ensure_dir, load_yaml_config, logger, read_text, write_text
from .llm_client import get_llm_client
from .scanner import run_nuclei_scan
from .server_runner import start_snippet_server, stop_server, wait_for_healthcheck
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
    help="Only generate code snippets; do not start servers or run nuclei scans.",
  )
  parser.add_argument(
    "--skip-nuclei",
    action="store_true",
    help="Skip nuclei scans even when not in dry-run mode.",
  )
  parser.add_argument(
    "--log",
    type=str,
    help="Base name for a log file; when set, console logs are also written to logs/<name>.log.",
  )
  return parser.parse_args()


def run_experiment(config_path: str | None = None, cli_args: Dict | None = None) -> None:
  """
  Main entrypoint for running the experiment programmatically.
  """
  if config_path is None or cli_args is None:
    args = _parse_args()
    config_path = args.config
    dry_run_flag = args.dry_run
    skip_nuclei_flag = args.skip_nuclei
    log_name = args.log
  else:
    dry_run_flag = bool(cli_args.get("dry_run", False))
    skip_nuclei_flag = bool(cli_args.get("skip_nuclei", False))
    log_name = cli_args.get("log")

  config = load_yaml_config(config_path)
  # CLI dry-run overrides config.
  if dry_run_flag:
    config.setdefault("experiment", {})
    config["experiment"]["dry_run"] = True

  experiment_cfg = config.get("experiment", {})
  iterations = int(experiment_cfg.get("iterations", 10))
  agent_ids = experiment_cfg.get("agents", [])
  vuln_ids = experiment_cfg.get("vulnerabilities", [])
  dry_run = bool(experiment_cfg.get("dry_run", False))
  # Whether to run nuclei; CLI --skip-nuclei can override this.
  run_nuclei = bool(experiment_cfg.get("run_nuclei", True))
  if skip_nuclei_flag:
    run_nuclei = False

  server_cfg = config.get("server", {})
  host = server_cfg.get("host", "127.0.0.1")
  base_port = int(server_cfg.get("base_port", 9000))
  startup_timeout_seconds = int(server_cfg.get("startup_timeout_seconds", 20))

  paths_cfg = config.get("paths", {})
  outputs_dir = paths_cfg.get("outputs_dir", "outputs")
  snippets_dir = paths_cfg.get("snippets_dir", "snippets")
  results_index = paths_cfg.get("results_index", "results.jsonl")

  ensure_dir(outputs_dir)
  ensure_dir(snippets_dir)

  # Optional file logging: if a log name is provided, mirror console logs to logs/<name>.log.
  if log_name:
    logs_dir = paths_cfg.get("logs_dir", "logs")
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

  # Parallelism configuration – number of agents processed concurrently per iteration.
  max_workers = int(experiment_cfg.get("max_workers", 1))
  if max_workers < 1:
    max_workers = 1

  # Log static LLM configuration once at the start of the run.
  llm_cfg = config.get("llm", {})
  logger.info(
    "LLM configuration: model=%s temperature=%s top_p=%s max_tokens=%s",
    llm_cfg.get("model"),
    llm_cfg.get("temperature"),
    llm_cfg.get("top_p"),
    llm_cfg.get("max_tokens"),
  )

  logger.info(
    "Starting experiment: iterations=%d agents=%s vulns=%s dry_run=%s",
    iterations,
    [a.id for a in agents],
    [v.id for v in vulns],
    dry_run,
  )

  # Helper to process a single agent for a given vulnerability and iteration.
  def _process_single_agent_iteration(
    vuln_id: str,
    vuln_base_snippet: str,
    agent_idx: int,
    agent,
    iteration: int,
  ) -> Tuple[str, int]:
    """
    Runs one full iteration for a single agent (LLM generation, optional serving
    and nuclei scanning), then appends a ResultRecord. Returns (agent_id, iteration).
    """

    # Determine the input code for this iteration.
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

    # Generate code using the LLM with a randomly selected prompt for this agent.
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

    # Best-effort syntax check.
    try:
      compile(generated_code, "<generated-snippet>", "exec")
    except SyntaxError as exc:
      logger.warning(
        "Generated code has syntax error for agent=%s iteration=%d: %s",
        agent.id,
        iteration,
        exc,
      )

    # Save snippet for this iteration.
    agent_dir = Path(outputs_dir) / agent.id / vuln_id
    ensure_dir(agent_dir)
    snippet_path = agent_dir / f"iteration_{iteration}.py"
    write_text(snippet_path, generated_code)

    # If dry-run, skip serving and scanning.
    if dry_run:
      logger.info(
        "Dry-run enabled; skipping server and nuclei for agent=%s iteration=%d.",
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
      )
      append_result_record(results_index, record)
      return agent.id, iteration

    # Start server and wait for health.
    port = base_port + agent_idx * 100 + iteration
    proc = None
    server_started = False
    nuclei_exit_code = None
    log_path = ""
    try:
      proc = start_snippet_server(str(snippet_path), port)
      server_started = wait_for_healthcheck(host, port, startup_timeout_seconds)
      if not server_started:
        logger.warning(
          "Server failed to start or health check failed for agent=%s iteration=%d",
          agent.id,
          iteration,
        )
      else:
        target_url = f"http://{host}:{port}/"
        if run_nuclei:
          nuclei_exit_code, log_path = run_nuclei_scan(
            target_url=target_url,
            agent=agent.id,
            vulnerability_id=vuln_id,
            iteration=iteration,
            config=config,
          )
        else:
          logger.info("Skipping nuclei scan for agent=%s iteration=%d (run_nuclei=False)", agent.id, iteration)
    finally:
      stop_server(proc)

    # Treat a run as successful if the server started and either nuclei
    # completed (exit code is not None) or nuclei was intentionally skipped.
    success = server_started and (not run_nuclei or nuclei_exit_code is not None)
    record = ResultRecord(
      agent=agent.id,
      vulnerability_id=vuln_id,
      iteration=iteration,
      prompt=instruction,
      model=config.get("llm", {}).get("model", "unknown"),
      success=success,
      server_started=server_started,
      nuclei_exit_code=nuclei_exit_code,
      snippet_path=str(snippet_path),
      log_path=log_path,
    )
    append_result_record(results_index, record)
    return agent.id, iteration

  # Main loop: per vulnerability, process each iteration; within an iteration,
  # process agents concurrently up to max_workers.
  for vuln in vulns:
    logger.info("Processing vulnerability: %s", vuln.id)
    base_snippet = read_text(vuln.base_snippet_path)

    for iteration in range(iterations):
      logger.info("Starting iteration %d for vuln=%s across %d agents (max_workers=%d)", iteration, vuln.id, len(agents), max_workers)

      if max_workers == 1:
        # Sequential execution (original behavior).
        for agent_idx, agent in enumerate(agents):
          _process_single_agent_iteration(
            vuln_id=vuln.id,
            vuln_base_snippet=base_snippet,
            agent_idx=agent_idx,
            agent=agent,
            iteration=iteration,
          )
      else:
        # Parallel execution across agents for this iteration.
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
          # Wait for all agents to complete this iteration; exceptions will surface here.
          for future in as_completed(futures):
            future.result()


if __name__ == "__main__":
  run_experiment()

