from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from .agents import resolve_agents_from_config
from .analyzer import analyze_run
from .generator import discover_snippets_from_dir, generate_code, write_run_metadata
from .io_utils import AI_CODE_DIR, ensure_dir, load_yaml_config, logger, read_text
from .llm_client import detect_available_models, get_llm_client
from .scan_runner import run_scans
from .static_scanner import detect_language, run_static_scan
from .vulnerabilities import Vulnerability, resolve_vulnerabilities_from_config


_TEST_RUN_DEFAULT_SNIPPET = "snippets/typescript/leakage/info_leakage_user_safe_base.ts"


def _parse_args() -> argparse.Namespace:
  parser = argparse.ArgumentParser(description="Iterative LLM vulnerability experiment runner.")
  parser.add_argument(
    "--config",
    type=str,
    default="config/config.yaml",
    help="Path to YAML configuration file.",
  )
  parser.add_argument(
    "--test-run",
    nargs="?",
    const=_TEST_RUN_DEFAULT_SNIPPET,
    default=None,
    metavar="SNIPPET",
    help=(
      "Run the LLM once (1 iteration, 1 vuln, 1 agent) AND run static scanners against "
      "a single snippet file. Optionally pass a path to the snippet to scan; omitting "
      f"the value defaults to {_TEST_RUN_DEFAULT_SNIPPET}. "
      "Scan results are logged but no output files or result records are written."
    ),
  )
  parser.add_argument(
    "--iterations",
    type=int,
    default=None,
    help=(
      "Number of iterations to run. Overrides experiment.iterations in config. "
      "Default when not specified: 5 (or 1 when --test-run is active)."
    ),
  )
  parser.add_argument(
    "--model",
    type=str,
    default=None,
    metavar="MODEL",
    help=(
      "LLM model to use. Overrides llm.model in config. Default: gpt-4o. "
      "Use 'all' to run against every provider whose API key is set in the environment. "
      "Examples: gpt-4o-mini  anthropic/claude-3-5-sonnet-20241022  groq/llama-3.3-70b-versatile  all"
    ),
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
  source_group = parser.add_mutually_exclusive_group()
  source_group.add_argument(
    "--snippet",
    type=str,
    default=None,
    metavar="PATH",
    help=(
      "Run the full experiment against a single snippet file, bypassing the "
      "vulnerability registry. Language is inferred from the file extension "
      "(.py → Python; .ts/.js and variants → TypeScript). The file's stem is "
      "used as the vulnerability ID in results and output paths. All other flags "
      "(--iterations, --model, --config scanner settings, etc.) apply as normal."
    ),
  )
  source_group.add_argument(
    "--base-code-dir",
    type=str,
    default=None,
    metavar="DIR",
    help=(
      "Run the full experiment against all snippet files found recursively under DIR, "
      "bypassing the vulnerability registry. Each file becomes its own vulnerability; "
      "IDs are derived from the relative file path (e.g. python/injection/xss_base.py "
      "→ python_injection_xss_base). Supported extensions: "
      ".py, .ts, .tsx, .js, .jsx, .mjs, .cjs. "
      "Mutually exclusive with --snippet."
    ),
  )
  return parser.parse_args()


def _make_run_id() -> str:
  """Return a filesystem-safe timestamp string: YYYY-MM-DD_HH-MM-SS."""
  return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def _execute_test_run(
  config: Dict,
  config_path: str,
  agents: list,
  vulns: list,
  test_run_snippet: str,
  run_dir: Path,
  run_id: str,
  active_model: str,
  iterations: int,
  logs_dir: str,
) -> None:
  """
  Execute the --test-run path: one LLM call + static scan of the specified
  snippet. No output files, outputs directory, or result records are written.
  """
  llm_client = get_llm_client(config_path=config_path, model_override=active_model)

  for vuln in vulns:
    vuln_language = detect_language(vuln.base_snippet_path)
    base_snippet = read_text(vuln.base_snippet_path)

    for iteration in range(iterations):
      for agent in agents:
        instruction = agent.random_instruction()
        logger.info(
          "Test-run iteration %d for agent=%s vuln=%s | prompt=%s",
          iteration, agent.id, vuln.id, instruction,
        )
        generated_code = llm_client.generate_from_snippet(
          base_snippet, instruction, language=vuln_language,
        )
        if not generated_code.strip():
          logger.warning(
            "Empty code generated for agent=%s vuln=%s iteration=%d",
            agent.id, vuln.id, iteration,
          )
        else:
          logger.info(
            "LLM response received for agent=%s vuln=%s iteration=%d (%d chars).",
            agent.id, vuln.id, iteration, len(generated_code),
          )
        logger.info(
          "Test-run complete for agent=%s vuln=%s iteration=%d — no files written.",
          agent.id, vuln.id, iteration,
        )

  # Static scan of the specified snippet file.
  if not Path(test_run_snippet).exists():
    logger.warning(
      "Test-run snippet not found, skipping static scan: %s", test_run_snippet,
    )
    return

  ensure_dir(logs_dir)
  logger.info("Test-run: running static scan against %s", test_run_snippet)

  agent = agents[0]
  vuln = vulns[0]
  test_static_result = run_static_scan(
    snippet_path=test_run_snippet,
    agent=agent.id,
    vulnerability_id=vuln.id,
    iteration=0,
    logs_dir=logs_dir,
  )

  separator = "=" * 60
  is_py_snippet = test_run_snippet.endswith(".py")
  bandit_line = (
    f"  Bandit  : HIGH={test_static_result.bandit.high}  "
    f"MEDIUM={test_static_result.bandit.medium}  "
    f"LOW={test_static_result.bandit.low}\n"
    if is_py_snippet else ""
  )
  logger.info(
    "\n%s\nTest-run scan results for %s\n"
    "%s"
    "  Semgrep : findings=%d\n"
    "  Log     : %s\n%s",
    separator,
    test_run_snippet,
    bandit_line,
    test_static_result.semgrep.findings,
    test_static_result.log_path,
    separator,
  )


def run_experiment(config_path: str | None = None, cli_args: Dict | None = None) -> None:
  """
  Main entrypoint for running the full three-component pipeline.

  Each invocation creates a new timestamped run directory:
    runs/<YYYY-MM-DD_HH-MM-SS>/
      ai-generated-code-snippets/ — LLM-generated code per agent/vuln/iteration
      logs/       — Bandit + Semgrep static scan logs
      results.jsonl
      run_metadata.json
      generation_log.jsonl

  Pipeline components
  -------------------
  1. generate_code()  — LLM generation; writes ai-generated-code-snippets/ and generation_log.jsonl
  2. run_scans()      — static analysis; writes logs/ and results.jsonl
  3. analyze_run()    — prints human-readable report from results.jsonl

  Use ``--test-run`` for a lightweight single-call check (no disk writes except
  the scan log). For a pure LLM connectivity check with no static scanning, use
  ``python utils/test_llm_connectivity.py`` instead.

  Nuclei dynamic scanning is handled separately via utils/nuclei_rescan.py after
  the run completes, targeting only iterations where static scans found issues.
  """
  if config_path is None or cli_args is None:
    args = _parse_args()
    config_path = args.config
    iterations_override = args.iterations
    model_arg = args.model
    run_id_override = args.run_id
    log_name = args.log
    test_run_snippet: str | None = args.test_run
    snippet_path_arg: str | None = args.snippet
    base_code_dir_arg: str | None = args.base_code_dir
  else:
    iterations_override = cli_args.get("iterations", None)
    model_arg = cli_args.get("model", None)
    run_id_override = cli_args.get("run_id", "")
    log_name = cli_args.get("log")
    test_run_snippet = cli_args.get("test_run", None)
    snippet_path_arg = cli_args.get("snippet", None)
    base_code_dir_arg = cli_args.get("base_code_dir", None)

  test_run_flag = test_run_snippet is not None

  config = load_yaml_config(config_path)

  # --- Resolve model(s) to run against ---------------------------------------
  config_model = config.get("llm", {}).get("model", "gpt-4o")

  if model_arg is None:
    models_to_run: List[str] = [config_model]
  elif model_arg.lower() == "all":
    models_to_run = detect_available_models()
    if not models_to_run:
      logger.warning(
        "--model all specified but no provider API keys detected in environment. "
        "Falling back to config model: %s", config_model,
      )
      models_to_run = [config_model]
    elif len(models_to_run) == 1:
      logger.info("--model all: only one provider key found, running with %s.", models_to_run[0])
  else:
    models_to_run = [model_arg]

  # Multi-model: dispatch a separate run for each model then return.
  if len(models_to_run) > 1:
    logger.info(
      "--model all: running experiment across %d models: %s", len(models_to_run), models_to_run,
    )
    base_run_id = run_id_override.strip() or _make_run_id()
    for model in models_to_run:
      model_slug = model.split("/")[-1]
      run_experiment(
        config_path=config_path,
        cli_args={
          "iterations": iterations_override,
          "model": model,
          "run_id": f"{base_run_id}_{model_slug}",
          "log": log_name,
          "test_run": test_run_snippet,
          "snippet": snippet_path_arg,
          "base_code_dir": base_code_dir_arg,
        },
      )
    return

  # Single model: inject into config so all downstream code uses it uniformly.
  active_model = models_to_run[0]
  config.setdefault("llm", {})
  config["llm"]["model"] = active_model

  experiment_cfg = config.get("experiment", {})

  # Resolve iteration count: CLI --iterations > test-run cap > config > default of 5.
  if iterations_override is not None:
    iterations = int(iterations_override)
  elif test_run_flag:
    iterations = 1
  else:
    iterations = int(experiment_cfg.get("iterations", 5))

  agent_ids = experiment_cfg.get("agents", [])
  vuln_ids = experiment_cfg.get("vulnerabilities", [])
  seed = experiment_cfg.get("random_seed")
  max_workers = max(1, int(experiment_cfg.get("max_workers", 1)))

  paths_cfg = config.get("paths", {})
  runs_dir = paths_cfg.get("runs_dir", "runs")

  run_id = run_id_override.strip() or _make_run_id()
  run_dir = Path(runs_dir) / run_id
  ensure_dir(run_dir)

  logs_dir = str(run_dir / "logs")
  results_index = str(run_dir / "results.jsonl")

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

  agents = resolve_agents_from_config(agent_ids, agents_cfg=config.get("agents", {}))

  if snippet_path_arg is not None:
    snippet_file = Path(snippet_path_arg)
    if not snippet_file.exists():
      logger.error("--snippet file not found: %s", snippet_path_arg)
      sys.exit(1)
    _language = detect_language(snippet_path_arg)
    if _language == "unknown":
      logger.warning(
        "--snippet: unrecognised extension for %s; Semgrep will still run with default packs.",
        snippet_path_arg,
      )
    vulns = [
      Vulnerability(
        id=snippet_file.stem,
        description=f"Ad-hoc snippet: {snippet_file.name}",
        base_snippet_path=str(snippet_file),
      )
    ]
    logger.info(
      "--snippet: running experiment against %s (language=%s, vuln_id=%s)",
      snippet_path_arg, _language, snippet_file.stem,
    )
  elif base_code_dir_arg is not None:
    try:
      vulns = discover_snippets_from_dir(Path(base_code_dir_arg))
    except (FileNotFoundError, NotADirectoryError) as exc:
      logger.error("%s", exc)
      sys.exit(1)
    if not vulns:
      logger.error(
        "--base-code-dir: no supported snippet files found in %s. "
        "Supported extensions: .py, .ts, .tsx, .js, .jsx, .mjs, .cjs",
        base_code_dir_arg,
      )
      sys.exit(1)
    logger.info(
      "--base-code-dir: discovered %d snippet(s) in %s",
      len(vulns), base_code_dir_arg,
    )
  else:
    vulns = resolve_vulnerabilities_from_config(vuln_ids)

  # --test-run: scope to the first vuln and first agent for a minimal check.
  if test_run_flag:
    vulns = vulns[:1]
    agents = agents[:1]

  # Print the startup banner.
  llm_cfg = config.get("llm", {})
  meta_path = str(run_dir / "run_metadata.json")
  if test_run_flag:
    scanners_line = f"test run — auto-detected  snippet={test_run_snippet}"
  else:
    scanners_line = (
      "auto-detected per snippet language (Bandit+Semgrep for Python, Semgrep for TypeScript)"
    )
  col = 19
  separator = "=" * 60
  if snippet_path_arg is not None:
    snippet_banner_line = f"\n%-*s{snippet_path_arg}" % (col, "Snippet")
  elif base_code_dir_arg is not None:
    snippet_banner_line = (
      f"\n%-*s{base_code_dir_arg} ({len(vulns)} snippets)" % (col, "Base code dir")
    )
  else:
    snippet_banner_line = ""
  logger.info(
    "\n%s\n%-*s%s\n%-*s%s\n%-*s%s\n%-*s%s\n%-*s%s\n%-*s%s\n%-*s%s%s\n%s",
    separator,
    col, "Random seed",   seed if seed is not None else "none",
    col, "Run ID",        run_id,
    col, "Run dir",       run_dir.resolve(),
    col, "LLM Provider",  f"model={active_model}",
    col, "Configuration", (
      f"iterations={iterations}  temperature={llm_cfg.get('temperature')}  "
      f"top_p={llm_cfg.get('top_p')}  max_tokens={llm_cfg.get('max_tokens')}"
    ),
    col, "Scanners",      scanners_line,
    col, "Metadata",      meta_path,
    snippet_banner_line,
    separator,
  )

  # --test-run: lightweight single-call check — no output files or results.jsonl.
  if test_run_flag:
    write_run_metadata(
      run_dir=run_dir,
      run_id=run_id,
      config=config,
      effective_iterations=iterations,
      effective_agents=[a.id for a in agents],
      effective_vulns=[v.id for v in vulns],
      test_run_snippet=test_run_snippet,
      snippet_path_arg=snippet_path_arg,
      base_code_dir_arg=base_code_dir_arg,
    )
    _execute_test_run(
      config=config,
      config_path=config_path,
      agents=agents,
      vulns=vulns,
      test_run_snippet=test_run_snippet,
      run_dir=run_dir,
      run_id=run_id,
      active_model=active_model,
      iterations=iterations,
      logs_dir=logs_dir,
    )
    return

  # Full pipeline: generate → scan → analyze.
  generate_code(
    config=config,
    config_path=config_path,
    run_dir=run_dir,
    agents=agents,
    vulns=vulns,
    iterations=iterations,
    max_workers=max_workers,
    seed=seed,
    model_override=active_model,
    test_run_snippet=test_run_snippet,
    snippet_path_arg=snippet_path_arg,
    base_code_dir_arg=base_code_dir_arg,
  )

  run_scans(run_dir=run_dir, config=config, max_workers=max_workers)

  analyze_run(run_dir=run_dir)

  logger.info("Run complete. Results: %s", results_index)


if __name__ == "__main__":
  run_experiment()
