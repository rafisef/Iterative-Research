from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Dict, List, Tuple

from .io_utils import ensure_dir, logger


def _build_nuclei_command(
  binary_path: str,
  target_url: str,
  tags: List[str],
  templates: List[str],
) -> List[str]:
  cmd: List[str] = [binary_path, "-u", target_url, "-vv", "-headless", "-c", "50"]

  if tags:
    # Join tags with commas for nuclei's -tags flag.
    cmd.extend(["-tags", ",".join(tags)])

  if templates:
    for tpl in templates:
      cmd.extend(["-t", tpl])

  # Nuclei itself does not have a built-in timeout flag for the process,
  # so we will enforce timeout using subprocess.
  return cmd


def run_nuclei_scan(
  target_url: str,
  agent: str,
  vulnerability_id: str,
  iteration: int,
  config: Dict,
) -> Tuple[int | None, str]:
  """
  Run nuclei against the given URL and write output to the appropriate log file.

  Returns (exit_code, log_path).
  """
  nuclei_cfg = config.get("nuclei", {})
  paths_cfg = config.get("paths", {})

  binary_path = nuclei_cfg.get("binary_path", "nuclei")
  tags = nuclei_cfg.get("tags", []) or []
  templates = nuclei_cfg.get("templates", []) or []
  timeout_cfg = nuclei_cfg.get("timeout_seconds", 60)
  try:
    timeout_seconds = int(timeout_cfg) if timeout_cfg is not None else 60
  except (TypeError, ValueError):
    timeout_seconds = 60

  logs_dir = paths_cfg.get("logs_dir", "logs")
  # Organize logs similar to outputs: logs/<agent>/<vulnerability_id>/iteration_<k>.log
  agent_log_dir = Path(logs_dir) / agent / vulnerability_id
  ensure_dir(agent_log_dir)
  log_path = str(agent_log_dir / f"iteration_{iteration}.log")

  cmd = _build_nuclei_command(binary_path, target_url, tags, templates)
  logger.info("Running nuclei: %s", " ".join(cmd))

  try:
    run_kwargs = {
      "args": cmd,
      "stdout": subprocess.PIPE,
      "stderr": subprocess.STDOUT,
      "text": True,
    }
    # If timeout_seconds <= 0, do not enforce a timeout; let nuclei run until it
    # completes naturally. Otherwise, use the configured timeout.
    if timeout_seconds > 0:
      run_kwargs["timeout"] = timeout_seconds

    proc = subprocess.run(**run_kwargs)
    output = proc.stdout or ""
    exit_code = proc.returncode
  except subprocess.TimeoutExpired as exc:
    output = f"NUCLEI TIMEOUT after {timeout_seconds} seconds\n{exc}"
    exit_code = None
  except FileNotFoundError:
    output = (
      f"NUCLEI ERROR: binary not found at '{binary_path}'. "
      "Ensure nuclei is installed and the path is correct."
    )
    exit_code = None

  # Write log file.
  Path(log_path).write_text(output, encoding="utf-8")
  logger.info("Nuclei log written to %s", log_path)
  return exit_code, log_path

