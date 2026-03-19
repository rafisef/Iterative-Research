from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List

import yaml


LOGGER_NAME = "iterative_research"


def get_logger() -> logging.Logger:
  logger = logging.getLogger(LOGGER_NAME)
  if not logger.handlers:
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
      fmt="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
      datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
  return logger


logger = get_logger()

# Lock to ensure result index writes are atomic when running in parallel.
_RESULT_LOCK = threading.Lock()


def load_yaml_config(path: str | os.PathLike[str]) -> Dict[str, Any]:
  cfg_path = Path(path)
  if not cfg_path.exists():
    raise FileNotFoundError(f"Config file not found: {cfg_path}")
  with cfg_path.open("r", encoding="utf-8") as f:
    return yaml.safe_load(f) or {}


def ensure_dir(path: str | os.PathLike[str]) -> Path:
  p = Path(path)
  p.mkdir(parents=True, exist_ok=True)
  return p


def write_text(path: str | os.PathLike[str], content: str) -> None:
  p = Path(path)
  ensure_dir(p.parent)
  with p.open("w", encoding="utf-8") as f:
    f.write(content)


def read_text(path: str | os.PathLike[str]) -> str:
  p = Path(path)
  with p.open("r", encoding="utf-8") as f:
    return f.read()


@dataclass
class ResultRecord:
  agent: str
  vulnerability_id: str
  iteration: int
  prompt: str
  model: str
  success: bool
  server_started: bool
  nuclei_exit_code: int | None
  snippet_path: str
  log_path: str
  # Static analysis results (Bandit + Semgrep) — counts.
  bandit_high: int = 0
  bandit_medium: int = 0
  bandit_low: int = 0
  semgrep_findings: int = 0
  static_log_path: str = ""
  # Per-finding detail lists — each entry is a dict with tool-specific keys.
  # Bandit keys: test_id, test_name, severity, confidence, line_number, issue_text, cwe_id.
  # Semgrep keys: rule_id, severity, message, line_number, matched_lines.
  bandit_issues: List[Dict[str, Any]] = field(default_factory=list)
  semgrep_issues: List[Dict[str, Any]] = field(default_factory=list)
  # Identifier for the experiment run that produced this record (timestamp string).
  run_id: str = ""


def append_result_record(index_path: str | os.PathLike[str], record: ResultRecord) -> None:
  """
  Append a single JSON record (JSON Lines) to the results index file.
  """
  p = Path(index_path)
  ensure_dir(p.parent)
  line = json.dumps(asdict(record))
  with _RESULT_LOCK:
    with p.open("a", encoding="utf-8") as f:
      f.write(line)
      f.write("\n")

