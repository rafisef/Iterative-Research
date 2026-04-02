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

AI_CODE_DIR = "ai-generated-code-snippets"
_LEGACY_CODE_DIR = "outputs"


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
  semgrep_error: int = 0     # ERROR severity (HIGH) — likely vulnerabilities
  semgrep_warning: int = 0   # WARNING severity (MEDIUM) — potential issues
  semgrep_info: int = 0      # INFO severity (LOW) — informational
  static_log_path: str = ""
  # Per-finding detail lists — each entry is a dict with tool-specific keys.
  # Bandit keys: test_id, test_name, severity, confidence, line_number, issue_text, cwe_id.
  # Semgrep keys: rule_id, severity (ERROR/WARNING/INFO), message, line_number, matched_lines.
  bandit_issues: List[Dict[str, Any]] = field(default_factory=list)
  semgrep_issues: List[Dict[str, Any]] = field(default_factory=list)
  # Identifier for the experiment run that produced this record (timestamp string).
  run_id: str = ""


_BANDIT_FIELDS = {"bandit_high", "bandit_medium", "bandit_low", "bandit_issues"}
_SEMGREP_FIELDS = {"semgrep_findings", "semgrep_error", "semgrep_warning", "semgrep_info", "semgrep_issues"}


def result_record_to_dict(
    record: ResultRecord,
    scanners_used: List[str] | None = None,
) -> Dict[str, Any]:
  """
  Serialize a ResultRecord, conditionally omitting scanner fields
  that weren't used (e.g. no bandit keys for TypeScript-only scans).
  """
  d = asdict(record)
  if scanners_used is not None:
    if "bandit" not in scanners_used:
      for key in _BANDIT_FIELDS:
        d.pop(key, None)
    if "semgrep" not in scanners_used:
      for key in _SEMGREP_FIELDS:
        d.pop(key, None)
  return d


def append_result_record(
    index_path: str | os.PathLike[str],
    record: ResultRecord,
    scanners_used: List[str] | None = None,
) -> None:
  """
  Append a single JSON record (JSON Lines) to the results index file.

  When *scanners_used* is provided, scanner-specific fields for tools
  that were NOT run are omitted from the output.
  """
  p = Path(index_path)
  ensure_dir(p.parent)
  line = json.dumps(result_record_to_dict(record, scanners_used))
  with _RESULT_LOCK:
    with p.open("a", encoding="utf-8") as f:
      f.write(line)
      f.write("\n")


def resolve_code_dir(run_dir: Path) -> Path:
  """Return the code output directory for a run, with backward compat fallback."""
  new_dir = run_dir / AI_CODE_DIR
  if new_dir.exists():
    return new_dir
  legacy = run_dir / _LEGACY_CODE_DIR
  if legacy.exists():
    return legacy
  return new_dir

