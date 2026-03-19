from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .io_utils import ensure_dir, logger


@dataclass
class BanditResult:
    high: int = 0
    medium: int = 0
    low: int = 0
    # Per-finding detail — each dict has: test_id, test_name, severity,
    # confidence, line_number, issue_text, cwe_id.
    issues: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


@dataclass
class SemgrepResult:
    findings: int = 0
    rules_matched: List[str] = field(default_factory=list)
    # Per-finding detail — each dict has: rule_id, severity, message,
    # line_number, matched_lines.
    issues: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


@dataclass
class StaticScanResult:
    bandit: BanditResult = field(default_factory=BanditResult)
    semgrep: SemgrepResult = field(default_factory=SemgrepResult)
    log_path: str = ""


def run_bandit(snippet_path: str) -> BanditResult:
    """
    Run Bandit SAST on a Python file and return severity counts plus per-finding detail.

    Bandit returns exit code 0 (no issues), 1 (issues found), or non-zero on error.
    Both 0 and 1 are treated as successful scans.
    """
    cmd = [sys.executable, "-m", "bandit", "-f", "json", "-q", snippet_path]
    logger.debug("Running bandit: %s", " ".join(cmd))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
        raw = proc.stdout or proc.stderr or ""
        if not raw.strip():
            return BanditResult(errors=["bandit returned empty output"])

        try:
            data: Dict[str, Any] = json.loads(raw)
        except json.JSONDecodeError:
            return BanditResult(errors=[f"bandit output was not valid JSON: {raw[:200]}"])

        metrics = data.get("metrics", {}).get("_totals", {})
        high = int(metrics.get("SEVERITY.HIGH", 0))
        medium = int(metrics.get("SEVERITY.MEDIUM", 0))
        low = int(metrics.get("SEVERITY.LOW", 0))

        issues: List[Dict[str, Any]] = []
        for r in data.get("results", []):
            cwe = r.get("issue_cwe") or {}
            issues.append({
                "test_id": r.get("test_id", ""),
                "test_name": r.get("test_name", ""),
                "severity": r.get("issue_severity", ""),
                "confidence": r.get("issue_confidence", ""),
                "line_number": r.get("line_number"),
                "issue_text": r.get("issue_text", ""),
                "cwe_id": cwe.get("id") if isinstance(cwe, dict) else None,
            })

        return BanditResult(high=high, medium=medium, low=low, issues=issues)

    except FileNotFoundError:
        return BanditResult(errors=["bandit not found; install with: pip install bandit"])
    except subprocess.TimeoutExpired:
        return BanditResult(errors=["bandit timed out after 60 seconds"])
    except Exception as exc:
        return BanditResult(errors=[str(exc)])


def _semgrep_binary() -> Optional[str]:
    """
    Return the semgrep executable path, or None if not found.

    Checks the same bin directory as the running Python interpreter first
    (covers venv installs), then falls back to PATH.
    """
    import shutil
    venv_semgrep = Path(sys.executable).parent / "semgrep"
    if venv_semgrep.exists():
        return str(venv_semgrep)
    return shutil.which("semgrep")


def run_semgrep(snippet_path: str, semgrep_config: str = "p/xss") -> SemgrepResult:
    """
    Run Semgrep on a Python file using the given rule config and return finding counts
    plus per-finding detail.

    semgrep_config can be a registry pack (e.g. "p/xss", "p/owasp-top-ten",
    "p/flask-security") or a path to a local rules directory.
    """
    binary = _semgrep_binary()
    if binary is None:
        return SemgrepResult(errors=["semgrep not found; install with: pip install semgrep"])

    cmd = [
        binary,
        "--config", semgrep_config,
        "--json",
        "--quiet",
        "--no-git-ignore",
        snippet_path,
    ]
    logger.debug("Running semgrep: %s", " ".join(cmd))

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        raw = proc.stdout or ""
        if not raw.strip():
            stderr = (proc.stderr or "").strip()
            if stderr:
                return SemgrepResult(errors=[f"semgrep error: {stderr[:300]}"])
            return SemgrepResult()

        try:
            data: Dict[str, Any] = json.loads(raw)
        except json.JSONDecodeError:
            return SemgrepResult(errors=[f"semgrep output was not valid JSON: {raw[:200]}"])

        results: List[Dict[str, Any]] = data.get("results", [])
        rules_matched = list({r.get("check_id", "unknown") for r in results})
        errors_list = [e.get("message", "") for e in data.get("errors", [])]

        issues: List[Dict[str, Any]] = []
        for r in results:
            extra = r.get("extra") or {}
            issues.append({
                "rule_id": r.get("check_id", ""),
                "severity": extra.get("severity", ""),
                "message": extra.get("message", ""),
                "line_number": (r.get("start") or {}).get("line"),
                "matched_lines": extra.get("lines", "").strip(),
            })

        return SemgrepResult(
            findings=len(results),
            rules_matched=rules_matched,
            issues=issues,
            errors=errors_list,
        )

    except FileNotFoundError:
        return SemgrepResult(errors=[f"semgrep binary not found at {binary}; install with: pip install semgrep"])
    except subprocess.TimeoutExpired:
        return SemgrepResult(errors=["semgrep timed out after 120 seconds"])
    except Exception as exc:
        return SemgrepResult(errors=[str(exc)])


def run_static_scan(
    snippet_path: str,
    backends: List[str],
    semgrep_config: str,
    agent: str,
    vulnerability_id: str,
    iteration: int,
    logs_dir: str,
) -> StaticScanResult:
    """
    Run all configured static analysis backends against a snippet file.

    Writes a combined JSON log to logs/<agent>/<vulnerability_id>/static_iteration_<N>.log
    and returns a StaticScanResult with findings and per-finding detail from each backend.
    """
    bandit_result = BanditResult()
    semgrep_result = SemgrepResult()

    if "bandit" in backends:
        logger.info(
            "Running bandit for agent=%s vuln=%s iteration=%d",
            agent, vulnerability_id, iteration,
        )
        bandit_result = run_bandit(snippet_path)
        if bandit_result.errors:
            logger.warning("Bandit errors: %s", bandit_result.errors)
        else:
            logger.info(
                "Bandit results: HIGH=%d MEDIUM=%d LOW=%d issues=%d",
                bandit_result.high, bandit_result.medium, bandit_result.low,
                len(bandit_result.issues),
            )

    if "semgrep" in backends:
        logger.info(
            "Running semgrep for agent=%s vuln=%s iteration=%d",
            agent, vulnerability_id, iteration,
        )
        semgrep_result = run_semgrep(snippet_path, semgrep_config)
        if semgrep_result.errors:
            logger.warning("Semgrep errors: %s", semgrep_result.errors)
        else:
            logger.info(
                "Semgrep results: findings=%d rules=%s",
                semgrep_result.findings, semgrep_result.rules_matched,
            )

    # Write combined log including per-finding detail.
    agent_log_dir = Path(logs_dir) / agent / vulnerability_id
    ensure_dir(agent_log_dir)
    log_path = str(agent_log_dir / f"static_iteration_{iteration}.log")

    log_data = {
        "snippet_path": snippet_path,
        "agent": agent,
        "vulnerability_id": vulnerability_id,
        "iteration": iteration,
        "bandit": {
            "high": bandit_result.high,
            "medium": bandit_result.medium,
            "low": bandit_result.low,
            "issues": bandit_result.issues,
            "errors": bandit_result.errors,
        },
        "semgrep": {
            "findings": semgrep_result.findings,
            "rules_matched": semgrep_result.rules_matched,
            "issues": semgrep_result.issues,
            "errors": semgrep_result.errors,
        },
    }
    Path(log_path).write_text(json.dumps(log_data, indent=2), encoding="utf-8")
    logger.info("Static scan log written to %s", log_path)

    return StaticScanResult(
        bandit=bandit_result,
        semgrep=semgrep_result,
        log_path=log_path,
    )
