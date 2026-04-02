from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .io_utils import ensure_dir, logger


# ---------------------------------------------------------------------------
# Language detection registry
# ---------------------------------------------------------------------------

_PYTHON_EXTS: frozenset[str] = frozenset({".py"})
_JS_TS_EXTS: frozenset[str] = frozenset({".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"})

# Default Semgrep rule packs per language (space-separated; passed as --config flags).
_DEFAULT_SEMGREP_PACKS: Dict[str, str] = {
    "python":     "p/python p/bandit p/owasp-top-ten",
    "typescript": "p/typescript p/javascript p/owasp-top-ten",
}

# Ordered list of scanner backends to invoke per language.
# To add a new scanner: implement run_<tool>(), add its name here.
_ENABLED_SCANNERS: Dict[str, List[str]] = {
    "python":     ["bandit", "semgrep"],
    "typescript": ["semgrep"],
}


def detect_language(path: str) -> str:
    """Infer the programming language from the file extension."""
    ext = Path(path).suffix.lower()
    if ext in _PYTHON_EXTS:
        return "python"
    if ext in _JS_TS_EXTS:
        return "typescript"
    return "unknown"


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class BanditResult:
    high: int = 0
    medium: int = 0
    low: int = 0
    issues: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


@dataclass
class SemgrepResult:
    findings: int = 0
    rules_matched: List[str] = field(default_factory=list)
    issues: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


@dataclass
class StaticScanResult:
    bandit: BanditResult = field(default_factory=BanditResult)
    semgrep: SemgrepResult = field(default_factory=SemgrepResult)
    log_path: str = ""


# ---------------------------------------------------------------------------
# Bandit (Python only)
# ---------------------------------------------------------------------------

def run_bandit(snippet_path: str) -> BanditResult:
    """Run Bandit SAST on a Python file and return severity counts plus per-finding detail."""
    cmd = [sys.executable, "-m", "bandit", "-f", "json", "-q", snippet_path]
    logger.debug("Running bandit: %s", " ".join(cmd))

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
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


# ---------------------------------------------------------------------------
# Semgrep (all languages)
# ---------------------------------------------------------------------------

def _semgrep_binary() -> Optional[str]:
    """Return the semgrep executable path, or None if not found."""
    import shutil
    venv_semgrep = Path(sys.executable).parent / "semgrep"
    if venv_semgrep.exists():
        return str(venv_semgrep)
    return shutil.which("semgrep")


def run_semgrep(snippet_path: str, semgrep_config: str = "p/xss") -> SemgrepResult:
    """
    Run Semgrep using the given rule config(s) and return finding counts plus
    per-finding detail.

    semgrep_config can be space-separated packs (e.g. "p/javascript p/owasp-top-ten").
    Each pack is passed as a separate --config flag to a single invocation.
    """
    binary = _semgrep_binary()
    if binary is None:
        return SemgrepResult(errors=["semgrep not found; install with: pip install semgrep"])

    configs = semgrep_config.split()
    if not configs:
        configs = ["p/xss"]

    cmd = [binary]
    for cfg in configs:
        cmd += ["--config", cfg]
    cmd += ["--json", "--quiet", "--no-git-ignore", snippet_path]
    logger.debug("Running semgrep: %s", " ".join(cmd))

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
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


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_static_scan(
    snippet_path: str,
    agent: str,
    vulnerability_id: str,
    iteration: int,
    logs_dir: str,
    semgrep_config_override: str = "",
) -> StaticScanResult:
    """
    Run all applicable static analysis backends against a snippet file.

    The language is detected automatically from the file extension and the
    appropriate scanners from _ENABLED_SCANNERS are invoked.  Semgrep rule
    packs come from _DEFAULT_SEMGREP_PACKS unless ``semgrep_config_override``
    is provided (per-vulnerability override from the registry).

    Writes a combined JSON log and returns a StaticScanResult.
    """
    language = detect_language(snippet_path)
    active_scanners = _ENABLED_SCANNERS.get(language, ["semgrep"])
    effective_semgrep_packs = (
        semgrep_config_override
        if semgrep_config_override
        else _DEFAULT_SEMGREP_PACKS.get(language, "p/owasp-top-ten")
    )

    bandit_result = BanditResult()
    semgrep_result = SemgrepResult()

    if "bandit" in active_scanners:
        logger.info("Running bandit for agent=%s vuln=%s iteration=%d", agent, vulnerability_id, iteration)
        bandit_result = run_bandit(snippet_path)
        if bandit_result.errors:
            logger.warning("Bandit errors: %s", bandit_result.errors)
        else:
            logger.info(
                "Bandit results: HIGH=%d MEDIUM=%d LOW=%d issues=%d",
                bandit_result.high, bandit_result.medium, bandit_result.low, len(bandit_result.issues),
            )

    if "semgrep" in active_scanners:
        logger.info("Running semgrep for agent=%s vuln=%s iteration=%d", agent, vulnerability_id, iteration)
        semgrep_result = run_semgrep(snippet_path, effective_semgrep_packs)
        if semgrep_result.errors:
            logger.warning("Semgrep errors: %s", semgrep_result.errors)
        else:
            logger.info("Semgrep results: findings=%d rules=%s", semgrep_result.findings, semgrep_result.rules_matched)

    agent_log_dir = Path(logs_dir) / agent / vulnerability_id
    ensure_dir(agent_log_dir)
    log_path = str(agent_log_dir / f"static_iteration_{iteration}.log")

    log_data = {
        "snippet_path": snippet_path,
        "language": language,
        "agent": agent,
        "vulnerability_id": vulnerability_id,
        "iteration": iteration,
        "bandit": {
            "high": bandit_result.high, "medium": bandit_result.medium, "low": bandit_result.low,
            "issues": bandit_result.issues, "errors": bandit_result.errors,
        },
        "semgrep": {
            "findings": semgrep_result.findings, "rules_matched": semgrep_result.rules_matched,
            "issues": semgrep_result.issues, "errors": semgrep_result.errors,
        },
    }
    Path(log_path).write_text(json.dumps(log_data, indent=2), encoding="utf-8")
    logger.info("Static scan log written to %s", log_path)

    return StaticScanResult(
        bandit=bandit_result,
        semgrep=semgrep_result,
        log_path=log_path,
    )
