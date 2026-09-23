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
_C_EXTS: frozenset[str] = frozenset({".c", ".h", ".cpp", ".cc", ".cxx", ".hpp"})
_JAVA_EXTS: frozenset[str] = frozenset({".java"})
_RUBY_EXTS: frozenset[str] = frozenset({".rb"})
_PHP_EXTS: frozenset[str] = frozenset({".php"})
_SWIFT_EXTS: frozenset[str] = frozenset({".swift"})
_KOTLIN_EXTS: frozenset[str] = frozenset({".kt"})


_ALL_EXTS: frozenset[str] = _PYTHON_EXTS | _JS_TS_EXTS | _C_EXTS | _JAVA_EXTS | _RUBY_EXTS | _PHP_EXTS | _SWIFT_EXTS | _KOTLIN_EXTS

# Per-language rule packs used as fallback when no config YAML rules are provided.
# Each value is space-separated paths or registry refs passed as --config flags.
_LANGUAGE_SEMGREP_PACKS: Dict[str, str] = {
    "python":     "p/python p/bandit p/owasp-top-ten",
    "typescript": "p/typescript p/javascript p/owasp-top-ten",
    "c":          "p/c p/owasp-top-ten",
    "java":       "p/java p/owasp-top-ten",
    "ruby":       "p/ruby p/owasp-top-ten",
    "php":        "p/php p/owasp-top-ten",
    "swift":      "p/swift p/owasp-top-ten",
    "kotlin":     "p/kotlin p/owasp-top-ten"
}

# Ordered list of scanner backends to invoke per language.
# To add a new scanner: implement run_<tool>(), add its name here.
_ENABLED_SCANNERS: Dict[str, List[str]] = {
    # "python":     ["bandit", "semgrep"],
    "python":     ["semgrep"],
    "typescript": ["semgrep"],
    "c":          ["semgrep"],
    "java":       ["semgrep"],
    "ruby":       ["semgrep"],
    "php":        ["semgrep"],
    "swift":      ["semgrep"],
    "kotlin":     ["semgrep"]
}


def detect_language(path: str) -> str:
    """Infer the programming language from the file extension."""
    ext = Path(path).suffix.lower()
    if ext in _PYTHON_EXTS:
        return "python"
    if ext in _JS_TS_EXTS:
        return "typescript"
    if ext in _C_EXTS:
        return "c"
    if ext in _JAVA_EXTS:
        return "java"
    if ext in _RUBY_EXTS:
        return "ruby"
    if ext in _PHP_EXTS:
        return "php"
    if ext in _SWIFT_EXTS:
        return "swift"
    if ext in _KOTLIN_EXTS:
        return "kotlin"
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
    # Canonical severity buckets — derived from each finding's true security
    # severity (extra.metadata.severity / impact) when available, otherwise
    # mapped from the rule level. high + medium + low == findings.
    high: int = 0       # HIGH severity — likely vulnerabilities
    medium: int = 0     # MEDIUM severity — potential issues
    low: int = 0        # LOW severity — informational
    # Legacy rule-level buckets, retained for backward compatibility.
    error: int = 0      # ERROR rule level
    warning: int = 0    # WARNING rule level
    info: int = 0       # INFO rule level
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

_SEMGREP_VENV = Path.home() / ".venvs" / "semgrep-env"

# Maps any severity token Semgrep may emit (rule level or metadata severity)
# onto the canonical HIGH / MEDIUM / LOW buckets used across the framework.
_SEV_LEVELS: Dict[str, str] = {
    "CRITICAL": "HIGH", "HIGH": "HIGH",
    "MEDIUM": "MEDIUM", "MODERATE": "MEDIUM", "WARNING": "MEDIUM",
    "LOW": "LOW", "INFO": "LOW",
    "ERROR": "HIGH",   # rule-level fallback (ERROR rules are likely vulns)
}


def _normalize_semgrep_severity(extra: Dict[str, Any]) -> str:
    """
    Derive a canonical HIGH/MEDIUM/LOW severity for a single Semgrep result.

    Prefers the finding's true security severity from ``extra.metadata``
    (``severity`` then ``impact``) which security rule packs populate, and
    falls back to the rule level (``extra.severity`` = ERROR/WARNING/INFO).
    Defaults to INFORMATIONAL when nothing is recognised.
    """
    meta = extra.get("metadata") or {}
    for key in ("severity", "impact"):
        val = meta.get(key)
        if isinstance(val, str) and val.upper() in _SEV_LEVELS:
            return _SEV_LEVELS[val.upper()]
    return _SEV_LEVELS.get((extra.get("severity") or "").upper(), "INFORMATIONAL")


def _as_str_list(val: Any) -> List[str]:
    """Normalise a Semgrep metadata field (str | list | None) to a list[str]."""
    if val is None:
        return []
    if isinstance(val, list):
        return [str(v) for v in val]
    return [str(val)]


def _semgrep_binary() -> Optional[str]:
    """
    Return the semgrep executable path, or None if not found.

    Search order:
      1. Isolated semgrep venv at ~/.venvs/semgrep-env/bin/semgrep
      2. Current virtualenv's bin/
      3. System PATH
    """
    import shutil

    isolated = _SEMGREP_VENV / "bin" / "semgrep"
    if isolated.exists():
        return str(isolated)
    venv_semgrep = Path(sys.executable).parent / "semgrep"
    if venv_semgrep.exists():
        return str(venv_semgrep)
    return shutil.which("semgrep")


def run_semgrep(snippet_path: str, semgrep_configs: List[str] | None = None) -> SemgrepResult:
    """
    Run Semgrep using the given rule config(s) and return finding counts plus
    per-finding detail.

    semgrep_configs is a list of --config values (local YAML paths or registry
    refs like "p/python"). When empty/None the language-specific fallback from
    _LANGUAGE_SEMGREP_PACKS is used.
    """
    binary = _semgrep_binary()
    if binary is None:
        return SemgrepResult(errors=["semgrep not found; install with: pip install semgrep"])

    if not semgrep_configs:
        language = detect_language(snippet_path)
        fallback = _LANGUAGE_SEMGREP_PACKS.get(language, "p/owasp-top-ten")
        semgrep_configs = fallback.split()

    cmd = [binary]
    for cfg in semgrep_configs:
        cmd += ["--config", cfg]
    cmd += ["--metrics=off", "--json", "--quiet", "--no-git-ignore", snippet_path]
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

        level_counts = {"ERROR": 0, "WARNING": 0, "INFO": 0}
        hml_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        issues: List[Dict[str, Any]] = []
        for r in results:
            extra = r.get("extra") or {}
            meta = extra.get("metadata") or {}
            level = (extra.get("severity") or "").upper()
            if level in level_counts:
                level_counts[level] += 1

            normalized = _normalize_semgrep_severity(extra)
            hml_counts[normalized] += 1

            issues.append({
                "rule_id": r.get("check_id", ""),
                "severity": level,                       # raw rule level (ERROR/WARNING/INFO)
                "severity_normalized": normalized,       # canonical HIGH/MEDIUM/LOW
                "confidence": (meta.get("confidence") or ""),
                "cwe": _as_str_list(meta.get("cwe")),
                "owasp": _as_str_list(meta.get("owasp")),
                "message": extra.get("message", ""),
                "line_number": (r.get("start") or {}).get("line"),
                "matched_lines": extra.get("lines", "").strip(),
            })

        return SemgrepResult(
            findings=len(results),
            high=hml_counts["HIGH"],
            medium=hml_counts["MEDIUM"],
            low=hml_counts["LOW"],
            error=level_counts["ERROR"],
            warning=level_counts["WARNING"],
            info=level_counts["INFO"],
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
    semgrep_configs: List[str] | None = None,
) -> StaticScanResult:
    """
    Run all applicable static analysis backends against a snippet file.

    The language is detected automatically from the file extension and the
    appropriate scanners from _ENABLED_SCANNERS are invoked.  Semgrep rule
    configs come from ``semgrep_configs`` (list of local YAML paths or
    registry refs).  When None, the language-specific fallback is used.

    Writes a combined JSON log and returns a StaticScanResult.
    """
    language = detect_language(snippet_path)
    active_scanners = _ENABLED_SCANNERS.get(language, ["semgrep"])

    bandit_result = BanditResult()
    semgrep_result = SemgrepResult()

    if "bandit" in active_scanners:
        logger.info(
            "Running bandit for agent=%s file=%s iteration=%d",
            agent, Path(snippet_path).name, iteration + 1,
        )
        bandit_result = run_bandit(snippet_path)
        if bandit_result.errors:
            logger.warning("Bandit errors: %s", bandit_result.errors)
        else:
            logger.info(
                "Bandit results: HIGH=%d MEDIUM=%d LOW=%d issues=%d",
                bandit_result.high, bandit_result.medium, bandit_result.low, len(bandit_result.issues),
            )

    if "semgrep" in active_scanners:
        logger.info(
            "Running semgrep for agent=%s file=%s iteration=%d",
            agent, Path(snippet_path).name, iteration + 1,
        )
        semgrep_result = run_semgrep(snippet_path, semgrep_configs)
        if semgrep_result.errors:
            logger.warning("Semgrep errors: %s", semgrep_result.errors)
        else:
            logger.info(
                "Semgrep results: findings=%d (HIGH=%d MEDIUM=%d LOW=%d) rules=%s",
                semgrep_result.findings, semgrep_result.high, semgrep_result.medium,
                semgrep_result.low, semgrep_result.rules_matched,
            )

    agent_log_dir = Path(logs_dir) / agent / vulnerability_id
    ensure_dir(agent_log_dir)
    log_path = str(agent_log_dir / f"static_iteration_{iteration}.log")

    log_data = {
        "snippet_path": snippet_path,
        "language": language,
        "agent": agent,
        # Use explicit filename field instead of legacy vulnerability id
        "file": Path(snippet_path).name,
        # Keep zero-based numeric index for internal compatibility
        "iteration": iteration,
        # Human-facing 1-based iteration for logs
        "iteration_display": iteration + 1,
        "bandit": {
            "high": bandit_result.high, "medium": bandit_result.medium, "low": bandit_result.low,
            "issues": bandit_result.issues, "errors": bandit_result.errors,
        },
        "semgrep": {
            "findings": semgrep_result.findings,
            "high": semgrep_result.high, "medium": semgrep_result.medium, "low": semgrep_result.low,
            "error": semgrep_result.error, "warning": semgrep_result.warning, "info": semgrep_result.info,
            "rules_matched": semgrep_result.rules_matched,
            "issues": semgrep_result.issues, "errors": semgrep_result.errors,
        },
    }
    Path(log_path).write_text(json.dumps(log_data, indent=2), encoding="utf-8")
    logger.info("Static scan log written to %s", log_path)

    return StaticScanResult(
        # bandit=bandit_result,
        semgrep=semgrep_result,
        log_path=log_path,
    )
