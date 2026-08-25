"""
framework/analyzer.py
----------------------
Analysis component of the three-component pipeline.

Responsibilities
----------------
- Read all ResultRecord entries from results.jsonl
- Print a human-readable summary:
    * Header: record counts, agents, models, vulnerabilities, iteration range
    * Per-vulnerability / per-agent trend table with bar charts
    * Per-finding detail (Bandit test IDs, Semgrep rule IDs, line numbers, code)
    * First → last iteration delta per agent
- Optional CSV export (one row per individual finding)

Public API
----------
    analyze_run(run_dir, *, vuln_filter, agent_filter, include_findings, csv_path) -> None

Helper utilities also used by utils/analyze.py CLI wrapper
----------------------------------------------------------
    load_results(results_path) -> List[Dict]
    group_records(records, filter_agent, filter_vuln) -> grouped dict
    print_summary(records, results_path) -> None
    print_trend_table(grouped, metric_keys) -> None
    print_finding_types(grouped) -> None
    write_csv(grouped, output_path) -> None
    list_runs(runs_dir) -> None
    find_latest_results(runs_dir) -> str | None
    resolve_run_path(run_arg, runs_dir) -> str | None
"""
from __future__ import annotations

import csv
import html
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .io_utils import logger


RUNS_DIR = "runs"


# ---------------------------------------------------------------------------
# Public pipeline entry point
# ---------------------------------------------------------------------------

def analyze_run(
    run_dir: Path,
    *,
    results_path: str | None = None,
    vuln_filter: str | None = None,
    agent_filter: str | None = None,
    include_findings: bool = True,
    csv_path: str | None = None,
) -> None:
    """
    Read results.jsonl from a run directory and print a human-readable summary.

    Parameters
    ----------
    run_dir:
        Path to the run directory (e.g. runs/2026-04-01_11-34-04).
    results_path:
        Explicit path to the results.jsonl to load. When omitted, defaults to
        ``run_dir / "results.jsonl"``.
    vuln_filter:
        When set, only show results for this vulnerability ID.
    agent_filter:
        When set, only show results for this agent ID.
    include_findings:
        When True (default), print per-iteration finding detail.
    csv_path:
        When set, also export results to a CSV file at this path.
    """
    results_path = results_path or str(run_dir / "results.jsonl")
    if not Path(results_path).exists():
        print(f"[info] No results.jsonl found in {run_dir}.")
        print("[info] Run 'python main.py' to create the first run.")
        return

    records = load_results(results_path)
    if not records:
        print(f"[info] results.jsonl exists but contains no records: {results_path}")
        return

    print_summary(records, results_path)

    grouped = group_records(
        records,
        filter_agent=agent_filter,
        filter_vuln=vuln_filter,
    )

    if not any(grouped.values()):
        print("[info] No matching records to display.")
        return

    all_records = [
        r
        for agent_data in grouped.values()
        for iter_data in agent_data.values()
        for r in iter_data.values()
    ]

    has_bandit = any(r.get("bandit_high") is not None for r in all_records)
    has_semgrep = any(r.get("semgrep_findings") is not None for r in all_records)
    has_static = has_bandit or has_semgrep

    if has_static:
        metric_keys: List[Tuple[str, str]] = []
        if has_bandit:
            metric_keys += [
                ("bandit_high", "Bandit HIGH"),
                ("bandit_medium", "Bandit MED"),
                ("bandit_low", "Bandit LOW"),
            ]
        if has_semgrep:
            metric_keys += [
                ("semgrep_high", "Semgrep HIGH"),
                ("semgrep_medium", "Semgrep MED"),
                ("semgrep_low", "Semgrep LOW"),
            ]
    else:
        metric_keys = [("nuclei_exit_code", "Nuclei exit")]

    print_trend_table(grouped, metric_keys)

    if include_findings:
        print_finding_types(grouped)

    if csv_path:
        write_csv(grouped, csv_path)


# ---------------------------------------------------------------------------
# Run discovery helpers (also used by the utils/analyze.py CLI wrapper)
# ---------------------------------------------------------------------------

def _all_run_dirs(runs_dir: str = RUNS_DIR) -> List[Path]:
    """Return all run directories sorted oldest → newest (by directory name)."""
    p = Path(runs_dir)
    if not p.exists():
        return []
    return sorted(
        [d for d in p.iterdir() if d.is_dir() and (d / "results.jsonl").exists()]
    )


def find_latest_results(runs_dir: str = RUNS_DIR) -> Optional[str]:
    """Return the results.jsonl path for the most recent run, or None."""
    dirs = _all_run_dirs(runs_dir)
    return str(dirs[-1] / "results.jsonl") if dirs else None


def resolve_run_path(run_arg: str, runs_dir: str = RUNS_DIR) -> Optional[str]:
    """
    Accept either a bare run ID (timestamp), a relative path, or absolute path
    and return the resolved results.jsonl path.
    """
    p = Path(run_arg)
    if p.is_file():
        return str(p)
    if p.is_dir() and (p / "results.jsonl").exists():
        return str(p / "results.jsonl")
    candidate = Path(runs_dir) / run_arg / "results.jsonl"
    if candidate.exists():
        return str(candidate)
    return None


def list_runs(runs_dir: str = RUNS_DIR) -> None:
    """Print a table of all available runs with key metadata."""
    dirs = _all_run_dirs(runs_dir)
    if not dirs:
        print(f"[info] No runs found in '{runs_dir}/'.")
        print("[info] Run 'python main.py' to create the first run.")
        return

    print(f"\n{'=' * 70}")
    print(f"  Available runs in {runs_dir}/  ({len(dirs)} total)")
    print(f"{'=' * 70}")
    print(f"  {'Run ID':<26}  {'Records':>7}  {'Model':<20}  {'Iterations'}")
    print(f"  {'-' * 26}  {'-' * 7}  {'-' * 20}  {'-' * 10}")

    latest_id = dirs[-1].name if dirs else ""
    for d in reversed(dirs):
        results_file = d / "results.jsonl"
        records = _count_lines(results_file)

        meta = _load_metadata(d)
        model = meta.get("model", "?") if meta else "?"
        iters = meta.get("iterations", "?") if meta else "?"
        agents = meta.get("agents", []) if meta else []
        agent_str = f"{len(agents)} agents" if agents else "?"

        marker = " ← latest" if d.name == latest_id else ""
        print(f"  {d.name:<26}  {records:>7}  {model:<20}  {iters} iters / {agent_str}{marker}")
    print()


def _count_lines(path: Path) -> int:
    try:
        return sum(1 for line in path.open(encoding="utf-8") if line.strip())
    except Exception:
        return 0


def _load_metadata(run_dir: Path) -> Optional[Dict[str, Any]]:
    meta_path = run_dir / "run_metadata.json"
    if not meta_path.exists():
        return None
    try:
        return json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def _backfill_semgrep_severity(rec: Dict[str, Any]) -> None:
    """
    Ensure the canonical semgrep_high/medium/low keys exist on a record.

    Records written before metadata-based severity (which only carry the legacy
    semgrep_error/warning/info rule-level counts) are mapped onto H/M/L using the
    same ERROR=HIGH, WARNING=MEDIUM, INFO=LOW convention, so old runs still render.
    Records that already have the new keys are left untouched.
    """
    if "semgrep_high" not in rec:
        rec["semgrep_high"] = rec.get("semgrep_error", 0)
    if "semgrep_medium" not in rec:
        rec["semgrep_medium"] = rec.get("semgrep_warning", 0)
    if "semgrep_low" not in rec:
        rec["semgrep_low"] = rec.get("semgrep_info", 0)


def load_results(results_path: str) -> List[Dict[str, Any]]:
    """Load all records from a results.jsonl file."""
    records = []
    p = Path(results_path)
    if not p.exists():
        print(f"[error] Results file not found: {results_path}", file=sys.stderr)
        sys.exit(1)
    with p.open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                _backfill_semgrep_severity(rec)
                records.append(rec)
            except json.JSONDecodeError as exc:
                print(f"[warn] Skipping malformed line {lineno}: {exc}", file=sys.stderr)
    return records


def _load_issues_from_log(log_path: str) -> Tuple[List[Dict], List[Dict]]:
    """
    Fallback: read bandit_issues and semgrep_issues from a static log file.
    Returns (bandit_issues, semgrep_issues).
    """
    p = Path(log_path)
    if not p.exists():
        return [], []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return (
            data.get("bandit", {}).get("issues", []),
            data.get("semgrep", {}).get("issues", []),
        )
    except Exception:
        return [], []


def _get_issues(rec: Dict[str, Any]) -> Tuple[List[Dict], List[Dict]]:
    """
    Return (bandit_issues, semgrep_issues) for a record.
    Prefers inline fields; falls back to the static log file for older records.
    """
    b = rec.get("bandit_issues") or []
    s = rec.get("semgrep_issues") or []
    if not b and not s:
        log_path = rec.get("static_log_path", "")
        if log_path:
            b, s = _load_issues_from_log(log_path)
    return b, s


# ---------------------------------------------------------------------------
# Grouping
# ---------------------------------------------------------------------------

def group_records(
    records: List[Dict[str, Any]],
    filter_agent: Optional[str] = None,
    filter_vuln: Optional[str] = None,
) -> Dict[str, Dict[str, Dict[int, Dict[str, Any]]]]:
    """Returns nested dict: vuln_id -> agent_id -> iteration -> record."""
    grouped: Dict[str, Dict[str, Dict[int, Dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(dict)
    )
    for r in records:
        agent = r.get("agent", "unknown")
        # records must now include 'file' — treat it as the canonical id
        vuln = r.get("file", "unknown")
        iteration = r.get("iteration", -1)
        if filter_agent and agent != filter_agent:
            continue
        if filter_vuln and vuln != filter_vuln:
            continue
        # Last record wins when duplicate agent/iteration keys exist.
        grouped[vuln][agent][iteration] = r
    return grouped


# ---------------------------------------------------------------------------
# Summary header
# ---------------------------------------------------------------------------

def print_summary(records: List[Dict[str, Any]], results_path: str) -> None:
    total = len(records)
    if total == 0:
        print("[info] No records found.")
        return

    agents = sorted({r.get("agent", "?") for r in records})
    vulns = sorted({r.get("file", "?") for r in records})
    models = sorted({r.get("model", "?") for r in records})
    iters = sorted({r.get("iteration", -1) for r in records})
    run_ids = sorted({r.get("run_id", "") for r in records if r.get("run_id")})

    run_dir = Path(results_path).parent
    meta = _load_metadata(run_dir)

    print(f"\n{'=' * 70}")
    print(f"  Results Summary")
    print(f"{'=' * 70}")
    if run_ids:
        print(f"  Run ID          : {run_ids[0]}")
    print(f"  Results file    : {results_path}")
    print(f"  Total records   : {total}")
    print(f"  Agents          : {', '.join(agents)}")
    print(f"  Vulnerabilities : {', '.join(vulns)}")
    print(f"  Models          : {', '.join(models)}")
    print(f"  Iterations      : {min(iters)} \u2013 {max(iters)}  ({len(iters)} distinct values)")

    has_static = any(r.get("bandit_high") is not None for r in records)
    has_nuclei = any(r.get("nuclei_exit_code") is not None for r in records)
    print(f"  Static scans    : {'yes' if has_static else 'no'}")
    print(f"  Nuclei scans    : {'yes' if has_nuclei else 'no'}")

    if meta:
        seed = meta.get("random_seed")
        if seed is not None:
            print(f"  Random seed     : {seed}")
        started = meta.get("started_at", "")
        if started:
            print(f"  Started at      : {started}")


# ---------------------------------------------------------------------------
# Trend table (counts + bar charts)
# ---------------------------------------------------------------------------

def _bar(value: int, max_value: int, width: int = 12) -> str:
    if max_value == 0:
        return " " * width
    filled = round((value / max_value) * width)
    return "\u2588" * filled + "\u2591" * (width - filled)


def print_trend_table(
    grouped: Dict[str, Dict[str, Dict[int, Dict[str, Any]]]],
    metric_keys: List[Tuple[str, str]],
) -> None:
    """Print an ASCII trend table for each vulnerability → agent combination."""
    for vuln_id, agents in sorted(grouped.items()):
        print(f"\n{'=' * 70}")
        print(f"  Vulnerability: {vuln_id}")
        print(f"{'=' * 70}")

        for agent_id, iterations in sorted(agents.items()):
            if not iterations:
                continue

            all_iters = sorted(iterations.keys())
            model = iterations[all_iters[0]].get("model", "?")
            print(f"\n  Agent: {agent_id}  |  Model: {model}")
            print(f"  {'Iter':<6}", end="")
            for _, label in metric_keys:
                print(f"  {label:<16}", end="")
            print(f"  {'Prompt (truncated)'}")
            print(f"  {'-' * 4}", end="")
            for _ in metric_keys:
                print(f"  {'-' * 16}", end="")
            print(f"  {'-' * 40}")

            max_vals = {key: 1 for key, _ in metric_keys}
            for rec in iterations.values():
                for key, _ in metric_keys:
                    max_vals[key] = max(max_vals[key], int(rec.get(key) or 0))

            for it in all_iters:
                rec = iterations[it]
                prompt_short = (rec.get("prompt") or "")[:38].replace("\n", " ")
                print(f"  {it:<6}", end="")
                for key, _ in metric_keys:
                    val = int(rec.get(key) or 0)
                    bar = _bar(val, max_vals[key])
                    print(f"  {val:<3} {bar} ", end="")
                print(f"  {prompt_short}")

        print(f"\n  {'--- Delta summary (first \u2192 last iteration) ---'}")
        for agent_id, iterations in sorted(agents.items()):
            if len(iterations) < 2:
                continue
            all_iters = sorted(iterations.keys())
            first = iterations[all_iters[0]]
            last = iterations[all_iters[-1]]
            deltas = []
            for key, label in metric_keys:
                delta = int(last.get(key) or 0) - int(first.get(key) or 0)
                sign = "+" if delta >= 0 else ""
                deltas.append(f"{label}: {sign}{delta}")
            print(f"  {agent_id:<14}  {' | '.join(deltas)}")


# ---------------------------------------------------------------------------
# Finding-type detail
# ---------------------------------------------------------------------------

def _format_bandit_issue(issue: Dict[str, Any]) -> str:
    test_id = issue.get("test_id", "?")
    test_name = issue.get("test_name", "?")
    severity = issue.get("severity", "?")
    confidence = issue.get("confidence", "?")
    line = issue.get("line_number", "?")
    text = (issue.get("issue_text") or "").strip()
    cwe = issue.get("cwe_id")
    cwe_str = f"  CWE-{cwe}" if cwe else ""
    return f"    [BANDIT] {test_id} ({severity}/{confidence}{cwe_str})  line {line}  {test_name}: {text}"


# Rule-level \u2192 canonical severity fallback for per-finding display of older records.
_SEMGREP_LEVEL_TO_HML = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}


def _semgrep_issue_severity(issue: Dict[str, Any]) -> str:
    """Resolve a Semgrep issue's canonical HIGH/MEDIUM/LOW severity, with fallback."""
    norm = issue.get("severity_normalized")
    if norm:
        return str(norm)
    raw = (issue.get("severity") or "").upper()
    return _SEMGREP_LEVEL_TO_HML.get(raw, issue.get("severity", "") or "?")


def _semgrep_issue_cwe(issue: Dict[str, Any]) -> str:
    """Join a Semgrep issue's CWE list into a display string (empty when absent)."""
    cwe = issue.get("cwe")
    if isinstance(cwe, list):
        return ", ".join(str(c) for c in cwe)
    return str(cwe) if cwe else ""


def _format_semgrep_issue(issue: Dict[str, Any]) -> str:
    rule_id = issue.get("rule_id", "?")
    severity = _semgrep_issue_severity(issue)
    line = issue.get("line_number", "?")
    message = (issue.get("message") or "").strip()
    cwe = _semgrep_issue_cwe(issue)
    cwe_str = f"  {cwe}" if cwe else ""
    matched = (issue.get("matched_lines") or "").strip().replace("\n", " ")
    matched_str = f'  \u2192 "{matched[:60]}"' if matched else ""
    return f"    [SEMGREP] {rule_id} ({severity}{cwe_str})  line {line}  {message}{matched_str}"


def print_finding_types(
    grouped: Dict[str, Dict[str, Dict[int, Dict[str, Any]]]],
) -> None:
    """
    Print per-iteration finding detail and a deduplicated unique-type summary
    per agent per vulnerability.
    """
    for vuln_id, agents in sorted(grouped.items()):
        print(f"\n{'=' * 70}")
        print(f"  Finding Types \u2014 Vulnerability: {vuln_id}")
        print(f"{'=' * 70}")

        for agent_id, iterations in sorted(agents.items()):
            if not iterations:
                continue

            all_iters = sorted(iterations.keys())
            unique_bandit: Dict[str, Dict[str, Any]] = {}
            unique_semgrep: Dict[str, Dict[str, Any]] = {}
            has_any = False
            iter_lines: List[str] = []

            for it in all_iters:
                rec = iterations[it]
                b_issues, s_issues = _get_issues(rec)

                if not b_issues and not s_issues:
                    iter_lines.append(f"    Iteration {it}: (no findings)")
                    continue

                has_any = True
                iter_lines.append(f"    Iteration {it}:")
                for issue in b_issues:
                    iter_lines.append(_format_bandit_issue(issue))
                    tid = issue.get("test_id", "?")
                    if tid not in unique_bandit:
                        unique_bandit[tid] = issue
                for issue in s_issues:
                    iter_lines.append(_format_semgrep_issue(issue))
                    rid = issue.get("rule_id", "?")
                    if rid not in unique_semgrep:
                        unique_semgrep[rid] = issue

            print(f"\n  Agent: {agent_id}")
            print(f"  {'-' * 60}")
            print("\n".join(iter_lines))

            if unique_bandit or unique_semgrep:
                print(f"\n  Unique finding types across all iterations (agent={agent_id}):")
                for tid, issue in sorted(unique_bandit.items()):
                    sev = issue.get("severity", "?")
                    name = issue.get("test_name", "?")
                    cwe = issue.get("cwe_id")
                    cwe_str = f"  CWE-{cwe}" if cwe else ""
                    print(f"    [BANDIT] {tid}{cwe_str}  ({sev})  {name}")
                for rid, issue in sorted(unique_semgrep.items()):
                    sev = _semgrep_issue_severity(issue)
                    cwe = _semgrep_issue_cwe(issue)
                    cwe_str = f"  {cwe}" if cwe else ""
                    msg = (issue.get("message") or "")[:80].strip()
                    print(f"    [SEMGREP] {rid}{cwe_str}  ({sev})  {msg}")
            elif not has_any:
                print(f"\n  No findings recorded for agent={agent_id}.")


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------

def write_csv(
    grouped: Dict[str, Dict[str, Dict[int, Dict[str, Any]]]],
    output_path: str,
) -> None:
    """
    Write a findings-expanded CSV — one row per individual scanner finding.

    When an iteration has no findings, a single row is still emitted with all
    finding columns empty so iteration-level counts remain queryable.

    Context columns (repeated per finding):
        run_id, file, agent, model, iteration, prompt,
        bandit_high, bandit_medium, bandit_low,
        semgrep_findings, semgrep_high, semgrep_medium, semgrep_low,
        nuclei_exit_code, server_started, success, snippet_path, static_log_path

    Finding columns (empty when no findings):
        finding_tool      — "bandit" | "semgrep" | ""
        finding_id        — Bandit test_id  /  Semgrep rule_id
        finding_name      — Bandit test_name  /  "" for Semgrep
        finding_severity  — HIGH | MEDIUM | LOW (canonical, both tools) | ""
        finding_confidence— Bandit/Semgrep confidence (HIGH/MEDIUM/LOW) | ""
        finding_cwe       — e.g. "CWE-78" (Bandit + Semgrep metadata)  |  ""
        finding_line      — source line number | ""
        finding_message   — Bandit issue_text  /  Semgrep message
        finding_code      — Semgrep matched_lines  /  "" for Bandit
    """
    context_fields = [
        "run_id", "file", "agent", "model", "iteration", "prompt",
        "bandit_high", "bandit_medium", "bandit_low",
        "semgrep_findings", "semgrep_high", "semgrep_medium", "semgrep_low",
        "nuclei_exit_code", "server_started", "success",
        "snippet_path", "static_log_path",
    ]
    finding_fields = [
        "finding_tool", "finding_id", "finding_name",
        "finding_severity", "finding_confidence", "finding_cwe",
        "finding_line", "finding_message", "finding_code",
    ]
    fieldnames = context_fields + finding_fields

    empty_finding: Dict[str, str] = {f: "" for f in finding_fields}

    def _bandit_row(issue: Dict[str, Any]) -> Dict[str, str]:
        cwe = issue.get("cwe_id")
        return {
            "finding_tool": "bandit",
            "finding_id": issue.get("test_id", ""),
            "finding_name": issue.get("test_name", ""),
            "finding_severity": issue.get("severity", ""),
            "finding_confidence": issue.get("confidence", ""),
            "finding_cwe": f"CWE-{cwe}" if cwe else "",
            "finding_line": str(issue.get("line_number", "")),
            "finding_message": (issue.get("issue_text") or "").strip(),
            "finding_code": "",
        }

    def _semgrep_row(issue: Dict[str, Any]) -> Dict[str, str]:
        return {
            "finding_tool": "semgrep",
            "finding_id": issue.get("rule_id", ""),
            "finding_name": "",
            "finding_severity": _semgrep_issue_severity(issue),
            "finding_confidence": str(issue.get("confidence", "") or ""),
            "finding_cwe": _semgrep_issue_cwe(issue),
            "finding_line": str(issue.get("line_number", "")),
            "finding_message": (issue.get("message") or "").strip(),
            "finding_code": (issue.get("matched_lines") or "").strip().replace("\n", " "),
        }

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()

        for vuln_id, agents in sorted(grouped.items()):
            for agent_id, iterations_map in sorted(agents.items()):
                for it in sorted(iterations_map.keys()):
                    rec = iterations_map[it]
                    context = {k: rec.get(k, "") for k in context_fields}
                    b_issues, s_issues = _get_issues(rec)

                    all_finding_rows: List[Dict[str, str]] = (
                        [_bandit_row(i) for i in b_issues]
                        + [_semgrep_row(i) for i in s_issues]
                    )

                    if not all_finding_rows:
                        writer.writerow({**context, **empty_finding})
                    else:
                        for finding in all_finding_rows:
                            writer.writerow({**context, **finding})

    print(f"\n[info] CSV written to: {output_path}")
    print(f"[info] Format: one row per finding (empty finding columns = no findings that iteration)")
    logger.info("CSV written to %s", output_path)


# ---------------------------------------------------------------------------
# JSON output (structured data for HTML export and programmatic use)
# ---------------------------------------------------------------------------

def analyze_run_json(
    run_dir: Path,
    *,
    results_path: str | None = None,
    vuln_filter: str | None = None,
    agent_filter: str | None = None,
) -> Dict[str, Any]:
    """
    Return the same analysis data as ``analyze_run()`` but as structured
    dicts/lists suitable for JSON serialization.

    The existing ``analyze_run()`` continues to print to stdout for CLI use;
    this function returns data without side effects.

    ``results_path`` overrides the default ``run_dir / "results.jsonl"`` location.
    """
    results_path = results_path or str(run_dir / "results.jsonl")
    if not Path(results_path).exists():
        return {"error": "no_results", "message": f"No results.jsonl found in {run_dir}"}

    records = load_results(results_path)
    if not records:
        return {"error": "empty_results", "message": "results.jsonl exists but has no records"}

    agents_set = sorted({r.get("agent", "?") for r in records})
    vulns_set = sorted({r.get("file", "?") for r in records})
    models_set = sorted({r.get("model", "?") for r in records})
    iters_set = sorted({r.get("iteration", -1) for r in records})
    run_ids = sorted({r.get("run_id", "") for r in records if r.get("run_id")})

    meta = _load_metadata(run_dir)

    summary = {
        "run_id": run_ids[0] if run_ids else None,
        "results_path": results_path,
        "total_records": len(records),
        "agents": agents_set,
        "vulnerabilities": vulns_set,
        "models": models_set,
        "iteration_range": [min(iters_set), max(iters_set)] if iters_set else [],
        "distinct_iterations": len(iters_set),
        "has_static_scans": any(
            r.get("bandit_high") is not None or r.get("semgrep_findings") is not None
            for r in records
        ),
        "has_nuclei_scans": any(r.get("nuclei_exit_code") is not None for r in records),
        "random_seed": meta.get("random_seed") if meta else None,
        "started_at": meta.get("started_at") if meta else None,
    }

    grouped = group_records(records, filter_agent=agent_filter, filter_vuln=vuln_filter)

    trends: List[Dict[str, Any]] = []
    deltas: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []

    for vuln_id, agents_data in sorted(grouped.items()):
        for agent_id, iterations in sorted(agents_data.items()):
            if not iterations:
                continue
            all_iters = sorted(iterations.keys())

            trend_rows = []
            for it in all_iters:
                rec = iterations[it]
                trend_rows.append({
                    "iteration": it,
                    "bandit_high": rec.get("bandit_high") or 0,
                    "bandit_medium": rec.get("bandit_medium") or 0,
                    "bandit_low": rec.get("bandit_low") or 0,
                    "semgrep_findings": rec.get("semgrep_findings") or 0,
                    "semgrep_high": rec.get("semgrep_high") or 0,
                    "semgrep_medium": rec.get("semgrep_medium") or 0,
                    "semgrep_low": rec.get("semgrep_low") or 0,
                    "prompt": (rec.get("prompt") or "")[:80],
                    "model": rec.get("model", "?"),
                })
            trends.append({
                "file": vuln_id,
                "agent": agent_id,
                "rows": trend_rows,
            })

            if len(all_iters) >= 2:
                first = iterations[all_iters[0]]
                last = iterations[all_iters[-1]]
                deltas.append({
                    "file": vuln_id,
                    "agent": agent_id,
                    "bandit_high_delta": int(last.get("bandit_high") or 0) - int(first.get("bandit_high") or 0),
                    "bandit_medium_delta": int(last.get("bandit_medium") or 0) - int(first.get("bandit_medium") or 0),
                    "bandit_low_delta": int(last.get("bandit_low") or 0) - int(first.get("bandit_low") or 0),
                    "semgrep_high_delta": int(last.get("semgrep_high") or 0) - int(first.get("semgrep_high") or 0),
                    "semgrep_medium_delta": int(last.get("semgrep_medium") or 0) - int(first.get("semgrep_medium") or 0),
                    "semgrep_low_delta": int(last.get("semgrep_low") or 0) - int(first.get("semgrep_low") or 0),
                })

            for it in all_iters:
                rec = iterations[it]
                b_issues, s_issues = _get_issues(rec)
                if b_issues or s_issues:
                    findings.append({
                        "file": vuln_id,
                        "agent": agent_id,
                        "iteration": it,
                        "bandit_issues": b_issues,
                        "semgrep_issues": s_issues,
                    })

    return {
        "summary": summary,
        "trends": trends,
        "deltas": deltas,
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# HTML visualization (self-contained — inline SVG, no external dependencies)
# ---------------------------------------------------------------------------

# Distinct line colors cycled across agents (prompting strategies).
_AGENT_COLORS = ["#3b82f6", "#22c55e", "#ef4444", "#a855f7", "#f59e0b", "#06b6d4", "#ec4899", "#84cc16"]
# Severity colors (match the CLI conventions).
_SEV_COLORS = {"high": "#ef4444", "medium": "#f59e0b", "low": "#3b82f6"}


def _nice_ymax(value: int) -> int:
    """Round a max value up to a clean axis bound (>= 1)."""
    if value <= 5:
        return max(1, value)
    import math
    mag = 10 ** (len(str(value)) - 1)
    return int(math.ceil(value / (mag / 2)) * (mag / 2))


def _svg_multiline(
    series_by_label: Dict[str, List[int]],
    x_labels: List[int],
    *,
    title: str,
    width: int = 860,
    height: int = 400,
) -> str:
    """Render a multi-series line chart (one line per label) as inline SVG."""
    ml, mr, mt, mb = 56, 160, 44, 48
    plot_w, plot_h = width - ml - mr, height - mt - mb
    n = len(x_labels)
    all_vals = [v for s in series_by_label.values() for v in s] or [0]
    ymax = _nice_ymax(max(all_vals))

    def px(i: int) -> float:
        return ml + (plot_w * i / (n - 1) if n > 1 else plot_w / 2)

    def py(v: float) -> float:
        return mt + plot_h * (1 - v / ymax)

    p: List[str] = [f'<svg viewBox="0 0 {width} {height}" class="chart" role="img">']
    p.append(f'<text x="{width/2:.0f}" y="22" class="t-title" text-anchor="middle">{html.escape(title)}</text>')

    # Y gridlines + labels — produce integer tick values to avoid duplicate
    # rounded labels when ymax is small (e.g. ymax=3 with 5 steps -> 0,1,1,2,2,3).
    import math
    if ymax <= 5:
        ticks = list(range(0, ymax + 1))
    else:
        step = math.ceil(ymax / 5)
        ticks = list(range(0, ymax + 1, step))
        if ticks[-1] != ymax:
            ticks.append(ymax)

    for val in ticks:
        yy = py(val)
        p.append(f'<line x1="{ml}" y1="{yy:.1f}" x2="{ml+plot_w}" y2="{yy:.1f}" class="grid"/>')
        p.append(f'<text x="{ml-8}" y="{yy+4:.1f}" class="t-axis" text-anchor="end">{int(val)}</text>')
    # Axes
    p.append(f'<line x1="{ml}" y1="{mt}" x2="{ml}" y2="{mt+plot_h}" class="axis"/>')
    p.append(f'<line x1="{ml}" y1="{mt+plot_h}" x2="{ml+plot_w}" y2="{mt+plot_h}" class="axis"/>')
    p.append(f'<text x="{ml+plot_w/2:.0f}" y="{height-10}" class="t-axis" text-anchor="middle">iteration</text>')

    # X tick labels (thin out when many)
    every = max(1, n // 14)
    for i, lab in enumerate(x_labels):
        if i % every == 0 or i == n - 1:
            p.append(f'<text x="{px(i):.1f}" y="{mt+plot_h+18:.0f}" class="t-axis" text-anchor="middle">{lab}</text>')

    # Series
    for idx, (label, vals) in enumerate(series_by_label.items()):
        color = _AGENT_COLORS[idx % len(_AGENT_COLORS)]
        pts = " ".join(f"{px(i):.1f},{py(v):.1f}" for i, v in enumerate(vals))
        p.append(f'<polyline points="{pts}" fill="none" stroke="{color}" stroke-width="2.5"/>')
        for i, v in enumerate(vals):
            p.append(f'<circle cx="{px(i):.1f}" cy="{py(v):.1f}" r="3" fill="{color}"><title>{html.escape(label)} — iter {x_labels[i]}: {v}</title></circle>')
        ly = mt + idx * 22
        p.append(f'<rect x="{ml+plot_w+24}" y="{ly}" width="12" height="12" fill="{color}"/>')
        p.append(f'<text x="{ml+plot_w+42}" y="{ly+11}" class="t-legend">{html.escape(label)}</text>')

    p.append("</svg>")
    return "".join(p)


def _svg_stacked_bars(
    x_labels: List[int],
    highs: List[int],
    meds: List[int],
    lows: List[int],
    *,
    title: str,
    width: int = 860,
    height: int = 400,
) -> str:
    """Render a stacked bar chart (LOW/MEDIUM/HIGH) per iteration as inline SVG."""
    ml, mr, mt, mb = 56, 160, 44, 48
    plot_w, plot_h = width - ml - mr, height - mt - mb
    n = len(x_labels)
    totals = [h + m + l for h, m, l in zip(highs, meds, lows)]
    ymax = _nice_ymax(max(totals) if totals else 0)

    def py(v: float) -> float:
        return mt + plot_h * (1 - v / ymax)

    slot = plot_w / max(1, n)
    bar_w = min(40, slot * 0.6)

    p: List[str] = [f'<svg viewBox="0 0 {width} {height}" class="chart" role="img">']
    p.append(f'<text x="{width/2:.0f}" y="22" class="t-title" text-anchor="middle">{html.escape(title)}</text>')

    import math
    if ymax <= 5:
        ticks = list(range(0, ymax + 1))
    else:
        step = math.ceil(ymax / 5)
        ticks = list(range(0, ymax + 1, step))
        if ticks[-1] != ymax:
            ticks.append(ymax)

    for val in ticks:
        yy = py(val)
        p.append(f'<line x1="{ml}" y1="{yy:.1f}" x2="{ml+plot_w}" y2="{yy:.1f}" class="grid"/>')
        p.append(f'<text x="{ml-8}" y="{yy+4:.1f}" class="t-axis" text-anchor="end">{int(val)}</text>')
    p.append(f'<line x1="{ml}" y1="{mt}" x2="{ml}" y2="{mt+plot_h}" class="axis"/>')
    p.append(f'<line x1="{ml}" y1="{mt+plot_h}" x2="{ml+plot_w}" y2="{mt+plot_h}" class="axis"/>')
    p.append(f'<text x="{ml+plot_w/2:.0f}" y="{height-10}" class="t-axis" text-anchor="middle">iteration</text>')

    every = max(1, n // 14)
    for i, lab in enumerate(x_labels):
        cx = ml + slot * i + slot / 2
        # Stack LOW (bottom) → MEDIUM → HIGH (top)
        base = mt + plot_h
        for sev, vals in (("low", lows), ("medium", meds), ("high", highs)):
            v = vals[i]
            if v <= 0:
                continue
            seg_h = plot_h * v / ymax
            y_top = base - seg_h
            p.append(
                f'<rect x="{cx-bar_w/2:.1f}" y="{y_top:.1f}" width="{bar_w:.1f}" height="{seg_h:.1f}" '
                f'fill="{_SEV_COLORS[sev]}"><title>iter {lab} — {sev.upper()}: {v}</title></rect>'
            )
            base = y_top
        if i % every == 0 or i == n - 1:
            p.append(f'<text x="{cx:.1f}" y="{mt+plot_h+18:.0f}" class="t-axis" text-anchor="middle">{lab}</text>')

    for idx, (sev, lbl) in enumerate((("high", "HIGH"), ("medium", "MEDIUM"), ("low", "LOW"))):
        ly = mt + idx * 22
        p.append(f'<rect x="{ml+plot_w+24}" y="{ly}" width="12" height="12" fill="{_SEV_COLORS[sev]}"/>')
        p.append(f'<text x="{ml+plot_w+42}" y="{ly+11}" class="t-legend">{lbl}</text>')

    p.append("</svg>")
    return "".join(p)


_HTML_CSS = """
  body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
         background: #0f172a; color: #e2e8f0; margin: 0; padding: 24px 32px; }
  h1 { font-size: 20px; margin: 0 0 4px; }
  h2 { font-size: 15px; color: #94a3b8; margin: 28px 0 8px; font-weight: 600; }
  a { color: #60a5fa; }
  .hypothesis { background: #1e293b; border: 1px solid #334155; border-radius: 8px;
                padding: 12px 16px; margin: 12px 0 20px; font-size: 14px; }
  .meta { color: #94a3b8; font-size: 13px; margin-bottom: 8px; }
  .chart { background: #1e293b; border: 1px solid #334155; border-radius: 8px;
           width: 100%; max-width: 900px; margin: 6px 0 18px; }
  .grid { stroke: #334155; stroke-width: 1; }
  .axis { stroke: #64748b; stroke-width: 1.5; }
  .t-title { fill: #e2e8f0; font-size: 14px; font-weight: 600; }
  .t-axis { fill: #94a3b8; font-size: 11px; }
  .t-legend { fill: #cbd5e1; font-size: 12px; }
  table { border-collapse: collapse; font-size: 13px; margin: 6px 0 18px; }
  th, td { border: 1px solid #334155; padding: 4px 10px; text-align: right; }
  th { background: #1e293b; color: #cbd5e1; }
  td:first-child, th:first-child { text-align: left; }
    details { margin-top: 10px; }
    summary { cursor: pointer; color: #94a3b8; }
    /* CWE dropdowns in table cells: make the summary inline and inherit cell color */
    details.cwe { display: inline-block; }
    details.cwe summary { display: inline; color: inherit; margin: 0 0 0 6px; }
    details.cwe summary::-webkit-details-marker { margin-right: 6px; }
  pre { background: #0b1220; border: 1px solid #334155; border-radius: 8px;
        padding: 12px; overflow:auto; font-size: 12px; max-height: 360px; }
"""


def write_html(
    run_dir: Path,
    output_path: str,
    *,
    results_path: str | None = None,
) -> None:
    """
    Write a self-contained HTML visualization of a run's results.

    The page is built to test the hypothesis from arXiv:2506.11022 — *does the
    LLM introduce more security vulnerabilities after each iteration?* — and
    contains, with no external/CDN dependencies:

      1. Three line charts — HIGH, MEDIUM, and LOW findings per iteration, one
         line per agent (prompting strategy), summed across all vulnerabilities.
      2. A stacked bar chart of HIGH/MEDIUM/LOW findings per iteration (all agents).
      3. Aggregated tables (per severity, by agent) plus the underlying data
         embedded as JSON for further statistical analysis.

    ``results_path`` overrides the default ``run_dir / "results.jsonl"`` location.
    """
    data = analyze_run_json(run_dir, results_path=results_path)
    if "error" in data:
        logger.warning("Cannot write HTML: %s", data.get("message", data["error"]))
        return

    summary = data["summary"]
    trends = data["trends"]
    deltas = data["deltas"]

    iterations = sorted({r["iteration"] for t in trends for r in t["rows"]})
    # Display labels for iterations in the HTML should start at 1 for readability
    display_iterations = [i + 1 for i in iterations]
    agents = sorted({t["agent"] for t in trends})

    # Aggregate across vulnerabilities — per agent, per iteration, per severity.
    by_agent: Dict[str, Dict[str, Dict[int, int]]] = {
        a: {sev: {it: 0 for it in iterations} for sev in ("high", "medium", "low")}
        for a in agents
    }
    sev_by_iter: Dict[int, Dict[str, int]] = {it: {"high": 0, "medium": 0, "low": 0} for it in iterations}
    for t in trends:
        agent = t["agent"]
        for r in t["rows"]:
            it = r["iteration"]
            counts = {
                "high": (r.get("bandit_high") or 0) + (r.get("semgrep_high") or 0),
                "medium": (r.get("bandit_medium") or 0) + (r.get("semgrep_medium") or 0),
                "low": (r.get("bandit_low") or 0) + (r.get("semgrep_low") or 0),
            }
            for sev, n in counts.items():
                by_agent[agent][sev][it] += n
                sev_by_iter[it][sev] += n

    def _series(sev: str) -> Dict[str, List[int]]:
        return {a: [by_agent[a][sev][it] for it in iterations] for a in agents}

    series_high = _series("high")
    series_medium = _series("medium")
    series_low = _series("low")
    highs = [sev_by_iter[it]["high"] for it in iterations]
    meds = [sev_by_iter[it]["medium"] for it in iterations]
    lows = [sev_by_iter[it]["low"] for it in iterations]

    # Build a lookup of CWEs per (agent, iteration, severity)
    findings = data.get("findings", [])
    def _normalize_cwes(raw) -> List[str]:
        if not raw:
            return []
        if isinstance(raw, list):
            items = [str(x).strip() for x in raw if x]
        else:
            items = [part.strip() for part in str(raw).split(",") if part.strip()]
        out: List[str] = []
        for it in items:
            if not it:
                continue
            if str(it).upper().startswith("CWE"):
                out.append(str(it))
            elif str(it).isdigit():
                out.append(f"CWE-{it}")
            else:
                out.append(str(it))
        return out

    findings_map: Dict[tuple, List[str]] = {}
    for f in findings:
        agent = f.get("agent")
        it = f.get("iteration")
        for issue in f.get("bandit_issues", []) or []:
            sev = (issue.get("severity") or "").lower()
            cwe = issue.get("cwe_id")
            cwes = [f"CWE-{cwe}"] if cwe else []
            if cwes:
                key = (agent, it, sev or "high")
                findings_map.setdefault(key, []).extend(cwes)
        for issue in f.get("semgrep_issues", []) or []:
            sev = _semgrep_issue_severity(issue).lower()
            raw_cwe = issue.get("cwe")
            cwes = _normalize_cwes(raw_cwe)
            if cwes:
                key = (agent, it, sev or "medium")
                findings_map.setdefault(key, []).extend(cwes)

    # Use 1-based display labels for charts while series data remains aligned by index
    chart_high = _svg_multiline(series_high, display_iterations, title="HIGH-severity findings per iteration, by agent")
    chart_medium = _svg_multiline(series_medium, display_iterations, title="MEDIUM-severity findings per iteration, by agent")
    chart_low = _svg_multiline(series_low, display_iterations, title="LOW-severity findings per iteration, by agent")
    chart_stacked = _svg_stacked_bars(display_iterations, highs, meds, lows, title="Findings by severity per iteration (all agents)")

    # Aggregated severity-by-iteration table.
    sev_rows = "".join(
        f"<tr><td>{display_iterations[i]}</td><td>{highs[i]}</td><td>{meds[i]}</td><td>{lows[i]}</td>"
        f"<td>{highs[i]+meds[i]+lows[i]}</td></tr>"
        for i, it in enumerate(iterations)
    )
    # Per-agent tables (one per severity).
    agent_head = "".join(f"<th>{html.escape(a)}</th>" for a in agents)

    def _agent_table(series: Dict[str, List[int]]) -> str:
        # Determine which severity this series represents
        if series is series_high:
            sev_key = "high"
        elif series is series_medium:
            sev_key = "medium"
        else:
            sev_key = "low"

        row_html: List[str] = []
        for i, it in enumerate(iterations):
            cell_html: List[str] = []
            for a in agents:
                count = series[a][i]
                if count and count > 0:
                    key = (a, it, sev_key)
                    cwes = findings_map.get(key, [])
                    if cwes:
                        list_html = "".join(f"<li>{html.escape(c)}</li>" for c in cwes)
                        details = (
                            f"<details class=\"cwe\"><summary>{count}</summary>"
                            f"<div><ul style=\"margin:6px 0 6px 18px;\">{list_html}</ul></div></details>"
                        )
                        cell_html.append(f"<td>{details}</td>")
                    else:
                        cell_html.append(f"<td>{count}</td>")
                else:
                    cell_html.append(f"<td>{count}</td>")
            # show 1-based iteration label to users
            row_html.append("<tr><td>" + str(display_iterations[i]) + "</td>" + "".join(cell_html) + "</tr>")

        return (
            f"<table><thead><tr><th>iteration</th>{agent_head}</tr></thead>"
            f"<tbody>{''.join(row_html)}</tbody></table>"
        )

    table_high = _agent_table(series_high)
    table_medium = _agent_table(series_medium)
    table_low = _agent_table(series_low)

    embedded = {
        "summary": summary,
        "iterations": iterations,
        "high_by_agent": series_high,
        "medium_by_agent": series_medium,
        "low_by_agent": series_low,
        "severity_by_iteration": {"high": highs, "medium": meds, "low": lows},
        "deltas": deltas,
        "findings": findings,
    }

    run_id = html.escape(str(summary.get("run_id") or run_dir.name))
    model = html.escape(", ".join(summary.get("models") or []) or "?")
    irange = summary.get("iteration_range") or []
    irange_str = f"{irange[0]}–{irange[1]}" if len(irange) == 2 else "?"

    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vulnerability trend — {run_id}</title>
<style>{_HTML_CSS}</style></head>
<body>
  <h1>Iterative security-degradation report — {run_id}</h1>
  <div class="meta">Model: {model} &nbsp;·&nbsp; Agents: {len(agents)} &nbsp;·&nbsp;
    Vulnerabilities: {len(summary.get('vulnerabilities') or [])} &nbsp;·&nbsp;
    Iterations: {irange_str} &nbsp;·&nbsp; Records: {summary.get('total_records', 0)}</div>
  <div class="hypothesis"><strong>Hypothesis:</strong> Does the LLM introduce more security
    vulnerabilities after each code-generation iteration?
    (<a href="https://arxiv.org/pdf/2506.11022" target="_blank" rel="noopener">arXiv:2506.11022</a>)
    &nbsp;Counts below are summed across all vulnerabilities in this run.</div>

  <h2>HIGH-severity findings per iteration, by agent</h2>
  {chart_high}

  <h2>MEDIUM-severity findings per iteration, by agent</h2>
  {chart_medium}

  <h2>LOW-severity findings per iteration, by agent</h2>
  {chart_low}

  <h2>Findings by severity per iteration (all agents)</h2>
  {chart_stacked}

  <h2>Severity totals per iteration</h2>
  <table><thead><tr><th>iteration</th><th>HIGH</th><th>MEDIUM</th><th>LOW</th><th>total</th></tr></thead>
    <tbody>{sev_rows}</tbody></table>

  <h2>HIGH-severity findings per iteration, by agent</h2>
  {table_high}

  <h2>MEDIUM-severity findings per iteration, by agent</h2>
  {table_medium}

  <h2>LOW-severity findings per iteration, by agent</h2>
  {table_low}

  <details><summary>Embedded data (JSON) — for additional statistics</summary>
    <pre id="data">{html.escape(json.dumps(embedded, indent=2))}</pre>
  </details>
  <script type="application/json" id="report-data">{json.dumps(embedded)}</script>
</body></html>
"""

    Path(output_path).write_text(doc, encoding="utf-8")
    print(f"\n[info] HTML written to: {output_path}")
    logger.info("HTML written to %s", output_path)
