#!/usr/bin/env python3
"""
analyze.py — Vulnerability trend analyzer for iterative LLM research results.

Reads results.jsonl from a timestamped run directory and prints:
  1. A summary header (record counts, agents, models, iteration range)
  2. Per-agent trend tables (Bandit HIGH/MED, Semgrep findings with bar charts)
  3. Per-agent finding-type detail (specific test IDs, rule IDs, CWEs, messages)
  4. A delta summary (first → last iteration change per agent)

Run discovery (in order of precedence):
  --results path/to/results.jsonl  → load that file directly
  --run 2026-03-18_14-30-00        → load runs/<run-id>/results.jsonl
  --run runs/2026-03-18_14-30-00   → load from an explicit path
  (none)                           → auto-detect the most recent run in runs/

Usage:
  python analyze.py                              # latest run
  python analyze.py --run 2026-03-18_14-30-00   # specific run by ID
  python analyze.py --list-runs                  # enumerate all runs
  python analyze.py --results results.jsonl      # explicit file (legacy)
  python analyze.py --csv out.csv --no-findings  # CSV export, no detail
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


RUNS_DIR = "runs"


# ---------------------------------------------------------------------------
# Run discovery
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
    # Direct path given
    p = Path(run_arg)
    if p.is_file():
        return str(p)
    if p.is_dir() and (p / "results.jsonl").exists():
        return str(p / "results.jsonl")
    # Treat as run ID under runs_dir
    candidate = Path(runs_dir) / run_arg / "results.jsonl"
    if candidate.exists():
        return str(candidate)
    return None


def list_runs(runs_dir: str = RUNS_DIR) -> None:
    """Print a table of all available runs with key metadata."""
    dirs = _all_run_dirs(runs_dir)
    if not dirs:
        print(f"[info] No runs found in '{runs_dir}/'.")
        print("[info] Run 'python -m framework.runner' to create the first run.")
        return

    print(f"\n{'=' * 70}")
    print(f"  Available runs in {runs_dir}/  ({len(dirs)} total)")
    print(f"{'=' * 70}")
    print(f"  {'Run ID':<26}  {'Records':>7}  {'Model':<20}  {'Iterations'}")
    print(f"  {'-' * 26}  {'-' * 7}  {'-' * 20}  {'-' * 10}")

    latest_id = dirs[-1].name if dirs else ""
    for d in reversed(dirs):  # newest first
        results_file = d / "results.jsonl"
        records = _count_lines(results_file)

        # Try to read metadata for model/iterations summary.
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

def load_results(results_path: str) -> List[Dict[str, Any]]:
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
                records.append(json.loads(line))
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
        vuln = r.get("vulnerability_id", "unknown")
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
    vulns = sorted({r.get("vulnerability_id", "?") for r in records})
    models = sorted({r.get("model", "?") for r in records})
    iters = sorted({r.get("iteration", -1) for r in records})
    run_ids = sorted({r.get("run_id", "") for r in records if r.get("run_id")})

    # Try to load run_metadata.json from the same directory as results.jsonl.
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
    print(f"  Iterations      : {min(iters)} – {max(iters)}  ({len(iters)} distinct values)")

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
    return "█" * filled + "░" * (width - filled)


def print_trend_table(
    grouped: Dict[str, Dict[str, Dict[int, Dict[str, Any]]]],
    metric_keys: List[Tuple[str, str]],
) -> None:
    """Prints an ASCII trend table for each vulnerability → agent combination."""
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
                    max_vals[key] = max(max_vals[key], int(rec.get(key, 0)))

            for it in all_iters:
                rec = iterations[it]
                prompt_short = (rec.get("prompt") or "")[:38].replace("\n", " ")
                print(f"  {it:<6}", end="")
                for key, _ in metric_keys:
                    val = int(rec.get(key, 0))
                    bar = _bar(val, max_vals[key])
                    print(f"  {val:<3} {bar} ", end="")
                print(f"  {prompt_short}")

        print(f"\n  {'--- Delta summary (first → last iteration) ---'}")
        for agent_id, iterations in sorted(agents.items()):
            if len(iterations) < 2:
                continue
            all_iters = sorted(iterations.keys())
            first = iterations[all_iters[0]]
            last = iterations[all_iters[-1]]
            deltas = []
            for key, label in metric_keys:
                delta = int(last.get(key, 0)) - int(first.get(key, 0))
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


def _format_semgrep_issue(issue: Dict[str, Any]) -> str:
    rule_id = issue.get("rule_id", "?")
    severity = issue.get("severity", "?")
    line = issue.get("line_number", "?")
    message = (issue.get("message") or "").strip()
    matched = (issue.get("matched_lines") or "").strip().replace("\n", " ")
    matched_str = f'  → "{matched[:60]}"' if matched else ""
    return f"    [SEMGREP] {rule_id} ({severity})  line {line}  {message}{matched_str}"


def print_finding_types(
    grouped: Dict[str, Dict[str, Dict[int, Dict[str, Any]]]],
) -> None:
    """
    Prints per-iteration finding detail and a deduplicated unique-type summary
    per agent per vulnerability.
    """
    for vuln_id, agents in sorted(grouped.items()):
        print(f"\n{'=' * 70}")
        print(f"  Finding Types — Vulnerability: {vuln_id}")
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
                    sev = issue.get("severity", "?")
                    msg = (issue.get("message") or "")[:80].strip()
                    print(f"    [SEMGREP] {rid}  ({sev})  {msg}")
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
        run_id, vulnerability_id, agent, model, iteration, prompt,
        bandit_high, bandit_medium, bandit_low, semgrep_findings,
        nuclei_exit_code, server_started, success, snippet_path, static_log_path

    Finding columns (empty when no findings):
        finding_tool      — "bandit" | "semgrep" | ""
        finding_id        — Bandit test_id  /  Semgrep rule_id
        finding_name      — Bandit test_name  /  "" for Semgrep
        finding_severity  — HIGH | MEDIUM | LOW | WARNING | ERROR | ""
        finding_confidence— Bandit confidence (HIGH/MEDIUM/LOW) | ""
        finding_cwe       — e.g. "CWE-78"  |  ""
        finding_line      — source line number | ""
        finding_message   — Bandit issue_text  /  Semgrep message
        finding_code      — Semgrep matched_lines  /  "" for Bandit
    """
    context_fields = [
        "run_id", "vulnerability_id", "agent", "model", "iteration", "prompt",
        "bandit_high", "bandit_medium", "bandit_low", "semgrep_findings",
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
            "finding_severity": issue.get("severity", ""),
            "finding_confidence": "",
            "finding_cwe": "",
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


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze iterative LLM research results and print vulnerability trends."
    )

    source_group = parser.add_mutually_exclusive_group()
    source_group.add_argument(
        "--results",
        type=str,
        default="",
        help="Direct path to a results.jsonl file.",
    )
    source_group.add_argument(
        "--run",
        type=str,
        default="",
        metavar="RUN_ID_OR_PATH",
        help=(
            "Run ID (e.g. 2026-03-18_14-30-00) or path to a run directory. "
            "Defaults to the most recent run in runs/."
        ),
    )
    source_group.add_argument(
        "--list-runs",
        action="store_true",
        help="List all available runs and exit.",
    )

    parser.add_argument(
        "--runs-dir",
        type=str,
        default=RUNS_DIR,
        help=f"Root directory containing all run folders (default: {RUNS_DIR}).",
    )
    parser.add_argument(
        "--csv",
        type=str,
        default="",
        help="If provided, also write results to this CSV file path.",
    )
    parser.add_argument(
        "--agent",
        type=str,
        default="",
        help="Filter output to a single agent ID.",
    )
    parser.add_argument(
        "--vuln",
        type=str,
        default="",
        help="Filter output to a single vulnerability ID.",
    )
    parser.add_argument(
        "--no-findings",
        action="store_true",
        help="Skip the per-finding detail section; show only trend tables.",
    )
    args = parser.parse_args()

    # --- Resolve which results.jsonl to load ----------------------------------
    if args.list_runs:
        list_runs(args.runs_dir)
        return

    if args.results:
        results_path = args.results
    elif args.run:
        results_path = resolve_run_path(args.run, args.runs_dir)
        if results_path is None:
            print(
                f"[error] Could not resolve run '{args.run}'. "
                f"Use --list-runs to see available runs.",
                file=sys.stderr,
            )
            sys.exit(1)
    else:
        results_path = find_latest_results(args.runs_dir)
        if results_path is None:
            print(
                f"[error] No runs found in '{args.runs_dir}/'. "
                "Run the experiment first: python -m framework.runner",
                file=sys.stderr,
            )
            sys.exit(1)
        print(f"[info] Auto-selected most recent run: {Path(results_path).parent.name}")

    # --- Load and analyze -----------------------------------------------------
    records = load_results(results_path)
    print_summary(records, results_path)

    grouped = group_records(
        records,
        filter_agent=args.agent or None,
        filter_vuln=args.vuln or None,
    )

    if not any(grouped.values()):
        print("[info] No matching records to display.")
        return

    has_static = any(
        r.get("bandit_high") is not None
        for agent_data in grouped.values()
        for iter_data in agent_data.values()
        for r in iter_data.values()
    )

    if has_static:
        metric_keys: List[Tuple[str, str]] = [
            ("bandit_high", "Bandit HIGH"),
            ("bandit_medium", "Bandit MED"),
            ("bandit_low", "Bandit LOW"),
            ("semgrep_findings", "Semgrep"),
        ]
    else:
        metric_keys = [("nuclei_exit_code", "Nuclei exit")]

    print_trend_table(grouped, metric_keys)

    if not args.no_findings:
        print_finding_types(grouped)

    if args.csv:
        write_csv(grouped, args.csv)


if __name__ == "__main__":
    main()
