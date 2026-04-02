#!/usr/bin/env python3
"""
utils/analyze.py — Vulnerability trend analyzer for iterative LLM research results.

Reads results.jsonl from a timestamped run directory and prints:
  1. A summary header (record counts, agents, models, iteration range)
  2. Per-agent trend tables (Bandit HIGH/MED, Semgrep findings with bar charts)
  3. Per-agent finding-type detail (specific test IDs, rule IDs, CWEs, messages)
  4. A delta summary (first → last iteration change per agent)

All analysis logic lives in framework/analyzer.py; this script is a thin CLI
wrapper responsible only for argument parsing and run-directory resolution.

Run discovery (in order of precedence):
  --results path/to/results.jsonl  → load that file directly
  --run 2026-03-18_14-30-00        → load runs/<run-id>/results.jsonl
  --run runs/2026-03-18_14-30-00   → load from an explicit path
  (none)                           → auto-detect the most recent run in runs/

Usage:
  python utils/analyze.py                              # latest run
  python utils/analyze.py --run 2026-03-18_14-30-00   # specific run by ID
  python utils/analyze.py --list-runs                  # enumerate all runs
  python utils/analyze.py --results results.jsonl      # explicit file (legacy)
  python utils/analyze.py --csv out.csv --no-findings  # CSV export, no detail
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running as a top-level script from the repo root.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from framework.analyzer import (
    analyze_run,
    find_latest_results,
    group_records,
    list_runs,
    load_results,
    print_finding_types,
    print_summary,
    print_trend_table,
    resolve_run_path,
    write_csv,
)


RUNS_DIR = "runs"


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
                "Run the experiment first: python main.py",
                file=sys.stderr,
            )
            sys.exit(1)
        print(f"[info] Auto-selected most recent run: {Path(results_path).parent.name}")

    # --- Delegate to framework/analyzer.py ------------------------------------
    run_dir = Path(results_path).parent
    analyze_run(
        run_dir=run_dir,
        vuln_filter=args.vuln or None,
        agent_filter=args.agent or None,
        include_findings=not args.no_findings,
        csv_path=args.csv or None,
    )


if __name__ == "__main__":
    main()
