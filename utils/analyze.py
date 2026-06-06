#!/usr/bin/env python3
"""
utils/analyze.py — Vulnerability trend analyzer for iterative LLM research results.

Reads a results.jsonl file (produced by the scan stage) and prints:
  1. A summary header (record counts, agents, models, iteration range)
  2. Per-agent trend tables (Bandit + Semgrep HIGH/MED/LOW with bar charts)
  3. Per-agent finding-type detail (specific test IDs, rule IDs, CWEs, messages)
  4. A delta summary (first → last iteration change per agent)

Optionally exports the data to CSV and/or a self-contained HTML report that
visualizes the core research hypothesis from arXiv:2506.11022 — does the LLM
introduce more security vulnerabilities after each iteration?

All analysis logic lives in framework/analyzer.py; this script is a thin CLI
wrapper responsible only for argument parsing.

Usage:
  python utils/analyze.py --list                                  # list run folders
  python utils/analyze.py -f runs/<run-id>/results.jsonl          # print report
  python utils/analyze.py -f runs/<run-id>/results.jsonl --csv out.csv
  python utils/analyze.py -f runs/<run-id>/results.jsonl --html out.html
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running as a top-level script from the repo root.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from framework.analyzer import analyze_run, list_runs, write_html


RUNS_DIR = "runs"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze iterative LLM research results and print vulnerability trends."
    )
    parser.add_argument(
        "-f", "--file",
        type=str,
        default="",
        metavar="PATH",
        help="Path to a results.jsonl file to analyze (required unless --list).",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List the run folders under the runs/ directory and exit.",
    )
    parser.add_argument(
        "--csv",
        type=str,
        default="",
        metavar="PATH",
        help="Output path for CSV results (one row per finding).",
    )
    parser.add_argument(
        "--html",
        type=str,
        default="",
        metavar="PATH",
        help="Output path for a self-contained HTML visualization of the data.",
    )
    args = parser.parse_args()

    if args.list:
        list_runs(RUNS_DIR)
        return

    if not args.file:
        parser.error("provide -f/--file <results.jsonl> (or use --list to see runs)")

    results_path = Path(args.file)
    if not results_path.is_file():
        print(f"[error] results file not found: {results_path}", file=sys.stderr)
        sys.exit(1)

    run_dir = results_path.parent

    # Print the full text report (and write CSV if requested).
    analyze_run(
        run_dir=run_dir,
        results_path=str(results_path),
        include_findings=True,
        csv_path=args.csv or None,
    )

    if args.html:
        write_html(run_dir, args.html, results_path=str(results_path))


if __name__ == "__main__":
    main()
