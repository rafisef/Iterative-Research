"""
utils/scan.py
--------------
Standalone CLI wrapper for the static-scanning component.

Reads run_metadata.json from an existing run directory to discover which
agents / vulnerabilities / iterations were generated, then runs Bandit and/or
Semgrep against every output file and appends ResultRecords to results.jsonl.

Can be pointed at any run directory, including ones created independently
(e.g. by utils/generate.py or manually populated).

Usage
-----
From the repository root:

    python utils/scan.py                              # scan the latest run
    python utils/scan.py --run 2026-04-01_11-34-04   # scan a specific run
    python utils/scan.py --run runs/my-run            # explicit path
    python utils/scan.py --config config/config.yaml  # custom config

To run the full pipeline in one step (generate + scan + analyze):
    python main.py
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running as a top-level script from the repo root.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from framework.io_utils import load_yaml_config, logger
from framework.scan_runner import run_scans


RUNS_DIR = "runs"


def _find_latest_run(runs_dir: str = RUNS_DIR) -> Path | None:
    """Return the most recently created run directory, or None if none exist."""
    runs_path = Path(runs_dir)
    if not runs_path.exists():
        return None
    subdirs = sorted(
        (p for p in runs_path.iterdir() if p.is_dir()),
        key=lambda p: p.name,
    )
    return subdirs[-1] if subdirs else None


def _resolve_run_dir(run_arg: str, runs_dir: str = RUNS_DIR) -> Path | None:
    """Accept a run ID or path and return the resolved run directory Path."""
    p = Path(run_arg)
    if p.is_dir():
        return p
    candidate = Path(runs_dir) / run_arg
    if candidate.is_dir():
        return candidate
    return None


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run static analysis (Bandit / Semgrep) on all generated output files "
            "in an existing run directory. Reads run_metadata.json to discover "
            "what to scan; writes results to results.jsonl."
        )
    )
    parser.add_argument(
        "--run",
        type=str,
        default="",
        metavar="RUN_ID_OR_PATH",
        help=(
            "Run ID (e.g. 2026-04-01_11-34-04) or path to a run directory. "
            "Defaults to the most recent run in runs/."
        ),
    )
    parser.add_argument(
        "--runs-dir",
        type=str,
        default=RUNS_DIR,
        help=f"Root directory containing all run folders. Default: {RUNS_DIR}.",
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config/config.yaml",
        help="Path to YAML configuration file. Default: config/config.yaml.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    # Resolve the run directory.
    if args.run:
        run_dir = _resolve_run_dir(args.run, args.runs_dir)
        if run_dir is None:
            logger.error(
                "Could not find run directory for '%s'. "
                "Use a valid run ID under %s/ or an explicit path.",
                args.run, args.runs_dir,
            )
            sys.exit(1)
    else:
        run_dir = _find_latest_run(args.runs_dir)
        if run_dir is None:
            logger.error(
                "No run directories found in '%s/'. "
                "Run code generation first:\n    python utils/generate.py",
                args.runs_dir,
            )
            sys.exit(1)
        logger.info("Auto-selected most recent run: %s", run_dir.name)

    config = load_yaml_config(args.config)
    experiment_cfg = config.get("experiment", {})
    max_workers = max(1, int(experiment_cfg.get("max_workers", 1)))

    logger.info("Scanning run directory: %s", run_dir.resolve())

    run_scans(run_dir=run_dir, config=config, max_workers=max_workers)

    logger.info(
        "Scan complete. Analyze results next:\n"
        "    python utils/analyze.py --run %s",
        run_dir.name,
    )


if __name__ == "__main__":
    main()
