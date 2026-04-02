"""
utils/scan.py
--------------
Standalone CLI wrapper for the static-scanning component.

Modes
-----
1) Run-directory mode (default):
    python utils/scan.py --run 2026-04-01_11-34-04

2) Baseline scan mode:
    python utils/scan.py --baseline-scan --snippet path/to/file.ts
    python utils/scan.py --baseline-scan --base-code-dir snippets/

3) Ad-hoc scan mode (re-scan any files without baseline tagging):
    python utils/scan.py --adhoc-scan --snippet path/to/file.ts
    python utils/scan.py --adhoc-scan --base-code-dir runs/my-run/ai-generated-code-snippets/

Options
-------
    --semgrep-config "p/xss p/owasp-top-ten"   Override Semgrep rulesets
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from framework.io_utils import load_yaml_config, logger
from framework.scan_runner import run_scans, scan_baseline


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
            "Run static analysis (Bandit / Semgrep) on generated output files "
            "in an existing run directory, or perform a baseline scan on "
            "arbitrary source files."
        )
    )

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--run",
        type=str,
        default="",
        metavar="RUN_ID_OR_PATH",
        help=(
            "Run ID (e.g. 2026-04-01_11-34-04) or path to a run directory. "
            "Defaults to the most recent run in runs/."
        ),
    )
    mode.add_argument(
        "--baseline-scan",
        action="store_true",
        help="Scan arbitrary files/directories to create a baseline of findings.",
    )
    mode.add_argument(
        "--adhoc-scan",
        action="store_true",
        help="Scan arbitrary files/directories (ad-hoc). Like baseline but tagged agent='scan'.",
    )

    parser.add_argument(
        "--snippet",
        type=str,
        default="",
        metavar="FILE",
        help="Single source file to scan (used with --baseline-scan or --adhoc-scan).",
    )
    parser.add_argument(
        "--base-code-dir",
        type=str,
        default="",
        metavar="DIR",
        help="Directory of source files to scan (used with --baseline-scan or --adhoc-scan).",
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
    parser.add_argument(
        "--semgrep-config",
        type=str,
        default="",
        metavar="RULESETS",
        help=(
            'Space-separated Semgrep rule packs to use instead of defaults. '
            'Example: "p/xss p/owasp-top-ten"'
        ),
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    if args.baseline_scan:
        target = args.snippet or args.base_code_dir
        if not target:
            logger.error(
                "--baseline-scan requires --snippet <FILE> or --base-code-dir <DIR>"
            )
            sys.exit(1)

        run_dir = scan_baseline(
            target=target,
            runs_dir=args.runs_dir,
            semgrep_config=args.semgrep_config,
        )
        logger.info(
            "Baseline scan complete. Analyze results:\n"
            "    python utils/analyze.py --run %s",
            run_dir.name,
        )
        return

    if args.adhoc_scan:
        target = args.snippet or args.base_code_dir
        if not target:
            logger.error(
                "--adhoc-scan requires --snippet <FILE> or --base-code-dir <DIR>"
            )
            sys.exit(1)

        from framework.scan_runner import scan_adhoc
        run_dir = scan_adhoc(
            target=target,
            runs_dir=args.runs_dir,
            semgrep_config=args.semgrep_config,
        )
        logger.info(
            "Adhoc scan complete. Analyze results:\n"
            "    python utils/analyze.py --run %s",
            run_dir.name,
        )
        return

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

    run_scans(
        run_dir=run_dir,
        config=config,
        max_workers=max_workers,
        semgrep_config_override=args.semgrep_config,
    )

    logger.info(
        "Scan complete. Analyze results next:\n"
        "    python utils/analyze.py --run %s",
        run_dir.name,
    )


if __name__ == "__main__":
    main()
