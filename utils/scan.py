"""
utils/scan.py
--------------
Standalone CLI wrapper for the static-scanning component.

Supports two modes:

1. **Run-directory mode** (default) — reads run_metadata.json from an
   existing run directory to discover which agents / vulnerabilities /
   iterations were generated, then runs Bandit and/or Semgrep against
   every output file and appends ResultRecords to results.jsonl.

2. **Snippet mode** — scans one or more arbitrary code files directly
   (via ``--snippet`` or ``--base-code-dir``).  No run directory is
   required; results are printed to stdout as JSON.

Usage
-----
From the repository root:

    # ── Run-directory mode ──────────────────────────────────────────
    python utils/scan.py                              # scan the latest run
    python utils/scan.py --run 2026-04-01_11-34-04   # scan a specific run
    python utils/scan.py --run runs/my-run            # explicit path

    # ── Snippet mode ────────────────────────────────────────────────
    python utils/scan.py --snippet snippets/typescript-vulnerable-code/injection/sql-injection.ts
    python utils/scan.py --snippet path/to/any_file.py
    python utils/scan.py --base-code-dir snippets/    # scan every supported file recursively

To run the full pipeline in one step (generate + scan + analyze):
    python main.py
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from framework.io_utils import load_yaml_config, logger
from framework.scan_runner import run_scans
from framework.static_scanner import (
    _DEFAULT_SEMGREP_PACKS,
    _JS_TS_EXTS,
    _PYTHON_EXTS,
    detect_language,
    run_bandit,
    run_semgrep,
)

RUNS_DIR = "runs"
_SNIPPET_EXTS = _PYTHON_EXTS | _JS_TS_EXTS


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


def _collect_snippets(base_dir: Path) -> List[Path]:
    """Recursively collect all supported code files under *base_dir*."""
    return sorted(
        p for p in base_dir.rglob("*")
        if p.is_file() and p.suffix.lower() in _SNIPPET_EXTS
    )


def _scan_snippet(snippet_path: Path) -> dict:
    """Run static analysis on a single file and return a results dict."""
    language = detect_language(str(snippet_path))
    packs = _DEFAULT_SEMGREP_PACKS.get(language, "p/owasp-top-ten")

    result: dict = {
        "file": str(snippet_path),
        "language": language,
    }

    if language == "python":
        bandit = run_bandit(str(snippet_path))
        result["bandit"] = {
            "high": bandit.high,
            "medium": bandit.medium,
            "low": bandit.low,
            "issues": bandit.issues,
            "errors": bandit.errors,
        }

    semgrep = run_semgrep(str(snippet_path), packs)
    result["semgrep"] = {
        "findings": semgrep.findings,
        "rules_matched": semgrep.rules_matched,
        "issues": semgrep.issues,
        "errors": semgrep.errors,
    }

    return result


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run static analysis (Bandit / Semgrep) on generated run files "
            "or arbitrary code snippets."
        )
    )

    target = parser.add_mutually_exclusive_group()
    target.add_argument(
        "--run",
        type=str,
        default="",
        metavar="RUN_ID_OR_PATH",
        help=(
            "Run ID (e.g. 2026-04-01_11-34-04) or path to a run directory. "
            "Defaults to the most recent run in runs/."
        ),
    )
    target.add_argument(
        "--snippet",
        type=str,
        default="",
        metavar="FILE",
        help="Scan a single code file directly (any .py/.ts/.js etc.).",
    )
    target.add_argument(
        "--base-code-dir",
        type=str,
        default="",
        metavar="DIR",
        help=(
            "Recursively scan all supported code files under DIR. "
            "Supported extensions: .py, .ts, .tsx, .js, .jsx, .mjs, .cjs."
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


# ── Snippet mode ──────────────────────────────────────────────────────────────

def _run_snippet_mode(files: List[Path]) -> None:
    """Scan one or more arbitrary files and print results to stdout."""
    all_results: List[dict] = []
    for f in files:
        logger.info("Scanning %s", f)
        all_results.append(_scan_snippet(f))

    # Print summary
    total_findings = 0
    for r in all_results:
        n_semgrep = r.get("semgrep", {}).get("findings", 0)
        n_bandit = sum(
            r.get("bandit", {}).get(sev, 0) for sev in ("high", "medium", "low")
        )
        total_findings += n_semgrep + n_bandit

        logger.info(
            "  %s  semgrep=%d%s",
            r["file"],
            n_semgrep,
            f"  bandit(H/M/L)={r['bandit']['high']}/{r['bandit']['medium']}/{r['bandit']['low']}"
            if "bandit" in r else "",
        )

    logger.info("Scan complete: %d file(s), %d total finding(s)", len(files), total_findings)

    print(json.dumps(all_results, indent=2))


# ── Run-directory mode ────────────────────────────────────────────────────────

def _run_directory_mode(args: argparse.Namespace) -> None:
    """Original behaviour: scan all output files in an existing run directory."""
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


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    args = _parse_args()

    if args.snippet:
        snippet = Path(args.snippet)
        if not snippet.is_file():
            logger.error("Snippet file not found: %s", snippet)
            sys.exit(1)
        _run_snippet_mode([snippet])
    elif args.base_code_dir:
        base_dir = Path(args.base_code_dir)
        if not base_dir.is_dir():
            logger.error("Directory not found: %s", base_dir)
            sys.exit(1)
        files = _collect_snippets(base_dir)
        if not files:
            logger.error("No supported code files found under %s", base_dir)
            sys.exit(1)
        logger.info("Found %d file(s) under %s", len(files), base_dir)
        _run_snippet_mode(files)
    else:
        _run_directory_mode(args)


if __name__ == "__main__":
    main()
