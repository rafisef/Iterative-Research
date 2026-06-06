"""
utils/scan.py
--------------
Standalone CLI wrapper for static Semgrep (+ Bandit for Python) scanning.

Scans either a single file or a directory (recursively) and writes a
results.jsonl file that can be analyzed with utils/analyze.py.

Usage:
  python utils/scan.py --code-snippet-individual path/to/file.ts -o out/results.jsonl
  python utils/scan.py --code-snippet-dir snippets/ -o out/results.jsonl
  python utils/scan.py --code-snippet-dir runs/my-run/ai-generated-code-snippets/ \\
      -o runs/my-run/results.jsonl --semgrep-config "p/xss p/owasp-top-ten"
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from framework.io_utils import logger
from framework.scan_runner import scan_files

_DEFAULT_SEMGREP_CONFIG = "auto"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan a file or directory with Semgrep (and Bandit for Python) "
                    "and write a results.jsonl.",
    )

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--code-snippet-dir",
        type=str,
        default="",
        metavar="DIR",
        help="Directory of code snippets to scan recursively.",
    )
    source.add_argument(
        "--code-snippet-individual",
        type=str,
        default="",
        metavar="FILE",
        help="Path to an individual file to scan.",
    )

    parser.add_argument(
        "-o", "--output",
        type=str,
        required=True,
        metavar="PATH",
        help="Output path for the results.jsonl scan file.",
    )
    parser.add_argument(
        "--semgrep-config",
        type=str,
        default=_DEFAULT_SEMGREP_CONFIG,
        metavar="RULESETS",
        help=(
            'Space-separated Semgrep rule packs to use instead of defaults. '
            'Example: "p/xss p/owasp-top-ten". '
            f'(default: {_DEFAULT_SEMGREP_CONFIG})'
        ),
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=1,
        metavar="N",
        help="Number of parallel worker threads to use for scanning (default: 1).",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    target = args.code_snippet_dir or args.code_snippet_individual

    try:
        output_path = scan_files(
            target=target,
            output_path=args.output,
            semgrep_config=args.semgrep_config,
            max_workers=args.max_workers,
        )
    except (FileNotFoundError, ValueError) as exc:
        logger.error("%s", exc)
        sys.exit(1)

    logger.info(
        "Scan complete. Analyze results:\n"
        "    python utils/analyze.py -f %s",
        output_path,
    )


if __name__ == "__main__":
    main()
