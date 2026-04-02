"""
utils/generate.py
------------------
Standalone CLI wrapper for the code-generation component.

Runs LLM generation for all configured agent × vulnerability combinations and
writes output files to a timestamped run directory under runs/.  No static
scanning is performed — run utils/scan.py afterwards to scan the outputs.

Usage
-----
From the repository root:

    python utils/generate.py                              # uses config defaults
    python utils/generate.py --run-id my-run              # custom run ID
    python utils/generate.py --model gpt-4o-mini --iterations 3
    python utils/generate.py --snippet snippets/typescript/injection/injection_sql_cmd_base.ts
    python utils/generate.py --base-code-dir snippets/python/
    python utils/generate.py --base-code-dir snippets/         # all languages
    python utils/generate.py --config config/config.yaml

To run the full pipeline in one step (generate + scan + analyze):
    python main.py
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

# Allow running as a top-level script from the repo root.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from framework.agents import resolve_agents_from_config
from framework.generator import discover_snippets_from_dir, generate_code
from framework.io_utils import ensure_dir, load_yaml_config, logger
from framework.static_scanner import detect_language
from framework.vulnerabilities import Vulnerability, resolve_vulnerabilities_from_config


def _make_run_id() -> str:
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate LLM code iterations for all agent × vulnerability combinations. "
            "Outputs are saved to runs/<run-id>/outputs/. "
            "Run utils/scan.py next to perform static analysis."
        )
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config/config.yaml",
        help="Path to YAML configuration file. Default: config/config.yaml.",
    )
    parser.add_argument(
        "--run-id",
        type=str,
        default="",
        help=(
            "Override the auto-generated run ID (YYYY-MM-DD_HH-MM-SS). "
            "Useful for naming or resuming an experiment."
        ),
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=None,
        help="Number of LLM improvement iterations. Overrides experiment.iterations in config.",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        metavar="MODEL",
        help=(
            "LLM model to use. Overrides llm.model in config. "
            "Examples: gpt-4o-mini  anthropic/claude-3-5-sonnet-20241022  groq/llama-3.3-70b-versatile"
        ),
    )
    source_group = parser.add_mutually_exclusive_group()
    source_group.add_argument(
        "--snippet",
        type=str,
        default=None,
        metavar="PATH",
        help=(
            "Run generation against a single snippet file, bypassing the vulnerability registry. "
            "Language is inferred from the file extension (.py → Python; .ts/.js → TypeScript). "
            "The file's stem is used as the vulnerability ID. "
            "Mutually exclusive with --base-code-dir."
        ),
    )
    source_group.add_argument(
        "--base-code-dir",
        type=str,
        default=None,
        metavar="DIR",
        help=(
            "Run generation against all snippet files found recursively under DIR, "
            "bypassing the vulnerability registry. Each file becomes its own vulnerability; "
            "IDs are derived from the relative file path "
            "(e.g. python/injection/xss_base.py → python_injection_xss_base). "
            "Supported extensions: .py, .ts, .tsx, .js, .jsx, .mjs, .cjs. "
            "Mutually exclusive with --snippet."
        ),
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    config = load_yaml_config(args.config)
    experiment_cfg = config.get("experiment", {})
    paths_cfg = config.get("paths", {})

    # Resolve model.
    llm_cfg = config.get("llm", {})
    active_model = args.model or llm_cfg.get("model", "gpt-4o")
    config.setdefault("llm", {})
    config["llm"]["model"] = active_model

    # Resolve iterations.
    iterations = (
        int(args.iterations)
        if args.iterations is not None
        else int(experiment_cfg.get("iterations", 5))
    )

    runs_dir = paths_cfg.get("runs_dir", "runs")
    run_id = args.run_id.strip() or _make_run_id()
    run_dir = Path(runs_dir) / run_id
    ensure_dir(run_dir)

    agent_ids = experiment_cfg.get("agents", [])
    vuln_ids = experiment_cfg.get("vulnerabilities", [])
    seed = experiment_cfg.get("random_seed")
    max_workers = max(1, int(experiment_cfg.get("max_workers", 1)))

    agents = resolve_agents_from_config(agent_ids, agents_cfg=config.get("agents", {}))

    snippet_path_arg: str | None = None
    base_code_dir_arg: str | None = None

    if args.snippet is not None:
        snippet_file = Path(args.snippet)
        if not snippet_file.exists():
            logger.error("--snippet file not found: %s", args.snippet)
            sys.exit(1)
        lang = detect_language(args.snippet)
        if lang == "unknown":
            logger.warning(
                "--snippet: unrecognised extension for %s; defaulting to TypeScript.",
                args.snippet,
            )
        vulns = [
            Vulnerability(
                id=snippet_file.stem,
                description=f"Ad-hoc snippet: {snippet_file.name}",
                base_snippet_path=str(snippet_file),
            )
        ]
        logger.info(
            "--snippet: generating against %s (language=%s, vuln_id=%s)",
            args.snippet, lang, snippet_file.stem,
        )
        snippet_path_arg = args.snippet
    elif args.base_code_dir is not None:
        try:
            vulns = discover_snippets_from_dir(Path(args.base_code_dir))
        except (FileNotFoundError, NotADirectoryError) as exc:
            logger.error("%s", exc)
            sys.exit(1)
        if not vulns:
            logger.error(
                "--base-code-dir: no supported snippet files found in %s. "
                "Supported extensions: .py, .ts, .tsx, .js, .jsx, .mjs, .cjs",
                args.base_code_dir,
            )
            sys.exit(1)
        logger.info(
            "--base-code-dir: discovered %d snippet(s) in %s",
            len(vulns), args.base_code_dir,
        )
        base_code_dir_arg = args.base_code_dir
    else:
        vulns = resolve_vulnerabilities_from_config(vuln_ids)

    logger.info(
        "Starting code generation — run_id=%s  model=%s  iterations=%d  "
        "agents=%s  vulns=%s",
        run_id, active_model, iterations,
        [a.id for a in agents],
        [v.id for v in vulns],
    )

    generate_code(
        config=config,
        config_path=args.config,
        run_dir=run_dir,
        agents=agents,
        vulns=vulns,
        iterations=iterations,
        max_workers=max_workers,
        seed=seed,
        model_override=active_model,
        snippet_path_arg=snippet_path_arg,
        base_code_dir_arg=base_code_dir_arg,
    )

    logger.info(
        "Generation complete. Run static scans next:\n"
        "    python utils/scan.py --run %s",
        run_id,
    )


if __name__ == "__main__":
    main()
