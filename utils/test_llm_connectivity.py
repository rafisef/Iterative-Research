"""
utils/test_llm_connectivity.py
--------------------------------
Standalone LLM connectivity check.

Confirms that the configured provider API key is valid and reachable by
making a single LLM call against the first vulnerability and first agent
in the config.  Nothing is written to disk — no run directory, no output
files, no results.jsonl.

Usage
-----
From the repository root:

    python utils/test_llm_connectivity.py
    python utils/test_llm_connectivity.py --model gpt-4o-mini
    python utils/test_llm_connectivity.py --model anthropic/claude-3-5-sonnet-20241022
    python utils/test_llm_connectivity.py --config config/config.yaml --model groq/llama-3.3-70b-versatile
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running as a top-level script from the repo root (python utils/test_llm_connectivity.py).
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from framework.agents import resolve_agents_from_config
from framework.io_utils import load_yaml_config, logger
from framework.llm_client import detect_available_models, get_llm_client
from framework.static_scanner import detect_language
from framework.vulnerabilities import resolve_vulnerabilities_from_config


def test_llm_connectivity(
    config_path: str = "config/config.yaml",
    model_override: str | None = None,
) -> None:
    """
    Verify LLM connectivity without writing any files.

    Loads the experiment config, resolves the first configured vulnerability
    and first configured agent, reads the base snippet, and makes a single
    LLM call.  Logs the response length on success.

    Parameters
    ----------
    config_path:
        Path to the YAML experiment config.  Defaults to ``config/config.yaml``.
    model_override:
        LiteLLM model string to use instead of the value in config.
        Pass ``"all"`` to iterate over every provider whose API key is present
        in the environment.
    """
    config = load_yaml_config(config_path)
    llm_cfg = config.get("llm", {})
    config_model: str = llm_cfg.get("model", "gpt-4o")

    # Resolve model(s).
    if model_override is None:
        models_to_check = [config_model]
    elif model_override.lower() == "all":
        models_to_check = detect_available_models()
        if not models_to_check:
            logger.warning(
                "--model all: no provider API keys detected. Falling back to config model: %s",
                config_model,
            )
            models_to_check = [config_model]
    else:
        models_to_check = [model_override]

    for model in models_to_check:
        _check_single_model(config, config_path, model)


def _check_single_model(config: dict, config_path: str, model: str) -> None:
    experiment_cfg = config.get("experiment", {})

    vuln_ids: list[str] = experiment_cfg.get("vulnerabilities", [])
    agent_ids: list[str] = experiment_cfg.get("agents", [])

    if not vuln_ids:
        logger.error("No vulnerabilities configured in %s — cannot run connectivity check.", config_path)
        sys.exit(1)
    if not agent_ids:
        logger.error("No agents configured in %s — cannot run connectivity check.", config_path)
        sys.exit(1)

    vuln = resolve_vulnerabilities_from_config([vuln_ids[0]])[0]
    agent = resolve_agents_from_config([agent_ids[0]], agents_cfg=config.get("agents", {}))[0]
    language = detect_language(vuln.base_snippet_path)

    snippet_path = Path(vuln.base_snippet_path)
    if not snippet_path.exists():
        logger.error("Base snippet not found: %s", snippet_path)
        sys.exit(1)

    base_snippet = snippet_path.read_text(encoding="utf-8")
    instruction = agent.random_instruction()

    logger.info(
        "Connectivity check — model=%s  vuln=%s  agent=%s  language=%s",
        model, vuln.id, agent.id, language,
    )
    logger.info("Prompt: %s", instruction)

    llm_client = get_llm_client(config_path=config_path, model_override=model)
    generated = llm_client.generate_from_snippet(base_snippet, instruction, language=language)

    if not generated.strip():
        logger.warning("Connectivity check FAILED — model=%s returned an empty response.", model)
    else:
        logger.info(
            "Connectivity check PASSED — model=%s responded with %d chars.",
            model, len(generated),
        )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Test LLM connectivity: makes one call and logs the result. Nothing written to disk.",
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config/config.yaml",
        help="Path to YAML config file. Default: config/config.yaml.",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        metavar="MODEL",
        help=(
            "LLM model to test. Overrides llm.model in config. "
            "Use 'all' to test every provider whose API key is set in the environment. "
            "Examples: gpt-4o-mini  anthropic/claude-3-5-sonnet-20241022  groq/llama-3.3-70b-versatile  all"
        ),
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    test_llm_connectivity(config_path=args.config, model_override=args.model)
