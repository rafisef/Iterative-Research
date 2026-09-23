"""
framework/generator.py
-----------------------
Code-generation component of the three-component pipeline.

Responsibilities
----------------
- Seed the RNG (reproducibility)
- For each vulnerability × iteration × agent: call the LLM, save output file
- Python syntax-check warning (preserved from the original runner)
- Previous-iteration fallback logic (preserved)
- Write run_metadata.json
- Write generation_log.jsonl (per-iteration prompt log consumed by scan_runner)

Public API
----------
    generate_code(config, config_path, run_dir, agents, vulns, iterations, **opts) -> Path
    write_run_metadata(run_dir, run_id, config, *, effective_iterations, ...) -> None
    discover_snippets_from_dir(base_dir) -> List[Vulnerability]
"""
from __future__ import annotations

import json
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from .agents import Agent
from .io_utils import AI_CODE_DIR, ensure_dir, logger, read_text, write_text
from .llm_client import get_llm_client, _fetch_supported_parameters
from .static_scanner import detect_language
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Cost estimation
# ---------------------------------------------------------------------------

# Token estimation constants.
# Average lines per snippet file (measured from code-snippets directory).
_AVG_LINES_PER_FILE = 63.5
# Average tokens per line of code (conservative estimate across Python/TS/JS).
_TOKENS_PER_LINE = 10.0
# Fixed prompt overhead tokens (instruction text, formatting, fences).
_PROMPT_OVERHEAD_TOKENS = 74

# Pricing per 1M tokens: (input_cost, output_cost)
MODEL_PRICING: Dict[str, tuple[float, float]] = {
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4.1": (2.00, 8.00),
    "gpt-4.1-mini": (0.40, 1.60),
    "gpt-4.1-nano": (0.10, 0.40),
    "gpt-5": (10.00, 30.00),
    "o3": (10.00, 40.00),
    "o3-mini": (1.10, 4.40),
    "o4-mini": (1.10, 4.40),
    "anthropic/claude-sonnet-4": (3.00, 15.00),
    "anthropic/claude-3-5-sonnet-20241022": (3.00, 15.00),
    "anthropic/claude-3-5-haiku-20241022": (0.80, 4.00),
    "anthropic/claude-opus-4": (15.00, 75.00),
    "gemini/gemini-2.0-flash": (0.10, 0.40),
    "gemini/gemini-2.5-flash": (0.15, 0.60),
    "gemini/gemini-2.5-pro": (1.25, 10.00),
    "groq/llama-3.3-70b-versatile": (0.59, 0.79),
    "together_ai/meta-llama/Llama-3-70b-chat-hf": (0.90, 0.90),
    "xai/grok-4": (3.00, 15.00),
    "xai/grok-3": (3.00, 15.00),
    # OpenRouter models (priced same as underlying model)
    "openrouter/anthropic/claude-sonnet-4": (3.00, 15.00),
    "openrouter/anthropic/claude-3.5-sonnet": (3.00, 15.00),
    "openrouter/anthropic/claude-opus-4": (15.00, 75.00),
    "openrouter/openai/gpt-4o": (2.50, 10.00),
    "openrouter/openai/gpt-4o-mini": (0.15, 0.60),
    "openrouter/google/gemini-2.5-flash": (0.15, 0.60),
    "openrouter/google/gemini-2.5-pro": (1.25, 10.00),
    "openrouter/meta-llama/llama-3.3-70b-instruct": (0.59, 0.79),
    "openrouter/deepseek/deepseek-chat-v3": (0.27, 1.10),
    "openrouter/qwen/qwen-2.5-coder-32b-instruct": (0.20, 0.20),
}


_openrouter_pricing_cache: Dict[str, tuple[float, float]] | None = None


def _fetch_openrouter_pricing() -> Dict[str, tuple[float, float]]:
    """
    Fetch live pricing from the OpenRouter /api/v1/models endpoint.
    Returns a dict of model_id -> (input_cost_per_1M, output_cost_per_1M).
    Results are cached for the lifetime of the process.
    """
    global _openrouter_pricing_cache
    if _openrouter_pricing_cache is not None:
        return _openrouter_pricing_cache

    import requests
    try:
        resp = requests.get("https://openrouter.ai/api/v1/models", timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logger.warning("Failed to fetch OpenRouter pricing: %s", exc)
        _openrouter_pricing_cache = {}
        return _openrouter_pricing_cache

    pricing_map: Dict[str, tuple[float, float]] = {}
    for model in data.get("data", []):
        model_id = model.get("id", "")
        p = model.get("pricing", {})
        prompt_cost = p.get("prompt")
        completion_cost = p.get("completion")
        if prompt_cost is not None and completion_cost is not None:
            # API returns cost per token as a string; convert to per-1M tokens.
            pricing_map[model_id] = (
                float(prompt_cost) * 1_000_000,
                float(completion_cost) * 1_000_000,
            )

    _openrouter_pricing_cache = pricing_map
    logger.info("Fetched pricing for %d models from OpenRouter.", len(pricing_map))
    return _openrouter_pricing_cache


def _lookup_pricing(model: str, use_openrouter: bool = False) -> tuple[float, float]:
    """
    Look up pricing for a model.
    When use_openrouter is True, fetches live pricing from the OpenRouter API first.
    Falls back to the static MODEL_PRICING table, then to a conservative default.
    """
    if use_openrouter:
        or_pricing = _fetch_openrouter_pricing()
        if model in or_pricing:
            return or_pricing[model]
        # Try without openrouter/ prefix in static table
        prefixed = f"openrouter/{model}"
        if prefixed in MODEL_PRICING:
            return MODEL_PRICING[prefixed]

    if model in MODEL_PRICING:
        return MODEL_PRICING[model]
    for key, pricing in MODEL_PRICING.items():
        if model.startswith(key) or key.startswith(model):
            return pricing
    return (3.00, 15.00)


def _compute_avg_lines(snippets_dir: Path | None) -> float:
    """
    Compute the average line count across all supported files in snippets_dir.
    Falls back to _AVG_LINES_PER_FILE if the directory is missing or empty.
    """
    if snippets_dir is None or not snippets_dir.is_dir():
        return _AVG_LINES_PER_FILE

    total_lines = 0
    file_count = 0
    for f in sorted(snippets_dir.rglob("*")):
        if f.is_file() and f.suffix in _SNIPPET_EXTENSIONS:
            try:
                total_lines += sum(1 for _ in f.open(encoding="utf-8", errors="ignore"))
                file_count += 1
            except OSError:
                continue

    if file_count == 0:
        return _AVG_LINES_PER_FILE
    return total_lines / file_count


def estimate_cost(
    model: str,
    num_files: int,
    num_agents: int,
    iterations: int,
    snippets_dir: Path | None = None,
    use_openrouter: bool = False,
) -> Dict[str, float]:
    """
    Estimate the total cost of a generation run.

    Uses the actual average line count from snippets_dir when provided,
    otherwise falls back to _AVG_LINES_PER_FILE.

    When use_openrouter is True, fetches live pricing from the OpenRouter API
    for accurate per-model costs.

    Assumptions:
    - Each snippet ≈ avg_lines × _TOKENS_PER_LINE tokens
    - Fixed overhead per call: _PROMPT_OVERHEAD_TOKENS (instruction + fences)
    - Output tokens ≈ same as input snippet tokens (LLM returns code of similar length)
    - Each call: input = snippet_tokens + overhead, output = snippet_tokens

    Returns dict with token counts, costs, and the avg_lines used.
    """
    avg_lines = _compute_avg_lines(snippets_dir)
    snippet_tokens = int(avg_lines * _TOKENS_PER_LINE)
    input_tokens_per_call = snippet_tokens + _PROMPT_OVERHEAD_TOKENS
    output_tokens_per_call = snippet_tokens

    total_calls = num_files * num_agents * iterations
    total_input_tokens = total_calls * input_tokens_per_call
    total_output_tokens = total_calls * output_tokens_per_call

    input_price_per_million, output_price_per_million = _lookup_pricing(model, use_openrouter=use_openrouter)
    input_cost = (total_input_tokens / 1_000_000) * input_price_per_million
    output_cost = (total_output_tokens / 1_000_000) * output_price_per_million
    total_cost = input_cost + output_cost

    return {
        "total_calls": total_calls,
        "avg_lines_per_file": avg_lines,
        "tokens_per_file": snippet_tokens,
        "total_input_tokens": total_input_tokens,
        "total_output_tokens": total_output_tokens,
        "input_cost": input_cost,
        "output_cost": output_cost,
        "total_cost": total_cost,
        "input_price_per_million": input_price_per_million,
        "output_price_per_million": output_price_per_million,
    }


def prompt_cost_confirmation(
    model: str,
    num_files: int,
    num_agents: int,
    iterations: int,
    provider: str | None = None,
    snippets_dir: Path | None = None,
    openrouter_cfg: Dict | None = None,
) -> None:
    """
    Print estimated costs and prompt the user for confirmation.
    Raises SystemExit if the user declines (Ctrl-C).
    """
    is_openrouter = provider == "OpenRouter"
    est = estimate_cost(
        model, num_files, num_agents, iterations,
        snippets_dir=snippets_dir, use_openrouter=is_openrouter,
    )

    # Determine reasoning status from config + model capabilities.
    if is_openrouter and openrouter_cfg:
        supported_params = _fetch_supported_parameters(model)
        model_supports_reasoning = "reasoning" in supported_params if supported_params else False
        reasoning_enabled = openrouter_cfg.get("reasoning_enabled", False)
        reasoning_effort = openrouter_cfg.get("reasoning_effort", "medium")
        if reasoning_enabled and model_supports_reasoning:
            reasoning_label = f"yes (effort={reasoning_effort})"
        elif reasoning_enabled and not model_supports_reasoning:
            reasoning_label = "UNSUPPORTED (model does not support reasoning)"
        else:
            reasoning_label = "no"
    else:
        reasoning_label = "no"

    provider_label = provider or "LiteLLM"
    separator = "=" * 60
    print(f"\n{separator}")
    print("  COST ESTIMATE")
    print(separator)
    print(f"  Provider:          {provider_label}")
    print(f"  Model:             {model}")
    print(f"  Reasoning:         {reasoning_label}")
    print(f"  Pricing:           ${est['input_price_per_million']:.2f} / ${est['output_price_per_million']:.2f} per 1M tokens (in/out)")
    print(f"  Files:             {num_files}")
    print(f"  Avg lines/file:    {est['avg_lines_per_file']:.1f}")
    print(f"  Tokens/file:       {est['tokens_per_file']:,}")
    print(f"  Agents:            {num_agents}")
    print(f"  Iterations:        {iterations}")
    print(f"  Total LLM calls:   {est['total_calls']:,}")
    print(f"  Est. input tokens: {est['total_input_tokens']:,}")
    print(f"  Est. output tokens:{est['total_output_tokens']:,}")
    print(separator)
    print(f"  Estimated cost:    ${est['total_cost']:.4f}")
    print(f"    Input:           ${est['input_cost']:.4f}")
    print(f"    Output:          ${est['output_cost']:.4f}")
    print(separator)

    try:
        response = input("\n  Proceed with generation? [Y/n] (Ctrl-C to cancel): ").strip().lower()
        if response in ("n", "no"):
            print("  Generation cancelled.")
            raise SystemExit(0)
    except KeyboardInterrupt:
        print("\n  Generation cancelled.")
        raise SystemExit(0)


@dataclass
class Vulnerability:
    id: str
    description: str
    base_snippet_path: str
    semgrep_config: str = ""


# Lock for generation_log.jsonl writes — multiple threads append concurrently.
_GENERATION_LOG_LOCK = threading.Lock()


def generate_code(
    config: Dict,
    config_path: str,
    run_dir: Path,
    agents: List[Agent],
    vulns: List[Vulnerability],
    iterations: int,
    *,
    max_workers: int = 1,
    seed: int | None = None,
    model_override: str | None = None,
    test_run_snippet: str | None = None,
    snippet_path_arg: str | None = None,
    base_code_dir_arg: str | None = None,
) -> Path:
    """
    Generate LLM code iterations for all agent × vulnerability combinations.

    Writes output files to:
        <run_dir>/ai-generated-code-snippets/<agent_id>/<vuln_id>/iteration_N.<ext>

    Writes per-iteration prompt/model info to:
        <run_dir>/generation_log.jsonl
    Each line: {"agent", "vuln_id", "iteration", "prompt", "model"}

    Writes run configuration to:
        <run_dir>/run_metadata.json

    Parameters
    ----------
    config:
        Loaded YAML config dict.
    config_path:
        Path to the YAML config file (forwarded to get_llm_client).
    run_dir:
        Timestamped run directory (already created by caller).
    agents:
        Resolved Agent objects to iterate over.
    vulns:
        Resolved Vulnerability objects to iterate over.
    iterations:
        Number of LLM improvement rounds per agent per vulnerability.
    max_workers:
        Thread pool size for parallel agent processing within each iteration.
    seed:
        Optional RNG seed for reproducible prompt selection.
    model_override:
        LiteLLM model string, overrides config value.
    test_run_snippet:
        Non-None when invoked via --test-run (recorded in metadata only).
    snippet_path_arg:
        Non-None when invoked via --snippet (recorded in metadata only).
    base_code_dir_arg:
        Non-None when invoked via --base-code-dir (recorded in metadata only).

    Returns
    -------
    Path
        The run_dir, for chaining convenience.
    """
    if seed is not None:
        random.seed(int(seed))

    llm_cfg = config.get("llm", {})
    openrouter_cfg = config.get("openrouter", {})

    # Resolve the active model — OpenRouter overrides when enabled and no CLI override.
    use_openrouter = openrouter_cfg.get("enabled") and not model_override
    if use_openrouter:
        active_model = openrouter_cfg.get("model", "")
    else:
        active_model = model_override or llm_cfg.get("model")

    if not active_model:
        logger.error(
            "No model selected. Please select a provider and/or model to continue.\n"
            "Set llm.model in config, enable the openrouter section, or pass --model on the CLI."
        )
        raise SystemExit(1)

    outputs_dir = run_dir / AI_CODE_DIR
    generation_log_path = run_dir / "generation_log.jsonl"

    # Resolve snippets directory for cost estimation line-count calculation.
    paths_cfg = config.get("paths", {})
    if base_code_dir_arg:
        cost_snippets_dir = Path(base_code_dir_arg)
    elif snippet_path_arg:
        cost_snippets_dir = Path(snippet_path_arg).parent
    else:
        cost_snippets_dir = Path(paths_cfg.get("snippets_dir", "snippets"))

    prompt_cost_confirmation(
        model=active_model,
        num_files=len(vulns),
        num_agents=len(agents),
        iterations=iterations,
        provider="OpenRouter" if use_openrouter else None,
        snippets_dir=cost_snippets_dir,
        openrouter_cfg=openrouter_cfg if use_openrouter else None,
    )

    # Create directories only after the user confirms — avoids leftover folders on cancel.
    ensure_dir(run_dir)
    ensure_dir(outputs_dir)

    llm_client = get_llm_client(config_path=config_path, model_override=model_override)
    effective_params = llm_client.get_effective_params()

    write_run_metadata(
        run_dir=run_dir,
        run_id=run_dir.name,
        config=config,
        effective_iterations=iterations,
        effective_agents=[a.id for a in agents],
        effective_vulns=[v.id for v in vulns],
        effective_params=effective_params,
        test_run_snippet=test_run_snippet,
        snippet_path_arg=snippet_path_arg,
        base_code_dir_arg=base_code_dir_arg,
    )

    def _generate_single(
        vuln_id: str,
        vuln_base_snippet: str,
        vuln_base_snippet_path: str,
        agent: Agent,
        iteration: int,
    ) -> None:
        ext = Path(vuln_base_snippet_path).suffix
        vuln_language = detect_language(vuln_base_snippet_path)
        is_python = vuln_language == "python"
        # ext = ".py" if is_python else ".ts"

        if iteration == 0:
            input_code = vuln_base_snippet
        else:
            prev_path = outputs_dir / agent.id / vuln_id / f"iteration_{iteration}{ext}"
            try:
                input_code = read_text(prev_path)
            except FileNotFoundError:
                logger.warning(
                    "Previous snippet not found for agent=%s file=%s iteration=%d at %s; "
                    "falling back to base snippet.",
                    agent.id, Path(vuln_base_snippet_path).name, iteration + 1, prev_path,
                )
                input_code = vuln_base_snippet

        instruction = agent.random_instruction()
        logger.info(
            "Iteration %d for agent=%s file=%s | prompt=%s",
            iteration + 1, agent.id, Path(vuln_base_snippet_path).name, instruction,
        )

        generated_code = llm_client.generate_from_snippet(
            input_code, instruction, language=vuln_language,
        )

        if not generated_code.strip():
            logger.warning(
                "Empty code generated for agent=%s file=%s iteration=%d",
                agent.id, Path(vuln_base_snippet_path).name, iteration + 1,
            )
        else:
            logger.info(
                "LLM response received for agent=%s file=%s iteration=%d (%d chars).",
                agent.id, Path(vuln_base_snippet_path).name, iteration + 1, len(generated_code),
            )

        if is_python:
            try:
                compile(generated_code, "<generated-snippet>", "exec")
            except SyntaxError as exc:
                logger.warning(
                    "Generated code has syntax error for agent=%s file=%s iteration=%d: %s",
                    agent.id, Path(vuln_base_snippet_path).name, iteration + 1, exc,
                )

        agent_dir = outputs_dir / agent.id / vuln_id
        ensure_dir(agent_dir)
        snippet_path = agent_dir / f"iteration_{iteration + 1}{ext}"
        write_text(snippet_path, generated_code)

        log_entry = json.dumps({
            "agent": agent.id,
            "file": Path(vuln_base_snippet_path).name,
            "iteration": iteration + 1,
            "prompt": instruction,
            "model": effective_params.get("model", active_model),
            "temperature": effective_params.get("temperature"),
            "top_p": effective_params.get("top_p"),
            "max_tokens": effective_params.get("max_tokens"),
            "reasoning_enabled": effective_params.get("reasoning_enabled"),
            "reasoning_effort": effective_params.get("reasoning_effort"),
        })
        with _GENERATION_LOG_LOCK:
            with open(generation_log_path, "a", encoding="utf-8") as f:
                f.write(log_entry + "\n")

        logger.info("Saved %s", snippet_path)

    max_workers = max(1, max_workers)

    for vuln in vulns:
        vuln_lang = detect_language(vuln.base_snippet_path)
        logger.info(
            "Generating code for vulnerability: %s (language=%s)", vuln.id, vuln_lang,
        )
        base_snippet = read_text(vuln.base_snippet_path)

        for iteration in range(iterations):
            logger.info(
                "Starting generation iteration %d for file=%s across %d agents (max_workers=%d)",
                    iteration + 1, Path(vuln.base_snippet_path).name, len(agents), max_workers,
            )

            if max_workers == 1:
                for agent in agents:
                    _generate_single(
                        vuln_id=vuln.id,
                        vuln_base_snippet=base_snippet,
                        vuln_base_snippet_path=vuln.base_snippet_path,
                        agent=agent,
                        iteration=iteration,
                    )
            else:
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = [
                        executor.submit(
                            _generate_single,
                            vuln.id,
                            base_snippet,
                            vuln.base_snippet_path,
                            agent,
                            iteration,
                        )
                        for agent in agents
                    ]
                    for future in as_completed(futures):
                        future.result()

    logger.info("Code generation complete. Outputs: %s/%s/", run_dir, AI_CODE_DIR)
    return run_dir


def write_run_metadata(
    run_dir: Path,
    run_id: str,
    config: Dict,
    *,
    effective_iterations: int,
    effective_agents: List[str],
    effective_vulns: List[str],
    effective_params: Dict | None = None,
    test_run_snippet: str | None = None,
    snippet_path_arg: str | None = None,
    base_code_dir_arg: str | None = None,
) -> None:
    """
    Persist a JSON snapshot of the run configuration alongside results.

    Uses the actual parameters from the LLM client (what gets sent to the API)
    rather than raw config values.
    """
    experiment_cfg = config.get("experiment", {})
    params = effective_params or {}

    metadata = {
        "run_id": run_id,
        "started_at": datetime.now().isoformat(),
        "model": params.get("model"),
        "temperature": params.get("temperature"),
        "top_p": params.get("top_p"),
        "max_tokens": params.get("max_tokens"),
        "reasoning_enabled": params.get("reasoning_enabled"),
        "reasoning_effort": params.get("reasoning_effort"),
        "iterations": effective_iterations,
        "agents": effective_agents,
        "vulnerabilities": effective_vulns,
        "random_seed": experiment_cfg.get("random_seed"),
        "test_run": test_run_snippet is not None,
        "test_run_snippet": test_run_snippet,
        "snippet": snippet_path_arg,
        "base_code_dir": base_code_dir_arg,
    }

    meta_path = run_dir / "run_metadata.json"
    meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    logger.info("Run metadata written to %s", meta_path)


# ---------------------------------------------------------------------------
# Directory-based snippet discovery
# ---------------------------------------------------------------------------

#: File extensions recognised as code snippets eligible for generation.
_SNIPPET_EXTENSIONS: frozenset[str] = frozenset(
    {".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".java", ".rb", ".php", ".swift", ".kt"}
)


def discover_snippets_from_dir(base_dir: Path) -> List[Vulnerability]:
    """
    Recursively discover all code snippet files under *base_dir* and return
    one ad-hoc ``Vulnerability`` per file.

    Supported extensions: .py, .ts, .tsx, .js, .jsx, .mjs, .cjs

    IDs are derived from each file's path relative to *base_dir* (without the
    extension), with path separators replaced by underscores — e.g.:

        base_dir = snippets/
        file     = snippets/python/injection/xss_base.py
        vuln_id  = python_injection_xss_base

    This ensures uniqueness even when the same stem appears in multiple
    subdirectories.  Files are yielded in sorted order for deterministic runs.

    Parameters
    ----------
    base_dir:
        Root directory to search (searched recursively).

    Returns
    -------
    List[Vulnerability]
        Ad-hoc Vulnerability objects whose ``base_snippet_path`` points to the
        discovered file.  Language is auto-detected by the scanner from the
        file extension — no manual tagging is required.

    Raises
    ------
    FileNotFoundError
        If *base_dir* does not exist or is not a directory.
    """
    base_dir = Path(base_dir)
    if not base_dir.exists():
        raise FileNotFoundError(f"--base-code-dir not found: {base_dir}")
    if not base_dir.is_dir():
        raise NotADirectoryError(f"--base-code-dir is not a directory: {base_dir}")

    found: List[Vulnerability] = []
    seen_ids: dict[str, str] = {}  # id → first path (collision detection)

    for snippet_file in sorted(base_dir.rglob("*")):
        if not snippet_file.is_file():
            continue
        if snippet_file.suffix.lower() not in _SNIPPET_EXTENSIONS:
            continue

        rel = snippet_file.relative_to(base_dir).with_suffix("")
        vuln_id = rel.as_posix().replace("/", "_").replace("-", "_").replace(" ", "_")

        if vuln_id in seen_ids:
            logger.warning(
                "discover_snippets_from_dir: ID collision '%s' for %s "
                "(already used by %s); appending suffix to disambiguate.",
                vuln_id, snippet_file, seen_ids[vuln_id],
            )
            vuln_id = f"{vuln_id}_{snippet_file.suffix.lstrip('.')}"

        seen_ids[vuln_id] = str(snippet_file)
        found.append(
            Vulnerability(
                id=vuln_id,
                description=f"Ad-hoc snippet: {snippet_file.name}",
                base_snippet_path=str(snippet_file),
            )
        )

    logger.info(
        "discover_snippets_from_dir: found %d snippet(s) in %s", len(found), base_dir,
    )
    return found
