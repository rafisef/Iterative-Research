# Running the Experiment

This page covers everything needed to install the framework, configure it, and execute an experiment run from scratch.

---

## Prerequisites

### Python

Python 3.10 or later is required. The included virtual environment (`ai-research-env`) was created with Python 3.13.

Verify your version:

```bash
python3 --version
```

### API Keys

LLM generation is routed through **LiteLLM**, which supports multiple providers. Set the API key for whichever provider you intend to use:

```bash
export OPENAI_API_KEY="sk-..."           # OpenAI (default: gpt-4o)
export ANTHROPIC_API_KEY="sk-ant-..."   # Anthropic
export GROQ_API_KEY="gsk_..."           # Groq (free tier)
# Ollama requires no key — runs locally
```

Add keys to your shell profile (`.zshrc`, `.bashrc`, etc.) to avoid re-setting them each session. See `config/config.yaml` for the LiteLLM model string format for each provider.

When using `--model all`, the runner automatically detects which keys are present and runs against all available providers.

### Static Analysis Tools

The framework runs **Bandit** and **Semgrep** as static analysis backends. These are installed automatically via `pip install -r requirements.txt` — no separate installation is required.

Scanner selection is **automatic** — no configuration needed. The framework detects the programming language from each snippet's file extension and applies the appropriate tools:


| Language                | File extensions                              | Scanners applied |
| ----------------------- | -------------------------------------------- | ---------------- |
| Python                  | `.py`                                        | Bandit + Semgrep |
| TypeScript / JavaScript | `.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, `.cjs` | Semgrep          |


Default Semgrep rule packs are chosen per language. Individual vulnerabilities can override the packs via `semgrep_config` in `framework/vulnerabilities.py`.

---

## Installation

```bash
# Navigate to the repository root
cd Iterative-Research

# Create a virtual environment
python3 -m venv ai-research-env

# Activate it
source ai-research-env/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

**Dependencies installed:**


| Package    | Version constraint | Purpose                                              |
| ---------- | ------------------ | ---------------------------------------------------- |
| `litellm`  | `==1.82.4`         | Multi-provider LLM client                            |
| `openai`   | `>=1.0.0`          | OpenAI SDK (used by LiteLLM)                         |
| `PyYAML`   | `>=6.0`            | YAML config loading                                  |
| `Flask`    | `>=3.0.0`          | Web framework used by generated Python snippets      |
| `gunicorn` | `>=21.2.0`         | WSGI server (available to generated Python snippets) |
| `requests` | `>=2.31.0`         | Health check polling in `server_runner.py`           |
| `bandit`   | `>=1.7.0`          | Static analysis for Python snippets                  |
| `semgrep`  | `>=1.0.0`          | Static analysis for all languages                    |


---

## Configuration

A single config file covers all experiments:


| File                 | Purpose                                                                 |
| -------------------- | ----------------------------------------------------------------------- |
| `config/config.yaml` | All vulnerabilities (Python + TypeScript). The only config file needed. |


The `experiment.vulnerabilities` list controls exactly which vulnerabilities run. Comment out any entries you want to skip — no separate language-specific files are needed because scanner selection is fully automatic.

Before running, review `config/config.yaml`. The minimum required changes are:

1. Confirm `llm.model` matches a model you have API access to (default: `gpt-4o`). Can also be overridden at runtime with `--model`.
2. Optionally adjust `experiment.iterations` (default: `5`). Can also be set at runtime with `--iterations`.
3. Optionally adjust `experiment.max_workers` for parallelism (default: `4`).

Scanner configuration is not part of the YAML file — the framework determines which tools to run automatically from the snippet file extension.

See the [Configuration Reference](./configuration.md) for a complete description of every key.

---

## Running

### Full pipeline (recommended)

The complete generate → scan → analyze pipeline is invoked from the repository root:

```bash
python main.py [OPTIONS]
```

### CLI Flags


| Flag                   | Type        | Description                                                                                                                                                                                                                                                                                                                       |
| ---------------------- | ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--config <path>`      | `string`    | Path to the YAML config file. Default: `config/config.yaml`.                                                                                                                                                                                                                                                                      |
| `--test-run [SNIPPET]` | flag / path | Run the LLM once (1 iteration, 1 vuln, 1 agent) **and** run static scanners against a single snippet file. Optionally pass a path to the snippet to scan; omitting the value defaults to `snippets/typescript/leakage/info_leakage_user_safe_base.ts`. Scan results are logged but no output files or result records are written. |
| `--snippet <path>`     | `string`    | Run the full experiment against a single arbitrary snippet file. Language is inferred from the file extension (`.py` → Python; `.ts`/`.js` and variants → TypeScript). The file's stem is used as the vulnerability ID in results and output paths. All other flags apply as normal. Mutually exclusive with `--base-code-dir`.   |
| `--base-code-dir <dir>` | `string`   | Run the full experiment against **all** snippet files found recursively under `DIR`, bypassing the vulnerability registry. IDs are derived from the relative file path (e.g. `python/injection/xss_base.py` → `python_injection_xss_base`). Supported extensions: `.py`, `.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, `.cjs`. Mutually exclusive with `--snippet`. |
| `--iterations <n>`     | `int`       | Number of iterations to run. Overrides `experiment.iterations` in config. Default: `5` (or `1` when `--test-run` is active).                                                                                                                                                                                                      |
| `--model <model>`      | `string`    | LLM model to use. Overrides `llm.model` in config. Default: `gpt-4o`. Use `all` to automatically run against every provider whose API key is set in the environment — each gets its own timestamped run directory.                                                                                                                |
| `--run-id <id>`        | `string`    | Override the auto-generated run ID (default: `YYYY-MM-DD_HH-MM-SS`). Useful for named or repeated runs.                                                                                                                                                                                                                           |
| `--log <name>`         | `string`    | Write log output to `runs/<run-id>/logs/<name>.log` in addition to the console.                                                                                                                                                                                                                                                   |


---

## Example Runs

### Verify LLM connectivity (no files written, minimal cost)

Use the dedicated connectivity utility to confirm your API key and model are working. It makes a single LLM call against the first configured vulnerability and agent, logs the response length, and exits — nothing is written to disk:

```bash
python utils/test_llm_connectivity.py
```

To test a specific model:

```bash
python utils/test_llm_connectivity.py --model gpt-4o-mini
python utils/test_llm_connectivity.py --model anthropic/claude-3-5-sonnet-20241022
python utils/test_llm_connectivity.py --model groq/llama-3.3-70b-versatile
```

To test every provider whose API key is set in the environment:

```bash
python utils/test_llm_connectivity.py --model all
```

---

### Full experiment run (all languages)

```bash
python main.py
```

Runs the complete pipeline: LLM generation → static analysis (auto-detected per language) → result recording. Uses the default of 5 iterations unless `experiment.iterations` is set in config.

---

### Override the model at runtime

```bash
python main.py --model gpt-4o-mini
python main.py --model anthropic/claude-3-5-sonnet-20241022
python main.py --model groq/llama-3.3-70b-versatile
python main.py --model ollama/codellama
```

Overrides `llm.model` in config without editing any files.

---

### Run across all available providers

```bash
python main.py --model all
```

Detects all provider API keys set in the environment and runs the full experiment once per provider. Each model gets its own run directory:

```
runs/2026-04-01_12-00-00_gpt-4o/
runs/2026-04-01_12-00-00_claude-3-5-sonnet-20241022/
runs/2026-04-01_12-00-00_llama-3.3-70b-versatile/
```

---

### Override iteration count at runtime

```bash
python main.py --iterations 10
```

Runs 10 iterations regardless of what `experiment.iterations` is set to in config.

---

### Run a subset of vulnerabilities

Comment out entries in `config/config.yaml` under `experiment.vulnerabilities` to scope the run. For example, to run only the Python XSS scenario, keep only `injection_xss_comment_page` and comment out all TypeScript entries. The appropriate scanners are applied automatically based on each snippet's file extension — no other changes are needed.

---

### Full run with file logging

```bash
python main.py --log experiment-2026-03-31
```

Console logs are mirrored to `runs/<run-id>/logs/experiment-2026-03-31.log`. Useful for long runs where you want a persistent record.

---

### Named run ID

```bash
python main.py --run-id paper-replication-ts
```

Creates the output directory at `runs/paper-replication-ts/` instead of a timestamp. Useful when you want predictable paths for downstream scripts.

---

### Replicate the original paper's 10-iteration setup

```bash
python main.py --iterations 10 --log paper-replication
```

This produces 40 iterations per vulnerability (10 per agent × 4 agents), matching the paper's experimental design.

---

## Running Individual Pipeline Components

The pipeline is split into three independently runnable components. You can execute them separately on existing data, or run the full pipeline in one step with `python main.py`.

### Component 1 — Code Generation

Generate LLM iterations for all configured agents and vulnerabilities. Nothing is scanned.

```bash
python utils/generate.py                              # uses config defaults
python utils/generate.py --run-id my-run              # custom run ID
python utils/generate.py --model gpt-4o-mini --iterations 3
python utils/generate.py --snippet snippets/typescript/injection/injection_sql_cmd_base.ts
python utils/generate.py --base-code-dir snippets/python/          # all Python snippets
python utils/generate.py --base-code-dir snippets/                 # all languages
```

Outputs are written to `runs/<run-id>/outputs/`. A `run_metadata.json` and `generation_log.jsonl` are also written to the run directory.

> **`--base-code-dir`** recursively discovers every supported snippet file (`.py`, `.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, `.cjs`) under the given directory. Each file is treated as its own vulnerability; the ID is derived from its path relative to `DIR` (e.g. `injection/xss_base.py` → `injection_xss_base`). This makes it easy to run generation over an entire snippet library in one command.

### Component 2 — Static Scanning

Run Bandit / Semgrep against all generated output files in an existing run directory. Reads `run_metadata.json` to discover what to scan.

```bash
python utils/scan.py                              # scan the latest run
python utils/scan.py --run 2026-04-01_11-34-04   # scan a specific run
python utils/scan.py --run runs/my-run            # explicit path
```

Results are appended to `runs/<run-id>/results.jsonl`.

### Component 3 — Analysis

Analyze scan results and print a human-readable report. Reads `results.jsonl`.

```bash
python utils/analyze.py                                  # latest run (auto-detected)
python utils/analyze.py --run 2026-03-31_21-49-13        # specific run by ID
python utils/analyze.py --list-runs                      # enumerate all available runs
python utils/analyze.py --vuln ts_injection              # filter to one vulnerability
python utils/analyze.py --agent security                 # filter to one agent
python utils/analyze.py --no-findings                    # trend tables only, skip per-finding detail
python utils/analyze.py --csv out.csv                    # also export to CSV
```

### Typical standalone workflow

```bash
# Step 1 — generate code
python utils/generate.py --run-id my-experiment

# Step 2 — scan generated files
python utils/scan.py --run my-experiment

# Step 3 — analyze results
python utils/analyze.py --run my-experiment
```

---

## Analyzing Results

After a run completes (via `python main.py` or the standalone components), use `utils/analyze.py` to summarize findings:

```bash
python utils/analyze.py                                  # latest run (auto-detected)
python utils/analyze.py --run 2026-03-31_21-49-13        # specific run by ID
python utils/analyze.py --list-runs                      # enumerate all available runs
python utils/analyze.py --vuln ts_injection              # filter to one vulnerability
python utils/analyze.py --agent security                 # filter to one agent
python utils/analyze.py --no-findings                    # trend tables only, skip per-finding detail
python utils/analyze.py --csv out.csv                    # also export to CSV
```

The output includes:

- A summary header (record count, agents, models, iteration range, scan types)
- Per-agent trend tables with ASCII bar charts for Bandit HIGH/MED/LOW and Semgrep findings
- Per-iteration finding detail (test IDs, rule IDs, CWEs, line numbers, matched code)
- A delta summary showing first → last iteration change per agent

The CSV export produces one row per individual scanner finding across all iterations, suitable for analysis in Excel, Python/pandas, or R.

---

## Dynamic Scanning with Nuclei (Optional, Post-Run)

Nuclei dynamic scanning is handled separately via `utils/nuclei_rescan.py` after a run completes. It targets only Python/Flask snippet outputs where static scans found issues. Configure the Nuclei binary path in `config/config.yaml` under the `nuclei:` block.

```bash
python utils/nuclei_rescan.py --run 2026-03-31_21-49-13
python utils/nuclei_rescan.py --all   # scan all iterations, not just flagged ones
```

Nuclei is **not** required for the main experiment loop.

---

## Monitoring a Run

At startup the runner prints a single formatted banner summarising the full run configuration, followed by per-iteration progress lines:

```
2026-04-01 11:34:04 [INFO] iterative_research -
============================================================
Random seed        42
Run ID             2026-04-01_11-34-04
Run dir            /Users/.../runs/2026-04-01_11-34-04
LLM Provider       model=gpt-4o
Configuration      iterations=5  temperature=0.7  top_p=1  max_tokens=2000
Scanners           auto-detected per snippet language (Bandit+Semgrep for Python, Semgrep for TypeScript)
Metadata           runs/2026-04-01_11-34-04/run_metadata.json
============================================================

2026-04-01 11:34:04 [INFO] iterative_research - Processing vulnerability: ts_injection (language=typescript, auto-detected)
2026-04-01 11:34:04 [INFO] iterative_research - Starting iteration 0 for vuln=ts_injection across 4 agents (max_workers=4)
2026-04-01 11:34:04 [INFO] iterative_research - Iteration 0 for agent=efficiency vuln=ts_injection | prompt=Optimize this code...
2026-04-01 11:34:07 [INFO] iterative_research - LLM response received for agent=efficiency vuln=ts_injection iteration=0 (842 chars).
2026-04-01 11:34:15 [INFO] iterative_research - Run complete. Results: runs/2026-04-01_11-34-04/results.jsonl
```

When `--test-run` is active, the `Scanners` line shows `test run` and no output files or result records are written after the scan:

```
Scanners           test run — auto-detected  snippet=snippets/typescript/leakage/info_leakage_user_safe_base.ts

2026-04-01 11:34:04 [INFO] iterative_research - Iteration 0 for agent=efficiency vuln=ts_input_validation | prompt=...
2026-04-01 11:34:06 [INFO] iterative_research - LLM response received for agent=efficiency vuln=ts_input_validation iteration=0 (299 chars).
2026-04-01 11:34:06 [INFO] iterative_research - Test-run complete for agent=efficiency vuln=ts_input_validation iteration=0 — no files written.
2026-04-01 11:34:06 [INFO] iterative_research - Run complete. Results: runs/2026-04-01_11-34-04/results.jsonl
```

**Key log events to watch for:**


| Log message                                                 | Meaning                                                                                                                                                                               |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `LLM response received for agent=... (N chars)`             | Successful LLM call. Shows character count of the response.                                                                                                                           |
| `Empty code generated`                                      | The LLM returned an empty response. Usually a model or quota issue.                                                                                                                   |
| `Generated code has syntax error`                           | The LLM returned Python with a syntax error. The file is still saved; static analysis proceeds but Bandit may report additional issues. TypeScript files do not have a compile check. |
| `Previous snippet not found … falling back to base snippet` | An output file from the previous iteration is missing. The base snippet is used as fallback for this iteration.                                                                       |
| `Model ... likely requires ... which is not set`            | A provider API key is missing for the selected model. Set the appropriate environment variable before running.                                                                        |


---

## Resuming a Partial Run

The runner does not currently support explicit resume. However, because output files are saved incrementally (`runs/<run-id>/outputs/<agent>/<vuln>/iteration_<N>.py` or `.ts`), you can:

1. Use `--iterations` to set only the remaining count.
2. Ensure the previously generated iteration files are in place so the runner reads `iteration_{N-1}` as input for iteration N.

A simpler approach is to re-run with a fresh `--run-id` pointing to a new directory.

---

## Troubleshooting

`**FileNotFoundError: Config file not found`**
→ Run from the repository root, or use `--config` with an absolute path.

`**KeyError: Unknown agent id: ...`**
→ Check that all agent IDs in your config file match entries in `framework/agents.py`.

`**KeyError: Unknown vulnerability id: ...**`
→ Check that all vulnerability IDs in your config file match entries in `framework/vulnerabilities.py`.

`**openai.AuthenticationError**`
→ Verify `OPENAI_API_KEY` is set in the current shell session.

`**--model all` falls back to config model**
→ No provider API keys were detected in the environment. Set at least one of `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GROQ_API_KEY`, or `TOGETHERAI_API_KEY` before using `--model all`.

**Semgrep takes a long time on the first run**
→ Semgrep downloads rule packs on first use. Subsequent runs use the local cache.

**Semgrep takes a long time on subsequent TypeScript runs**
→ Semgrep caches rule packs locally after the first download. If the cache is stale, delete `~/.semgrep/cache` and re-run.