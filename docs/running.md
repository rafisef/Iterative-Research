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

### OpenAI API Key

All LLM generation is routed through OpenAI's Chat Completions API. You need an active API key with access to the model specified in `config/config.yaml` (default: `gpt-4o`).

Set it as an environment variable:

```bash
export OPENAI_API_KEY="sk-..."
```

Add it to your shell profile (`.zshrc`, `.bashrc`, etc.) to avoid re-setting it each session.

### Nuclei

[Nuclei](https://github.com/projectdiscovery/nuclei) is the security scanner used to evaluate generated snippets. It is only required if `run_nuclei: true` (the default). You can skip it during initial setup with `--skip-nuclei` or `run_nuclei: false`.

**Install via Homebrew (macOS):**

```bash
brew install nuclei
```

**Install via Go:**

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

**Verify the installation and find the binary path:**

```bash
which nuclei        # e.g. /opt/homebrew/bin/nuclei
# or
ls ~/go/bin/nuclei  # e.g. /Users/you/go/bin/nuclei
```

Set the full path in `config/config.yaml`:

```yaml
nuclei:
  binary_path: /opt/homebrew/bin/nuclei
```

Update Nuclei's template database on first use:

```bash
nuclei -update-templates
```

---

## Installation

```bash
# Navigate to the repository root
cd "Iterative Research"

# Create a virtual environment
python3 -m venv ai-research-env

# Activate it
source ai-research-env/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

**Dependencies installed:**

| Package | Version constraint | Purpose |
|---|---|---|
| `openai` | `>=1.0.0` | OpenAI Python SDK (Chat Completions API) |
| `PyYAML` | `>=6.0` | YAML config loading |
| `Flask` | `>=3.0.0` | Web framework used by generated snippets |
| `gunicorn` | `>=21.2.0` | WSGI server (available to generated snippets) |
| `requests` | `>=2.31.0` | Health check polling in `server_runner.py` |

---

## Configuration

Before running, review and update `config/config.yaml`. The minimum required changes are:

1. **Set `nuclei.binary_path`** to the full path of your Nuclei binary.
2. Optionally adjust `experiment.iterations` (default `3`; the paper used `10`).
3. Optionally change `llm.model` to the model you want to test with.

See the [Configuration Reference](./configuration.md) for a complete description of every key.

---

## Running

The experiment is invoked as a Python module from the repository root:

```bash
python -m framework.runner [OPTIONS]
```

### CLI Flags

| Flag | Type | Description |
|---|---|---|
| `--config <path>` | `string` | Path to the YAML config file. Default: `config/config.yaml`. |
| `--dry-run` | flag | Generate and save code snippets only. No servers are started and no Nuclei scans are run. Overrides `experiment.dry_run` in config. |
| `--skip-nuclei` | flag | Start servers and run health checks, but skip Nuclei scans. Overrides `experiment.run_nuclei` in config. |
| `--log <name>` | `string` | Write log output to `logs/<name>.log` in addition to the console. |

---

## Example Runs

### Verify LLM connectivity (no servers, no scanning)

The fastest way to confirm your OpenAI key and model are working:

```bash
python -m framework.runner --dry-run
```

This generates and saves code snippets for every agent/vulnerability/iteration combination defined in config, but skips all server and Nuclei steps. Check `outputs/` to see the generated files.

---

### Test server startup without scanning

Useful for verifying that generated snippets actually start and pass health checks:

```bash
python -m framework.runner --skip-nuclei
```

This runs the full pipeline through health-check verification but skips the Nuclei step. No Nuclei installation is required.

---

### Full experiment run

```bash
python -m framework.runner
```

Runs the complete pipeline: LLM generation → server launch → health check → Nuclei scan → result recording. Requires a configured Nuclei binary.

---

### Full run with file logging

```bash
python -m framework.runner --log experiment-2026-03-18
```

Console logs are mirrored to `logs/experiment-2026-03-18.log`. Useful for long runs where you want a persistent record of the console output separate from Nuclei scan logs.

---

### Use a different config file

```bash
python -m framework.runner --config config/gpt-4-turbo.yaml
```

Handy for running comparative experiments across different models without editing the default config.

---

### Replicate the original paper's 10-iteration setup

Update `config/config.yaml`:

```yaml
experiment:
  iterations: 10
  agents:
    - efficiency
    - feature
    - security
    - ambiguous
  max_workers: 4
```

Then run:

```bash
python -m framework.runner --log paper-replication
```

This produces 40 iterations in total (10 per agent), matching the paper's experimental design.

---

## Monitoring a Run

The runner emits structured log lines to stdout (and optionally a log file):

```
2026-03-18 12:00:00 [INFO] iterative_research - LLM configuration: model=gpt-4o temperature=0.7 top_p=1.0 max_tokens=2000
2026-03-18 12:00:00 [INFO] iterative_research - Starting experiment: iterations=3 agents=['efficiency', 'feature', 'security', 'ambiguous'] vulns=['injection_xss_comment_page'] dry_run=False
2026-03-18 12:00:00 [INFO] iterative_research - Processing vulnerability: injection_xss_comment_page
2026-03-18 12:00:00 [INFO] iterative_research - Starting iteration 0 for vuln=injection_xss_comment_page across 4 agents (max_workers=4)
2026-03-18 12:00:00 [INFO] iterative_research - Iteration 0 for agent=efficiency vuln=injection_xss_comment_page | prompt=Optimize this code for better performance...
2026-03-18 12:00:05 [INFO] iterative_research - Starting server for outputs/efficiency/injection_xss_comment_page/iteration_0.py on port 9000
2026-03-18 12:00:06 [INFO] iterative_research - Health check succeeded for http://127.0.0.1:9000/health
2026-03-18 12:00:06 [INFO] iterative_research - Running nuclei: /path/to/nuclei -u http://127.0.0.1:9000/ -vv -headless -c 50 -tags xss
2026-03-18 12:01:10 [INFO] iterative_research - Nuclei log written to logs/efficiency/injection_xss_comment_page/iteration_0.log
2026-03-18 12:01:10 [INFO] iterative_research - Server process pid=12345 stopped with code -15
```

**Key log events to watch for:**

| Log message | Meaning |
|---|---|
| `Health check failed` | The generated snippet failed to start or crashed immediately. The Nuclei scan is skipped; the result is recorded with `server_started=false`. |
| `Generated code has syntax error` | The LLM returned Python with a syntax error. The file is still saved and a server start is attempted (which will likely fail). |
| `Empty code generated` | The LLM returned an empty response. Usually a model or quota issue. |
| `NUCLEI ERROR: binary not found` | The `nuclei.binary_path` in config is incorrect. |
| `NUCLEI TIMEOUT` | The scan exceeded `nuclei.timeout_seconds`. Consider setting `timeout_seconds: 0`. |

---

## Resuming a Partial Run

The runner does not currently support explicit resume. However, because output files are saved incrementally (`outputs/<agent>/<vuln>/iteration_<N>.py`), you can:

1. Reduce `iterations` in config to the remaining count.
2. Manually move existing outputs so the runner picks up where it left off (the runner reads `iteration_{N-1}.py` as input for iteration N).

A simpler approach is to re-run with a fresh config pointing to a new `outputs_dir` and `results_index`.

---

## Troubleshooting

**`FileNotFoundError: Config file not found`**
→ Run from the repository root, or use `--config` with an absolute path.

**`KeyError: Unknown agent id: ...`**
→ Check that all agent IDs in `config.yaml` match entries in `framework/agents.py`.

**`KeyError: Unknown vulnerability id: ...`**
→ Check that all vulnerability IDs in `config.yaml` match entries in `framework/vulnerabilities.py`.

**`NUCLEI ERROR: binary not found`**
→ Set the full absolute path to the nuclei binary in `nuclei.binary_path`.

**Server health check always fails**
→ Run with `--dry-run` first to inspect the generated snippet. A Python syntax error or missing `--port` handler in the generated code will cause immediate crash.

**`openai.AuthenticationError`**
→ Verify `OPENAI_API_KEY` is set in the current shell session.

**Port already in use**
→ A previous server process may still be running. Use `lsof -i :<port>` to find and kill it, or change `server.base_port` in config.
