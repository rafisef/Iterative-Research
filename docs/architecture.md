# Architecture

This document describes the internal structure of Iterative Research: how the modules fit together, how data flows through the system, and the complete lifecycle of a single experiment iteration.

---

## Module Overview

```
framework/
├── runner.py          Entry point and experiment orchestration loop
├── agents.py          Prompting agent definitions and registry
├── vulnerabilities.py Vulnerability registry (base snippets + metadata)
├── llm_client.py      LLM API abstraction (OpenAI implementation)
├── server_runner.py   Flask snippet server lifecycle management
├── scanner.py         Nuclei vulnerability scanner integration
└── io_utils.py        Shared utilities: logging, config I/O, result records
```

Each module has a single, well-defined responsibility. The `runner.py` module is the only one that imports from all others; all other modules are leaf nodes with no cross-dependencies (except `io_utils`, which is imported by all).

### Dependency Graph

```
runner.py
├── agents.py          (resolve agents from config)
├── vulnerabilities.py (resolve vulns from config)
├── llm_client.py      (generate code from snippet + instruction)
│   └── io_utils.py
├── server_runner.py   (start / health-check / stop Flask server)
│   └── io_utils.py
├── scanner.py         (run nuclei scan against live server)
│   └── io_utils.py
└── io_utils.py        (config loading, file I/O, result appending)
```

---

## Module Reference

### `framework/runner.py`

The top-level orchestrator. Responsibilities:

- Parse CLI arguments (`--config`, `--dry-run`, `--skip-nuclei`, `--log`).
- Load and validate `config/config.yaml`.
- Resolve agents and vulnerabilities from config IDs.
- Instantiate the LLM client.
- Drive the outer loops: **vulnerability → iteration → agent**.
- Optionally parallelise agent processing within each iteration using `ThreadPoolExecutor`.
- Coordinate the four-phase pipeline per agent-iteration: **generate → save → serve → scan**.
- Write a `ResultRecord` to `results.jsonl` after every agent-iteration.

The inner function `_process_single_agent_iteration` encapsulates the full pipeline for one (agent, vulnerability, iteration) triple, making it safe to submit to a thread pool.

**Entrypoint:** `python -m framework.runner`

---

### `framework/agents.py`

Defines the `Agent` dataclass and the static agent registry.

```python
@dataclass(frozen=True)
class Agent:
    id: str
    description: str
    instructions: List[str]   # Pool of prompt variants

    def random_instruction(self) -> str: ...
```

Each agent holds a list of semantically equivalent prompt instructions. `random_instruction()` picks one at random per iteration, reducing sensitivity to any single phrasing. Agents are identified by a short string ID (e.g. `"security"`) which is used in config, file paths, and result records.

See [Agents](./agents.md) for full details.

---

### `framework/vulnerabilities.py`

Defines the `Vulnerability` dataclass and the static vulnerability registry.

```python
@dataclass(frozen=True)
class Vulnerability:
    id: str
    description: str
    base_snippet_path: str    # Relative path to the starting snippet
```

The base snippet is the known-secure starting point for the experiment. It is read once at the beginning of each vulnerability's outer loop and reused as the fallback if an intermediate iteration's output file is missing.

See [Vulnerabilities](./vulnerabilities.md) for full details.

---

### `framework/llm_client.py`

Provides a `LLMClient` protocol and a concrete `OpenAIClientImpl`.

```python
class LLMClient(Protocol):
    def generate_from_snippet(self, snippet: str, agent_instruction: str) -> str: ...
```

`OpenAIClientImpl` wraps the OpenAI Python SDK's Chat Completions API. It:

1. Builds a structured prompt combining the agent instruction, constraints (single runnable file, no Markdown), and the current code snippet.
2. Calls the configured model with the configured `temperature`, `max_tokens`, and `top_p`.
3. Strips any Markdown fences the model may include despite explicit instructions.

Configuration is read from `config/config.yaml` under the `llm` key. The `get_llm_client()` factory function selects the implementation based on `llm.provider`.

---

### `framework/server_runner.py`

Manages the lifecycle of generated Flask snippet servers.

| Function | Description |
|---|---|
| `start_snippet_server(path, port)` | Spawns `python <snippet> --port <port>` as a `subprocess.Popen` |
| `wait_for_healthcheck(host, port, timeout)` | Polls `GET /health` until HTTP 200 or timeout |
| `stop_server(proc)` | Sends SIGTERM, waits up to 10s, escalates to SIGKILL if needed, drains pipes |

Ports are computed as `base_port + agent_index * 100 + iteration`, ensuring no two concurrent agent-iterations share a port.

All snippets must expose a `/health` endpoint returning HTTP 200 and accept a `--port` CLI argument for the framework to work correctly.

---

### `framework/scanner.py`

Wraps the [Nuclei](https://github.com/projectdiscovery/nuclei) binary as a subprocess call.

```python
def run_nuclei_scan(target_url, agent, vulnerability_id, iteration, config) -> Tuple[int | None, str]:
    ...
```

The function:

1. Constructs the nuclei command: `nuclei -u <url> -vv -headless -c 50 [-tags ...] [-t ...]`.
2. Runs it as a subprocess, capturing combined stdout/stderr.
3. Enforces a configurable Python-side timeout (`nuclei.timeout_seconds`; `0` disables it).
4. Writes the full scan output to `logs/<agent>/<vuln_id>/iteration_<N>.log`.
5. Returns `(exit_code, log_path)`. `exit_code` is `None` on timeout or binary-not-found.

---

### `framework/io_utils.py`

Shared infrastructure used by all other modules.

| Component | Description |
|---|---|
| `logger` | Named `logging.Logger` (`iterative_research`) with an ISO-timestamp formatter |
| `load_yaml_config(path)` | Safe-loads a YAML file, raises `FileNotFoundError` if missing |
| `ensure_dir(path)` | `mkdir -p` equivalent; returns a `Path` |
| `write_text(path, content)` | UTF-8 file write, creates parent directories automatically |
| `read_text(path)` | UTF-8 file read |
| `ResultRecord` | Dataclass for one agent-iteration outcome |
| `append_result_record(path, record)` | Thread-safe JSON Lines append to the results index |

`_RESULT_LOCK` is a module-level `threading.Lock` that serialises writes to `results.jsonl` when `max_workers > 1`.

---

## Experiment Loop — Detailed Flow

```
run_experiment()
│
├── Load config/config.yaml
├── Resolve agents[]  ← agents.py
├── Resolve vulns[]   ← vulnerabilities.py
├── Instantiate LLMClient ← llm_client.py
│
└── for each vulnerability:
    │   base_snippet = read(vuln.base_snippet_path)
    │
    └── for each iteration (0 … N-1):
        │
        └── for each agent  [ThreadPoolExecutor if max_workers > 1]:
            │
            ├── 1. RESOLVE INPUT
            │       iteration==0 → base_snippet
            │       iteration >0 → outputs/<agent>/<vuln>/iteration_{N-1}.py
            │
            ├── 2. GENERATE
            │       instruction = agent.random_instruction()
            │       code = llm_client.generate_from_snippet(input, instruction)
            │       compile(code)  ← syntax check (warning only)
            │
            ├── 3. SAVE
            │       write outputs/<agent>/<vuln>/iteration_<N>.py
            │
            ├── [if dry_run → write ResultRecord{success=False} and continue]
            │
            ├── 4. SERVE
            │       port = base_port + agent_idx*100 + iteration
            │       proc = start_snippet_server(snippet_path, port)
            │       ok   = wait_for_healthcheck(host, port, timeout)
            │
            ├── 5. SCAN  [if run_nuclei and server_started]
            │       exit_code, log_path = run_nuclei_scan(url, ...)
            │
            ├── 6. STOP SERVER
            │       stop_server(proc)
            │
            └── 7. RECORD
                    append ResultRecord → results.jsonl
```

---

## Port Allocation

Ports are deterministically assigned to avoid collisions when agents run in parallel:

```
port = base_port + (agent_index × 100) + iteration
```

With the default `base_port: 9000` and four agents over ten iterations:

| Agent index | Iterations 0–9 |
|---|---|
| 0 (efficiency) | 9000–9009 |
| 1 (feature) | 9100–9109 |
| 2 (security) | 9200–9209 |
| 3 (ambiguous) | 9300–9309 |

No two concurrent agent-iterations share a port as long as `max_workers ≤ number of agents` and `iteration` advances sequentially (which it does — all agents complete iteration N before any starts N+1).

---

## Threading Model

When `max_workers > 1`, the runner creates a `ThreadPoolExecutor` for the agent dimension of the inner loop. The outer loops (vulnerability and iteration) remain sequential, ensuring:

- All agents finish iteration N before iteration N+1 begins, maintaining the correct input-chaining semantics.
- Each agent-iteration operates on a unique port and output file path, so there are no file or network conflicts.
- The only shared mutable state is the `results.jsonl` file, protected by `_RESULT_LOCK` in `io_utils.py`.

---

## Data Formats

### Snippet files

Plain Python source files. Each is a complete, self-contained Flask web application. They are named `iteration_<N>.py` and stored under `outputs/<agent_id>/<vulnerability_id>/`.

### `results.jsonl`

Newline-delimited JSON. One object per agent-iteration. See [Results & Output](./results.md) for the full schema.

### Nuclei log files

Plain text (nuclei's combined stdout+stderr). Stored under `logs/<agent_id>/<vulnerability_id>/iteration_<N>.log`. Intended for manual review.
