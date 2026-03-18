# Configuration Reference

All experiment parameters are controlled by a single YAML file, defaulting to `config/config.yaml`. A different path can be specified with the `--config` CLI flag.

The file is divided into five top-level sections: `llm`, `experiment`, `server`, `nuclei`, and `paths`.

---

## Full Example

```yaml
llm:
  provider: openai
  model: gpt-4o
  temperature: 0.7
  top_p: 1
  max_tokens: 2000

experiment:
  iterations: 3
  vulnerabilities:
    - injection_xss_comment_page
  agents:
    - efficiency
    - feature
    - security
    - ambiguous
  dry_run: false
  run_nuclei: true
  max_workers: 4

server:
  host: 127.0.0.1
  base_port: 9000
  startup_timeout_seconds: 20

nuclei:
  binary_path: /Users/you/go/bin/nuclei
  tags:
    - xss
  templates: []
  timeout_seconds: 0

paths:
  outputs_dir: outputs
  logs_dir: logs
  snippets_dir: snippets
  results_index: results.jsonl
```

---

## `llm` Section

Controls which language model is used and how it generates code.

| Key | Type | Default | Description |
|---|---|---|---|
| `provider` | `string` | `"openai"` | LLM provider. Currently only `"openai"` is supported. See [Extending the Framework](./extending.md) to add new providers. |
| `model` | `string` | `"gpt-4o"` | OpenAI model identifier. Any model accessible via the Chat Completions API is valid (e.g. `gpt-4o`, `gpt-4.1-mini`, `gpt-4-turbo`). |
| `temperature` | `float` | `0.7` | Sampling temperature. Higher values (e.g. `1.0`) increase output diversity; lower values (e.g. `0.2`) make outputs more deterministic. |
| `top_p` | `float \| null` | `1.0` | Nucleus sampling probability mass. Set to `null` to omit the parameter entirely from the API call. OpenAI recommends not adjusting both `temperature` and `top_p` simultaneously. |
| `max_tokens` | `int` | `2000` | Maximum number of tokens in the completion. Should be large enough to contain a complete Python file. Increase if generated snippets are being truncated. |

**Notes:**
- The `OPENAI_API_KEY` environment variable must be set. If it is missing, a warning is logged and API calls will fail at runtime.
- Model availability depends on your OpenAI account tier.

---

## `experiment` Section

Controls the high-level experiment parameters.

| Key | Type | Default | Description |
|---|---|---|---|
| `iterations` | `int` | `10` | Number of iterative improvement rounds per agent per vulnerability. The paper used `10`. Each iteration feeds the previous iteration's output back as input. |
| `vulnerabilities` | `list[string]` | `[]` | List of vulnerability IDs to test. Each ID must exist in the vulnerability registry (`framework/vulnerabilities.py`). |
| `agents` | `list[string]` | `[]` | List of agent IDs to use. Each ID must exist in the agent registry (`framework/agents.py`). |
| `dry_run` | `bool` | `false` | When `true`, generated code is saved to disk but no Flask servers are started and no Nuclei scans are run. Useful for testing LLM connectivity and output quality cheaply. Can also be set via `--dry-run` CLI flag. |
| `run_nuclei` | `bool` | `true` | When `false`, Flask servers are still started and health-checked, but Nuclei scans are skipped. Useful for verifying that generated snippets are runnable without requiring a Nuclei installation. Can be overridden with `--skip-nuclei`. |
| `max_workers` | `int` | `1` | Number of agent threads per iteration. When `> 1`, agents within the same iteration run concurrently using `ThreadPoolExecutor`. Iterations themselves always run sequentially. Set to `1` for fully sequential, easier-to-debug execution. |

**Interaction between `dry_run` and `run_nuclei`:**

| `dry_run` | `run_nuclei` | Behaviour |
|---|---|---|
| `true` | (any) | Generate + save code only. No servers, no scans. |
| `false` | `true` | Full pipeline: generate → serve → scan. |
| `false` | `false` | Generate + serve + health-check, but skip scan. |

---

## `server` Section

Controls how generated snippet servers are started.

| Key | Type | Default | Description |
|---|---|---|---|
| `host` | `string` | `"127.0.0.1"` | Network interface for both Flask servers and health-check polling. Keep as `127.0.0.1` unless you have a specific need to bind to other interfaces. |
| `base_port` | `int` | `9000` | Starting port number for port allocation. Ports are assigned as `base_port + (agent_index × 100) + iteration`. With 4 agents and 10 iterations, ports `9000–9309` are used. |
| `startup_timeout_seconds` | `int` | `20` | Maximum seconds to wait for a snippet server's `/health` endpoint to return HTTP 200 before declaring startup failure. Increase if generated snippets take longer to initialise. |

**Port allocation example** (default `base_port: 9000`):

```
efficiency  → 9000, 9001, 9002, ...
feature     → 9100, 9101, 9102, ...
security    → 9200, 9201, 9202, ...
ambiguous   → 9300, 9301, 9302, ...
```

---

## `nuclei` Section

Controls the Nuclei vulnerability scanner.

| Key | Type | Default | Description |
|---|---|---|---|
| `binary_path` | `string` | `"nuclei"` | Absolute or relative path to the Nuclei binary. Using an absolute path (e.g. `/Users/you/go/bin/nuclei`) is recommended to avoid `PATH` issues when running in virtual environments. |
| `tags` | `list[string]` | `[]` | Nuclei template tags to include in the scan (maps to `-tags` flag). For XSS testing, use `["xss"]`. Multiple tags are joined with commas. |
| `templates` | `list[string]` | `[]` | Paths to specific Nuclei template files or directories (maps to `-t` flag, one per entry). Leave empty to rely solely on `tags`. |
| `timeout_seconds` | `int` | `60` | Maximum seconds the Python process waits for a Nuclei subprocess to complete. Set to `0` or any non-positive value to disable the Python-side timeout and let Nuclei run to natural completion. This is the recommended setting when using `headless` mode. |

**Nuclei command constructed:**

```bash
<binary_path> -u <target_url> -vv -headless -c 50 [-tags <tag1,tag2>] [-t <template>]
```

- `-vv` — verbose output, captured to the log file.
- `-headless` — enables headless browser-based templates (required for XSS detection).
- `-c 50` — concurrency limit for template execution.

---

## `paths` Section

Controls where the framework reads and writes files.

| Key | Type | Default | Description |
|---|---|---|---|
| `outputs_dir` | `string` | `"outputs"` | Directory where generated Python snippets are saved. Created automatically if it doesn't exist. Structure: `<outputs_dir>/<agent_id>/<vulnerability_id>/iteration_<N>.py` |
| `logs_dir` | `string` | `"logs"` | Directory where Nuclei scan logs are saved. Created automatically. Structure: `<logs_dir>/<agent_id>/<vulnerability_id>/iteration_<N>.log` |
| `snippets_dir` | `string` | `"snippets"` | Directory containing base vulnerability snippets. Referenced by the vulnerability registry. |
| `results_index` | `string` | `"results.jsonl"` | Path to the append-only JSON Lines results index. Created automatically. See [Results & Output](./results.md) for the schema. |

All paths are relative to the current working directory at the time the runner is invoked (typically the repository root).

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `OPENAI_API_KEY` | Yes (for LLM calls) | OpenAI API key. If unset, a warning is logged at startup and all API calls will fail. |

---

## Configuration Loading

Config is loaded by `framework/io_utils.load_yaml_config()`. The function:

1. Resolves the path relative to the current working directory.
2. Raises `FileNotFoundError` if the file does not exist.
3. Uses `yaml.safe_load()` — arbitrary Python objects in YAML are not evaluated.
4. Returns an empty dict `{}` if the file is empty.

Missing keys at any nesting level fall back to hardcoded defaults in the respective module (e.g. `model` defaults to `"gpt-4o"` in `llm_client.py`).
