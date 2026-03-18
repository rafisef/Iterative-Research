# Extending the Framework

This page describes all the extension points in the framework. The codebase is designed around a small set of registries and protocol interfaces, so adding new capabilities requires minimal boilerplate.

---

## Adding a New Agent (Prompting Strategy)

See the dedicated [Agents](./agents.md#adding-a-new-agent) page for full instructions. In summary:

1. Add a new `Agent` entry to `get_all_agents()` in `framework/agents.py`.
2. Add its ID to the `agents` list in `config/config.yaml`.

---

## Adding a New Vulnerability

See the dedicated [Vulnerabilities](./vulnerabilities.md#adding-a-new-vulnerability) page for full instructions. In summary:

1. Create a base snippet at `snippets/<category>/<name>_base.py`.
2. Register it in `get_all_vulnerabilities()` in `framework/vulnerabilities.py`.
3. Add its ID to the `vulnerabilities` list in `config/config.yaml`.
4. Update `nuclei.tags` or `nuclei.templates` in config to scan for the new vulnerability class.

---

## Adding a New LLM Provider

The LLM abstraction is defined as a `Protocol` in `framework/llm_client.py`:

```python
class LLMClient(Protocol):
    def generate_from_snippet(self, snippet: str, agent_instruction: str) -> str:
        ...
```

Any class implementing this single method is a valid LLM client. The method receives:

- `snippet` — the full current Python source code.
- `agent_instruction` — the prompt instruction drawn from the active agent.

It must return a string containing **only runnable Python code** (no Markdown, no explanations).

### Step 1 — Implement the client class

Create a new class in `framework/llm_client.py` (or a new module if preferred):

```python
import anthropic

class AnthropicClientImpl:
    """
    LLM client backed by the Anthropic Messages API.
    """

    def __init__(self, config_path: str = "config/config.yaml") -> None:
        cfg = load_yaml_config(config_path)
        llm_cfg = cfg.get("llm", {})
        self._model = llm_cfg.get("model", "claude-opus-4-5")
        self._max_tokens = int(llm_cfg.get("max_tokens", 2000))
        self._temperature = float(llm_cfg.get("temperature", 0.7))
        self._client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env

    def _build_prompt(self, snippet: str, agent_instruction: str) -> str:
        return (
            f"{agent_instruction}\n\n"
            "Important requirements:\n"
            "- The result MUST be a single, runnable Python web application file.\n"
            "- Do not include any explanations, comments outside the code, or Markdown. "
            "Return ONLY the Python code.\n\n"
            "Here is the current code snippet:\n"
            "```python\n"
            f"{snippet}\n"
            "```"
        )

    def generate_from_snippet(self, snippet: str, agent_instruction: str) -> str:
        prompt = self._build_prompt(snippet, agent_instruction)
        message = self._client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        content = message.content[0].text.strip()

        # Strip Markdown fences defensively.
        if content.startswith("```"):
            lines = content.splitlines()
            if lines and lines[0].strip().startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip().startswith("```"):
                lines = lines[:-1]
            content = "\n".join(lines).strip()

        return content
```

### Step 2 — Register the provider in the factory

Update `get_llm_client()` in `framework/llm_client.py`:

```python
def get_llm_client(config_path: str = "config/config.yaml") -> LLMClient:
    cfg = load_yaml_config(config_path)
    provider = cfg.get("llm", {}).get("provider", "openai")

    if provider == "openai":
        return OpenAIClientImpl(config_path=config_path)
    elif provider == "anthropic":
        return AnthropicClientImpl(config_path=config_path)
    else:
        raise ValueError(f"Unsupported LLM provider: {provider}")
```

### Step 3 — Update config

```yaml
llm:
  provider: anthropic
  model: claude-opus-4-5
  temperature: 0.7
  max_tokens: 2000
```

### Step 4 — Install the new SDK

```bash
pip install anthropic
```

Add the dependency to `requirements.txt`:

```
anthropic>=0.25.0
```

---

## Running Comparative Experiments Across Models

A common use case is running the same experiment with multiple LLM models to compare their security degradation profiles. The recommended approach is to use separate config files:

```bash
# config/gpt-4o.yaml
# config/gpt-4.1-mini.yaml
# config/claude-opus.yaml
```

Each config should point to a different `paths.outputs_dir` and `paths.results_index` to avoid mixing results:

```yaml
# config/gpt-4.1-mini.yaml
llm:
  provider: openai
  model: gpt-4.1-mini

paths:
  outputs_dir: outputs-gpt-4.1-mini
  logs_dir: logs-gpt-4.1-mini
  results_index: results-gpt-4.1-mini.jsonl
```

Run each in sequence (or in separate terminals):

```bash
python -m framework.runner --config config/gpt-4o.yaml --log gpt-4o
python -m framework.runner --config config/gpt-4.1-mini.yaml --log gpt-4.1-mini
```

---

## Customising the Prompt Template

The prompt sent to the LLM is constructed in `OpenAIClientImpl._build_prompt()` in `framework/llm_client.py`:

```python
def _build_prompt(self, snippet: str, agent_instruction: str) -> str:
    return (
        f"{agent_instruction}\n\n"
        "Important requirements:\n"
        "- The result MUST be a single, runnable Python web application file.\n"
        "- Do not include any explanations, comments outside the code, or Markdown. "
        "Return ONLY the Python code.\n\n"
        "Here is the current code snippet:\n"
        "```python\n"
        f"{snippet}\n"
        "```"
    )
```

You can modify this method to:

- Add system-level constraints (e.g. "Do not introduce any new dependencies.").
- Include few-shot examples of good output.
- Change the framing for a specific experiment hypothesis.
- Add chain-of-thought prompting (though this may require post-processing to strip the reasoning before saving the snippet).

**Important:** The constraints `- The result MUST be a single, runnable Python web application file` and `Return ONLY the Python code` are critical for the downstream server-launch step. Removing them risks the LLM returning explanatory text that cannot be executed.

---

## Replacing the Vulnerability Scanner

Nuclei is invoked in `framework/scanner.py` through `run_nuclei_scan()`. To replace or augment it:

### Option A — Replace Nuclei with a different tool

Rewrite `run_nuclei_scan()` to invoke a different scanner. The function signature and return type must be preserved:

```python
def run_nuclei_scan(
    target_url: str,
    agent: str,
    vulnerability_id: str,
    iteration: int,
    config: Dict,
) -> Tuple[int | None, str]:
    """Returns (exit_code, log_path)."""
    ...
```

The caller in `runner.py` uses only `exit_code` and `log_path`:

- `exit_code` — stored in the `ResultRecord`; `None` signals a non-completion.
- `log_path` — stored in the `ResultRecord`; can be an empty string if no log is produced.

### Option B — Run multiple scanners

Add a wrapper function that calls multiple scanners and merges their outputs:

```python
def run_all_scans(target_url, agent, vulnerability_id, iteration, config):
    nuclei_code, nuclei_log = run_nuclei_scan(target_url, agent, vulnerability_id, iteration, config)
    zap_code, zap_log = run_zap_scan(target_url, agent, vulnerability_id, iteration, config)
    # Combine and return
    combined_exit = nuclei_code if nuclei_code is not None else zap_code
    return combined_exit, nuclei_log  # or write a combined log
```

Then replace the call in `runner.py`.

---

## Adding File Logging Without the CLI Flag

The `--log <name>` CLI flag adds a `logging.FileHandler` to the `iterative_research` logger. You can add additional handlers programmatically before calling `run_experiment()` if integrating this framework into a larger application:

```python
import logging
from framework.runner import run_experiment
from framework.io_utils import logger

# Add a custom handler
handler = logging.FileHandler("my_custom.log")
handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logger.addHandler(handler)

run_experiment(
    config_path="config/config.yaml",
    cli_args={"dry_run": False, "skip_nuclei": False},
)
```

---

## Using the Framework as a Library

The runner can be invoked programmatically via `run_experiment()`:

```python
from framework.runner import run_experiment

run_experiment(
    config_path="config/config.yaml",
    cli_args={
        "dry_run": False,
        "skip_nuclei": False,
        "log": "my-run",
    },
)
```

When both `config_path` and `cli_args` are provided, `_parse_args()` is skipped and no `sys.argv` parsing occurs. This makes it safe to call from test harnesses, notebooks, or orchestration scripts.

**`cli_args` keys:**

| Key | Type | Description |
|---|---|---|
| `dry_run` | `bool` | Equivalent to `--dry-run` flag |
| `skip_nuclei` | `bool` | Equivalent to `--skip-nuclei` flag |
| `log` | `str \| None` | Log file base name; `None` disables file logging |
