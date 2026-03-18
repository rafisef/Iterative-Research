from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol

from openai import OpenAI

from .io_utils import logger
from .io_utils import load_yaml_config


class LLMClient(Protocol):
  """
  Minimal interface used by the experiment runner.
  """

  def generate_from_snippet(self, snippet: str, agent_instruction: str) -> str:  # pragma: no cover - interface
    ...


@dataclass
class OpenAIConfig:
  model: str
  temperature: float
  max_tokens: int
  top_p: float | None = None


class OpenAIClientImpl:
  """
  Thin wrapper around the OpenAI Python SDK.
  """

  def __init__(self, config_path: str = "config/config.yaml") -> None:
    cfg = load_yaml_config(config_path)
    llm_cfg = cfg.get("llm", {})

    self._config = OpenAIConfig(
      model=llm_cfg.get("model", "gpt-4o"),
      temperature=float(llm_cfg.get("temperature", 0.7)),
      max_tokens=int(llm_cfg.get("max_tokens", 2000)),
      top_p=float(llm_cfg.get("top_p", 1.0)) if llm_cfg.get("top_p") is not None else None,
    )

    if not os.getenv("OPENAI_API_KEY"):
      logger.warning("Environment variable OPENAI_API_KEY is not set. OpenAI calls will fail.")

    self._client = OpenAI()

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
    # Using Chat Completions API for broad compatibility.
    kwargs: dict = {
      "model": self._config.model,
      "messages": [
        {"role": "system", "content": "You are a helpful coding assistant."},
        {"role": "user", "content": prompt},
      ],
      "temperature": self._config.temperature,
      "max_tokens": self._config.max_tokens,
    }
    if self._config.top_p is not None:
      kwargs["top_p"] = self._config.top_p
    resp = self._client.chat.completions.create(**kwargs)
    content = (resp.choices[0].message.content or "").strip()

    # Some models may still wrap Python code in Markdown fences despite explicit
    # instructions. Strip common ``` / ```python fences if present so the saved
    # snippets remain valid Python files.
    if content.startswith("```"):
      lines = content.splitlines()
      # Remove leading fence lines.
      if lines and lines[0].strip().startswith("```"):
        lines = lines[1:]
      # Remove trailing fence line if present.
      if lines and lines[-1].strip().startswith("```"):
        lines = lines[:-1]
      content = "\n".join(lines).strip()

    return content


def get_llm_client(config_path: str = "config/config.yaml") -> LLMClient:
  """
  Factory function – currently only OpenAI is supported, but this can be
  extended later for other providers.
  """
  cfg = load_yaml_config(config_path)
  provider = cfg.get("llm", {}).get("provider", "openai")
  if provider != "openai":
    raise ValueError(f"Unsupported LLM provider: {provider}")
  return OpenAIClientImpl(config_path=config_path)

