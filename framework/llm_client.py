from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Protocol

import litellm

from .io_utils import load_yaml_config, logger

# Silence LiteLLM's verbose startup banners in library mode.
litellm.suppress_debug_info = True


class LLMClient(Protocol):
    """
    Minimal interface used by the experiment runner.
    """

    def generate_from_snippet(self, snippet: str, agent_instruction: str) -> str:  # pragma: no cover - interface
        ...


@dataclass
class LLMConfig:
    model: str
    temperature: float
    max_tokens: int
    top_p: Optional[float] = None


class LiteLLMClientImpl:
    """
    LiteLLM-backed client that supports OpenAI, Ollama, Groq, Anthropic, and
    any other provider LiteLLM understands — controlled entirely through config.

    Provider examples (set llm.model in config.yaml):
      - OpenAI:     gpt-4o, gpt-4o-mini, o3-mini
      - Ollama:     ollama/codellama, ollama/llama3.2, ollama/deepseek-coder
      - Groq:       groq/llama-3.3-70b-versatile  (free tier)
      - Anthropic:  anthropic/claude-3-5-sonnet-20241022
      - Together:   together_ai/meta-llama/Llama-3-70b-chat-hf  (free credits)

    Required env vars vary by provider:
      - OpenAI:    OPENAI_API_KEY
      - Groq:      GROQ_API_KEY
      - Anthropic: ANTHROPIC_API_KEY
      - Ollama:    none (local)
    """

    def __init__(self, config_path: str = "config/config.yaml") -> None:
        cfg = load_yaml_config(config_path)
        llm_cfg = cfg.get("llm", {})

        self._config = LLMConfig(
            model=llm_cfg.get("model", "gpt-4o"),
            temperature=float(llm_cfg.get("temperature", 0.7)),
            max_tokens=int(llm_cfg.get("max_tokens", 2000)),
            top_p=float(llm_cfg.get("top_p", 1.0)) if llm_cfg.get("top_p") is not None else None,
        )

        self._warn_missing_key()
        logger.info("LiteLLM client initialised with model=%s", self._config.model)

    def _warn_missing_key(self) -> None:
        """Emit a warning if the expected API key for the configured provider is absent."""
        model = self._config.model
        checks: List[tuple[str, str]] = [
            ("gpt-", "OPENAI_API_KEY"),
            ("o1", "OPENAI_API_KEY"),
            ("o3", "OPENAI_API_KEY"),
            ("groq/", "GROQ_API_KEY"),
            ("anthropic/", "ANTHROPIC_API_KEY"),
            ("together_ai/", "TOGETHERAI_API_KEY"),
        ]
        for prefix, env_var in checks:
            if model.startswith(prefix) and not os.getenv(env_var):
                logger.warning(
                    "Model %s likely requires %s which is not set in the environment.",
                    model,
                    env_var,
                )
                return

    def _build_messages(self, snippet: str, agent_instruction: str) -> List[Dict[str, str]]:
        user_content = (
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
        return [
            {"role": "system", "content": "You are a helpful coding assistant."},
            {"role": "user", "content": user_content},
        ]

    def generate_from_snippet(self, snippet: str, agent_instruction: str) -> str:
        messages = self._build_messages(snippet, agent_instruction)
        kwargs: Dict[str, Any] = {
            "model": self._config.model,
            "messages": messages,
            "temperature": self._config.temperature,
            "max_tokens": self._config.max_tokens,
        }
        if self._config.top_p is not None:
            kwargs["top_p"] = self._config.top_p

        resp = litellm.completion(**kwargs)
        content = (resp.choices[0].message.content or "").strip()

        # Some models wrap output in Markdown fences despite explicit instructions.
        if content.startswith("```"):
            lines = content.splitlines()
            if lines and lines[0].strip().startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip().startswith("```"):
                lines = lines[:-1]
            content = "\n".join(lines).strip()

        return content


def get_llm_client(config_path: str = "config/config.yaml") -> LLMClient:
    """
    Factory function — returns a LiteLLM-backed client for any supported provider.
    The provider is inferred automatically from the model name in config.yaml.
    """
    return LiteLLMClientImpl(config_path=config_path)
