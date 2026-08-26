from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Protocol

import litellm
import openai

from .io_utils import load_yaml_config, logger

# Silence LiteLLM's verbose startup banners in library mode.
litellm.suppress_debug_info = True

# Canonical provider registry: (env_var, default_model_string).
# Order determines display priority when --model all is used.
PROVIDER_DEFAULTS: List[tuple[str, str]] = [
    ("OPENAI_API_KEY",     "gpt-4o"),
    ("ANTHROPIC_API_KEY",  "anthropic/claude-3-5-sonnet-20241022"),
    ("GEMINI_API_KEY",     "gemini/gemini-2.0-flash"),
    ("GROQ_API_KEY",       "groq/llama-3.3-70b-versatile"),
    ("TOGETHERAI_API_KEY", "together_ai/meta-llama/Llama-3-70b-chat-hf"),
    ("OPENROUTER_API_KEY", "openrouter/anthropic/claude-sonnet-4"),
]


def detect_available_models() -> List[str]:
    """Return the default model string for every provider whose API key is set in the environment."""
    return [model for env_var, model in PROVIDER_DEFAULTS if os.getenv(env_var)]


class LLMClient(Protocol):
    """
    Minimal interface used by the experiment runner.
    """

    def generate_from_snippet(self, snippet: str, agent_instruction: str, language: str = "python") -> str:  # pragma: no cover - interface
        ...


@dataclass
class LLMConfig:
    model: str
    temperature: float
    max_tokens: int
    top_p: Optional[float] = None
    request_delay_seconds: float = 0.0


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

    def __init__(self, config_path: str = "config/config.yaml", model_override: Optional[str] = None) -> None:
        cfg = load_yaml_config(config_path)
        llm_cfg = cfg.get("llm", {})
        openrouter_cfg = cfg.get("openrouter", {})

        # Determine model: OpenRouter config takes precedence when enabled,
        # unless an explicit CLI model_override was provided.
        use_openrouter = openrouter_cfg.get("enabled") and not model_override
        if model_override:
            resolved_model = model_override
        elif use_openrouter:
            or_model = openrouter_cfg.get("model", "")
            resolved_model = f"openrouter/{or_model}" if not or_model.startswith("openrouter/") else or_model
            self._setup_openrouter(openrouter_cfg)
        else:
            resolved_model = llm_cfg.get("model", "gpt-4o")

        # When OpenRouter is active, its parameters override the llm section.
        # Missing keys fall back to the llm section value.
        active_cfg = openrouter_cfg if use_openrouter else {}

        def _resolve(key: str, default):
            val = active_cfg.get(key) if use_openrouter else None
            if val is not None:
                return val
            return llm_cfg.get(key, default)

        resolved_top_p = _resolve("top_p", None)

        self._config = LLMConfig(
            model=resolved_model,
            temperature=float(_resolve("temperature", 0.7)),
            max_tokens=int(_resolve("max_tokens", 2000)),
            top_p=float(resolved_top_p) if resolved_top_p is not None else None,
            request_delay_seconds=float(_resolve("request_delay_seconds", 0.0)),
        )

        self._extra_headers: Dict[str, str] = {}
        if openrouter_cfg.get("enabled") and not model_override:
            if openrouter_cfg.get("app_name"):
                self._extra_headers["X-Title"] = openrouter_cfg["app_name"]
            if openrouter_cfg.get("site_url"):
                self._extra_headers["HTTP-Referer"] = openrouter_cfg["site_url"]

        self._warn_missing_key()
        logger.info("LiteLLM client initialised with model=%s", self._config.model)

    @staticmethod
    def _setup_openrouter(openrouter_cfg: Dict[str, Any]) -> None:
        """Set OPENROUTER_API_KEY from config if not already in the environment."""
        api_key = openrouter_cfg.get("api_key")
        if api_key and not os.getenv("OPENROUTER_API_KEY"):
            os.environ["OPENROUTER_API_KEY"] = api_key
        if not os.getenv("OPENROUTER_API_KEY"):
            logger.warning(
                "OpenRouter is enabled but OPENROUTER_API_KEY is not set "
                "(neither in environment nor in config)."
            )

    def _warn_missing_key(self) -> None:
        """Emit a warning if the expected API key for the configured provider is absent."""
        model = self._config.model
        checks: List[tuple[str, str]] = [
            ("gpt-", "OPENAI_API_KEY"),
            ("o1", "OPENAI_API_KEY"),
            ("o3", "OPENAI_API_KEY"),
            ("groq/", "GROQ_API_KEY"),
            ("anthropic/", "ANTHROPIC_API_KEY"),
            ("gemini/", "GEMINI_API_KEY"),
            ("together_ai/", "TOGETHERAI_API_KEY"),
            ("openrouter/", "OPENROUTER_API_KEY"),
        ]
        for prefix, env_var in checks:
            if model.startswith(prefix) and not os.getenv(env_var):
                logger.warning(
                    "Model %s likely requires %s which is not set in the environment.",
                    model,
                    env_var,
                )
                return

    def _build_messages(self, snippet: str, agent_instruction: str, language: str = "python") -> List[Dict[str, str]]:
        lang = language.lower()
        fence = lang
        requirements = (
                "Important requirements:\n"
                "- Do not include any explanations, prose, or Markdown outside the code block.\n"
                "- Remove any comments pressent in the code if applicable.\n"
                "- Return ONLY the code.\n"
            )
        '''
        Requirements for different script extensions IF NEEDED.
        if lang == "typescript":
            fence = "typescript"
            requirements = (
                "Important requirements:\n"
                "- The result MUST be a single TypeScript module (.ts) — do not add an entry point or server boilerplate unless it already exists in the snippet.\n"
                "- Preserve all existing type annotations; add stricter types where appropriate.\n"
                "- Do not include any explanations, prose, or Markdown outside the code block.\n"
                "- Return ONLY the TypeScript code.\n"
            )
        if lang == "python":
            fence = "python"
            requirements = (
                "Important requirements:\n"
                "- The result MUST be a single, runnable Python web application file.\n"
                "- Do not include any explanations, comments outside the code, or Markdown.\n"
                "- Return ONLY the Python code.\n"
            )
        '''
        user_content = (
            f"{agent_instruction}\n\n"
            f"{requirements}\n"
            f"Here is the current code snippet:\n"
            f"```{fence}\n"
            f"{snippet}\n"
            f"```"
        )
        return [
            {"role": "system", "content": "You are a helpful coding assistant."},
            {"role": "user", "content": user_content},
        ]

    def generate_from_snippet(self, snippet: str, agent_instruction: str, language: str = "python") -> str:
        if self._config.request_delay_seconds > 0:
            time.sleep(self._config.request_delay_seconds)

        messages = self._build_messages(snippet, agent_instruction, language=language)
        kwargs: Dict[str, Any] = {
            "model": self._config.model,
            "messages": messages,
            "temperature": self._config.temperature,
            "max_tokens": self._config.max_tokens,
        }
        if self._config.top_p is not None:
            kwargs["top_p"] = self._config.top_p
        if self._extra_headers:
            kwargs["extra_headers"] = self._extra_headers

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


_openrouter_supported_params_cache: Dict[str, List[str]] = {}


def _fetch_supported_parameters(model: str) -> List[str]:
    """
    Fetch the supported_parameters list for a model from the OpenRouter API.
    Results are cached for the process lifetime.
    """
    if model in _openrouter_supported_params_cache:
        return _openrouter_supported_params_cache[model]

    import requests

    try:
        resp = requests.get("https://openrouter.ai/api/v1/models", timeout=15)
        resp.raise_for_status()
        for entry in resp.json().get("data", []):
            params = entry.get("supported_parameters", [])
            _openrouter_supported_params_cache[entry["id"]] = params
    except Exception as exc:
        logger.warning("Failed to fetch supported parameters from OpenRouter: %s", exc)
        _openrouter_supported_params_cache[model] = []
        return []

    return _openrouter_supported_params_cache.get(model, [])


class OpenRouterClientImpl:
    """
    Direct OpenRouter client using the OpenAI-compatible API at
    https://openrouter.ai/api/v1 — bypasses LiteLLM entirely.

    Activated when openrouter.enabled is true in config and no CLI model override
    is provided.
    """

    def __init__(self, config_path: str = "config/config.yaml") -> None:
        cfg = load_yaml_config(config_path)
        llm_cfg = cfg.get("llm", {})
        openrouter_cfg = cfg.get("openrouter", {})

        self._model = openrouter_cfg.get("model", "")

        def _resolve(key: str, default):
            val = openrouter_cfg.get(key)
            if val is not None:
                return val
            return llm_cfg.get(key, default)

        resolved_top_p = _resolve("top_p", None)

        self._config = LLMConfig(
            model=self._model,
            temperature=float(_resolve("temperature", 0.7)),
            max_tokens=int(_resolve("max_tokens", 2000)),
            top_p=float(resolved_top_p) if resolved_top_p is not None else None,
            request_delay_seconds=float(_resolve("request_delay_seconds", 0.0)),
        )

        self._supported_params = _fetch_supported_parameters(self._model)
        if self._supported_params:
            unsupported = []
            if "temperature" not in self._supported_params:
                unsupported.append("temperature")
            if "top_p" not in self._supported_params:
                unsupported.append("top_p")
            if "max_tokens" not in self._supported_params:
                unsupported.append("max_tokens")
            if unsupported:
                logger.info(
                    "Model %s does not support: %s — these will be omitted from requests.",
                    self._model, ", ".join(unsupported),
                )

        api_key = openrouter_cfg.get("api_key") or os.getenv("OPENROUTER_API_KEY") or ""
        if not api_key:
            logger.warning(
                "OpenRouter is enabled but no API key found "
                "(set OPENROUTER_API_KEY or openrouter.api_key in config)."
            )

        extra_headers: Dict[str, str] = {}
        if openrouter_cfg.get("app_name"):
            extra_headers["X-Title"] = openrouter_cfg["app_name"]
        if openrouter_cfg.get("site_url"):
            extra_headers["HTTP-Referer"] = openrouter_cfg["site_url"]

        self._client = openai.OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=api_key,
            default_headers=extra_headers or None,
        )

        logger.info("OpenRouter client initialised with model=%s", self._model)

    def _build_messages(self, snippet: str, agent_instruction: str, language: str = "python") -> List[Dict[str, str]]:
        lang = language.lower()
        fence = lang
        requirements = (
            "Important requirements:\n"
            "- Do not include any explanations, prose, or Markdown outside the code block.\n"
            "- Do not include any comments in or outside the code block.\n"
            "- Return ONLY the code.\n"
        )
        user_content = (
            f"{agent_instruction}\n\n"
            f"{requirements}\n"
            f"Here is the current code snippet:\n"
            f"```{fence}\n"
            f"{snippet}\n"
            f"```"
        )
        return [
            {"role": "system", "content": "You are a helpful coding assistant."},
            {"role": "user", "content": user_content},
        ]

    def generate_from_snippet(self, snippet: str, agent_instruction: str, language: str = "python") -> str:
        if self._config.request_delay_seconds > 0:
            time.sleep(self._config.request_delay_seconds)

        messages = self._build_messages(snippet, agent_instruction, language=language)

        kwargs: Dict[str, Any] = {
            "model": self._model,
            "messages": messages,
        }

        supported = self._supported_params
        if not supported or "temperature" in supported:
            kwargs["temperature"] = self._config.temperature
        if not supported or "max_tokens" in supported:
            kwargs["max_tokens"] = self._config.max_tokens
        if self._config.top_p is not None and (not supported or "top_p" in supported):
            kwargs["top_p"] = self._config.top_p

        extra_body: Dict[str, Any] = {}
        if supported and "include_reasoning" in supported:
            extra_body["include_reasoning"] = True
        if extra_body:
            kwargs["extra_body"] = extra_body

        resp = self._client.chat.completions.create(**kwargs)
        msg = resp.choices[0].message
        content = (msg.content or "").strip()

        # Log raw response for debugging empty generations.
        logger.debug(
            "Raw OpenRouter response — model=%s content_length=%d finish_reason=%s",
            self._model, len(content), resp.choices[0].finish_reason,
        )
        if not content:
            raw_msg = msg.model_dump() if hasattr(msg, "model_dump") else str(msg)
            logger.warning(
                "Empty content from model=%s. Raw message: %s", self._model, raw_msg,
            )

        # Reasoning models may return output in a reasoning field with empty content.
        if not content:
            reasoning = getattr(msg, "reasoning_content", None) or getattr(msg, "reasoning", None)
            if reasoning:
                content = reasoning.strip()
                logger.info("Using reasoning content as output (content field was empty).")

        if content.startswith("```"):
            lines = content.splitlines()
            if lines and lines[0].strip().startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip().startswith("```"):
                lines = lines[:-1]
            content = "\n".join(lines).strip()

        return content


def get_llm_client(config_path: str = "config/config.yaml", model_override: Optional[str] = None) -> LLMClient:
    """
    Factory function — returns the appropriate LLM client.

    When openrouter.enabled is true in config (and no CLI model_override is given),
    returns an OpenRouterClientImpl that calls the OpenRouter API directly.
    Otherwise returns a LiteLLM-backed client.
    """
    cfg = load_yaml_config(config_path)
    openrouter_cfg = cfg.get("openrouter", {})

    if openrouter_cfg.get("enabled") and not model_override:
        return OpenRouterClientImpl(config_path=config_path)

    return LiteLLMClientImpl(config_path=config_path, model_override=model_override)
