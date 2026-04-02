"""Reference data API: vulnerabilities, agents, available models, and env vars."""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

import yaml
from fastapi import APIRouter
from pydantic import BaseModel

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from framework.vulnerabilities import get_all_vulnerabilities
from framework.llm_client import PROVIDER_DEFAULTS, detect_available_models
from framework.static_scanner import detect_language

router = APIRouter(tags=["reference"])

_CONFIG_PATH = _REPO_ROOT / "config" / "config.yaml"

_KNOWN_ENV_VARS = [env for env, _ in PROVIDER_DEFAULTS]


@router.get("/vulnerabilities")
async def list_vulnerabilities():
    """Return all registered vulnerabilities."""
    all_vulns = get_all_vulnerabilities()
    return [
        {
            "id": v.id,
            "description": v.description,
            "base_snippet_path": v.base_snippet_path,
            "semgrep_config": v.semgrep_config,
            "language": detect_language(v.base_snippet_path),
        }
        for v in all_vulns.values()
    ]


@router.get("/agents")
async def list_agents():
    """Return all configured agents from config.yaml."""
    if not _CONFIG_PATH.exists():
        return []
    raw = _CONFIG_PATH.read_text(encoding="utf-8")
    try:
        cfg = yaml.safe_load(raw) or {}
    except yaml.YAMLError:
        return []
    agents_cfg = cfg.get("agents", {})
    return [
        {
            "id": agent_id,
            "description": data.get("description", ""),
            "instructions": data.get("instructions", []),
        }
        for agent_id, data in agents_cfg.items()
        if isinstance(data, dict)
    ]


@router.get("/models/available")
async def list_available_models():
    """Detect which LLM providers have API keys set in the environment."""
    models = detect_available_models()
    return {"models": models}


# ── Environment variables for LLM providers ──────────────────────────────────

@router.get("/env")
async def list_env_vars():
    """
    Return the known LLM provider env vars with their current status.
    Values are masked — only whether they are set is exposed.
    """
    return [
        {
            "name": env_var,
            "is_set": bool(os.environ.get(env_var)),
            "default_model": model,
        }
        for env_var, model in PROVIDER_DEFAULTS
    ]


class EnvVarBody(BaseModel):
    name: str
    value: str


@router.put("/env")
async def set_env_var(body: EnvVarBody):
    """Set an environment variable in the running backend process."""
    os.environ[body.name] = body.value
    return {"status": "set", "name": body.name, "is_set": True}


@router.delete("/env/{name}")
async def delete_env_var(name: str):
    """Unset an environment variable from the running backend process."""
    os.environ.pop(name, None)
    return {"status": "unset", "name": name, "is_set": False}


# ── Filesystem path autocomplete ─────────────────────────────────────────────

_SNIPPET_EXTENSIONS = frozenset({".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"})


@router.get("/autocomplete/path")
async def autocomplete_path(prefix: str = "", dirs_only: bool = False):
    """
    Return filesystem entries matching *prefix* relative to the repo root.

    Used by the frontend for tab-completion on snippet file / directory inputs.
    When dirs_only=True only directories are returned (for base-code-dir).
    Results are capped at 30 entries.
    """
    base = _REPO_ROOT / prefix
    parent = base.parent if not base.is_dir() else base
    partial = "" if base.is_dir() and prefix.endswith("/") else base.name

    if not parent.exists():
        return []

    results: List[dict] = []
    try:
        for entry in sorted(parent.iterdir()):
            if entry.name.startswith("."):
                continue
            if partial and not entry.name.lower().startswith(partial.lower()):
                continue

            rel = str(entry.relative_to(_REPO_ROOT))
            is_dir = entry.is_dir()

            if dirs_only and not is_dir:
                continue
            if not dirs_only and not is_dir and entry.suffix.lower() not in _SNIPPET_EXTENSIONS:
                continue

            results.append({
                "path": rel + ("/" if is_dir else ""),
                "is_dir": is_dir,
            })
            if len(results) >= 30:
                break
    except PermissionError:
        pass

    return results
