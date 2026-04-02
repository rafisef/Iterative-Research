"""Config API: read and write config.yaml."""
from __future__ import annotations

import sys
from pathlib import Path

import yaml
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_CONFIG_PATH = _REPO_ROOT / "config" / "config.yaml"

router = APIRouter(tags=["config"])


class ConfigUpdateBody(BaseModel):
    content: str


@router.get("/config")
async def get_config():
    """Return the current config.yaml as parsed JSON plus the raw YAML string."""
    if not _CONFIG_PATH.exists():
        raise HTTPException(status_code=404, detail="config.yaml not found")
    raw = _CONFIG_PATH.read_text(encoding="utf-8")
    try:
        parsed = yaml.safe_load(raw) or {}
    except yaml.YAMLError as exc:
        return {"raw": raw, "parsed": None, "error": str(exc)}
    return {"raw": raw, "parsed": parsed, "error": None}


@router.put("/config")
async def put_config(body: ConfigUpdateBody):
    """Overwrite config.yaml with new YAML content. Validates before saving."""
    try:
        parsed = yaml.safe_load(body.content)
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {exc}")
    if parsed is None:
        raise HTTPException(status_code=400, detail="YAML content is empty")
    _CONFIG_PATH.write_text(body.content, encoding="utf-8")
    return {"status": "saved", "parsed": parsed}
