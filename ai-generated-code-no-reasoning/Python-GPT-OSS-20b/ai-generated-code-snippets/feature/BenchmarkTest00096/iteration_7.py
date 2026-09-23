import os
import asyncio
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Mapping

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

def _env_bool(value: str) -> bool:
    return value.lower() in {"1", "true", "yes"}

@dataclass
class AppConfig:
    host: str = field(default_factory=lambda: os.getenv("APP_HOST", "localhost"))
    port: int = field(default_factory=lambda: int(os.getenv("APP_PORT", "8000")))
    debug: bool = field(default_factory=lambda: _env_bool(os.getenv("APP_DEBUG", "false")))
    db_url: str = field(default_factory=lambda: os.getenv("DB_URL", "sqlite:///db.sqlite3"))
    secret_key: str = field(default_factory=lambda: os.getenv("SECRET_KEY", "supersecret"))
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))

    @classmethod
    def from_env(cls, prefix: str = "", env: Optional[Mapping[str, str]] = None) -> "AppConfig":
        env = env or os.environ
        data = {
            "host": env.get(f"{prefix}HOST", "localhost"),
            "port": int(env.get(f"{prefix}PORT", "8000")),
            "debug": _env_bool(env.get(f"{prefix}DEBUG", "false")),
            "db_url": env.get(f"{prefix}DB_URL", "sqlite:///db.sqlite3"),
            "secret_key": env.get(f"{prefix}SECRET_KEY", "supersecret"),
            "log_level": env.get(f"{prefix}LOG_LEVEL", "INFO"),
        }
        return cls(**data)

    @classmethod
    def from_dict(cls, overrides: Optional[Dict[str, Any]] = None) -> "AppConfig":
        config = cls.from_env()
        if overrides:
            config = cls(**{**config.__dict__, **overrides})
        return config

    @classmethod
    async def from_dict_async(cls, overrides: Optional[Dict[str, Any]] = None) -> "AppConfig":
        await asyncio.sleep(0)
        return cls.from_dict(overrides)

    def __post_init__(self):
        if not self.secret_key:
            raise ValueError("SECRET_KEY must be set")

async def load_config_async(overrides: Optional[Dict[str, Any]] = None) -> AppConfig:
    return await AppConfig.from_dict_async(overrides)

config = AppConfig.from_dict()