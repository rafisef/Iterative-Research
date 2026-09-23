import os
from dataclasses import dataclass, field
from typing import Optional, Dict, Any

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
    def from_dict(cls, overrides: Optional[Dict[str, Any]] = None) -> "AppConfig":
        data = {
            "host": os.getenv("APP_HOST", "localhost"),
            "port": int(os.getenv("APP_PORT", "8000")),
            "debug": _env_bool(os.getenv("APP_DEBUG", "false")),
            "db_url": os.getenv("DB_URL", "sqlite:///db.sqlite3"),
            "secret_key": os.getenv("SECRET_KEY", "supersecret"),
            "log_level": os.getenv("LOG_LEVEL", "INFO"),
        }
        if overrides:
            data.update(overrides)
        return cls(**data)

    def __post_init__(self):
        if not self.secret_key:
            raise ValueError("SECRET_KEY must be set")


config = AppConfig.from_dict()