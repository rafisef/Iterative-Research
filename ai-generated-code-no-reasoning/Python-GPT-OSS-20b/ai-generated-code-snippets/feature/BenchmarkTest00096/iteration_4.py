import os
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class AppConfig:
    host: str = field(default_factory=lambda: os.getenv("APP_HOST", "localhost"))
    port: int = field(default_factory=lambda: int(os.getenv("APP_PORT", "8000")))
    debug: bool = field(default_factory=lambda: os.getenv("APP_DEBUG", "false").lower() in {"1", "true", "yes"})
    db_url: str = field(default_factory=lambda: os.getenv("DB_URL", "sqlite:///db.sqlite3"))
    secret_key: str = field(default_factory=lambda: os.getenv("SECRET_KEY", "supersecret"))
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))

    def __post_init__(self):
        if not self.secret_key:
            raise ValueError("SECRET_KEY must be set")

config = AppConfig()