import os
import asyncio
import json
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Mapping, Coroutine, Awaitable, Type

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

def _env_bool(value: str) -> bool:
    return value.lower() in {"1", "true", "yes"}

class AuthProviderRegistry:
    _registry: Dict[str, Type["AuthProvider"]] = {}

    @classmethod
    def register(cls, name: str, provider_cls: Type["AuthProvider"]):
        cls._registry[name.lower()] = provider_cls

    @classmethod
    def get(cls, name: str) -> Optional[Type["AuthProvider"]]:
        return cls._registry.get(name.lower())

class AuthProvider:
    name: str
    config: Dict[str, Any]

    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config

    def validate(self) -> None:
        raise NotImplementedError

class GoogleAuthProvider(AuthProvider):
    def validate(self) -> None:
        required = {"client_id", "client_secret", "redirect_uri"}
        if not required.issubset(self.config):
            missing = required - self.config.keys()
            raise ValueError(f"Missing Google provider config keys: {missing}")

class GitHubAuthProvider(AuthProvider):
    def validate(self) -> None:
        required = {"client_id", "client_secret", "redirect_uri"}
        if not required.issubset(self.config):
            missing = required - self.config.keys()
            raise ValueError(f"Missing GitHub provider config keys: {missing}")

AuthProviderRegistry.register("google", GoogleAuthProvider)
AuthProviderRegistry.register("github", GitHubAuthProvider)

@dataclass
class AppConfig:
    host: str = field(default_factory=lambda: os.getenv("APP_HOST", "localhost"))
    port: int = field(default_factory=lambda: int(os.getenv("APP_PORT", "8000")))
    debug: bool = field(default_factory=lambda: _env_bool(os.getenv("APP_DEBUG", "false")))
    db_url: str = field(default_factory=lambda: os.getenv("DB_URL", "sqlite:///db.sqlite3"))
    secret_key: str = field(default_factory=lambda: os.getenv("SECRET_KEY", "supersecret"))
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    auth_providers: Dict[str, Dict[str, Any]] = field(default_factory=dict)

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
            "auth_providers": {},
        }
        providers = env.get(f"{prefix}AUTH_PROVIDERS", "")
        for provider in [p.strip() for p in providers.split(",") if p.strip()]:
            provider_key = provider.lower()
            provider_dict: Dict[str, Any] = {}
            prefix_key = f"{prefix}{provider.upper()}_"
            for key, value in env.items():
                if key.startswith(prefix_key):
                    subkey = key[len(prefix_key) :]
                    provider_dict[subkey.lower()] = value
            if provider_dict:
                data["auth_providers"][provider_key] = provider_dict
        return cls(**data)

    @classmethod
    def from_dict(cls, overrides: Optional[Dict[str, Any]] = None) -> "AppConfig":
        config = cls.from_env()
        if overrides:
            overrides = overrides.copy()
            if "auth_providers" in overrides and isinstance(overrides["auth_providers"], dict):
                merged = config.auth_providers.copy()
                merged.update(overrides["auth_providers"])
                overrides["auth_providers"] = merged
            config = cls(**{**config.__dict__, **overrides})
        return config

    @classmethod
    async def from_dict_async(cls, overrides: Optional[Dict[str, Any]] = None) -> "AppConfig":
        await asyncio.sleep(0)
        return cls.from_dict(overrides)

    def __post_init__(self):
        if not self.secret_key:
            raise ValueError("SECRET_KEY must be set")

    def get_auth_provider(self, name: str) -> AuthProvider:
        provider_cls = AuthProviderRegistry.get(name)
        if not provider_cls:
            raise ValueError(f"Unknown auth provider: {name}")
        config = self.auth_providers.get(name.lower(), {})
        provider = provider_cls(name, config)
        provider.validate()
        return provider

    def validate_auth_providers(self) -> None:
        for name in self.auth_providers:
            self.get_auth_provider(name)

async def load_config_async(overrides: Optional[Dict[str, Any]] = None) -> AppConfig:
    return await AppConfig.from_dict_async(overrides)

config = AppConfig.from_dict()

@dataclass
class Session:
    user_id: str
    data: Dict[str, Any] = field(default_factory=dict)

class SessionManager:
    _sessions: Dict[str, Session] = {}
    _lock: asyncio.Lock = asyncio.Lock()

    @classmethod
    async def get_session(cls, user_id: str) -> Session:
        async with cls._lock:
            if user_id not in cls._sessions:
                cls._sessions[user_id] = Session(user_id=user_id)
            return cls._sessions[user_id]

    @classmethod
    async def delete_session(cls, user_id: str) -> None:
        async with cls._lock:
            cls._sessions.pop(user_id, None)

    @classmethod
    async def list_sessions(cls) -> Dict[str, Session]:
        async with cls._lock:
            return dict(cls._sessions)

async def handle_user_session(user_id: str) -> Awaitable[None]:
    session = await SessionManager.get_session(user_id)
    session.data["last_active"] = asyncio.get_event_loop().time()
    await asyncio.sleep(0)

async def main() -> None:
    await asyncio.gather(
        handle_user_session("alice"),
        handle_user_session("bob"),
        handle_user_session("alice"),
    )
    sessions = await SessionManager.list_sessions()
    for uid, sess in sessions.items():
        print(f"User {uid} session data: {sess.data}")

if __name__ == "__main__":
    asyncio.run(main())