'''
OWASP Benchmark for Python v0.1

This file is part of the Open Web Application Security Project (OWASP) Benchmark Project.
For details, please see https://owasp.org/www-project-benchmark.

The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation, version 3.

The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

  Author: Theo Cartsonis
  Created: 2025
'''

from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import asyncio
import concurrent.futures
import urllib.parse
import elementpath
import xml.etree.ElementTree as ET
import helpers.utils
import os
import sqlite3
import threading
import time
import logging
import hashlib
import hmac
import base64
import json
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, Tuple, List

logger = logging.getLogger(__name__)


def _get_env_int(key, default):
    try:
        return int(os.environ.get(key, str(default)))
    except (ValueError, TypeError):
        return default


def _get_env_bool(key, default):
    val = os.environ.get(key)
    if val is None:
        return default
    return val.strip().lower() == "true"


def _get_env_str(key, default):
    val = os.environ.get(key)
    if val is None:
        return default
    return val


def _get_env_float(key, default):
    try:
        return float(os.environ.get(key, str(default)))
    except (ValueError, TypeError):
        return default


def load_config():
    default_max_workers = concurrent.futures.ThreadPoolExecutor()._max_workers
    return {
        "THREAD_POOL_SIZE": _get_env_int("BENCHMARK_THREAD_POOL_SIZE", default_max_workers),
        "COOKIE_NAME": _get_env_str("BENCHMARK_COOKIE_NAME", "BenchmarkTest00013"),
        "COOKIE_VALUE": _get_env_str("BENCHMARK_COOKIE_VALUE", "2222"),
        "COOKIE_MAX_AGE": _get_env_int("BENCHMARK_COOKIE_MAX_AGE", 60 * 3),
        "COOKIE_SECURE": _get_env_bool("BENCHMARK_COOKIE_SECURE", True),
        "COOKIE_DOMAIN": _get_env_str("BENCHMARK_COOKIE_DOMAIN", "localhost"),
        "COOKIE_DEFAULT_VALUE": _get_env_str("BENCHMARK_COOKIE_DEFAULT_VALUE", "noCookieValueSupplied"),
        "ROUTE_PREFIX": _get_env_str("BENCHMARK_ROUTE_PREFIX", "/benchmark/xpathi-00/BenchmarkTest00013"),
        "USE_ASYNC_DEFAULT": _get_env_bool("BENCHMARK_USE_ASYNC_DEFAULT", False),
        "XML_FILE_PATH": _get_env_str("BENCHMARK_XML_FILE_PATH", f"{helpers.utils.RES_DIR}/employees.xml"),
        "STORAGE_BACKEND": _get_env_str("BENCHMARK_STORAGE_BACKEND", "file").lower(),
        "DB_PATH": _get_env_str("BENCHMARK_DB_PATH", f"{helpers.utils.RES_DIR}/employees.db"),
        "ASYNC_TIMEOUT": _get_env_float("BENCHMARK_ASYNC_TIMEOUT", 30.0),
        "RETRY_COUNT": _get_env_int("BENCHMARK_RETRY_COUNT", 3),
        "RETRY_DELAY": _get_env_float("BENCHMARK_RETRY_DELAY", 0.5),
        "ENABLE_CACHE": _get_env_bool("BENCHMARK_ENABLE_CACHE", False),
        "CACHE_TTL": _get_env_int("BENCHMARK_CACHE_TTL", 60),
        "AUTH_PROVIDER": _get_env_str("BENCHMARK_AUTH_PROVIDER", "basic"),
        "AUTH_SECRET_KEY": _get_env_str("BENCHMARK_AUTH_SECRET_KEY", "default-secret-key-change-in-production"),
        "AUTH_TOKEN_TTL": _get_env_int("BENCHMARK_AUTH_TOKEN_TTL", 3600),
        "AUTH_OAUTH_CLIENT_ID": _get_env_str("BENCHMARK_AUTH_OAUTH_CLIENT_ID", ""),
        "AUTH_OAUTH_CLIENT_SECRET": _get_env_str("BENCHMARK_AUTH_OAUTH_CLIENT_SECRET", ""),
        "AUTH_OAUTH_AUTHORIZE_URL": _get_env_str("BENCHMARK_AUTH_OAUTH_AUTHORIZE_URL", ""),
        "AUTH_OAUTH_TOKEN_URL": _get_env_str("BENCHMARK_AUTH_OAUTH_TOKEN_URL", ""),
        "AUTH_OAUTH_USERINFO_URL": _get_env_str("BENCHMARK_AUTH_OAUTH_USERINFO_URL", ""),
        "AUTH_LDAP_SERVER": _get_env_str("BENCHMARK_AUTH_LDAP_SERVER", ""),
        "AUTH_LDAP_PORT": _get_env_int("BENCHMARK_AUTH_LDAP_PORT", 389),
        "AUTH_LDAP_BASE_DN": _get_env_str("BENCHMARK_AUTH_LDAP_BASE_DN", ""),
        "AUTH_LDAP_USE_TLS": _get_env_bool("BENCHMARK_AUTH_LDAP_USE_TLS", False),
        "AUTH_SAML_ENTITY_ID": _get_env_str("BENCHMARK_AUTH_SAML_ENTITY_ID", ""),
        "AUTH_SAML_SSO_URL": _get_env_str("BENCHMARK_AUTH_SAML_SSO_URL", ""),
        "AUTH_SAML_CERTIFICATE": _get_env_str("BENCHMARK_AUTH_SAML_CERTIFICATE", ""),
        "AUTH_MULTI_PROVIDERS": _get_env_str("BENCHMARK_AUTH_MULTI_PROVIDERS", "basic"),
        "AUTH_ALLOW_MULTIPLE": _get_env_bool("BENCHMARK_AUTH_ALLOW_MULTIPLE", False),
    }


config = load_config()

executor = concurrent.futures.ThreadPoolExecutor(max_workers=config["THREAD_POOL_SIZE"])

COOKIE_NAME = config["COOKIE_NAME"]
COOKIE_VALUE = config["COOKIE_VALUE"]
COOKIE_MAX_AGE = config["COOKIE_MAX_AGE"]
COOKIE_SECURE = config["COOKIE_SECURE"]
COOKIE_DOMAIN = config["COOKIE_DOMAIN"]
COOKIE_DEFAULT_VALUE = config["COOKIE_DEFAULT_VALUE"]
BENCHMARK_ROUTE_PREFIX = config["ROUTE_PREFIX"]
BENCHMARK_USE_ASYNC_DEFAULT = config["USE_ASYNC_DEFAULT"]
XML_FILE_PATH = config["XML_FILE_PATH"]
STORAGE_BACKEND = config["STORAGE_BACKEND"]
DB_PATH = config["DB_PATH"]
ASYNC_TIMEOUT = config["ASYNC_TIMEOUT"]
RETRY_COUNT = config["RETRY_COUNT"]
RETRY_DELAY = config["RETRY_DELAY"]
ENABLE_CACHE = config["ENABLE_CACHE"]
CACHE_TTL = config["CACHE_TTL"]
AUTH_PROVIDER = config["AUTH_PROVIDER"]
AUTH_SECRET_KEY = config["AUTH_SECRET_KEY"]
AUTH_TOKEN_TTL = config["AUTH_TOKEN_TTL"]
AUTH_MULTI_PROVIDERS = config["AUTH_MULTI_PROVIDERS"]
AUTH_ALLOW_MULTIPLE = config["AUTH_ALLOW_MULTIPLE"]

_cache = {}
_cache_lock = threading.Lock()
_async_loop = None
_async_loop_lock = threading.Lock()


def _get_or_create_event_loop():
    global _async_loop
    with _async_loop_lock:
        if _async_loop is None or _async_loop.is_closed():
            _async_loop = asyncio.new_event_loop()
            t = threading.Thread(target=_async_loop.run_forever, daemon=True)
            t.start()
        return _async_loop


def _cache_get(key):
    if not ENABLE_CACHE:
        return None
    with _cache_lock:
        entry = _cache.get(key)
        if entry is None:
            return None
        value, expiry = entry
        if time.time() > expiry:
            del _cache[key]
            return None
        return value


def _cache_set(key, value):
    if not ENABLE_CACHE:
        return
    with _cache_lock:
        _cache[key] = (value, time.time() + CACHE_TTL)


def _cache_invalidate(key=None):
    with _cache_lock:
        if key is None:
            _cache.clear()
        elif key in _cache:
            del _cache[key]


class AuthResult:
    def __init__(self, success: bool, user_id: Optional[str] = None,
                 provider: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None,
                 error: Optional[str] = None):
        self.success = success
        self.user_id = user_id
        self.provider = provider
        self.metadata = metadata or {}
        self.error = error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "user_id": self.user_id,
            "provider": self.provider,
            "metadata": self.metadata,
            "error": self.error,
        }


class BaseAuthProvider(ABC):
    def __init__(self, provider_name: str, config: Dict[str, Any]):
        self.provider_name = provider_name
        self.config = config

    @abstractmethod
    def authenticate(self, credentials: Dict[str, Any]) -> AuthResult:
        pass

    @abstractmethod
    def validate_token(self, token: str) -> AuthResult:
        pass

    def generate_token(self, user_id: str, metadata: Optional[Dict[str, Any]] = None) -> str:
        payload = {
            "user_id": user_id,
            "provider": self.provider_name,
            "issued_at": time.time(),
            "expires_at": time.time() + self.config.get("AUTH_TOKEN_TTL", 3600),
            "metadata": metadata or {},
        }
        payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        payload_b64 = base64.urlsafe_b64encode(payload_bytes).decode("utf-8")
        secret = self.config.get("AUTH_SECRET_KEY", "").encode("utf-8")
        sig = hmac.new(secret, payload_b64.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{payload_b64}.{sig}"

    def decode_token(self, token: str) -> Optional[Dict[str, Any]]:
        try:
            parts = token.split(".")
            if len(parts) != 2:
                return None
            payload_b64, sig = parts[0], parts[1]
            secret = self.config.get("AUTH_SECRET_KEY", "").encode("utf-8")
            expected_sig = hmac.new(secret, payload_b64.encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, expected_sig):
                return None
            payload_bytes = base64.urlsafe_b64decode(payload_b64.encode("utf-8"))
            payload = json.loads(payload_bytes.decode("utf-8"))
            if time.time() > payload.get("expires_at", 0):
                return None
            return payload
        except Exception:
            return None


class BasicAuthProvider(BaseAuthProvider):
    def __init__(self, config: Dict[str, Any]):
        super().__init__("basic", config)
        self._users: Dict[str, str] = {}
        self._users_lock = threading.Lock()

    def add_user(self, username: str, password: str):
        hashed = hashlib.sha256(password.encode("utf-8")).hexdigest()
        with self._users_lock:
            self._users[username] = hashed

    def authenticate(self, credentials: Dict[str, Any]) -> AuthResult:
        username = credentials.get("username", "")
        password = credentials.get("password", "")
        if not username or not password:
            return AuthResult(success=False, provider=self.provider_name, error="Missing credentials")
        hashed = hashlib.sha256(password.encode("utf-8")).hexdigest()
        with self._users_lock:
            stored = self._users.get(username)
        if stored and hmac.compare_digest(stored, hashed):
            token = self.generate_token(username, {"username": username})
            return AuthResult(
                success=True,
                user_id=username,
                provider=self.provider_name,
                metadata={"token": token, "username": username},
            )
        return AuthResult(success=False, provider=self.provider_name, error="Invalid credentials")

    def validate_token(self, token: str) -> AuthResult:
        payload = self.decode_token(token)
        if payload is None:
            return AuthResult(success=False, provider=self.provider_name, error="Invalid or expired token")
        if payload.get("provider") != self.provider_name:
            return AuthResult(success=False, provider=self.provider_name, error="Token provider mismatch")
        return AuthResult(
            success=True,
            user_id=payload.get("user_id"),
            provider=self.provider_name,
            metadata=payload.get("metadata", {}),
        )


class ApiKeyAuthProvider(BaseAuthProvider):
    def __init__(self, config: Dict[str, Any]):
        super().__init__("apikey", config)
        self._api_keys: Dict[str, Dict[str, Any]] = {}
        self._api_keys_lock = threading.Lock()

    def register_key(self, api_key: str, user_id: str, metadata: Optional[Dict[str, Any]] = None):
        hashed_key = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        with self._api_keys_lock:
            self._api_keys[hashed_key] = {
                "user_id": user_id,
                "metadata": metadata or {},
                "created_at": time.time(),
            }

    def authenticate(self, credentials: Dict[str, Any]) -> AuthResult:
        api_key = credentials.get("api_key", "")
        if not api_key:
            return AuthResult(success=False, provider=self.provider_name, error="Missing API key")
        hashed_key = hashlib.sha256(api_key.encode("utf-8")).hexdigest()
        with self._api_keys_lock:
            key_data = self._api_keys.get(hashed_key)
        if key_data is None:
            return AuthResult(success=False, provider=self.provider_name, error="Invalid API key")
        user_id = key_data["user_id"]
        token = self.generate_token(user_id, key_data.get("metadata", {}))
        return AuthResult(
            success=True,
            user_id=user_id,
            provider=self.provider_name,
            metadata={"token": token, **key_data.get("metadata", {})},
        )

    def validate_token(self, token: str) -> AuthResult:
        payload = self.decode_token(token)
        if payload is None:
            return AuthResult(success=False, provider=self.provider_name, error="Invalid or expired token")
        if payload.get("provider") != self.provider_name:
            return AuthResult(success=False, provider=self.provider_name, error="Token provider mismatch")
        return Auth