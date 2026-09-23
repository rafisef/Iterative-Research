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
import aiofiles
import hashlib
import base64
import io
import urllib.parse
import helpers.utils
import concurrent.futures
import os
import threading
import time
import logging
import hmac
import secrets
import json
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List, Union
from dataclasses import dataclass, field
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _get_env_bool(key: str, default: bool) -> bool:
    val = os.environ.get(key)
    if val is None:
        return default
    return val.lower() == 'true'


def _get_env_int(key: str, default: int) -> int:
    val = os.environ.get(key)
    if val is None:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def _get_env_float(key: str, default: float) -> float:
    val = os.environ.get(key)
    if val is None:
        return default
    try:
        return float(val)
    except (ValueError, TypeError):
        return default


def _get_env_str(key: str, default: str) -> str:
    return os.environ.get(key, default)


def _get_env_list(key: str, default: List[str], separator: str = ',') -> List[str]:
    val = os.environ.get(key)
    if val is None:
        return default
    return val.split(separator)


@dataclass
class BenchmarkConfig:
    thread_pool_size: int = field(default_factory=lambda: _get_env_int('BENCHMARK_THREAD_POOL_SIZE', 10))
    hash_algorithm: str = field(default_factory=lambda: _get_env_str('BENCHMARK_HASH_ALGORITHM', 'md5'))
    password_file: str = field(default_factory=lambda: _get_env_str(
        'BENCHMARK_PASSWORD_FILE',
        f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt'
    ))
    cookie_name: str = field(default_factory=lambda: _get_env_str('BENCHMARK_COOKIE_NAME', 'BenchmarkTest00054'))
    cookie_secret: str = field(default_factory=lambda: _get_env_str('BENCHMARK_COOKIE_SECRET', 'someSecret'))
    cookie_max_age: int = field(default_factory=lambda: _get_env_int('BENCHMARK_COOKIE_MAX_AGE', 60 * 3))
    cookie_secure: bool = field(default_factory=lambda: _get_env_bool('BENCHMARK_COOKIE_SECURE', True))
    cookie_domain: str = field(default_factory=lambda: _get_env_str('BENCHMARK_COOKIE_DOMAIN', 'localhost'))
    default_async: bool = field(default_factory=lambda: _get_env_bool('BENCHMARK_DEFAULT_ASYNC', False))
    input_read_limit: int = field(default_factory=lambda: _get_env_int('BENCHMARK_INPUT_READ_LIMIT', 1000))
    route_prefix: str = field(default_factory=lambda: _get_env_str(
        'BENCHMARK_ROUTE_PREFIX',
        '/benchmark/hash-00/BenchmarkTest00054'
    ))
    hash_iterations: int = field(default_factory=lambda: _get_env_int('BENCHMARK_HASH_ITERATIONS', 1))
    write_timeout: float = field(default_factory=lambda: _get_env_float('BENCHMARK_WRITE_TIMEOUT', 5.0))
    retry_attempts: int = field(default_factory=lambda: _get_env_int('BENCHMARK_RETRY_ATTEMPTS', 3))
    retry_delay: float = field(default_factory=lambda: _get_env_float('BENCHMARK_RETRY_DELAY', 0.1))
    auth_provider: str = field(default_factory=lambda: _get_env_str('BENCHMARK_AUTH_PROVIDER', 'cookie'))
    auth_token_header: str = field(default_factory=lambda: _get_env_str('BENCHMARK_AUTH_TOKEN_HEADER', 'X-Auth-Token'))
    auth_basic_realm: str = field(default_factory=lambda: _get_env_str('BENCHMARK_AUTH_BASIC_REALM', 'BenchmarkTest'))
    auth_jwt_secret: str = field(default_factory=lambda: _get_env_str('BENCHMARK_AUTH_JWT_SECRET', 'jwt-secret-key'))
    auth_api_keys_file: str = field(default_factory=lambda: _get_env_str('BENCHMARK_AUTH_API_KEYS_FILE', ''))
    auth_session_timeout: int = field(default_factory=lambda: _get_env_int('BENCHMARK_AUTH_SESSION_TIMEOUT', 3600))
    auth_multi_providers: List[str] = field(default_factory=lambda: _get_env_list('BENCHMARK_AUTH_MULTI_PROVIDERS', []))

    @classmethod
    def from_env(cls) -> 'BenchmarkConfig':
        return cls()

    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> 'BenchmarkConfig':
        instance = cls()
        for key, value in config_dict.items():
            if hasattr(instance, key):
                setattr(instance, key, value)
        return instance

    @classmethod
    def from_json_file(cls, file_path: str) -> 'BenchmarkConfig':
        with open(file_path, 'r') as f:
            config_dict = json.load(f)
        instance = cls.from_dict(config_dict)
        for field_name in instance.__dataclass_fields__:
            env_key = f'BENCHMARK_{field_name.upper()}'
            env_val = os.environ.get(env_key)
            if env_val is not None:
                field_type = type(getattr(instance, field_name))
                if field_type == bool:
                    setattr(instance, field_name, env_val.lower() == 'true')
                elif field_type == int:
                    try:
                        setattr(instance, field_name, int(env_val))
                    except (ValueError, TypeError):
                        pass
                elif field_type == float:
                    try:
                        setattr(instance, field_name, float(env_val))
                    except (ValueError, TypeError):
                        pass
                elif field_type == list:
                    setattr(instance, field_name, env_val.split(','))
                else:
                    setattr(instance, field_name, env_val)
        return instance

    def to_dict(self) -> Dict[str, Any]:
        return {
            field_name: getattr(self, field_name)
            for field_name in self.__dataclass_fields__
        }


_config = BenchmarkConfig.from_env()

_HASH_ALGORITHM = _config.hash_algorithm
_PASSWORD_FILE = _config.password_file
_COOKIE_NAME = _config.cookie_name
_COOKIE_SECRET = _config.cookie_secret
_COOKIE_MAX_AGE = _config.cookie_max_age
_COOKIE_SECURE = _config.cookie_secure
_COOKIE_DOMAIN = _config.cookie_domain
_DEFAULT_ASYNC = _config.default_async
_INPUT_READ_LIMIT = _config.input_read_limit
_ROUTE_PREFIX = _config.route_prefix
_HASH_ITERATIONS = _config.hash_iterations
_WRITE_TIMEOUT = _config.write_timeout
_RETRY_ATTEMPTS = _config.retry_attempts
_RETRY_DELAY = _config.retry_delay
_AUTH_PROVIDER = _config.auth_provider
_AUTH_TOKEN_HEADER = _config.auth_token_header
_AUTH_BASIC_REALM = _config.auth_basic_realm
_AUTH_JWT_SECRET = _config.auth_jwt_secret
_AUTH_API_KEYS_FILE = _config.auth_api_keys_file
_AUTH_SESSION_TIMEOUT = _config.auth_session_timeout
_AUTH_MULTI_PROVIDERS = _config.auth_multi_providers

_executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=_config.thread_pool_size
)

_file_lock = threading.Lock()
_async_file_lock = asyncio.Lock() if False else None
_sessions_lock = threading.Lock()
_active_sessions: Dict[str, Dict[str, Any]] = {}
_api_keys_cache: Optional[Dict[str, str]] = None
_api_keys_cache_lock = threading.Lock()


def reload_config_from_env() -> BenchmarkConfig:
    global _config
    global _HASH_ALGORITHM, _PASSWORD_FILE, _COOKIE_NAME, _COOKIE_SECRET
    global _COOKIE_MAX_AGE, _COOKIE_SECURE, _COOKIE_DOMAIN, _DEFAULT_ASYNC
    global _INPUT_READ_LIMIT, _ROUTE_PREFIX, _HASH_ITERATIONS, _WRITE_TIMEOUT
    global _RETRY_ATTEMPTS, _RETRY_DELAY, _AUTH_PROVIDER, _AUTH_TOKEN_HEADER
    global _AUTH_BASIC_REALM, _AUTH_JWT_SECRET, _AUTH_API_KEYS_FILE
    global _AUTH_SESSION_TIMEOUT, _AUTH_MULTI_PROVIDERS

    _config = BenchmarkConfig.from_env()

    _HASH_ALGORITHM = _config.hash_algorithm
    _PASSWORD_FILE = _config.password_file
    _COOKIE_NAME = _config.cookie_name
    _COOKIE_SECRET = _config.cookie_secret
    _COOKIE_MAX_AGE = _config.cookie_max_age
    _COOKIE_SECURE = _config.cookie_secure
    _COOKIE_DOMAIN = _config.cookie_domain
    _DEFAULT_ASYNC = _config.default_async
    _INPUT_READ_LIMIT = _config.input_read_limit
    _ROUTE_PREFIX = _config.route_prefix
    _HASH_ITERATIONS = _config.hash_iterations
    _WRITE_TIMEOUT = _config.write_timeout
    _RETRY_ATTEMPTS = _config.retry_attempts
    _RETRY_DELAY = _config.retry_delay
    _AUTH_PROVIDER = _config.auth_provider
    _AUTH_TOKEN_HEADER = _config.auth_token_header
    _AUTH_BASIC_REALM = _config.auth_basic_realm
    _AUTH_JWT_SECRET = _config.auth_jwt_secret
    _AUTH_API_KEYS_FILE = _config.auth_api_keys_file
    _AUTH_SESSION_TIMEOUT = _config.auth_session_timeout
    _AUTH_MULTI_PROVIDERS = _config.auth_multi_providers

    return _config


def get_config() -> BenchmarkConfig:
    return _config


def _get_or_create_event_loop() -> asyncio.AbstractEventLoop:
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop


def run_sync_or_async(coro_or_func, *args, **kwargs):
    if asyncio.iscoroutinefunction(coro_or_func):
        loop = _get_or_create_event_loop()
        if loop.is_running():
            future = asyncio.ensure_future(coro_or_func(*args, **kwargs))
            return future
        else:
            return loop.run_until_complete(coro_or_func(*args, **kwargs))
    else:
        return coro_or_func(*args, **kwargs)


class AuthProviderType(Enum):
    COOKIE = 'cookie'
    TOKEN = 'token'
    BASIC = 'basic'
    JWT = 'jwt'
    API_KEY = 'api_key'
    SESSION = 'session'
    MULTI = 'multi'


@dataclass
class AuthResult:
    authenticated: bool
    identity: Optional[str] = None
    provider: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class AuthProviderConfig:
    provider_type: AuthProviderType
    enabled: bool = True
    priority: int = 0
    config: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_env(cls, provider_type: AuthProviderType, prefix: str = 'BENCHMARK_AUTH') -> 'AuthProviderConfig':
        type_prefix = f'{prefix}_{provider_type.value.upper()}'
        enabled = _get_env_bool(f'{type_prefix}_ENABLED', True)
        priority = _get_env_int(f'{type_prefix}_PRIORITY', 0)
        config: Dict[str, Any] = {}

        if provider_type == AuthProviderType.COOKIE:
            config['cookie_name'] = _get_env_str(f'{type_prefix}_COOKIE_NAME', _COOKIE_NAME)
            config['cookie_secret'] = _get_env_str(f'{type_prefix}_COOKIE_SECRET', _COOKIE_SECRET)
        elif provider_type == AuthProviderType.TOKEN:
            config['header_name'] = _get_env_str(f'{type_prefix}_HEADER_NAME', _AUTH_TOKEN_HEADER)
        elif provider_type == AuthProviderType.BASIC:
            config['realm'] = _get_env_str(f'{type_prefix}_REALM', _AUTH_BASIC_REALM)
        elif provider_type == AuthProviderType.JWT:
            config['secret'] = _get_env_str(f'{type_prefix}_SECRET', _AUTH_JWT_SECRET)
        elif provider_type == AuthProviderType.API_KEY:
            config['api_keys_file'] = _get_env_str(f'{type_prefix}_KEYS_FILE', _AUTH_API_KEYS_FILE)
        elif provider_type == AuthProviderType.SESSION:
            config['session_timeout'] = _get_env_int(f'{type_prefix}_TIMEOUT', _AUTH_SESSION_TIMEOUT)

        return cls(provider_type=provider_type, enabled=enabled, priority=priority, config=config)


class BaseAuthProvider(ABC):
    def __init__(self, config: AuthProviderConfig):
        self.config = config
        self.provider_type = config.provider_type

    @abstractmethod
    def authenticate(self, request_context: Dict[str, Any]) -> AuthResult:
        pass

    async def authenticate_async(self, request_context: Dict[str, Any]) -> AuthResult:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_executor, self.authenticate, request_context)

    @abstractmethod
    def extract_credentials(self, request_context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        pass

    async def extract_credentials_async(self, request_context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        loop = asyncio.get_event_loop()
        return await loop.run_