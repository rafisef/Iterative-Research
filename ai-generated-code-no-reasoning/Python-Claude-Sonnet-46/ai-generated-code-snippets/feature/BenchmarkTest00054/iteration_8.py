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
from typing import Optional, Dict, Any, List, Union, Callable, Awaitable, TypeVar
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

T = TypeVar('T')


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
    log_level: str = field(default_factory=lambda: _get_env_str('BENCHMARK_LOG_LEVEL', 'INFO'))
    max_request_size: int = field(default_factory=lambda: _get_env_int('BENCHMARK_MAX_REQUEST_SIZE', 1048576))
    enable_metrics: bool = field(default_factory=lambda: _get_env_bool('BENCHMARK_ENABLE_METRICS', False))
    metrics_port: int = field(default_factory=lambda: _get_env_int('BENCHMARK_METRICS_PORT', 9090))
    cors_origins: List[str] = field(default_factory=lambda: _get_env_list('BENCHMARK_CORS_ORIGINS', []))
    rate_limit_enabled: bool = field(default_factory=lambda: _get_env_bool('BENCHMARK_RATE_LIMIT_ENABLED', False))
    rate_limit_requests: int = field(default_factory=lambda: _get_env_int('BENCHMARK_RATE_LIMIT_REQUESTS', 100))
    rate_limit_window: int = field(default_factory=lambda: _get_env_int('BENCHMARK_RATE_LIMIT_WINDOW', 60))
    tls_enabled: bool = field(default_factory=lambda: _get_env_bool('BENCHMARK_TLS_ENABLED', False))
    tls_cert_file: str = field(default_factory=lambda: _get_env_str('BENCHMARK_TLS_CERT_FILE', ''))
    tls_key_file: str = field(default_factory=lambda: _get_env_str('BENCHMARK_TLS_KEY_FILE', ''))
    db_url: str = field(default_factory=lambda: _get_env_str('BENCHMARK_DB_URL', ''))
    db_pool_size: int = field(default_factory=lambda: _get_env_int('BENCHMARK_DB_POOL_SIZE', 5))
    db_pool_timeout: float = field(default_factory=lambda: _get_env_float('BENCHMARK_DB_POOL_TIMEOUT', 30.0))
    cache_enabled: bool = field(default_factory=lambda: _get_env_bool('BENCHMARK_CACHE_ENABLED', False))
    cache_ttl: int = field(default_factory=lambda: _get_env_int('BENCHMARK_CACHE_TTL', 300))
    cache_max_size: int = field(default_factory=lambda: _get_env_int('BENCHMARK_CACHE_MAX_SIZE', 1000))
    allowed_hash_algorithms: List[str] = field(default_factory=lambda: _get_env_list(
        'BENCHMARK_ALLOWED_HASH_ALGORITHMS',
        ['md5', 'sha1', 'sha256', 'sha512']
    ))
    response_encoding: str = field(default_factory=lambda: _get_env_str('BENCHMARK_RESPONSE_ENCODING', 'utf-8'))
    temp_dir: str = field(default_factory=lambda: _get_env_str('BENCHMARK_TEMP_DIR', '/tmp'))
    async_pool_size: int = field(default_factory=lambda: _get_env_int('BENCHMARK_ASYNC_POOL_SIZE', 5))
    request_timeout: float = field(default_factory=lambda: _get_env_float('BENCHMARK_REQUEST_TIMEOUT', 30.0))
    health_check_path: str = field(default_factory=lambda: _get_env_str('BENCHMARK_HEALTH_CHECK_PATH', '/health'))
    debug_mode: bool = field(default_factory=lambda: _get_env_bool('BENCHMARK_DEBUG_MODE', False))

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

    @classmethod
    def from_env_file(cls, env_file_path: str) -> 'BenchmarkConfig':
        if os.path.exists(env_file_path):
            with open(env_file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, _, value = line.partition('=')
                        key = key.strip()
                        value = value.strip().strip('"').strip("'")
                        if key not in os.environ:
                            os.environ[key] = value
        return cls.from_env()

    @classmethod
    def from_merged(cls, *sources: Dict[str, Any]) -> 'BenchmarkConfig':
        merged: Dict[str, Any] = {}
        for source in sources:
            merged.update(source)
        return cls.from_dict(merged)

    def override_from_env(self) -> 'BenchmarkConfig':
        for field_name in self.__dataclass_fields__:
            env_key = f'BENCHMARK_{field_name.upper()}'
            env_val = os.environ.get(env_key)
            if env_val is not None:
                field_type = type(getattr(self, field_name))
                if field_type == bool:
                    setattr(self, field_name, env_val.lower() == 'true')
                elif field_type == int:
                    try:
                        setattr(self, field_name, int(env_val))
                    except (ValueError, TypeError):
                        pass
                elif field_type == float:
                    try:
                        setattr(self, field_name, float(env_val))
                    except (ValueError, TypeError):
                        pass
                elif field_type == list:
                    setattr(self, field_name, env_val.split(','))
                else:
                    setattr(self, field_name, env_val)
        return self

    def to_dict(self) -> Dict[str, Any]:
        return {
            field_name: getattr(self, field_name)
            for field_name in self.__dataclass_fields__
        }

    def to_env_dict(self) -> Dict[str, str]:
        result: Dict[str, str] = {}
        for field_name in self.__dataclass_fields__:
            env_key = f'BENCHMARK_{field_name.upper()}'
            value = getattr(self, field_name)
            if isinstance(value, list):
                result[env_key] = ','.join(str(v) for v in value)
            else:
                result[env_key] = str(value)
        return result

    def validate(self) -> List[str]:
        errors: List[str] = []
        if self.hash_algorithm not in self.allowed_hash_algorithms:
            errors.append(
                f'hash_algorithm "{self.hash_algorithm}" not in allowed_hash_algorithms {self.allowed_hash_algorithms}'
            )
        if self.thread_pool_size < 1:
            errors.append(f'thread_pool_size must be >= 1, got {self.thread_pool_size}')
        if self.hash_iterations < 1:
            errors.append(f'hash_iterations must be >= 1, got {self.hash_iterations}')
        if self.retry_attempts < 0:
            errors.append(f'retry_attempts must be >= 0, got {self.retry_attempts}')
        if self.retry_delay < 0:
            errors.append(f'retry_delay must be >= 0, got {self.retry_delay}')
        if self.write_timeout <= 0:
            errors.append(f'write_timeout must be > 0, got {self.write_timeout}')
        if self.request_timeout <= 0:
            errors.append(f'request_timeout must be > 0, got {self.request_timeout}')
        if self.tls_enabled:
            if not self.tls_cert_file:
                errors.append('tls_cert_file must be set when tls_enabled is True')
            if not self.tls_key_file:
                errors.append('tls_key_file must be set when tls_enabled is True')
        if self.rate_limit_enabled:
            if self.rate_limit_requests < 1:
                errors.append(f'rate_limit_requests must be >= 1, got {self.rate_limit_requests}')
            if self.rate_limit_window < 1:
                errors.append(f'rate_limit_window must be >= 1, got {self.rate_limit_window}')
        if self.db_pool_size < 1:
            errors.append(f'db_pool_size must be >= 1, got {self.db_pool_size}')
        if self.cache_ttl < 0:
            errors.append(f'