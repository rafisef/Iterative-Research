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

from flask import redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html
import threading
import uuid
import time
import os
import json
import sqlite3
import asyncio
import aiofiles
import aiofiles.os
import aiosqlite
from functools import wraps

session_store = {}
session_store_lock = threading.Lock()
async_session_store_lock = asyncio.Lock()

_config = {
    'STORAGE_BACKEND': 'memory',
    'FILE_STORAGE_PATH': '/tmp/sessions',
    'DB_STORAGE_PATH': '/tmp/sessions.db',
    'SESSION_MAX_AGE': 180,
    'SESSION_ID_LENGTH': 36,
    'DB_POOL_TIMEOUT': 30,
    'FILE_ENCODING': 'utf-8',
    'CLEANUP_INTERVAL': 300,
    'MAX_SESSIONS': 10000,
    'SESSION_COOKIE_NAME': 'session_id',
    'SESSION_COOKIE_SECURE': False,
    'SESSION_COOKIE_HTTPONLY': True,
    'SESSION_COOKIE_SAMESITE': 'Lax',
    'ENABLE_ASYNC': True,
    'LOG_LEVEL': 'INFO',
}

_CONFIG_SCHEMA = {
    'STORAGE_BACKEND': {'env': 'SESSION_STORAGE_BACKEND', 'type': 'str'},
    'FILE_STORAGE_PATH': {'env': 'SESSION_FILE_STORAGE_PATH', 'type': 'str'},
    'DB_STORAGE_PATH': {'env': 'SESSION_DB_STORAGE_PATH', 'type': 'str'},
    'SESSION_MAX_AGE': {'env': 'SESSION_MAX_AGE', 'type': 'int'},
    'SESSION_ID_LENGTH': {'env': 'SESSION_ID_LENGTH', 'type': 'int'},
    'DB_POOL_TIMEOUT': {'env': 'SESSION_DB_POOL_TIMEOUT', 'type': 'int'},
    'FILE_ENCODING': {'env': 'SESSION_FILE_ENCODING', 'type': 'str'},
    'CLEANUP_INTERVAL': {'env': 'SESSION_CLEANUP_INTERVAL', 'type': 'int'},
    'MAX_SESSIONS': {'env': 'SESSION_MAX_SESSIONS', 'type': 'int'},
    'SESSION_COOKIE_NAME': {'env': 'SESSION_COOKIE_NAME', 'type': 'str'},
    'SESSION_COOKIE_SECURE': {'env': 'SESSION_COOKIE_SECURE', 'type': 'bool'},
    'SESSION_COOKIE_HTTPONLY': {'env': 'SESSION_COOKIE_HTTPONLY', 'type': 'bool'},
    'SESSION_COOKIE_SAMESITE': {'env': 'SESSION_COOKIE_SAMESITE', 'type': 'str'},
    'ENABLE_ASYNC': {'env': 'SESSION_ENABLE_ASYNC', 'type': 'bool'},
    'LOG_LEVEL': {'env': 'SESSION_LOG_LEVEL', 'type': 'str'},
}

_VALID_STORAGE_BACKENDS = {'memory', 'file', 'database'}
_VALID_SAMESITE_VALUES = {'Strict', 'Lax', 'None'}
_VALID_LOG_LEVELS = {'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'}

_CONFIG_VALIDATORS = {
    'STORAGE_BACKEND': lambda v: v in _VALID_STORAGE_BACKENDS,
    'SESSION_COOKIE_SAMESITE': lambda v: v in _VALID_SAMESITE_VALUES,
    'LOG_LEVEL': lambda v: v.upper() in _VALID_LOG_LEVELS,
    'SESSION_MAX_AGE': lambda v: isinstance(v, int) and v > 0,
    'SESSION_ID_LENGTH': lambda v: isinstance(v, int) and v > 0,
    'DB_POOL_TIMEOUT': lambda v: isinstance(v, int) and v > 0,
    'CLEANUP_INTERVAL': lambda v: isinstance(v, int) and v > 0,
    'MAX_SESSIONS': lambda v: isinstance(v, int) and v > 0,
    'FILE_ENCODING': lambda v: isinstance(v, str) and len(v) > 0,
    'FILE_STORAGE_PATH': lambda v: isinstance(v, str) and len(v) > 0,
    'DB_STORAGE_PATH': lambda v: isinstance(v, str) and len(v) > 0,
    'SESSION_COOKIE_NAME': lambda v: isinstance(v, str) and len(v) > 0,
    'SESSION_COOKIE_SECURE': lambda v: isinstance(v, bool),
    'SESSION_COOKIE_HTTPONLY': lambda v: isinstance(v, bool),
    'ENABLE_ASYNC': lambda v: isinstance(v, bool),
}


def _get_env_bool(key, default):
    val = os.environ.get(key)
    if val is None:
        return default
    return val.strip().lower() in ('1', 'true', 'yes', 'on')


def _get_env_int(key, default):
    val = os.environ.get(key)
    if val is None:
        return default
    try:
        return int(val)
    except ValueError:
        return default


def _validate_config_value(config_key, value):
    validator = _CONFIG_VALIDATORS.get(config_key)
    if validator is None:
        return True
    return validator(value)


def _coerce_config_value(config_key, value):
    schema = _CONFIG_SCHEMA.get(config_key)
    if schema is None:
        return value
    typ = schema.get('type', 'str')
    if typ == 'bool':
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in ('1', 'true', 'yes', 'on')
        return bool(value)
    elif typ == 'int':
        if isinstance(value, int):
            return value
        try:
            return int(value)
        except (ValueError, TypeError):
            return _config[config_key]
    elif typ == 'str':
        return str(value)
    return value


def _load_config_from_env():
    for config_key, schema in _CONFIG_SCHEMA.items():
        env_key = schema['env']
        typ = schema['type']
        if typ == 'bool':
            val = _get_env_bool(env_key, None)
        elif typ == 'int':
            val = _get_env_int(env_key, None)
        else:
            val = os.environ.get(env_key)
        if val is not None:
            if _validate_config_value(config_key, val):
                _config[config_key] = val
            else:
                coerced = _coerce_config_value(config_key, val)
                if _validate_config_value(config_key, coerced):
                    _config[config_key] = coerced


_load_config_from_env()


def configure(
    storage_backend=None,
    file_storage_path=None,
    db_storage_path=None,
    session_max_age=None,
    session_id_length=None,
    db_pool_timeout=None,
    file_encoding=None,
    cleanup_interval=None,
    max_sessions=None,
    session_cookie_name=None,
    session_cookie_secure=None,
    session_cookie_httponly=None,
    session_cookie_samesite=None,
    enable_async=None,
    log_level=None,
    from_env=False,
    env_prefix=None,
    env_file=None,
    env_file_encoding='utf-8',
    mapping=None,
    json_env_var=None,
    prefixed_env=None,
    override_env=False,
):
    if env_file is not None:
        configure_from_env_file(env_file, encoding=env_file_encoding)

    if from_env:
        _load_config_from_env_with_prefix(env_prefix)

    if json_env_var is not None:
        configure_from_json_env_var(json_env_var)

    if prefixed_env is not None:
        configure_from_prefixed_env(prefixed_env)

    if override_env:
        _load_config_from_env()

    if mapping is not None:
        configure_from_mapping(mapping)

    updates = {
        'STORAGE_BACKEND': storage_backend,
        'FILE_STORAGE_PATH': file_storage_path,
        'DB_STORAGE_PATH': db_storage_path,
        'SESSION_MAX_AGE': session_max_age,
        'SESSION_ID_LENGTH': session_id_length,
        'DB_POOL_TIMEOUT': db_pool_timeout,
        'FILE_ENCODING': file_encoding,
        'CLEANUP_INTERVAL': cleanup_interval,
        'MAX_SESSIONS': max_sessions,
        'SESSION_COOKIE_NAME': session_cookie_name,
        'SESSION_COOKIE_SECURE': session_cookie_secure,
        'SESSION_COOKIE_HTTPONLY': session_cookie_httponly,
        'SESSION_COOKIE_SAMESITE': session_cookie_samesite,
        'ENABLE_ASYNC': enable_async,
        'LOG_LEVEL': log_level,
    }

    for config_key, value in updates.items():
        if value is not None:
            coerced = _coerce_config_value(config_key, value)
            if _validate_config_value(config_key, coerced):
                _config[config_key] = coerced


def _load_config_from_env_with_prefix(prefix=None):
    for config_key, schema in _CONFIG_SCHEMA.items():
        if prefix is not None:
            env_key = f"{prefix}_{config_key}"
        else:
            env_key = schema['env']
        typ = schema['type']
        if typ == 'bool':
            val = _get_env_bool(env_key, None)
        elif typ == 'int':
            val = _get_env_int(env_key, None)
        else:
            val = os.environ.get(env_key)
        if val is not None:
            coerced = _coerce_config_value(config_key, val)
            if _validate_config_value(config_key, coerced):
                _config[config_key] = coerced


def configure_from_mapping(mapping):
    for key, value in mapping.items():
        key_upper = key.upper()
        if key_upper in _config:
            coerced = _coerce_config_value(key_upper, value)
            if _validate_config_value(key_upper, coerced):
                _config[key_upper] = coerced


def configure_from_env_file(filepath, encoding='utf-8'):
    if not os.path.isfile(filepath):
        return
    with open(filepath, 'r', encoding=encoding) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' not in line:
                continue
            env_key, _, raw_value = line.partition('=')
            env_key = env_key.strip()
            raw_value = raw_value.strip().strip('"').strip("'")
            os.environ.setdefault(env_key, raw_value)
    _load_config_from_env()


def configure_from_env_file_override(filepath, encoding='utf-8'):
    if not os.path.isfile(filepath):
        return
    with open(filepath, 'r', encoding=encoding) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' not in line:
                continue
            env_key, _, raw_value = line.partition('=')
            env_key = env_key.strip()
            raw_value = raw_value.strip().strip('"').strip("'")
            os.environ[env_key] = raw_value
    _load_config_from_env()


def configure_from_json_env_var(env_var_name):
    raw = os.environ.get(env_var_name)
    if raw is None:
        return
    try:
        mapping = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return
    if isinstance(mapping, dict):
        configure_from_mapping(mapping)


def configure_from_prefixed_env(prefix):
    prefix_upper = prefix.upper().rstrip('_') + '_'
    mapping = {}
    for env_key, env_val in os.environ.items():
        if env_key.upper().startswith(prefix_upper):
            config_key = env_key[len(prefix_upper):]
            mapping[config_key] = env_val
    configure_from_mapping(mapping)


def configure_from_json_file(filepath, encoding='utf-8'):
    if not os.path.isfile(filepath):
        return
    with open(filepath, 'r', encoding=encoding) as f:
        try:
            mapping = json.load(f)
        except (json.JSONDecodeError, ValueError):
            return
    if isinstance(mapping, dict):
        configure_from_mapping(mapping)


def configure_from_env_mapping(env_to_config_mapping):
    for env_key, config_key in env_to_config_mapping.items():
        config_key_upper = config_key.upper()
        if config_key_upper not in _config:
            continue
        schema = _CONFIG_SCHEMA.get(config_key_upper)
        if schema is None:
            continue
        typ = schema['type']
        if typ == 'bool':
            val = _get_env_bool(env_key, None)
        elif typ == 'int':
            val = _get_env_int(env_key, None)
        else:
            val = os.environ.get(env_key)
        if val is not None:
            coerced = _coerce_config_value(config_key_upper, val)
            if _validate_config_value(config_key_upper, coerced):
                _config[config_key_upper] = coerced


def reset_config():
    _config.update({
        'STORAGE_BACKEND': 'memory',
        'FILE_STORAGE_PATH': '/tmp/sessions',
        'DB_STORAGE_PATH': '/tmp/sessions.db',
        'SESSION_MAX_AGE': 180,
        'SESSION_ID_LENGTH': 36,
        'DB_POOL_TIMEOUT': 30,
        'FILE_ENCODING': 'utf-8',
        'CLEANUP_INTERVAL': 300,
        'MAX_SESSIONS': 10000,
        'SESSION_COOKIE_NAME': 'session_id',
        'SESSION_COOKIE_SECURE': False,
        'SESSION_COOKIE_HTTPONLY': True,
        'SESSION_COOKIE_SAMESITE': 'Lax',
        'ENABLE_ASYNC': True,
        'LOG_LEVEL': 'INFO',
    })


def get_config(key=None):
    if