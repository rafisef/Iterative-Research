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
import asyncio
import urllib.parse
import base64
import flask
import sqlite3
import os
import json
import threading
import uuid
import time
from functools import wraps
from concurrent.futures import ThreadPoolExecutor


def _get_env_bool(key, default):
    val = os.environ.get(key)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _get_env_int(key, default):
    val = os.environ.get(key)
    if val is None:
        return default
    try:
        return int(val.strip())
    except (ValueError, AttributeError):
        return default


def _get_env_str(key, default):
    val = os.environ.get(key)
    if val is None:
        return default
    stripped = val.strip()
    return stripped if stripped else default


FILE_STORAGE_PATH = _get_env_str("FILE_STORAGE_PATH", "storage/redirect_data.json")
DB_STORAGE_PATH = _get_env_str("DB_STORAGE_PATH", "storage/redirect_data.db")
SESSION_STORAGE_PATH = _get_env_str("SESSION_STORAGE_PATH", "storage/sessions.json")
STORAGE_DIR = _get_env_str("STORAGE_DIR", "storage")
storage_lock = threading.Lock()
session_lock = threading.RLock()

SESSION_TIMEOUT = _get_env_int("SESSION_TIMEOUT", 1800)

_active_sessions = {}
_session_store_lock = threading.RLock()
_session_user_locks = {}
_session_user_locks_lock = threading.Lock()
_user_session_index = {}
_user_session_index_lock = threading.RLock()
_session_semaphore = None

DEFAULT_STORAGE_TYPE = _get_env_str("DEFAULT_STORAGE_TYPE", "file")

COOKIE_SECURE = _get_env_bool("COOKIE_SECURE", True)
COOKIE_HTTPONLY = _get_env_bool("COOKIE_HTTPONLY", True)
COOKIE_SAMESITE = _get_env_str("COOKIE_SAMESITE", "Lax")
COOKIE_PATH = _get_env_str("COOKIE_PATH", "/benchmark/redirect-00/BenchmarkTest00067")
COOKIE_NAME = _get_env_str("COOKIE_NAME", "benchmark_session_id")

SESSION_ROUTE_PREFIX = _get_env_str("SESSION_ROUTE_PREFIX", "/benchmark/redirect-00/BenchmarkTest00067")

MAX_SESSION_USER_DATA_SIZE = _get_env_int("MAX_SESSION_USER_DATA_SIZE", 65536)
MAX_REDIRECT_VALUE_SIZE = _get_env_int("MAX_REDIRECT_VALUE_SIZE", 65536)
COOKIE_MAX_AGE = _get_env_int("COOKIE_MAX_AGE", SESSION_TIMEOUT)
DB_TIMEOUT = _get_env_int("DB_TIMEOUT", 30)
ENABLE_SESSION_PERSISTENCE = _get_env_bool("ENABLE_SESSION_PERSISTENCE", False)
ALLOW_ASYNC_REDIRECT = _get_env_bool("ALLOW_ASYNC_REDIRECT", True)
SESSION_CLEANUP_INTERVAL = _get_env_int("SESSION_CLEANUP_INTERVAL", 300)
MAX_CONCURRENT_SESSIONS = _get_env_int("MAX_CONCURRENT_SESSIONS", 10000)
MAX_SESSIONS_PER_USER = _get_env_int("MAX_SESSIONS_PER_USER", 10)
SESSION_POOL_WORKERS = _get_env_int("SESSION_POOL_WORKERS", 8)
LOG_LEVEL = _get_env_str("LOG_LEVEL", "WARNING")
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", None)
FLASK_ENV = _get_env_str("FLASK_ENV", "production")
ALLOWED_REDIRECT_HOSTS = [
    h.strip()
    for h in _get_env_str("ALLOWED_REDIRECT_HOSTS", "").split(",")
    if h.strip()
]

_session_executor = ThreadPoolExecutor(max_workers=SESSION_POOL_WORKERS)
_cleanup_thread = None
_cleanup_stop_event = threading.Event()

_auth_providers = {}
_auth_providers_lock = threading.RLock()

_provider_session_index = {}
_provider_session_index_lock = threading.RLock()

_provider_user_map = {}
_provider_user_map_lock = threading.RLock()


def _get_session_semaphore():
    global _session_semaphore
    if _session_semaphore is None:
        _session_semaphore = threading.Semaphore(MAX_CONCURRENT_SESSIONS)
    return _session_semaphore


def _get_user_session_lock(user_id):
    with _session_user_locks_lock:
        if user_id not in _session_user_locks:
            _session_user_locks[user_id] = threading.RLock()
        return _session_user_locks[user_id]


def _register_user_session(user_id, session_id):
    with _user_session_index_lock:
        if user_id not in _user_session_index:
            _user_session_index[user_id] = set()
        _user_session_index[user_id].add(session_id)


def _unregister_user_session(user_id, session_id):
    with _user_session_index_lock:
        if user_id in _user_session_index:
            _user_session_index[user_id].discard(session_id)
            if not _user_session_index[user_id]:
                del _user_session_index[user_id]


def _get_user_sessions(user_id):
    with _user_session_index_lock:
        return set(_user_session_index.get(user_id, set()))


def _count_user_sessions(user_id):
    with _user_session_index_lock:
        return len(_user_session_index.get(user_id, set()))


def _enforce_max_sessions_per_user(user_id):
    user_lock = _get_user_session_lock(user_id)
    with user_lock:
        session_ids = _get_user_sessions(user_id)
        if len(session_ids) < MAX_SESSIONS_PER_USER:
            return True
        sessions_with_times = []
        with _session_store_lock:
            for sid in session_ids:
                entry = _active_sessions.get(sid)
                if entry is not None:
                    sessions_with_times.append((sid, entry.get("last_accessed", entry.get("created_at", 0))))
        if not sessions_with_times:
            return True
        sessions_with_times.sort(key=lambda x: x[1])
        oldest_sid = sessions_with_times[0][0]
        _destroy_session_internal(oldest_sid, user_id)
        return True


def _destroy_session_internal(session_id, user_id=None):
    sem = _get_session_semaphore()
    with _session_store_lock:
        entry = _active_sessions.pop(session_id, None)
    if entry is not None:
        uid = user_id or entry.get("user_id")
        if uid:
            _unregister_user_session(uid, session_id)
        provider_name = entry.get("auth_provider")
        if provider_name:
            _unregister_provider_session(provider_name, session_id)
        sem.release()


def _register_provider_session(provider_name, session_id):
    with _provider_session_index_lock:
        if provider_name not in _provider_session_index:
            _provider_session_index[provider_name] = set()
        _provider_session_index[provider_name].add(session_id)


def _unregister_provider_session(provider_name, session_id):
    with _provider_session_index_lock:
        if provider_name in _provider_session_index:
            _provider_session_index[provider_name].discard(session_id)
            if not _provider_session_index[provider_name]:
                del _provider_session_index[provider_name]


def _get_provider_sessions(provider_name):
    with _provider_session_index_lock:
        return set(_provider_session_index.get(provider_name, set()))


def _register_provider_user(provider_name, external_user_id, internal_user_id):
    with _provider_user_map_lock:
        if provider_name not in _provider_user_map:
            _provider_user_map[provider_name] = {}
        _provider_user_map[provider_name][external_user_id] = internal_user_id


def _get_internal_user_id(provider_name, external_user_id):
    with _provider_user_map_lock:
        return _provider_user_map.get(provider_name, {}).get(external_user_id)


def _remove_provider_user(provider_name, external_user_id):
    with _provider_user_map_lock:
        if provider_name in _provider_user_map:
            _provider_user_map[provider_name].pop(external_user_id, None)
            if not _provider_user_map[provider_name]:
                del _provider_user_map[provider_name]


def register_auth_provider(provider_name, provider_config):
    if not isinstance(provider_name, str) or not provider_name.strip():
        return False
    if not isinstance(provider_config, dict):
        return False
    required_fields = {"authenticate", "validate_token"}
    if not required_fields.issubset(provider_config.keys()):
        return False
    if not callable(provider_config["authenticate"]):
        return False
    if not callable(provider_config["validate_token"]):
        return False
    with _auth_providers_lock:
        _auth_providers[provider_name] = {
            "name": provider_name,
            "authenticate": provider_config["authenticate"],
            "validate_token": provider_config["validate_token"],
            "refresh_token": provider_config.get("refresh_token"),
            "revoke_token": provider_config.get("revoke_token"),
            "get_user_info": provider_config.get("get_user_info"),
            "logout": provider_config.get("logout"),
            "config": provider_config.get("config", {}),
            "enabled": provider_config.get("enabled", True),
            "registered_at": time.time()
        }
    return True


def unregister_auth_provider(provider_name):
    with _auth_providers_lock:
        if provider_name not in _auth_providers:
            return False
        del _auth_providers[provider_name]
    sessions_to_destroy = _get_provider_sessions(provider_name)
    for sid in sessions_to_destroy:
        destroy_session(sid)
    return True


def get_auth_provider(provider_name):
    with _auth_providers_lock:
        provider = _auth_providers.get(provider_name)
        if provider is None:
            return None
        return dict(provider)


def list_auth_providers():
    with _auth_providers_lock:
        return [
            {
                "name": name,
                "enabled": p["enabled"],
                "registered_at": p["registered_at"],
                "has_refresh": p["refresh_token"] is not None,
                "has_revoke": p["revoke_token"] is not None,
                "has_user_info": p["get_user_info"] is not None,
                "has_logout": p["logout"] is not None
            }
            for name, p in _auth_providers.items()
        ]


def enable_auth_provider(provider_name):
    with _auth_providers_lock:
        if provider_name not in _auth_providers:
            return False
        _auth_providers[provider_name]["enabled"] = True
    return True


def disable_auth_provider(provider_name):
    with _auth_providers_lock:
        if provider_name not in _auth_providers:
            return False
        _auth_providers[provider_name]["enabled"] = False
    return True


def authenticate_with_provider(provider_name, credentials):
    with _auth_providers_lock:
        provider = _auth_providers.get(provider_name)
        if provider is None:
            return None, "Provider not found"
        if not provider["enabled"]:
            return None, "Provider disabled"
        authenticate_fn = provider["authenticate"]
        get_user_info_fn = provider.get("get_user_info")
    try:
        auth_result = authenticate_fn(credentials)
        if auth_result is None:
            return None, "Authentication failed"
        if not isinstance(auth_result, dict):
            return None, "Invalid authentication result"
        token = auth_result.get("token")
        external_user_id = auth_result.get("user_id")
        if not token or not external_user_id:
            return None, "Missing token or user_id in authentication result"
        internal_user_id = _get_internal_user_id(provider_name, external_user_id)
        if internal_user_id is None:
            internal_user_id = str(uuid.uuid4())
            _register_provider_user(provider_name, external_user_id, internal_user_id)
        user_info = {}
        if get_user_info_fn is not None:
            try:
                user_info = get_user_info_fn(token) or {}
            except Exception:
                user_info = {}
        session_id = create_session(
            user_id=internal_user_id,
            user_data={
                "auth_provider": provider_name,
                "external_user_id": external_user_id,
                "token": token,
                "user_info": user_info,
                "auth_result": {k: v for k, v in auth_result.items() if k != "token"}
            },
            metadata={
                "provider": provider_name,
                "authenticated_at": time.time()
            }
        )
        if session_id is None:
            return None, "Session creation failed"
        with _session_store_lock:
            entry = _active_sessions.get(session_id)
            if entry is not None:
                entry["auth_provider"] = provider_name
        _register_provider_session(provider_name, session_id)
        return session_id, None
    except Exception as e:
        return None, str(e)


def validate_provider_token(provider_name, token):
    with _auth_providers_lock:
        provider = _auth_providers.get(provider_name)
        if provider is None:
            return False, "Provider not found"
        if not provider["enabled"]:
            return False, "Provider disabled"
        validate_fn = provider["validate_token"]
    try:
        result = validate_fn(token)
        if isinstance(result, bool):
            return result, None if result else "Token invalid"
        if isinstance(result, dict):
            valid = result.get("valid", False)
            error = result.get("error") if not valid else None
            return valid, error
        return False, "Invalid validation result"