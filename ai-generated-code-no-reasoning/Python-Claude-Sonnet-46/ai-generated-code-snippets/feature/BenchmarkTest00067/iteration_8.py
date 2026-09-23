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


def register_auth_provider(name, provider):
    with _auth_providers_lock:
        _auth_providers[name] = provider


def unregister_auth_provider(name):
    with _auth_providers_lock:
        return _auth_providers.pop(name, None)


def get_auth_provider(name):
    with _auth_providers_lock:
        return _auth_providers.get(name)


def list_auth_providers():
    with _auth_providers_lock:
        return list(_auth_providers.keys())


def authenticate_with_provider(provider_name, credentials):
    provider = get_auth_provider(provider_name)
    if provider is None:
        return None
    return provider.authenticate(credentials)


async def async_authenticate_with_provider(provider_name, credentials):
    provider = get_auth_provider(provider_name)
    if provider is None:
        return None
    loop = asyncio.get_event_loop()
    if hasattr(provider, "async_authenticate"):
        return await provider.async_authenticate(credentials)
    return await loop.run_in_executor(_session_executor, provider.authenticate, credentials)


def authenticate_with_any_provider(credentials):
    with _auth_providers_lock:
        providers = dict(_auth_providers)
    for name, provider in providers.items():
        result = provider.authenticate(credentials)
        if result is not None:
            result["auth_provider"] = name
            return result
    return None


async def async_authenticate_with_any_provider(credentials):
    with _auth_providers_lock:
        providers = dict(_auth_providers)
    loop = asyncio.get_event_loop()
    for name, provider in providers.items():
        if hasattr(provider, "async_authenticate"):
            result = await provider.async_authenticate(credentials)
        else:
            result = await loop.run_in_executor(_session_executor, provider.authenticate, credentials)
        if result is not None:
            result["auth_provider"] = name
            return result
    return None


class BaseAuthProvider:
    def authenticate(self, credentials):
        raise NotImplementedError

    async def async_authenticate(self, credentials):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_session_executor, self.authenticate, credentials)

    def get_user_info(self, user_id):
        raise NotImplementedError

    async def async_get_user_info(self, user_id):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_session_executor, self.get_user_info, user_id)

    def refresh_token(self, token):
        return None

    async def async_refresh_token(self, token):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_session_executor, self.refresh_token, token)

    def revoke_token(self, token):
        return False

    async def async_revoke_token(self, token):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_session_executor, self.revoke_token, token)


class LocalAuthProvider(BaseAuthProvider):
    def __init__(self, users=None):
        self._users = users or {}
        self._lock = threading.RLock()

    def add_user(self, username, password_hash, user_data=None):
        with self._lock:
            self._users[username] = {
                "password_hash": password_hash,
                "user_data": user_data or {}
            }

    async def async_add_user(self, username, password_hash, user_data=None):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(_session_executor, self.add_user, username, password_hash, user_data)

    def remove_user(self, username):
        with self._lock:
            return self._users.pop(username, None)

    async def async_remove_user(self, username):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_session_executor, self.remove_user, username)

    def authenticate(self, credentials):
        username = credentials.get("username")
        password_hash = credentials.get("password_hash")
        if not username or not password_hash:
            return None
        with self._lock:
            user = self._users.get(username)
            if user is None:
                return None
            if user["password_hash"] != password_hash:
                return None
            return {
                "user_id": username,
                "username": username,
                "user_data": dict(user["user_data"])
            }

    async def async_authenticate(self, credentials):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_session_executor, self.authenticate, credentials)

    def get_user_info(self, user_id):
        with self._lock:
            user = self._users.get(user_id)
            if user is None:
                return None
            return {
                "user_id": user_id,
                "username": user_id,
                "user_data": dict(user["user_data"])
            }

    async def async_get_user_info(self, user_id):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_session_executor, self.get_user_info, user_id)


class TokenAuthProvider(BaseAuthProvider):
    def __init__(self):
        self._tokens = {}
        self._lock = threading.RLock()

    def issue_token(self, user_id, user_data=None, ttl=None):
        token = str(uuid.uuid4())
        now = time.time()
        with self._lock:
            self._tokens[token] = {
                "user_id": user_id,
                "user_data": user_data or {},
                "created_at": now,
                "expires_at": now + ttl if ttl else None
            }
        return token

    async def async_issue_token(self, user_id, user_data=None, ttl=None):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_session_executor, self.issue_token, user_id, user_data, ttl)

    def revoke_token(self, token):
        with self._lock:
            return self._tokens.pop(token, None) is not None

    async def async_revoke_token(self, token):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_session_executor, self.revoke_token, token)

    def authenticate(self, credentials):
        token = credentials.get("token")
        if not token:
            return None
        with self._lock:
            entry = self._tokens.get(token)
            if entry is None:
                return None
            if entry["expires_at"] is not None and time.time() > entry["expires_at"]:
                del self._tokens[token]
                return None
            return {
                "user_id": entry["user_id"],
                "user_data": dict(entry["user_data"]),
                "token": token
            }

    async def async_authenticate(self, credentials):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_session_executor, self.authenticate, credentials)

    def get_user_info(self, user_id):
        with self._lock:
            for token, entry in self._tokens.items():
                if entry["user_id"] == user_id:
                    return {
                        "user_id": user_id,
                        "user_data": dict(entry["user_data"])
                    }
        return None

    async def async_get_user_info(self, user_id):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_session_executor, self.get_user_info, user_id)

    def cleanup_expired_tokens(self):
        now = time.time()
        expired = []
        with self._lock:
            for token, entry in list(self._tokens.items()):
                if entry["expires_at"] is not None and now > entry["expires_at"]:
                    expired.append(token)
            for token in expired:
                del self._tokens[token]
        return len(expired)

    async def async_cleanup_expired_tokens(self):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_session_executor, self.cleanup_expired_tokens)


class OAuthProvider(BaseAuthProvider):
    def __init__(self, client_id, client_secret, token_endpoint, userinfo_endpoint, provider_name=None):
        self._client_id = client_id
        self._client_secret = client_secret
        self._token_endpoint = token_endpoint
        self._userinfo_endpoint = userinfo_endpoint
        self._provider_name = provider_name or "oauth"
        self._token_cache = {}
        self._lock = threading.RLock()

    def authenticate(self, credentials):
        access_token = credentials.get("access_token")
        if not access_token:
            return None
        with self._lock:
            cached = self._token_cache.get(access_token)
            if cached is not None:
                if cached.get("expires_at") is None or time.time() < cached["expires_at"]:
                    return dict(cached)
                else:
                    del self._token_cache[access_token]
        return None

    async def async_authenticate(self, credentials):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_session_executor, self.authenticate, credentials)

    def store_token_info(self, access_token, user_id, user_data=None, expires_in=None):
        now = time.time()
        entry = {
            "user_id": user_id,
            "access_token": access_token,
            "user_data": user_data or {},
            "created_at": now,
            "expires_at": now + expires_in if expires_in else None
        }
        with self._lock:
            self._token_cache[access_token] = entry
        return entry

    async def async_store_token_info(self, access_token, user_id, user_data=None, expires_in=None):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            _session_executor, self.store_token_info, access_token, user_id, user_data, expires_in
        )

    def revoke_token(self, token):
        with self._lock:
            return self._token_cache.pop(token, None) is not None

    async def async_revoke_token(self, token):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_session_executor, self.revoke_token, token)

    def get_user_info(self, user_id):
        with self._lock:
            for token, entry in self._token_cache.items():
                if entry["user_id"] == user_id:
                    return {
                        "user_id": user_id,
                        "user_