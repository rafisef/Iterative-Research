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
        sem.release()


def create_session(user_id=None, user_data=None, metadata=None):
    sem = _get_session_semaphore()
    if not sem.acquire(blocking=False):
        return None
    if user_id is not None:
        _enforce_max_sessions_per_user(user_id)
    session_id = str(uuid.uuid4())
    now = time.time()
    entry = {
        "session_id": session_id,
        "user_id": user_id,
        "user_data": user_data or {},
        "metadata": metadata or {},
        "created_at": now,
        "last_accessed": now,
        "expires_at": now + SESSION_TIMEOUT,
        "concurrent_access_count": 0,
        "access_lock": threading.RLock()
    }
    with _session_store_lock:
        _active_sessions[session_id] = entry
    if user_id is not None:
        _register_user_session(user_id, session_id)
    return session_id


def get_session(session_id):
    with _session_store_lock:
        entry = _active_sessions.get(session_id)
        if entry is None:
            return None
        now = time.time()
        if now > entry["expires_at"]:
            uid = entry.get("user_id")
            del _active_sessions[session_id]
            if uid:
                _unregister_user_session(uid, session_id)
            _get_session_semaphore().release()
            return None
        entry["last_accessed"] = now
        entry["expires_at"] = now + SESSION_TIMEOUT
        return {k: v for k, v in entry.items() if k != "access_lock"}


def update_session(session_id, user_data=None, metadata=None):
    with _session_store_lock:
        entry = _active_sessions.get(session_id)
        if entry is None:
            return False
        now = time.time()
        if now > entry["expires_at"]:
            uid = entry.get("user_id")
            del _active_sessions[session_id]
            if uid:
                _unregister_user_session(uid, session_id)
            _get_session_semaphore().release()
            return False
        access_lock = entry["access_lock"]
    with access_lock:
        with _session_store_lock:
            entry = _active_sessions.get(session_id)
            if entry is None:
                return False
            if user_data is not None:
                serialized = json.dumps(user_data)
                if len(serialized) > MAX_SESSION_USER_DATA_SIZE:
                    return False
                entry["user_data"] = user_data
            if metadata is not None:
                entry["metadata"] = metadata
            now = time.time()
            entry["last_accessed"] = now
            entry["expires_at"] = now + SESSION_TIMEOUT
    return True


def destroy_session(session_id):
    with _session_store_lock:
        entry = _active_sessions.get(session_id)
        if entry is None:
            return False
        uid = entry.get("user_id")
        del _active_sessions[session_id]
    if uid:
        _unregister_user_session(uid, session_id)
    _get_session_semaphore().release()
    return True


def destroy_all_user_sessions(user_id):
    session_ids = _get_user_sessions(user_id)
    destroyed = 0
    for sid in session_ids:
        if destroy_session(sid):
            destroyed += 1
    return destroyed


async def async_create_session(user_id=None, user_data=None, metadata=None):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_session_executor, create_session, user_id, user_data, metadata)


async def async_get_session(session_id):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_session_executor, get_session, session_id)


async def async_update_session(session_id, user_data=None, metadata=None):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_session_executor, update_session, session_id, user_data, metadata)


async def async_destroy_session(session_id):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_session_executor, destroy_session, session_id)


async def async_destroy_all_user_sessions(user_id):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_session_executor, destroy_all_user_sessions, user_id)


def cleanup_expired_sessions():
    now = time.time()
    expired = []
    with _session_store_lock:
        for sid, entry in list(_active_sessions.items()):
            if now > entry["expires_at"]:
                expired.append((sid, entry.get("user_id")))
    for sid, uid in expired:
        with _session_store_lock:
            removed = _active_sessions.pop(sid, None)
        if removed is not None:
            if uid:
                _unregister_user_session(uid, sid)
            _get_session_semaphore().release()
    return len(expired)


async def async_cleanup_expired_sessions():
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_session_executor, cleanup_expired_sessions)


def _cleanup_worker():
    while not _cleanup_stop_event.is_set():
        _cleanup_stop_event.wait(timeout=SESSION_CLEANUP_INTERVAL)
        if not _cleanup_stop_event.is_set():
            cleanup_expired_sessions()


def start_cleanup_thread():
    global _cleanup_thread
    if _cleanup_thread is None or not _cleanup_thread.is_alive():
        _cleanup_stop_event.clear()
        _cleanup_thread = threading.Thread(target=_cleanup_worker, daemon=True, name="session-cleanup")
        _cleanup_thread.start()


def stop_cleanup_thread():
    _cleanup_stop_event.set()
    if _cleanup_thread is not None:
        _cleanup_thread.join(timeout=10)


def get_active_session_count():
    with _session_store_lock:
        return len(_active_sessions)


def get_active_user_count():
    with _user_session_index_lock:
        return len(_user_session_index)


def get_session_stats():
    with _session_store_lock:
        total = len(_active_sessions)
    with _user_session_index_lock:
        users = len(_user_session_index)
        per_user = {uid: len(sids) for uid, sids in _user_session_index.items()}
    return {
        "total_sessions": total,
        "active_users": users,
        "sessions_per_user": per_user,
        "max_concurrent_sessions": MAX_CONCURRENT_SESSIONS,
        "max_sessions_per_user": MAX_SESSIONS_PER_USER,
        "session_timeout": SESSION_TIMEOUT
    }


def session_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        session_id = request.cookies.get(COOKIE_NAME)
        if not session_id:
            return flask.jsonify({"error": "No session"}), 401
        sess = get_session(session_id)
        if sess is None:
            return flask.jsonify({"error": "Invalid or expired session"}), 401
        request.current_session = sess
        return f(*args, **kwargs)
    return decorated


def concurrent_session_middleware(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        session_id = request.cookies.get(COOKIE_NAME)
        if session_id:
            with _session_store_lock:
                entry = _