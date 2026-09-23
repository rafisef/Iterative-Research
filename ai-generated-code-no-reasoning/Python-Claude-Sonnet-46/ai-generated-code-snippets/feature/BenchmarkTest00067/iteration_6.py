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


def _get_or_create_session_user_lock(session_id):
    with _session_user_locks_lock:
        if session_id not in _session_user_locks:
            _session_user_locks[session_id] = threading.RLock()
        return _session_user_locks[session_id]


def _remove_session_user_lock(session_id):
    with _session_user_locks_lock:
        _session_user_locks.pop(session_id, None)


def ensure_storage_dir():
    os.makedirs(STORAGE_DIR, exist_ok=True)


def init_file_storage():
    ensure_storage_dir()
    if not os.path.exists(FILE_STORAGE_PATH):
        with open(FILE_STORAGE_PATH, 'w') as f:
            json.dump({}, f)


def init_session_storage():
    ensure_storage_dir()
    if not os.path.exists(SESSION_STORAGE_PATH):
        with open(SESSION_STORAGE_PATH, 'w') as f:
            json.dump({}, f)


def init_db_storage():
    ensure_storage_dir()
    conn = sqlite3.connect(DB_STORAGE_PATH, timeout=DB_TIMEOUT)
    cursor = conn.cursor()
    cursor.execute('PRAGMA journal_mode=WAL')
    cursor.execute('PRAGMA synchronous=NORMAL')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS redirect_data (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_sessions (
            session_id TEXT PRIMARY KEY,
            user_data TEXT NOT NULL,
            created_at REAL NOT NULL,
            last_active REAL NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_user_sessions_last_active
        ON user_sessions(last_active)
    ''')
    conn.commit()
    conn.close()


def _start_cleanup_thread():
    global _cleanup_thread
    if _cleanup_thread is not None and _cleanup_thread.is_alive():
        return
    _cleanup_stop_event.clear()

    def cleanup_loop():
        while not _cleanup_stop_event.wait(timeout=SESSION_CLEANUP_INTERVAL):
            try:
                cleanup_expired_sessions()
                if ENABLE_SESSION_PERSISTENCE:
                    cleanup_expired_sessions_from_db()
            except Exception:
                pass

    _cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True, name="session-cleanup")
    _cleanup_thread.start()


def stop_cleanup_thread():
    _cleanup_stop_event.set()
    if _cleanup_thread is not None:
        _cleanup_thread.join(timeout=5)


def cleanup_expired_sessions():
    now = time.time()
    expired = []
    with _session_store_lock:
        for sid, entry in list(_active_sessions.items()):
            if now - entry["last_active"] > SESSION_TIMEOUT:
                expired.append(sid)
        for sid in expired:
            del _active_sessions[sid]
    for sid in expired:
        _remove_session_user_lock(sid)
    return len(expired)


def cleanup_expired_sessions_from_db():
    try:
        init_db_storage()
        conn = sqlite3.connect(DB_STORAGE_PATH, timeout=DB_TIMEOUT)
        cursor = conn.cursor()
        cutoff = time.time() - SESSION_TIMEOUT
        cursor.execute('DELETE FROM user_sessions WHERE last_active < ?', (cutoff,))
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        return deleted
    except Exception:
        return 0


def create_session(user_data=None):
    session_id = str(uuid.uuid4())
    now = time.time()
    session_entry = {
        "session_id": session_id,
        "user_data": user_data or {},
        "created_at": now,
        "last_active": now,
        "concurrent_requests": 0
    }
    with _session_store_lock:
        if MAX_CONCURRENT_SESSIONS and len(_active_sessions) >= MAX_CONCURRENT_SESSIONS:
            now_inner = time.time()
            expired = [
                sid for sid, e in _active_sessions.items()
                if now_inner - e["last_active"] > SESSION_TIMEOUT
            ]
            for sid in expired:
                del _active_sessions[sid]
                _remove_session_user_lock(sid)
            if len(_active_sessions) >= MAX_CONCURRENT_SESSIONS:
                raise RuntimeError("Maximum concurrent session limit reached")
        _active_sessions[session_id] = session_entry
    _get_or_create_session_user_lock(session_id)
    return session_id


def get_session(session_id):
    user_lock = _get_or_create_session_user_lock(session_id)
    with user_lock:
        with _session_store_lock:
            entry = _active_sessions.get(session_id)
            if entry is None:
                return None
            now = time.time()
            if now - entry["last_active"] > SESSION_TIMEOUT:
                del _active_sessions[session_id]
                _remove_session_user_lock(session_id)
                return None
            entry["last_active"] = now
            return dict(entry)


def update_session(session_id, user_data):
    user_lock = _get_or_create_session_user_lock(session_id)
    with user_lock:
        with _session_store_lock:
            entry = _active_sessions.get(session_id)
            if entry is None:
                return False
            now = time.time()
            if now - entry["last_active"] > SESSION_TIMEOUT:
                del _active_sessions[session_id]
                _remove_session_user_lock(session_id)
                return False
            entry["user_data"].update(user_data)
            entry["last_active"] = now
            return True


def delete_session(session_id):
    user_lock = _get_or_create_session_user_lock(session_id)
    with user_lock:
        with _session_store_lock:
            if session_id in _active_sessions:
                del _active_sessions[session_id]
                _remove_session_user_lock(session_id)
                return True
        return False


def list_active_sessions():
    now = time.time()
    with _session_store_lock:
        expired = [sid for sid, entry in list(_active_sessions.items())
                   if now - entry["last_active"] > SESSION_TIMEOUT]
        for sid in expired:
            del _active_sessions[sid]
            _remove_session_user_lock(sid)
        return {sid: dict(entry) for sid, entry in _active_sessions.items()}


def get_active_session_count():
    with _session_store_lock:
        return len(_active_sessions)


def acquire_session_concurrent_slot(session_id):
    user_lock = _get_or_create_session_user_lock(session_id)
    with user_lock:
        with _session_store_lock:
            entry = _active_sessions.get(session_id)
            if entry is None:
                return False
            entry["concurrent_requests"] = entry.get("concurrent_requests", 0) + 1
            return True


def release_session_concurrent_slot(session_id):
    user_lock = _get_or_create_session_user_lock(session_id)
    with user_lock:
        with _session_store_lock:
            entry = _active_sessions.get(session_id)
            if entry is None:
                return
            count = entry.get("concurrent_requests", 0)
            entry["concurrent_requests"] = max(0, count - 1)


def persist_session_to_db(session_id, user_data):
    init_db_storage()
    conn = sqlite3.connect(DB_STORAGE_PATH, timeout=DB_TIMEOUT)
    cursor = conn.cursor()
    now = time.time()
    cursor.execute('''
        INSERT OR REPLACE INTO user_sessions (session_id, user_data, created_at, last_active)
        VALUES (?, ?, ?, ?)
    ''', (session_id, json.dumps(user_data), now, now))
    conn.commit()
    conn.close()


def persist_session_to_db_async(session_id, user_data):
    return _session_executor.submit(persist_session_to_db, session_id, user_data)


def load_session_from_db(session_id):
    init_db_storage()
    conn = sqlite3.connect(DB_STORAGE_PATH, timeout=DB_TIMEOUT)
    cursor = conn.cursor()
    cursor.execute('SELECT user_data, created_at, last_active FROM user_sessions WHERE session_id = ?', (session_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        now = time.time()
        if now - row[2] > SESSION_TIMEOUT:
            delete_session_from_db(session_id)
            return None
        return {
            "session_id": session_id,
            "user_data": json.loads(row[0]),
            "created_at": row[1],
            "last_active": row[2]
        }
    return None


def delete_session_from_db(session_id):
    init_db_storage()
    conn = sqlite3.connect(DB_STORAGE_PATH, timeout=DB_TIMEOUT)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM user_sessions WHERE session_id = ?', (session_id,))
    conn.commit()
    conn.close()


def save_to_file(key, value):
    with storage_lock:
        init_file_storage()
        with open(FILE_STORAGE_PATH, 'r') as f:
            data = json.load(f)
        data[key] = value
        with open(FILE_STORAGE_PATH, 'w') as f:
            json.dump(data, f)


def load_from_file(key, default=None):
    with storage_lock:
        init_file_storage()
        with open(FILE_STORAGE_PATH, 'r') as f:
            data = json.load(f)
        return data.get(key, default)


def save_to_db(key, value):
    init_db_storage()
    conn = sqlite3.connect(DB_STORAGE_PATH, timeout=DB_TIMEOUT)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO redirect_data (key, value) VALUES (?, ?)
    ''', (key, value))
    conn.commit()
    conn.close()


def load_from_db(key, default=None):
    init_db_storage()
    conn = sqlite3.connect(DB_STORAGE_PATH, timeout=DB_TIMEOUT)
    cursor = conn.cursor()
    cursor.execute('SELECT value FROM redirect_data WHERE key = ?', (key,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0]
    return default


def save_redirect_data(