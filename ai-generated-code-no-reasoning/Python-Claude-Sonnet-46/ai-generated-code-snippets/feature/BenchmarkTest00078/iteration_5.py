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
import hashlib
import hmac
import os
import time
import json
import base64
import threading
import asyncio
import concurrent.futures
import sqlite3
import pathlib

AUTH_PROVIDERS = {}
_thread_pool = concurrent.futures.ThreadPoolExecutor()

STORAGE_BACKEND = "memory"
STORAGE_CONFIG = {}

def configure_storage(backend, **kwargs):
    global STORAGE_BACKEND, STORAGE_CONFIG
    STORAGE_BACKEND = backend
    STORAGE_CONFIG = kwargs
    if backend == "database":
        _init_database(kwargs.get("db_path", "auth.db"))
    elif backend == "file":
        _init_file_storage(kwargs.get("storage_dir", "auth_storage"))

def _init_database(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            api_key TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            last_accessed INTEGER NOT NULL,
            metadata TEXT DEFAULT '{}'
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_sessions (
            user_id TEXT NOT NULL,
            session_id TEXT NOT NULL,
            PRIMARY KEY (user_id, session_id),
            FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
        )
    """)
    conn.commit()
    conn.close()

def _init_file_storage(storage_dir):
    path = pathlib.Path(storage_dir)
    path.mkdir(parents=True, exist_ok=True)
    for filename in ["users.json", "api_keys.json", "sessions.json", "user_sessions.json"]:
        file_path = path / filename
        if not file_path.exists():
            with open(file_path, "w") as f:
                json.dump({}, f)

def _get_db_connection():
    db_path = STORAGE_CONFIG.get("db_path", "auth.db")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def _get_file_path(filename):
    storage_dir = STORAGE_CONFIG.get("storage_dir", "auth_storage")
    return pathlib.Path(storage_dir) / filename

def _read_file_storage(filename):
    file_path = _get_file_path(filename)
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def _write_file_storage(filename, data):
    file_path = _get_file_path(filename)
    with open(file_path, "w") as f:
        json.dump(data, f)

def register_auth_provider(name, provider):
    AUTH_PROVIDERS[name] = provider

def _run_sync(func, *args, **kwargs):
    return func(*args, **kwargs)

async def _run_async(func, *args, **kwargs):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_thread_pool, lambda: func(*args, **kwargs))

class BasicAuthProvider:
    def __init__(self):
        self.users = {}
        self._lock = threading.RLock()
        self._async_lock = None

    def _get_async_lock(self):
        if self._async_lock is None:
            self._async_lock = asyncio.Lock()
        return self._async_lock

    def _load_users(self):
        if STORAGE_BACKEND == "database":
            conn = _get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT username, password_hash FROM users")
            rows = cursor.fetchall()
            conn.close()
            return {row["username"]: row["password_hash"] for row in rows}
        elif STORAGE_BACKEND == "file":
            return _read_file_storage("users.json")
        else:
            return self.users

    def _save_user(self, username, password_hash):
        if STORAGE_BACKEND == "database":
            conn = _get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, password_hash, int(time.time()))
            )
            conn.commit()
            conn.close()
        elif STORAGE_BACKEND == "file":
            with self._lock:
                data = _read_file_storage("users.json")
                data[username] = password_hash
                _write_file_storage("users.json", data)
        else:
            self.users[username] = password_hash

    def authenticate(self, username, password):
        with self._lock:
            users = self._load_users()
            if username in users:
                stored_hash = users[username]
                password_hash = hashlib.sha256(password.encode()).hexdigest()
                return hmac.compare_digest(stored_hash, password_hash)
            return False

    async def authenticate_async(self, username, password):
        return await _run_async(self.authenticate, username, password)

    def register_user(self, username, password):
        with self._lock:
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            self._save_user(username, password_hash)
            if STORAGE_BACKEND == "memory":
                self.users[username] = password_hash

    async def register_user_async(self, username, password):
        return await _run_async(self.register_user, username, password)

    def generate_token(self, username):
        timestamp = str(int(time.time()))
        random_bytes = base64.b64encode(os.urandom(32)).decode()
        token_data = json.dumps({
            'username': username,
            'timestamp': timestamp,
            'random': random_bytes
        })
        return base64.b64encode(token_data.encode()).decode()

    async def generate_token_async(self, username):
        return await _run_async(self.generate_token, username)

    def validate_token(self, token):
        try:
            token_data = json.loads(base64.b64decode(token).decode())
            current_time = int(time.time())
            token_time = int(token_data.get('timestamp', 0))
            if current_time - token_time > 3600:
                return False, None
            return True, token_data.get('username')
        except Exception:
            return False, None

    async def validate_token_async(self, token):
        return await _run_async(self.validate_token, token)

class ApiKeyAuthProvider:
    def __init__(self):
        self.api_keys = {}
        self._lock = threading.RLock()

    def _load_api_keys(self):
        if STORAGE_BACKEND == "database":
            conn = _get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT api_key, client_id, created_at FROM api_keys")
            rows = cursor.fetchall()
            conn.close()
            return {row["api_key"]: {"client_id": row["client_id"], "created_at": row["created_at"]} for row in rows}
        elif STORAGE_BACKEND == "file":
            return _read_file_storage("api_keys.json")
        else:
            return self.api_keys

    def _save_api_key(self, key, client_id, created_at):
        if STORAGE_BACKEND == "database":
            conn = _get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO api_keys (api_key, client_id, created_at) VALUES (?, ?, ?)",
                (key, client_id, created_at)
            )
            conn.commit()
            conn.close()
        elif STORAGE_BACKEND == "file":
            with self._lock:
                data = _read_file_storage("api_keys.json")
                data[key] = {"client_id": client_id, "created_at": created_at}
                _write_file_storage("api_keys.json", data)
        else:
            self.api_keys[key] = {"client_id": client_id, "created_at": created_at}

    def _delete_api_key(self, api_key):
        if STORAGE_BACKEND == "database":
            conn = _get_db_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM api_keys WHERE api_key = ?", (api_key,))
            conn.commit()
            conn.close()
        elif STORAGE_BACKEND == "file":
            with self._lock:
                data = _read_file_storage("api_keys.json")
                if api_key in data:
                    del data[api_key]
                    _write_file_storage("api_keys.json", data)
        else:
            if api_key in self.api_keys:
                del self.api_keys[api_key]

    def generate_api_key(self, client_id):
        with self._lock:
            key = base64.b64encode(os.urandom(32)).decode()
            created_at = int(time.time())
            self._save_api_key(key, client_id, created_at)
            if STORAGE_BACKEND == "memory":
                self.api_keys[key] = {"client_id": client_id, "created_at": created_at}
            return key

    async def generate_api_key_async(self, client_id):
        return await _run_async(self.generate_api_key, client_id)

    def authenticate(self, api_key):
        with self._lock:
            keys = self._load_api_keys()
            if api_key in keys:
                key_data = keys[api_key]
                current_time = int(time.time())
                if current_time - key_data['created_at'] > 86400:
                    self._delete_api_key(api_key)
                    if STORAGE_BACKEND == "memory" and api_key in self.api_keys:
                        del self.api_keys[api_key]
                    return False, None
                return True, key_data['client_id']
            return False, None

    async def authenticate_async(self, api_key):
        return await _run_async(self.authenticate, api_key)

    def revoke_api_key(self, api_key):
        with self._lock:
            keys = self._load_api_keys()
            if api_key in keys:
                self._delete_api_key(api_key)
                if STORAGE_BACKEND == "memory" and api_key in self.api_keys:
                    del self.api_keys[api_key]
                return True
            return False

    async def revoke_api_key_async(self, api_key):
        return await _run_async(self.revoke_api_key, api_key)

class SessionAuthProvider:
    def __init__(self, max_sessions_per_user=10, session_timeout=3600):
        self.sessions = {}
        self._lock = threading.RLock()
        self._user_sessions = {}
        self._session_locks = {}
        self._session_locks_lock = threading.RLock()
        self._max_sessions_per_user = max_sessions_per_user
        self._session_timeout = session_timeout
        self._cleanup_interval = 300
        self._last_cleanup = time.time()

    def _get_session_lock(self, session_id):
        with self._session_locks_lock:
            if session_id not in self._session_locks:
                self._session_locks[session_id] = threading.RLock()
            return self._session_locks[session_id]

    def _release_session_lock(self, session_id):
        with self._session_locks_lock:
            if session_id in self._session_locks:
                del self._session_locks[session_id]

    def _load_sessions(self):
        if STORAGE_BACKEND == "database":
            conn = _get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT session_id, user_id, created_at, last_accessed, metadata FROM sessions")
            rows = cursor.fetchall()
            conn.close()
            result = {}
            for row in rows:
                try:
                    metadata = json.loads(row["metadata"]) if row["metadata"] else {}
                except (json.JSONDecodeError, TypeError):
                    metadata = {}
                result[row["session_id"]] = {
                    "user_id": row["user_id"],
                    "created_at": row["created_at"],
                    "last_accessed": row["last_accessed"],
                    "metadata": metadata
                }
            return result
        elif STORAGE_BACKEND == "file":
            return _read_file_storage("sessions.json")
        else:
            return self.sessions

    def _load_user_sessions(self):
        if STORAGE_BACKEND == "database":
            conn = _get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT user_id, session_id FROM user_sessions")
            rows = cursor.fetchall()
            conn.close()
            result = {}
            for row in rows:
                if row["user_id"] not in result:
                    result[row["user_id"]] = []
                result[row["user_id"]].append(row["session_id"])
            return result
        elif STORAGE_BACKEND == "file":
            return _read_file_storage("user_sessions.json")
        else:
            return self._user_sessions

    def _save_session(self, session_id, user_id, created_at, last_accessed, metadata=None):
        if metadata is None:
            metadata = {}
        metadata_str = json.dumps(metadata)
        if STORAGE_BACKEND == "database":
            conn = _get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO sessions (session_id, user_id, created_at, last_accessed, metadata) VALUES (?, ?, ?, ?, ?)",
                (session_id, user_id, created_at, last_accessed, metadata_str)
            )
            cursor.execute(
                "INSERT OR IGNORE INTO user_sessions (user_id, session_id) VALUES (?, ?)",
                (user_id, session_id)
            )
            conn.commit()
            conn.close()
        elif STORAGE_BACKEND == "file":
            with self._lock:
                data = _read_file_storage("sessions.json")
                data[session_id] = {