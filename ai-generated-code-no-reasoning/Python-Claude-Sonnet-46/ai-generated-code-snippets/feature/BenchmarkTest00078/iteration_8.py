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

class SessionManager:
    def __init__(self):
        self.sessions = {}
        self.user_sessions = {}
        self._lock = threading.RLock()
        self._session_ttl = 3600
        self._max_sessions_per_user = 10

    def set_session_ttl(self, ttl):
        with self._lock:
            self._session_ttl = ttl

    def set_max_sessions_per_user(self, max_sessions):
        with self._lock:
            self._max_sessions_per_user = max_sessions

    def _load_sessions(self):
        if STORAGE_BACKEND == "database":
            conn = _get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT session_id, user_id, created_at, last_accessed, metadata FROM sessions")
            rows = cursor.fetchall()
            conn.close()
            return {
                row["session_id"]: {
                    "user_id": row["user_id"],
                    "created_at": row["created_at"],
                    "last_accessed": row["last_accessed"],
                    "metadata": json.loads(row["metadata"])
                }
                for row in rows
            }
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
                uid = row["user_id"]
                sid = row["session_id"]
                if uid not in result:
                    result[uid] = []
                result[uid].append(sid)
            return result
        elif STORAGE_BACKEND == "file":
            return _read_file_storage("user_sessions.json")
        else:
            return self.user_sessions

    def _save_session(self, session_id, user_id, created_at, last_accessed, metadata):
        if STORAGE_BACKEND == "database":
            conn = _get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO sessions (session_id, user_id, created_at, last_accessed, metadata) VALUES (?, ?, ?, ?, ?)",
                (session_id, user_id, created_at, last_accessed, json.dumps(metadata))
            )
            cursor.execute(
                "INSERT OR IGNORE INTO user_sessions (user_id, session_id) VALUES (?, ?)",
                (user_id, session_id)
            )
            conn.commit()
            conn.close()
        elif STORAGE_BACKEND == "file":
            with self._lock:
                sessions_data = _read_file_storage("sessions.json")
                sessions_data[session_id] = {
                    "user_id": user_id,
                    "created_at": created_at,
                    "last_accessed": last_accessed,
                    "metadata": metadata
                }
                _write_file_storage("sessions.json", sessions_data)
                user_sessions_data = _read_file_storage("user_sessions.json")
                if user_id not in user_sessions_data:
                    user_sessions_data[user_id] = []
                if session_id not in user_sessions_data[user_id]:
                    user_sessions_data[user_id].append(session_id)
                _write_file_storage("user_sessions.json", user_sessions_data)
        else:
            self.sessions[session_id] = {
                "user_id": user_id,
                "created_at": created_at,
                "last_accessed": last_accessed,
                "metadata": metadata
            }
            if user_id not in self.user_sessions:
                self.user_sessions[user_id] = []
            if session_id not in self.user_sessions[user_id]:
                self.user_sessions[user_id].append(session_id)

    def _update_session_last_accessed(self, session_id, last_accessed):
        if STORAGE_BACKEND == "database":
            conn = _get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE sessions SET last_accessed = ? WHERE session_id = ?",
                (last_accessed, session_id)
            )
            conn.commit()
            conn.close()
        elif STORAGE_BACKEND == "file":
            with self._lock:
                sessions_data = _read_file_storage("sessions.json")
                if session_id in sessions_data:
                    sessions_data[session_id]["last_accessed"] = last_accessed
                    _write_file_storage("sessions.json", sessions_data)
        else:
            if session_id in self.sessions:
                self.sessions[session_id]["last_accessed"] = last_accessed

    def _update_session_metadata(self, session_id, metadata):
        if STORAGE_BACKEND == "database":
            conn = _get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE sessions SET metadata = ? WHERE session_id = ?",
                (json.dumps(metadata), session_id)
            )
            conn.commit()
            conn.close()
        elif STORAGE_BACKEND == "file":
            with self._lock:
                sessions_data = _read_file_storage("sessions.json")
                if session_id in sessions_data:
                    sessions_data[session_id]["metadata"] = metadata
                    _write_file_storage("sessions.json", sessions_data)
        else:
            if session_id in self.sessions:
                self.sessions[session_id]["metadata"] = metadata

    def _delete_session(self, session_id):
        if STORAGE_BACKEND == "database":
            conn = _get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT user_id FROM sessions WHERE session_id = ?", (session_id,))
            row = cursor.fetchone()
            if row:
                cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
                cursor.execute("DELETE FROM user_sessions WHERE session_id = ?", (session_id,))
                conn.commit()
            conn.close()
        elif STORAGE_BACKEND == "file":
            with self._lock:
                sessions_data = _read_file_storage("sessions.json")
                session_info = sessions_data.pop(session_id, None)
                _write_file_storage("sessions.json", sessions_data)
                if session_info:
                    user_sessions_data = _read_file_storage("user_sessions.json")
                    uid = session_info.get("user_id")
                    if uid in user_sessions_data:
                        user_sessions_data[uid] = [s for s in user_sessions_data[uid] if s != session_id]
                        if not user_sessions_data[uid]:
                            del user_sessions_data[uid]
                        _write_file_storage("user_sessions.json", user_sessions_data)
        else:
            session_info = self.sessions.pop(session_id, None)
            if session_info:
                uid = session_info.get("user_id")
                if uid in self.user_sessions:
                    self.user_sessions[uid] = [s for s in self.user_sessions[uid] if s != session_id]
                    if not self.user_sessions[uid]:
                        del self.user_sessions[uid]

    def _delete_all_user_sessions(self, user_id):
        if STORAGE_BACKEND == "database":
            conn = _get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT session_id FROM user_sessions WHERE user_id = ?", (user_id,))
            rows = cursor.fetchall()
            for row in rows:
                cursor.execute("DELETE FROM sessions WHERE session_id = ?", (row["session_id"],))
            cursor.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_id,))
            conn.commit()
            conn.close()
        elif STORAGE_BACKEND == "file":
            with self._lock:
                user_sessions_data = _read_file_storage("user_sessions.json")
                session_ids = user_sessions_data.pop(user_id, [])
                _write_file_storage("user_sessions.json", user_sessions_data)
                sessions_data = _read_file_storage("sessions.json")
                for sid in session_ids:
                    sessions_data.pop(sid, None)
                _write_file_storage("sessions.json", sessions_data)
        else:
            session_ids = self.user_sessions.pop(user_id, [])
            for sid in session_ids:
                self.sessions.pop(sid, None)

    def _enforce_session_limit(self, user_id):
        user_sessions_map = self._load_user_sessions()
        session_ids = user_sessions_map.get(user_id, [])
        if len(session_ids) >= self._max_sessions_per_user:
            all_sessions = self._load_sessions()
            user_session_details = [
                (sid, all_sessions[sid]["last_accessed"])
                for sid in session_ids
                if sid in all_sessions
            ]
            user_session_details.sort(key=lambda x: x[1])
            sessions_to_remove = len(session_ids) - self._max_sessions_per_user + 1
            for i in range(sessions_to_remove):
                if i < len(user_session_details):
                    self._delete_session(user_session_details[i][0])

    def create_session(self, user_id, metadata=None):
        with self._lock:
            self._enforce_session_limit(user_id)
            session_id = base64.b64encode(os.urandom(32)).decode()
            now = int(time.time())
            self._save_session(session_id, user_id, now, now, metadata or {})
            return session_id

    async def create_session_async(self, user_id, metadata=None):
        return await _run_async(self.create_session, user_id, metadata)

    def get_session(self, session_id):
        with self._lock:
            sessions = self._load_sessions()
            session_data = sessions.get(session_id)
            if not session_data:
                return None
            now = int(time.time())
            if now - session_data["last_accessed"] > self._session_ttl:
                self._delete_session(session_id)
                return None
            self._update_session_last_accessed(session_id, now)
            if STORAGE_BACKEND == "memory":
                self.sessions[session_id]["last_accessed"] = now
            return session_data

    async def get_session_async(self, session_id):
        return await _run_async(self.get_session, session_id)

    def update_session_metadata(self, session_id, metadata):
        with self._lock:
            sessions = self._load_sessions()
            if session_id not in sessions:
                return False
            self._update_session_metadata(session_id, metadata)
            if STORAGE_BACKEND == "memory":
                self.sessions[session_id]["metadata"] = metadata
            return True

    async def update_session_metadata_async(self, session_id, metadata):
        return await _run_async(self.update_