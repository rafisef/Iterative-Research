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
import asyncio
import uuid
import json
import os
import sqlite3
import aiosqlite
import time
import hashlib
import hmac
import aiofiles
import aiofiles.os
from contextlib import contextmanager, asynccontextmanager
from typing import Optional, Dict, Any

session_store = {}
session_lock = threading.Lock()
async_session_lock = asyncio.Lock()
session_locks = {}
session_locks_lock = threading.Lock()
async_session_locks = {}
async_session_locks_lock = asyncio.Lock()
user_session_index = {}
user_session_index_lock = threading.Lock()
async_user_session_index = {}
async_user_session_index_lock = asyncio.Lock()

STORAGE_BACKEND = os.environ.get('SESSION_STORAGE_BACKEND', 'memory')
SESSION_FILE_DIR = os.environ.get('SESSION_FILE_DIR', '/tmp/sessions')
SESSION_DB_PATH = os.environ.get('SESSION_DB_PATH', '/tmp/sessions.db')
SESSION_MAX_AGE = int(os.environ.get('SESSION_MAX_AGE', 1800))
SESSION_SECRET = os.environ.get('SESSION_SECRET', os.urandom(32).hex())
MAX_SESSIONS_PER_USER = int(os.environ.get('MAX_SESSIONS_PER_USER', 10))
SESSION_ROTATION_INTERVAL = int(os.environ.get('SESSION_ROTATION_INTERVAL', 300))
MAX_CONCURRENT_REQUESTS_PER_SESSION = int(os.environ.get('MAX_CONCURRENT_REQUESTS_PER_SESSION', 10))

session_request_counts = {}
session_request_counts_lock = threading.Lock()
async_session_request_counts = {}
async_session_request_counts_lock = asyncio.Lock()

db_pool = []
db_pool_lock = threading.Lock()
DB_POOL_SIZE = int(os.environ.get('DB_POOL_SIZE', 5))

def _get_db_connection():
    with db_pool_lock:
        if db_pool:
            return db_pool.pop()
    conn = sqlite3.connect(SESSION_DB_PATH, check_same_thread=False)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA synchronous=NORMAL')
    conn.execute('PRAGMA cache_size=10000')
    conn.execute('PRAGMA temp_store=MEMORY')
    return conn

def _release_db_connection(conn):
    with db_pool_lock:
        if len(db_pool) < DB_POOL_SIZE:
            db_pool.append(conn)
            return
    conn.close()

@contextmanager
def _db_connection():
    conn = _get_db_connection()
    try:
        yield conn
    except Exception:
        conn.rollback()
        raise
    finally:
        _release_db_connection(conn)

def _get_session_lock(session_id):
    with session_locks_lock:
        if session_id not in session_locks:
            session_locks[session_id] = threading.RLock()
        return session_locks[session_id]

async def _async_get_session_lock(session_id):
    async with async_session_locks_lock:
        if session_id not in async_session_locks:
            async_session_locks[session_id] = asyncio.Lock()
        return async_session_locks[session_id]

def _release_session_lock(session_id):
    with session_locks_lock:
        if session_id in session_locks:
            del session_locks[session_id]

async def _async_release_session_lock(session_id):
    async with async_session_locks_lock:
        if session_id in async_session_locks:
            del async_session_locks[session_id]

def _increment_session_request_count(session_id):
    with session_request_counts_lock:
        count = session_request_counts.get(session_id, 0)
        if count >= MAX_CONCURRENT_REQUESTS_PER_SESSION:
            return False
        session_request_counts[session_id] = count + 1
        return True

def _decrement_session_request_count(session_id):
    with session_request_counts_lock:
        if session_id in session_request_counts:
            session_request_counts[session_id] = max(0, session_request_counts[session_id] - 1)
            if session_request_counts[session_id] == 0:
                del session_request_counts[session_id]

async def _async_increment_session_request_count(session_id):
    async with async_session_request_counts_lock:
        count = async_session_request_counts.get(session_id, 0)
        if count >= MAX_CONCURRENT_REQUESTS_PER_SESSION:
            return False
        async_session_request_counts[session_id] = count + 1
        return True

async def _async_decrement_session_request_count(session_id):
    async with async_session_request_counts_lock:
        if session_id in async_session_request_counts:
            async_session_request_counts[session_id] = max(0, async_session_request_counts[session_id] - 1)
            if async_session_request_counts[session_id] == 0:
                del async_session_request_counts[session_id]

@contextmanager
def session_request_context(session_id):
    allowed = _increment_session_request_count(session_id)
    if not allowed:
        raise RuntimeError(f"Too many concurrent requests for session {session_id}")
    try:
        yield
    finally:
        _decrement_session_request_count(session_id)

@asynccontextmanager
async def async_session_request_context(session_id):
    allowed = await _async_increment_session_request_count(session_id)
    if not allowed:
        raise RuntimeError(f"Too many concurrent requests for session {session_id}")
    try:
        yield
    finally:
        await _async_decrement_session_request_count(session_id)

def _sign_session_id(session_id):
    signature = hmac.new(
        SESSION_SECRET.encode(),
        session_id.encode(),
        hashlib.sha256
    ).hexdigest()
    return f"{session_id}.{signature}"

def _verify_session_id(signed_session_id):
    if not signed_session_id or '.' not in signed_session_id:
        return None
    parts = signed_session_id.rsplit('.', 1)
    if len(parts) != 2:
        return None
    session_id, signature = parts
    expected_signature = hmac.new(
        SESSION_SECRET.encode(),
        session_id.encode(),
        hashlib.sha256
    ).hexdigest()
    if hmac.compare_digest(signature, expected_signature):
        return session_id
    return None

def _init_file_storage():
    os.makedirs(SESSION_FILE_DIR, exist_ok=True)

async def _async_init_file_storage():
    await aiofiles.os.makedirs(SESSION_FILE_DIR, exist_ok=True)

def _init_db_storage():
    with _db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                created_at REAL NOT NULL,
                last_accessed REAL NOT NULL,
                user_id TEXT,
                rotation_at REAL,
                concurrent_count INTEGER DEFAULT 0
            )
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_sessions_last_accessed ON sessions(last_accessed)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_sessions_rotation ON sessions(rotation_at)
        ''')
        conn.commit()

async def _async_init_db_storage():
    async with aiosqlite.connect(SESSION_DB_PATH) as conn:
        await conn.execute('PRAGMA journal_mode=WAL')
        await conn.execute('PRAGMA synchronous=NORMAL')
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                created_at REAL NOT NULL,
                last_accessed REAL NOT NULL,
                user_id TEXT,
                rotation_at REAL,
                concurrent_count INTEGER DEFAULT 0
            )
        ''')
        await conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)
        ''')
        await conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_sessions_last_accessed ON sessions(last_accessed)
        ''')
        await conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_sessions_rotation ON sessions(rotation_at)
        ''')
        await conn.commit()

def _get_session_file_path(session_id):
    return os.path.join(SESSION_FILE_DIR, f"{session_id}.json")

def _is_session_expired(data):
    if not isinstance(data, dict):
        return True
    last_accessed = data.get('_last_accessed', 0)
    return (time.time() - last_accessed) > SESSION_MAX_AGE

def _needs_rotation(data):
    if not isinstance(data, dict):
        return False
    rotation_at = data.get('_rotation_at', 0)
    return (time.time() - rotation_at) > SESSION_ROTATION_INTERVAL

def _touch_session_data(data):
    if isinstance(data, dict):
        now = time.time()
        data['_last_accessed'] = now
        if '_rotation_at' not in data:
            data['_rotation_at'] = now
    return data

def _update_user_session_index(user_id, session_id, add=True):
    if not user_id:
        return
    with user_session_index_lock:
        if add:
            if user_id not in user_session_index:
                user_session_index[user_id] = set()
            user_session_index[user_id].add(session_id)
        else:
            if user_id in user_session_index:
                user_session_index[user_id].discard(session_id)
                if not user_session_index[user_id]:
                    del user_session_index[user_id]

async def _async_update_user_session_index(user_id, session_id, add=True):
    if not user_id:
        return
    async with async_user_session_index_lock:
        if add:
            if user_id not in async_user_session_index:
                async_user_session_index[user_id] = set()
            async_user_session_index[user_id].add(session_id)
        else:
            if user_id in async_user_session_index:
                async_user_session_index[user_id].discard(session_id)
                if not async_user_session_index[user_id]:
                    del async_user_session_index[user_id]

def _get_user_sessions_from_index(user_id):
    with user_session_index_lock:
        return set(user_session_index.get(user_id, set()))

async def _async_get_user_sessions_from_index(user_id):
    async with async_user_session_index_lock:
        return set(async_user_session_index.get(user_id, set()))

def _count_user_sessions_file(user_id):
    count = 0
    try:
        for fname in os.listdir(SESSION_FILE_DIR):
            if fname.endswith('.json'):
                fpath = os.path.join(SESSION_FILE_DIR, fname)
                try:
                    with open(fpath, 'r') as f:
                        d = json.load(f)
                    if d.get('user') == user_id and not _is_session_expired(d):
                        count += 1
                except Exception:
                    pass
    except Exception:
        pass
    return count

async def _async_count_user_sessions_file(user_id):
    count = 0
    try:
        entries = await aiofiles.os.listdir(SESSION_FILE_DIR)
        tasks = []
        for fname in entries:
            if fname.endswith('.json'):
                fpath = os.path.join(SESSION_FILE_DIR, fname)
                tasks.append(_async_read_session_file_for_count(fpath, user_id))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        count = sum(1 for r in results if r is True)
    except Exception:
        pass
    return count

async def _async_read_session_file_for_count(fpath, user_id):
    try:
        async with aiofiles.open(fpath, 'r') as f:
            content = await f.read()
        d = json.loads(content)
        if d.get('user') == user_id and not _is_session_expired(d):
            return True
    except Exception:
        pass
    return False

def _count_user_sessions_db(conn, user_id):
    cursor = conn.cursor()
    cursor.execute(
        'SELECT COUNT(*) FROM sessions WHERE user_id = ? AND last_accessed > ?',
        (user_id, time.time() - SESSION_MAX_AGE)
    )
    row = cursor.fetchone()
    return row[0] if row else 0

async def _async_count_user_sessions_db(conn, user_id):
    async with conn.execute(
        'SELECT COUNT(*) FROM sessions WHERE user_id = ? AND last_accessed > ?',
        (user_id, time.time() - SESSION_MAX_AGE)
    ) as cursor:
        row = await cursor.fetchone()
    return row[0] if row else 0

def _count_user_sessions_memory(user_id):
    count = 0
    user_sessions = _get_user_sessions_from_index(user_id)
    for sid in user_sessions:
        data = session_store.get(sid)
        if data and data.get('user') == user_id and not _is_session_expired(data):
            count += 1
    return count

async def _async_count_user_sessions_memory(user_id):
    count = 0
    user_sessions = await _async_get_user_sessions_from_index(user_id)
    async with async_session_lock:
        for sid in user_sessions:
            data = session_store.get(sid)
            if data and data.get('user') == user_id and not _is_session_expired(data):
                count += 1
    return count

def _evict_oldest_user_session_memory(user_id):
    user_sessions = _get_user_sessions_from_index(user_id)
    oldest_sid = None
    oldest_time = float('inf')
    with session_lock:
        for sid in user_sessions:
            data = session_store.get(sid)
            if data:
                last_accessed = data.get('