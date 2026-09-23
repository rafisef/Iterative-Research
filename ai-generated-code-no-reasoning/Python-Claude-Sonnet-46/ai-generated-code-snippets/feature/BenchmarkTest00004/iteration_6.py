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

session_store = {}
session_lock = threading.Lock()
async_session_lock = asyncio.Lock()
session_locks = {}
session_locks_lock = threading.Lock()
async_session_locks = {}
async_session_locks_lock = asyncio.Lock()

STORAGE_BACKEND = os.environ.get('SESSION_STORAGE_BACKEND', 'memory')
SESSION_FILE_DIR = os.environ.get('SESSION_FILE_DIR', '/tmp/sessions')
SESSION_DB_PATH = os.environ.get('SESSION_DB_PATH', '/tmp/sessions.db')
SESSION_MAX_AGE = int(os.environ.get('SESSION_MAX_AGE', 1800))
SESSION_SECRET = os.environ.get('SESSION_SECRET', os.urandom(32).hex())
MAX_SESSIONS_PER_USER = int(os.environ.get('MAX_SESSIONS_PER_USER', 10))

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
    conn = sqlite3.connect(SESSION_DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            data TEXT NOT NULL,
            created_at REAL NOT NULL,
            last_accessed REAL NOT NULL,
            user_id TEXT
        )
    ''')
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)
    ''')
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_sessions_last_accessed ON sessions(last_accessed)
    ''')
    conn.commit()
    conn.close()

async def _async_init_db_storage():
    async with aiosqlite.connect(SESSION_DB_PATH) as conn:
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                created_at REAL NOT NULL,
                last_accessed REAL NOT NULL,
                user_id TEXT
            )
        ''')
        await conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)
        ''')
        await conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_sessions_last_accessed ON sessions(last_accessed)
        ''')
        await conn.commit()

def _get_session_file_path(session_id):
    return os.path.join(SESSION_FILE_DIR, f"{session_id}.json")

def _is_session_expired(data):
    if not isinstance(data, dict):
        return True
    last_accessed = data.get('_last_accessed', 0)
    return (time.time() - last_accessed) > SESSION_MAX_AGE

def _touch_session_data(data):
    if isinstance(data, dict):
        data['_last_accessed'] = time.time()
    return data

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
        for fname in entries:
            if fname.endswith('.json'):
                fpath = os.path.join(SESSION_FILE_DIR, fname)
                try:
                    async with aiofiles.open(fpath, 'r') as f:
                        content = await f.read()
                    d = json.loads(content)
                    if d.get('user') == user_id and not _is_session_expired(d):
                        count += 1
                except Exception:
                    pass
    except Exception:
        pass
    return count

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
    for sid, data in session_store.items():
        if data.get('user') == user_id and not _is_session_expired(data):
            count += 1
    return count

async def _async_count_user_sessions_memory(user_id):
    count = 0
    async with async_session_lock:
        for sid, data in session_store.items():
            if data.get('user') == user_id and not _is_session_expired(data):
                count += 1
    return count

def cleanup_expired_sessions():
    if STORAGE_BACKEND == 'file':
        _init_file_storage()
        with session_lock:
            try:
                for fname in os.listdir(SESSION_FILE_DIR):
                    if fname.endswith('.json'):
                        fpath = os.path.join(SESSION_FILE_DIR, fname)
                        try:
                            with open(fpath, 'r') as f:
                                data = json.load(f)
                            if _is_session_expired(data):
                                os.remove(fpath)
                                session_id = fname[:-5]
                                _release_session_lock(session_id)
                        except Exception:
                            pass
            except Exception:
                pass
    elif STORAGE_BACKEND == 'database':
        _init_db_storage()
        with session_lock:
            try:
                conn = sqlite3.connect(SESSION_DB_PATH)
                cursor = conn.cursor()
                cursor.execute(
                    'DELETE FROM sessions WHERE last_accessed < ?',
                    (time.time() - SESSION_MAX_AGE,)
                )
                conn.commit()
                conn.close()
            except Exception:
                pass
    else:
        with session_lock:
            expired = [
                sid for sid, data in session_store.items()
                if _is_session_expired(data)
            ]
            for sid in expired:
                del session_store[sid]
                _release_session_lock(sid)

async def async_cleanup_expired_sessions():
    if STORAGE_BACKEND == 'file':
        await _async_init_file_storage()
        async with async_session_lock:
            try:
                entries = await aiofiles.os.listdir(SESSION_FILE_DIR)
                for fname in entries:
                    if fname.endswith('.json'):
                        fpath = os.path.join(SESSION_FILE_DIR, fname)
                        try:
                            async with aiofiles.open(fpath, 'r') as f:
                                content = await f.read()
                            data = json.loads(content)
                            if _is_session_expired(data):
                                await aiofiles.os.remove(fpath)
                                session_id = fname[:-5]
                                await _async_release_session_lock(session_id)
                        except Exception:
                            pass
            except Exception:
                pass
    elif STORAGE_BACKEND == 'database':
        await _async_init_db_storage()
        async with async_session_lock:
            try:
                async with aiosqlite.connect(SESSION_DB_PATH) as conn:
                    await conn.execute(
                        'DELETE FROM sessions WHERE last_accessed < ?',
                        (time.time() - SESSION_MAX_AGE,)
                    )
                    await conn.commit()
            except Exception:
                pass
    else:
        async with async_session_lock:
            expired = [
                sid for sid, data in session_store.items()
                if _is_session_expired(data)
            ]
            for sid in expired:
                del session_store[sid]
                await _async_release_session_lock(sid)

def create_session(session_id, data):
    now = time.time()
    data = _touch_session_data(dict(data))
    data['_created_at'] = now
    user_id = data.get('user')

    if STORAGE_BACKEND == 'file':
        _init_file_storage()
        file_path = _get_session_file_path(session_id)
        lock = _get_session_lock(session_id)
        with lock:
            with session_lock:
                if user_id and _count_user_sessions_file(user_id) >= MAX_SESSIONS_PER_USER:
                    cleanup_expired_sessions()
            with open(file_path, 'w') as f:
                json.dump(data, f)
    elif STORAGE_BACKEND == 'database':
        _init_db_storage()
        lock = _get_session_lock(session_id)
        with lock:
            with session_lock:
                conn = sqlite3.connect(SESSION_DB_PATH)
                if user_id and _count_user_sessions_db(conn, user_id) >= MAX_SESSIONS_PER_USER:
                    conn.close()
                    cleanup_expired_sessions()
                    conn = sqlite3.connect(SESSION_DB_PATH)
                cursor = conn.cursor()
                cursor.execute(
                    'INSERT OR REPLACE INTO sessions (session_id, data, created_at, last_accessed, user_id) VALUES (?, ?, ?, ?, ?)',
                    (session_id, json.dumps(data), now, now, user_id)
                )
                conn.commit()
                conn.close()
    else:
        lock = _get_session_lock(session_id)
        with lock:
            with session_lock:
                if user_id and _count_user_sessions_memory(user_id) >= MAX_SESSIONS_PER_USER:
                    cleanup_expired_sessions()
                session_store[session_id] = data

async def async_create_session(session_id, data):
    now = time.time()
    data = _touch_session_data(dict(data))
    data['_created_at'] = now
    user_id = data.get('user')

    if STORAGE_BACKEND == 'file':
        await _async_init_file_storage()
        file_path = _get_session_file_path(session_id)
        lock = await _async_get_session_lock(session_id)
        async with lock:
            async with async_session_lock:
                count = await _async_count_user_sessions_file(user_id)
                if user_id and count >= MAX_SESSIONS_PER_USER:
                    await async_cleanup_expired_sessions()
            async with aiofiles.open(file_path, 'w') as f:
                await f.write(json.dumps(data))
    elif STORAGE_BACKEND == 'database':
        await _async_init_db_storage()
        lock = await _async_get_session_lock(session_id)
        async with lock:
            async with async_session_lock:
                async with aiosqlite.connect(SESSION_DB_PATH) as conn:
                    count = await _async_count_user_sessions_db(conn, user_id)
                    if user_id and count >= MAX_SESSIONS_PER_USER:
                        await async_cleanup_expired_sessions()
                    await conn.execute(
                        'INSERT OR REPLACE INTO sessions (session_id, data, created_at, last_accessed, user_id) VALUES (?, ?, ?, ?, ?)',
                        (session_id, json.dumps(data), now, now, user_id)
                    )
                    await conn.commit()
    else:
        lock = await _async_get_session_lock(session_id)
        async with lock:
            async with async_session_lock:
                count = await _async_count_user_sessions_memory(user_id)
                if user_id and count >= MAX_SESSIONS_PER_USER:
                    await async_cleanup_expired_sessions()
                session_store[session_id] = data

def get_session(session_id):
    if STORAGE_BACKEND == 'file':
        _init_file_storage()
        file_path = _get_session_file_path(session_id)
        lock = _get_session_lock(session_id)
        with lock:
            if not os.path.exists(file_path):
                return {}
            try:
                with open(file_path, 'r') as f:
                    data