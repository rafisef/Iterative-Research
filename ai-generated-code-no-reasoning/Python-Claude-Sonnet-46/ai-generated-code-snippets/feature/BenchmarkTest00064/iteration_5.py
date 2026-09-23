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

def _load_config_from_env():
    env_map = {
        'SESSION_STORAGE_BACKEND': 'STORAGE_BACKEND',
        'SESSION_FILE_STORAGE_PATH': 'FILE_STORAGE_PATH',
        'SESSION_DB_STORAGE_PATH': 'DB_STORAGE_PATH',
        'SESSION_MAX_AGE': 'SESSION_MAX_AGE',
        'SESSION_ID_LENGTH': 'SESSION_ID_LENGTH',
        'SESSION_DB_POOL_TIMEOUT': 'DB_POOL_TIMEOUT',
        'SESSION_FILE_ENCODING': 'FILE_ENCODING',
        'SESSION_CLEANUP_INTERVAL': 'CLEANUP_INTERVAL',
        'SESSION_MAX_SESSIONS': 'MAX_SESSIONS',
        'SESSION_COOKIE_NAME': 'SESSION_COOKIE_NAME',
        'SESSION_COOKIE_SECURE': 'SESSION_COOKIE_SECURE',
        'SESSION_COOKIE_HTTPONLY': 'SESSION_COOKIE_HTTPONLY',
        'SESSION_COOKIE_SAMESITE': 'SESSION_COOKIE_SAMESITE',
        'SESSION_ENABLE_ASYNC': 'ENABLE_ASYNC',
        'SESSION_LOG_LEVEL': 'LOG_LEVEL',
    }
    bool_keys = {'SESSION_COOKIE_SECURE', 'SESSION_COOKIE_HTTPONLY', 'SESSION_ENABLE_ASYNC'}
    int_keys = {'SESSION_MAX_AGE', 'SESSION_ID_LENGTH', 'SESSION_DB_POOL_TIMEOUT',
                'SESSION_CLEANUP_INTERVAL', 'SESSION_MAX_SESSIONS'}

    for env_key, config_key in env_map.items():
        if env_key in bool_keys:
            _config[config_key] = _get_env_bool(env_key, _config[config_key])
        elif env_key in int_keys:
            _config[config_key] = _get_env_int(env_key, _config[config_key])
        else:
            val = os.environ.get(env_key)
            if val is not None:
                _config[config_key] = val

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
):
    if storage_backend is not None:
        _config['STORAGE_BACKEND'] = storage_backend
    if file_storage_path is not None:
        _config['FILE_STORAGE_PATH'] = file_storage_path
    if db_storage_path is not None:
        _config['DB_STORAGE_PATH'] = db_storage_path
    if session_max_age is not None:
        _config['SESSION_MAX_AGE'] = session_max_age
    if session_id_length is not None:
        _config['SESSION_ID_LENGTH'] = session_id_length
    if db_pool_timeout is not None:
        _config['DB_POOL_TIMEOUT'] = db_pool_timeout
    if file_encoding is not None:
        _config['FILE_ENCODING'] = file_encoding
    if cleanup_interval is not None:
        _config['CLEANUP_INTERVAL'] = cleanup_interval
    if max_sessions is not None:
        _config['MAX_SESSIONS'] = max_sessions
    if session_cookie_name is not None:
        _config['SESSION_COOKIE_NAME'] = session_cookie_name
    if session_cookie_secure is not None:
        _config['SESSION_COOKIE_SECURE'] = session_cookie_secure
    if session_cookie_httponly is not None:
        _config['SESSION_COOKIE_HTTPONLY'] = session_cookie_httponly
    if session_cookie_samesite is not None:
        _config['SESSION_COOKIE_SAMESITE'] = session_cookie_samesite
    if enable_async is not None:
        _config['ENABLE_ASYNC'] = enable_async
    if log_level is not None:
        _config['LOG_LEVEL'] = log_level

def get_config(key=None):
    if key is not None:
        return _config.get(key)
    return dict(_config)

def _get_storage_backend():
    return _config['STORAGE_BACKEND']

def _get_file_storage_path():
    return _config['FILE_STORAGE_PATH']

def _get_db_storage_path():
    return _config['DB_STORAGE_PATH']

def _get_session_max_age():
    return _config['SESSION_MAX_AGE']

def _get_file_encoding():
    return _config['FILE_ENCODING']

def _get_db_pool_timeout():
    return _config['DB_POOL_TIMEOUT']

STORAGE_BACKEND = property(_get_storage_backend)
FILE_STORAGE_PATH = property(_get_file_storage_path)
DB_STORAGE_PATH = property(_get_db_storage_path)

_db_lock = threading.Lock()
_async_db_lock = asyncio.Lock()


def _init_file_storage():
    os.makedirs(_get_file_storage_path(), exist_ok=True)


async def _async_init_file_storage():
    await asyncio.to_thread(os.makedirs, _get_file_storage_path(), exist_ok=True)


def _init_db_storage():
    with _db_lock:
        conn = sqlite3.connect(_get_db_storage_path(), timeout=_get_db_pool_timeout())
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at REAL NOT NULL,
                data TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()


async def _async_init_db_storage():
    async with _async_db_lock:
        async with aiosqlite.connect(_get_db_storage_path()) as conn:
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    data TEXT NOT NULL
                )
            ''')
            await conn.commit()


def _file_path(session_id):
    return os.path.join(_get_file_storage_path(), f"{session_id}.json")


def create_session(user_id):
    session_id = str(uuid.uuid4())
    session_data = {
        'user_id': user_id,
        'created_at': time.time(),
        'data': {}
    }

    backend = _get_storage_backend()

    if backend == 'file':
        _init_file_storage()
        with open(_file_path(session_id), 'w', encoding=_get_file_encoding()) as f:
            json.dump(session_data, f)
    elif backend == 'database':
        _init_db_storage()
        with _db_lock:
            conn = sqlite3.connect(_get_db_storage_path(), timeout=_get_db_pool_timeout())
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO sessions (session_id, user_id, created_at, data) VALUES (?, ?, ?, ?)',
                (session_id, user_id, session_data['created_at'], json.dumps(session_data['data']))
            )
            conn.commit()
            conn.close()
    else:
        with session_store_lock:
            if len(session_store) >= _config['MAX_SESSIONS']:
                oldest = min(session_store.items(), key=lambda x: x[1]['created_at'], default=None)
                if oldest:
                    del session_store[oldest[0]]
            session_store[session_id] = session_data

    return session_id


async def async_create_session(user_id):
    session_id = str(uuid.uuid4())
    session_data = {
        'user_id': user_id,
        'created_at': time.time(),
        'data': {}
    }

    backend = _get_storage_backend()

    if backend == 'file':
        await _async_init_file_storage()
        async with aiofiles.open(_file_path(session_id), 'w', encoding=_get_file_encoding()) as f:
            await f.write(json.dumps(session_data))
    elif backend == 'database':
        await _async_init_db_storage()
        async with _async_db_lock:
            async with aiosqlite.connect(_get_db_storage_path()) as conn:
                await conn.execute(
                    'INSERT INTO sessions (session_id, user_id, created_at, data) VALUES (?, ?, ?, ?)',
                    (session_id, user_id, session_data['created_at'], json.dumps(session_data['data']))
                )
                await conn.commit()
    else:
        async with async_session_store_lock:
            if len(session_store) >= _config['MAX_SESSIONS']:
                oldest = min(session_store.items(), key=lambda x: x[1]['created_at'], default=None)
                if oldest:
                    del session_store[oldest[0]]
            session_store[session_id] = session_data

    return session_id


def get_session(session_id):
    backend = _get_storage_backend()

    if backend == 'file':
        _init_file_storage()
        path = _file_path(session_id)
        if os.path.exists(path):
            with open(path, 'r', encoding=_get_file_encoding()) as f:
                return json.load(f)
        return None
    elif backend == 'database':
        _init_db_storage()
        with _db_lock:
            conn = sqlite3.connect(_get_db_storage_path(), timeout=_get_db_pool_timeout())
            cursor = conn.cursor()
            cursor.execute(
                'SELECT session_id, user_id, created_at, data FROM sessions WHERE session_id = ?',
                (session_id,)
            )
            row = cursor.fetchone()
            conn.close()
        if row:
            return {
                'user_id': row[1],
                'created_at': row[2],
                'data': json.loads(row[3])
            }
        return None
    else:
        with session_store_lock:
            return session_store.get(session_id)


async def async_get_session(session_id):
    backend = _get_storage_backend()

    if backend == 'file':
        await _async_init_file_storage()
        path = _file_path(session_id)
        if await asyncio.to_thread(os.path.exists, path):
            async with aiofiles.open(path, 'r', encoding=_get_file_encoding()) as f:
                content = await f.read()
                return json.loads(content)
        return None
    elif backend == 'database':
        await _async_init_db_storage()
        async with _async_db_lock:
            async with aiosqlite.connect(_get_db_storage_path()) as conn:
                async with conn.execute(
                    'SELECT session_id, user_id, created_at, data FROM sessions WHERE session_id = ?',
                    (session_id,)
                ) as cursor:
                    row = await cursor.fetchone()
        if row:
            return {
                'user_id': row[1],
                'created_at': row[2],
                'data': json.loads(row[3])
            }
        return None
    else:
        async with async_session_store_lock:
            return session_store.get(session_id)


def update_session(session_id, key, value):
    backend = _get_storage_backend()

    if backend == 'file':
        _init_file_storage()
        path = _file_path(session_id)
        if os.path.exists(path):
            with open(path, 'r', encoding=_get_file_encoding()) as f:
                session_data = json.load(f)
            session_data['data'][key] = value
            with open(path, 'w', encoding=_get_file_encoding()) as f:
                json.dump(session_data, f)
            return True
        return False
    elif backend == 'database':
        _init_db_storage()
        with _db_lock:
            conn = sqlite3.connect(_get_db_storage_path(), timeout=_get_db_pool_timeout())
            cursor = conn.cursor()
            cursor.execute(
                'SELECT data FROM sessions WHERE session_id = ?',
                (session_id,)
            )
            row = cursor.fetchone()
            if row:
                data = json.loads(row[0])
                data[key] = value
                cursor.execute(
                    'UPDATE sessions SET data = ? WHERE session_id = ?',
                    (json.dumps(data), session_id)
                )
                conn.commit()
                conn.close()
                return True
            conn.close()
        return False
    else:
        with session_store_lock:
            if session_id in session_store:
                session_store[session_id]['data'][key] = value
                return True
            return False


async def