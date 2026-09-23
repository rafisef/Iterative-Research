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

import os
import json
import sqlite3
import threading
import uuid
import time
from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html


_file_lock = threading.Lock()
_db_lock = threading.Lock()
_session_store_lock = threading.RLock()
_in_memory_sessions = {}


def _get_config():
    return {
        'COOKIE_MAX_AGE': int(os.environ.get('BENCHMARK_COOKIE_MAX_AGE', 60 * 3)),
        'COOKIE_SECURE': os.environ.get('BENCHMARK_COOKIE_SECURE', 'true').lower() == 'true',
        'COOKIE_DOMAIN': os.environ.get('BENCHMARK_COOKIE_DOMAIN', 'localhost'),
        'BENCHMARK_PREFIX': os.environ.get('BENCHMARK_PREFIX', '90583'),
        'BENCHMARK_SUFFIX': os.environ.get('BENCHMARK_SUFFIX', 'abcd'),
        'USER_PREFIX': os.environ.get('BENCHMARK_USER_PREFIX', 'Nancy'),
        'STORAGE_TYPE': os.environ.get('BENCHMARK_STORAGE_TYPE', 'file'),
        'STORAGE_FILE_PATH': os.environ.get('BENCHMARK_STORAGE_FILE_PATH', 'benchmark_sessions.json'),
        'STORAGE_DB_PATH': os.environ.get('BENCHMARK_STORAGE_DB_PATH', 'benchmark_sessions.db'),
        'AUTH_PROVIDERS': os.environ.get('BENCHMARK_AUTH_PROVIDERS', 'local').split(','),
        'OAUTH_CLIENT_ID': os.environ.get('BENCHMARK_OAUTH_CLIENT_ID', ''),
        'OAUTH_CLIENT_SECRET': os.environ.get('BENCHMARK_OAUTH_CLIENT_SECRET', ''),
        'OAUTH_AUTH_URL': os.environ.get('BENCHMARK_OAUTH_AUTH_URL', ''),
        'OAUTH_TOKEN_URL': os.environ.get('BENCHMARK_OAUTH_TOKEN_URL', ''),
        'OAUTH_USERINFO_URL': os.environ.get('BENCHMARK_OAUTH_USERINFO_URL', ''),
        'LDAP_SERVER': os.environ.get('BENCHMARK_LDAP_SERVER', ''),
        'LDAP_PORT': int(os.environ.get('BENCHMARK_LDAP_PORT', 389)),
        'LDAP_BASE_DN': os.environ.get('BENCHMARK_LDAP_BASE_DN', ''),
        'SAML_IDP_METADATA_URL': os.environ.get('BENCHMARK_SAML_IDP_METADATA_URL', ''),
        'SAML_SP_ENTITY_ID': os.environ.get('BENCHMARK_SAML_SP_ENTITY_ID', ''),
        'SESSION_EXPIRY_SECONDS': int(os.environ.get('BENCHMARK_SESSION_EXPIRY_SECONDS', 60 * 30)),
        'MAX_SESSIONS_PER_USER': int(os.environ.get('BENCHMARK_MAX_SESSIONS_PER_USER', 10)),
    }


_config_overrides = {}


def configure(**kwargs):
    _config_overrides.update(kwargs)


def get_config_value(key):
    if key in _config_overrides:
        return _config_overrides[key]
    return _get_config().get(key)


COOKIE_MAX_AGE = int(os.environ.get('BENCHMARK_COOKIE_MAX_AGE', 60 * 3))
COOKIE_SECURE = os.environ.get('BENCHMARK_COOKIE_SECURE', 'true').lower() == 'true'
COOKIE_DOMAIN = os.environ.get('BENCHMARK_COOKIE_DOMAIN', 'localhost')
BENCHMARK_PREFIX = os.environ.get('BENCHMARK_PREFIX', '90583')
BENCHMARK_SUFFIX = os.environ.get('BENCHMARK_SUFFIX', 'abcd')
USER_PREFIX = os.environ.get('BENCHMARK_USER_PREFIX', 'Nancy')
STORAGE_TYPE = os.environ.get('BENCHMARK_STORAGE_TYPE', 'file')
STORAGE_FILE_PATH = os.environ.get('BENCHMARK_STORAGE_FILE_PATH', 'benchmark_sessions.json')
STORAGE_DB_PATH = os.environ.get('BENCHMARK_STORAGE_DB_PATH', 'benchmark_sessions.db')
AUTH_PROVIDERS = os.environ.get('BENCHMARK_AUTH_PROVIDERS', 'local').split(',')
OAUTH_CLIENT_ID = os.environ.get('BENCHMARK_OAUTH_CLIENT_ID', '')
OAUTH_CLIENT_SECRET = os.environ.get('BENCHMARK_OAUTH_CLIENT_SECRET', '')
OAUTH_AUTH_URL = os.environ.get('BENCHMARK_OAUTH_AUTH_URL', '')
OAUTH_TOKEN_URL = os.environ.get('BENCHMARK_OAUTH_TOKEN_URL', '')
OAUTH_USERINFO_URL = os.environ.get('BENCHMARK_OAUTH_USERINFO_URL', '')
LDAP_SERVER = os.environ.get('BENCHMARK_LDAP_SERVER', '')
LDAP_PORT = int(os.environ.get('BENCHMARK_LDAP_PORT', 389))
LDAP_BASE_DN = os.environ.get('BENCHMARK_LDAP_BASE_DN', '')
SAML_IDP_METADATA_URL = os.environ.get('BENCHMARK_SAML_IDP_METADATA_URL', '')
SAML_SP_ENTITY_ID = os.environ.get('BENCHMARK_SAML_SP_ENTITY_ID', '')


def generate_session_id():
    return str(uuid.uuid4())


def get_current_timestamp():
    return int(time.time())


def is_session_expired(session_data):
    expiry = get_config_value('SESSION_EXPIRY_SECONDS')
    created_at = session_data.get('created_at', 0)
    last_accessed = session_data.get('last_accessed', created_at)
    return (get_current_timestamp() - last_accessed) > expiry


def init_file_storage():
    path = get_config_value('STORAGE_FILE_PATH')
    with _file_lock:
        if not os.path.exists(path):
            with open(path, 'w') as f:
                json.dump({}, f)


def init_db_storage():
    path = get_config_value('STORAGE_DB_PATH')
    with _db_lock:
        conn = sqlite3.connect(path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                cookie_name TEXT PRIMARY KEY,
                cookie_value TEXT NOT NULL,
                user_id TEXT,
                session_id TEXT,
                created_at INTEGER,
                last_accessed INTEGER
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS auth_providers (
                provider_name TEXT PRIMARY KEY,
                provider_config TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_auth_mappings (
                user_id TEXT NOT NULL,
                provider_name TEXT NOT NULL,
                provider_user_id TEXT NOT NULL,
                PRIMARY KEY (user_id, provider_name)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                provider_name TEXT,
                created_at INTEGER NOT NULL,
                last_accessed INTEGER NOT NULL,
                session_data TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_sessions_active ON user_sessions(is_active)')
        conn.commit()
        conn.close()


def read_from_file(cookie_name):
    path = get_config_value('STORAGE_FILE_PATH')
    with _file_lock:
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            return data.get(cookie_name)
        except (FileNotFoundError, json.JSONDecodeError):
            return None


def write_to_file(cookie_name, cookie_value):
    path = get_config_value('STORAGE_FILE_PATH')
    with _file_lock:
        try:
            with open(path, 'r') as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            data = {}
        data[cookie_name] = cookie_value
        with open(path, 'w') as f:
            json.dump(data, f)


def delete_from_file(cookie_name):
    path = get_config_value('STORAGE_FILE_PATH')
    with _file_lock:
        try:
            with open(path, 'r') as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return
        data.pop(cookie_name, None)
        with open(path, 'w') as f:
            json.dump(data, f)


def read_from_db(cookie_name):
    path = get_config_value('STORAGE_DB_PATH')
    with _db_lock:
        conn = sqlite3.connect(path)
        cursor = conn.cursor()
        cursor.execute('SELECT cookie_value FROM sessions WHERE cookie_name = ?', (cookie_name,))
        row = cursor.fetchone()
        conn.close()
    if row:
        return row[0]
    return None


def write_to_db(cookie_name, cookie_value):
    path = get_config_value('STORAGE_DB_PATH')
    with _db_lock:
        conn = sqlite3.connect(path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO sessions (cookie_name, cookie_value)
            VALUES (?, ?)
            ON CONFLICT(cookie_name) DO UPDATE SET cookie_value = excluded.cookie_value
        ''', (cookie_name, cookie_value))
        conn.commit()
        conn.close()


def delete_from_db(cookie_name):
    path = get_config_value('STORAGE_DB_PATH')
    with _db_lock:
        conn = sqlite3.connect(path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM sessions WHERE cookie_name = ?', (cookie_name,))
        conn.commit()
        conn.close()


def storage_read(cookie_name):
    if get_config_value('STORAGE_TYPE') == 'database':
        return read_from_db(cookie_name)
    return read_from_file(cookie_name)


def storage_write(cookie_name, cookie_value):
    if get_config_value('STORAGE_TYPE') == 'database':
        write_to_db(cookie_name, cookie_value)
    else:
        write_to_file(cookie_name, cookie_value)


def storage_delete(cookie_name):
    if get_config_value('STORAGE_TYPE') == 'database':
        delete_from_db(cookie_name)
    else:
        delete_from_file(cookie_name)


def create_user_session(user_id, provider_name, extra_data=None):
    session_id = generate_session_id()
    now = get_current_timestamp()
    session_data = {
        'session_id': session_id,
        'user_id': user_id,
        'provider_name': provider_name,
        'created_at': now,
        'last_accessed': now,
        'is_active': True,
    }
    if extra_data:
        session_data.update(extra_data)

    max_sessions = get_config_value('MAX_SESSIONS_PER_USER')
    _enforce_max_sessions(user_id, max_sessions)

    if get_config_value('STORAGE_TYPE') == 'database':
        _write_user_session_to_db(session_id, user_id, provider_name, now, session_data)
    else:
        with _session_store_lock:
            if user_id not in _in_memory_sessions:
                _in_memory_sessions[user_id] = {}
            _in_memory_sessions[user_id][session_id] = session_data

    return session_id


def _write_user_session_to_db(session_id, user_id, provider_name, now, session_data):
    path = get_config_value('STORAGE_DB_PATH')
    with _db_lock:
        conn = sqlite3.connect(path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO user_sessions (session_id, user_id, provider_name, created_at, last_accessed, session_data, is_active)
            VALUES (?, ?, ?, ?, ?, ?, 1)
        ''', (session_id, user_id, provider_name, now, now, json.dumps(session_data)))
        conn.commit()
        conn.close()


def _enforce_max_sessions(user_id, max_sessions):
    if get_config_value('STORAGE_TYPE') == 'database':
        _enforce_max_sessions_db(user_id, max_sessions)
    else:
        _enforce_max_sessions_memory(user_id, max_sessions)


def _enforce_max_sessions_db(user_id, max_sessions):
    path = get_config_value('STORAGE_DB_PATH')
    with _db_lock:
        conn = sqlite3.connect(path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT session_id FROM user_sessions
            WHERE user_id = ? AND is_active = 1
            ORDER BY last_accessed ASC
        ''', (user_id,))
        rows = cursor.fetchall()
        if len(rows) >= max_sessions:
            sessions_to_remove = rows[:len(rows) - max_sessions + 1]
            for row in sessions_to_remove:
                cursor.execute('UPDATE user_sessions SET is_active = 0 WHERE session_id = ?', (row[0],))
        conn.commit()
        conn.close()


def _enforce_max_sessions_memory(user_id, max_sessions):
    with _session_store_lock:
        user_sessions = _in_memory_sessions.get(user_id, {})
        active_sessions = {
            sid: sdata for sid, sdata in user_sessions.items()
            if sdata.get('is_active', True) and not is_session_expired(sdata)
        }
        if len(active_sessions) >= max_sessions:
            sorted_sessions = sorted(active_sessions.items(), key=lambda x: x[1].get('last_accessed', 0))
            sessions_to_remove = sorted_sessions[:len(active_sessions) - max_sessions + 1]
            for sid, _ in sessions_to_remove:
                if sid in _in_memory_sessions.get(user_id, {}):
                    _in_memory_sessions[user_id][sid]['is_active'] = False


def get_user_session(session_id):
    if get_config_value('STORAGE_TYPE') == 'database':
        return _get_user_session_from_db(session_id)
    return _get_user_session_from_memory(session_id)


def _get_user_session_from_db(session_id):