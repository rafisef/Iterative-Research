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
import configparser
import xml.dom.minidom
import xml.sax.handler
import os
import time
import hashlib
import hmac
import collections
import json
import sqlite3
import abc

session_store = {}
session_store_lock = threading.RLock()
session_activity = {}
session_user_map = {}
active_sessions_per_user = collections.defaultdict(set)

DEFAULT_CONFIG = {
    'KEY_A': 'a-Value',
    'SECTION_NAME': 'section60568',
    'COOKIE_HTTPONLY': 'true',
    'COOKIE_SAMESITE': 'Strict',
    'ENABLE_EXTERNAL_ENTITIES': 'true',
    'SESSION_MAX_HISTORY': '100',
    'XML_PARSE_TIMEOUT': '30',
    'COOKIE_SECURE': 'false',
    'COOKIE_PATH': '/',
    'COOKIE_DOMAIN': '',
    'LOG_LEVEL': 'INFO',
    'MAX_PARAM_LENGTH': '1024',
    'ALLOWED_METHODS': 'GET,POST',
    'RESPONSE_ENCODING': 'utf-8',
    'ENABLE_SESSION_TRACKING': 'true',
    'SESSION_TIMEOUT': '3600',
    'MAX_CONCURRENT_SESSIONS_PER_USER': '10',
    'SESSION_CLEANUP_INTERVAL': '300',
    'SESSION_TOKEN_SECRET': 'default-secret-change-me',
    'MAX_TOTAL_SESSIONS': '10000',
    'STORAGE_BACKEND': 'memory',
    'FILE_STORAGE_PATH': 'sessions',
    'DB_STORAGE_PATH': 'sessions.db',
}

_file_config = {}
_file_config_lock = threading.Lock()
_file_config_loaded = False
_cleanup_timer = None
_cleanup_timer_lock = threading.Lock()

_storage_backend = None
_storage_backend_lock = threading.Lock()


class StorageBackend(abc.ABC):

    @abc.abstractmethod
    def save_session(self, session_id, session_data, last_active, user_id):
        pass

    @abc.abstractmethod
    def load_session(self, session_id):
        pass

    @abc.abstractmethod
    def delete_session(self, session_id):
        pass

    @abc.abstractmethod
    def list_sessions(self):
        pass

    @abc.abstractmethod
    def update_activity(self, session_id, last_active):
        pass

    @abc.abstractmethod
    def close(self):
        pass


class FileStorageBackend(StorageBackend):

    def __init__(self, storage_path):
        self._path = storage_path
        self._lock = threading.RLock()
        os.makedirs(self._path, exist_ok=True)

    def _session_file(self, session_id):
        safe_id = session_id.replace('/', '_').replace('\\', '_')
        return os.path.join(self._path, f'{safe_id}.json')

    def save_session(self, session_id, session_data, last_active, user_id):
        with self._lock:
            file_path = self._session_file(session_id)
            serializable_data = {
                k: v for k, v in session_data.items()
                if not isinstance(v, threading.Lock)
            }
            payload = {
                'session_id': session_id,
                'session_data': serializable_data,
                'last_active': last_active,
                'user_id': user_id,
            }
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(payload, f)
            except (OSError, IOError):
                pass

    def load_session(self, session_id):
        with self._lock:
            file_path = self._session_file(session_id)
            if not os.path.isfile(file_path):
                return None
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    payload = json.load(f)
                session_data = payload.get('session_data', {})
                session_data['concurrent_lock'] = threading.Lock()
                return {
                    'session_data': session_data,
                    'last_active': payload.get('last_active', 0),
                    'user_id': payload.get('user_id'),
                }
            except (OSError, IOError, json.JSONDecodeError):
                return None

    def delete_session(self, session_id):
        with self._lock:
            file_path = self._session_file(session_id)
            try:
                if os.path.isfile(file_path):
                    os.remove(file_path)
            except (OSError, IOError):
                pass

    def list_sessions(self):
        with self._lock:
            sessions = []
            try:
                for fname in os.listdir(self._path):
                    if fname.endswith('.json'):
                        session_id = fname[:-5]
                        data = self.load_session(session_id)
                        if data is not None:
                            sessions.append((session_id, data))
            except (OSError, IOError):
                pass
            return sessions

    def update_activity(self, session_id, last_active):
        with self._lock:
            file_path = self._session_file(session_id)
            if not os.path.isfile(file_path):
                return
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    payload = json.load(f)
                payload['last_active'] = last_active
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(payload, f)
            except (OSError, IOError, json.JSONDecodeError):
                pass

    def close(self):
        pass


class DatabaseStorageBackend(StorageBackend):

    def __init__(self, db_path):
        self._db_path = db_path
        self._local = threading.local()
        self._init_lock = threading.Lock()
        self._initialize_db()

    def _get_connection(self):
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _initialize_db(self):
        with self._init_lock:
            conn = sqlite3.connect(self._db_path, check_same_thread=False)
            try:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS sessions (
                        session_id TEXT PRIMARY KEY,
                        session_data TEXT NOT NULL,
                        last_active REAL NOT NULL,
                        user_id TEXT NOT NULL
                    )
                ''')
                conn.commit()
            finally:
                conn.close()

    def save_session(self, session_id, session_data, last_active, user_id):
        conn = self._get_connection()
        serializable_data = {
            k: v for k, v in session_data.items()
            if not isinstance(v, threading.Lock)
        }
        try:
            data_json = json.dumps(serializable_data)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO sessions (session_id, session_data, last_active, user_id)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    session_data = excluded.session_data,
                    last_active = excluded.last_active,
                    user_id = excluded.user_id
            ''', (session_id, data_json, last_active, user_id))
            conn.commit()
        except (sqlite3.Error, json.JSONDecodeError):
            pass

    def load_session(self, session_id):
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT session_data, last_active, user_id FROM sessions WHERE session_id = ?',
                (session_id,)
            )
            row = cursor.fetchone()
            if row is None:
                return None
            session_data = json.loads(row['session_data'])
            session_data['concurrent_lock'] = threading.Lock()
            return {
                'session_data': session_data,
                'last_active': row['last_active'],
                'user_id': row['user_id'],
            }
        except (sqlite3.Error, json.JSONDecodeError):
            return None

    def delete_session(self, session_id):
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
            conn.commit()
        except sqlite3.Error:
            pass

    def list_sessions(self):
        conn = self._get_connection()
        sessions = []
        try:
            cursor = conn.cursor()
            cursor.execute('SELECT session_id, session_data, last_active, user_id FROM sessions')
            rows = cursor.fetchall()
            for row in rows:
                try:
                    session_data = json.loads(row['session_data'])
                    session_data['concurrent_lock'] = threading.Lock()
                    sessions.append((row['session_id'], {
                        'session_data': session_data,
                        'last_active': row['last_active'],
                        'user_id': row['user_id'],
                    }))
                except json.JSONDecodeError:
                    continue
        except sqlite3.Error:
            pass
        return sessions

    def update_activity(self, session_id, last_active):
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE sessions SET last_active = ? WHERE session_id = ?',
                (last_active, session_id)
            )
            conn.commit()
        except sqlite3.Error:
            pass

    def close(self):
        if hasattr(self._local, 'conn') and self._local.conn is not None:
            try:
                self._local.conn.close()
            except sqlite3.Error:
                pass
            self._local.conn = None


def get_storage_backend():
    global _storage_backend
    with _storage_backend_lock:
        if _storage_backend is not None:
            return _storage_backend
        backend_type = get_config('STORAGE_BACKEND').lower()
        if backend_type == 'file':
            storage_path = get_config('FILE_STORAGE_PATH')
            _storage_backend = FileStorageBackend(storage_path)
        elif backend_type == 'database':
            db_path = get_config('DB_STORAGE_PATH')
            _storage_backend = DatabaseStorageBackend(db_path)
        else:
            _storage_backend = None
        return _storage_backend


def load_file_config(config_path=None):
    global _file_config, _file_config_loaded
    with _file_config_lock:
        if config_path is None:
            config_path = os.environ.get('BENCHMARK_CONFIG_FILE', 'benchmark.cfg')
        if os.path.isfile(config_path):
            parser = configparser.ConfigParser()
            parser.read(config_path)
            for section in parser.sections():
                for key, value in parser.items(section):
                    _file_config[key.upper()] = value
        _file_config_loaded = True


def get_config(key):
    global _file_config_loaded
    if not _file_config_loaded:
        load_file_config()
    env_key = f'BENCHMARK_{key}'
    env_value = os.environ.get(env_key)
    if env_value is not None:
        return env_value
    file_value = _file_config.get(key)
    if file_value is not None:
        return file_value
    return DEFAULT_CONFIG.get(key)


def get_config_bool(key):
    return get_config(key).lower() == 'true'


def get_config_int(key):
    try:
        return int(get_config(key))
    except (TypeError, ValueError):
        try:
            return int(DEFAULT_CONFIG.get(key, '0'))
        except (TypeError, ValueError):
            return 0


def generate_session_token(session_id):
    secret = get_config('SESSION_TOKEN_SECRET').encode('utf-8')
    token = hmac.new(secret, session_id.encode('utf-8'), hashlib.sha256).hexdigest()
    return token


def validate_session_token(session_id, token):
    expected = generate_session_token(session_id)
    return hmac.compare_digest(expected, token)


def _schedule_cleanup():
    global _cleanup_timer
    with _cleanup_timer_lock:
        if _cleanup_timer is not None:
            _cleanup_timer.cancel()
        interval = get_config_int('SESSION_CLEANUP_INTERVAL')
        if interval <= 0:
            interval = 300
        _cleanup_timer = threading.Timer(interval, _run_cleanup)
        _cleanup_timer.daemon = True
        _cleanup_timer.start()


def _run_cleanup():
    cleanup_expired_sessions()
    _schedule_cleanup()


def _persist_session(session_id, session_data, last_active, user_id):
    backend = get_storage_backend()
    if backend is not None:
        backend.save_session(session_id, session_data, last_active, user_id)


def _delete_persisted_session(session_id):
    backend = get_storage_backend()
    if backend is not None:
        backend.delete_session(session_id)


def _update_persisted_activity(session_id, last_active):
    backend = get_storage_backend()
    if backend is not None:
        backend.update_activity(session_id, last_active)


def _load_persisted_session(session_id):
    backend = get_storage_backend()
    if backend is None:
        return None
    return backend.load_session(session_id)


def _restore_session_from_backend(session_id):
    data = _load_persisted_session(session_id)
    if data is None:
        return False
    session_data = data['session_data']
    last_active = data['last_active']
    user_id = data['user_id']
    session_store[session_id] = session_data
    session_activity[session_id] = last_active
    session_user_map[session_id] = user_id
    active_sessions_per_user[user_id].add(session_id)
    return True


def cleanup_expired_sessions():
    timeout = get_config_int('SESSION_TIMEOUT')
    now = time.time()
    expired = []
    backend = get_storage_backend()

    if backend is not None:
        persisted = backend.list_sessions()
        with session_store_lock:
            for session