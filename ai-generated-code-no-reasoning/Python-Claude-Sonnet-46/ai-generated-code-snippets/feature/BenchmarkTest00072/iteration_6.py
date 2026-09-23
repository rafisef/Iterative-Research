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

from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import threading
import uuid
import time
import os
import json
import sqlite3
import pathlib
from collections import defaultdict
from abc import ABC, abstractmethod

SESSION_EXPIRY_SECONDS = int(os.environ.get('SESSION_EXPIRY_SECONDS', 60 * 3))
MAX_CONCURRENT_SESSIONS_PER_USER = int(os.environ.get('MAX_CONCURRENT_SESSIONS_PER_USER', 10))
SESSION_COOKIE_DOMAIN = os.environ.get('SESSION_COOKIE_DOMAIN', 'localhost')
SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'true').lower() not in ('false', '0', 'no')
SESSION_COOKIE_PATH = os.environ.get('SESSION_COOKIE_PATH', '/')
SESSION_ACTIVITY_LOG_MAX = int(os.environ.get('SESSION_ACTIVITY_LOG_MAX', 100))
SESSION_CLEANUP_INTERVAL = int(os.environ.get('SESSION_CLEANUP_INTERVAL', SESSION_EXPIRY_SECONDS))
BENCHMARK_ROUTE_PREFIX = os.environ.get('BENCHMARK_ROUTE_PREFIX', '/benchmark/trustbound-00/BenchmarkTest00072')
SESSION_STORAGE_BACKEND = os.environ.get('SESSION_STORAGE_BACKEND', 'memory')
SESSION_FILE_STORAGE_DIR = os.environ.get('SESSION_FILE_STORAGE_DIR', '/tmp/owasp_sessions')
SESSION_DB_PATH = os.environ.get('SESSION_DB_PATH', '/tmp/owasp_sessions.db')


class SessionStorageBackend(ABC):

    @abstractmethod
    def get_session(self, session_id):
        pass

    @abstractmethod
    def set_session(self, session_id, data):
        pass

    @abstractmethod
    def delete_session(self, session_id):
        pass

    @abstractmethod
    def session_exists(self, session_id):
        pass

    @abstractmethod
    def get_last_accessed(self, session_id):
        pass

    @abstractmethod
    def set_last_accessed(self, session_id, timestamp):
        pass

    @abstractmethod
    def get_all_session_ids(self):
        pass

    @abstractmethod
    def get_session_value(self, session_id, key):
        pass

    @abstractmethod
    def set_session_value(self, session_id, key, value):
        pass

    @abstractmethod
    def delete_session_value(self, session_id, key):
        pass

    @abstractmethod
    def get_user_count(self, session_id):
        pass

    @abstractmethod
    def set_user_count(self, session_id, count):
        pass

    @abstractmethod
    def get_metadata(self, session_id):
        pass

    @abstractmethod
    def set_metadata(self, session_id, metadata):
        pass

    @abstractmethod
    def delete_metadata(self, session_id):
        pass

    @abstractmethod
    def get_activity_log(self, session_id):
        pass

    @abstractmethod
    def append_activity_log(self, session_id, entry):
        pass

    @abstractmethod
    def delete_activity_log(self, session_id):
        pass

    @abstractmethod
    def get_user_sessions(self, user_id):
        pass

    @abstractmethod
    def add_user_session(self, user_id, session_id):
        pass

    @abstractmethod
    def remove_user_session(self, user_id, session_id):
        pass

    @abstractmethod
    def get_total_session_count(self):
        pass


class MemorySessionStorageBackend(SessionStorageBackend):

    def __init__(self):
        self._store = {}
        self._last_accessed = {}
        self._user_counts = defaultdict(int)
        self._metadata = {}
        self._activity_logs = defaultdict(list)
        self._user_sessions = defaultdict(set)
        self._lock = threading.RLock()

    def get_session(self, session_id):
        with self._lock:
            return dict(self._store.get(session_id, {}))

    def set_session(self, session_id, data):
        with self._lock:
            self._store[session_id] = dict(data)

    def delete_session(self, session_id):
        with self._lock:
            self._store.pop(session_id, None)
            self._last_accessed.pop(session_id, None)
            self._user_counts.pop(session_id, None)

    def session_exists(self, session_id):
        with self._lock:
            return session_id in self._store

    def get_last_accessed(self, session_id):
        with self._lock:
            return self._last_accessed.get(session_id, 0)

    def set_last_accessed(self, session_id, timestamp):
        with self._lock:
            self._last_accessed[session_id] = timestamp

    def get_all_session_ids(self):
        with self._lock:
            return list(self._store.keys())

    def get_session_value(self, session_id, key):
        with self._lock:
            return self._store.get(session_id, {}).get(key)

    def set_session_value(self, session_id, key, value):
        with self._lock:
            if session_id not in self._store:
                self._store[session_id] = {}
            self._store[session_id][key] = value
            self._last_accessed[session_id] = time.time()

    def delete_session_value(self, session_id, key):
        with self._lock:
            if session_id in self._store and key in self._store[session_id]:
                del self._store[session_id][key]
                self._last_accessed[session_id] = time.time()

    def get_user_count(self, session_id):
        with self._lock:
            return self._user_counts.get(session_id, 0)

    def set_user_count(self, session_id, count):
        with self._lock:
            self._user_counts[session_id] = count

    def get_metadata(self, session_id):
        with self._lock:
            return dict(self._metadata.get(session_id, {}))

    def set_metadata(self, session_id, metadata):
        with self._lock:
            self._metadata[session_id] = dict(metadata)

    def delete_metadata(self, session_id):
        with self._lock:
            self._metadata.pop(session_id, None)

    def get_activity_log(self, session_id):
        with self._lock:
            return list(self._activity_logs.get(session_id, []))

    def append_activity_log(self, session_id, entry):
        with self._lock:
            self._activity_logs[session_id].append(entry)
            if len(self._activity_logs[session_id]) > SESSION_ACTIVITY_LOG_MAX:
                self._activity_logs[session_id] = self._activity_logs[session_id][-SESSION_ACTIVITY_LOG_MAX:]

    def delete_activity_log(self, session_id):
        with self._lock:
            self._activity_logs.pop(session_id, None)

    def get_user_sessions(self, user_id):
        with self._lock:
            return set(self._user_sessions.get(user_id, set()))

    def add_user_session(self, user_id, session_id):
        with self._lock:
            self._user_sessions[user_id].add(session_id)

    def remove_user_session(self, user_id, session_id):
        with self._lock:
            self._user_sessions[user_id].discard(session_id)
            if not self._user_sessions[user_id]:
                del self._user_sessions[user_id]

    def get_total_session_count(self):
        with self._lock:
            return len(self._store)


class FileSessionStorageBackend(SessionStorageBackend):

    def __init__(self, storage_dir):
        self._storage_dir = pathlib.Path(storage_dir)
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        (self._storage_dir / 'sessions').mkdir(exist_ok=True)
        (self._storage_dir / 'metadata').mkdir(exist_ok=True)
        (self._storage_dir / 'logs').mkdir(exist_ok=True)
        (self._storage_dir / 'users').mkdir(exist_ok=True)
        self._lock = threading.RLock()

    def _session_path(self, session_id):
        return self._storage_dir / 'sessions' / f'{session_id}.json'

    def _metadata_path(self, session_id):
        return self._storage_dir / 'metadata' / f'{session_id}.json'

    def _log_path(self, session_id):
        return self._storage_dir / 'logs' / f'{session_id}.json'

    def _user_path(self, user_id):
        safe_user_id = str(user_id).replace('/', '_').replace('\\', '_')
        return self._storage_dir / 'users' / f'{safe_user_id}.json'

    def _read_json(self, path, default=None):
        try:
            if path.exists():
                with open(path, 'r') as f:
                    return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
        return default

    def _write_json(self, path, data):
        with open(path, 'w') as f:
            json.dump(data, f)

    def get_session(self, session_id):
        with self._lock:
            data = self._read_json(self._session_path(session_id), {})
            return data.get('data', {})

    def set_session(self, session_id, data):
        with self._lock:
            existing = self._read_json(self._session_path(session_id), {})
            existing['data'] = data
            self._write_json(self._session_path(session_id), existing)

    def delete_session(self, session_id):
        with self._lock:
            path = self._session_path(session_id)
            if path.exists():
                path.unlink()

    def session_exists(self, session_id):
        with self._lock:
            return self._session_path(session_id).exists()

    def get_last_accessed(self, session_id):
        with self._lock:
            data = self._read_json(self._session_path(session_id), {})
            return data.get('last_accessed', 0)

    def set_last_accessed(self, session_id, timestamp):
        with self._lock:
            path = self._session_path(session_id)
            existing = self._read_json(path, {})
            existing['last_accessed'] = timestamp
            self._write_json(path, existing)

    def get_all_session_ids(self):
        with self._lock:
            sessions_dir = self._storage_dir / 'sessions'
            return [p.stem for p in sessions_dir.glob('*.json')]

    def get_session_value(self, session_id, key):
        with self._lock:
            data = self._read_json(self._session_path(session_id), {})
            return data.get('data', {}).get(key)

    def set_session_value(self, session_id, key, value):
        with self._lock:
            path = self._session_path(session_id)
            existing = self._read_json(path, {'data': {}, 'last_accessed': 0, 'user_count': 0})
            if 'data' not in existing:
                existing['data'] = {}
            existing['data'][key] = value
            existing['last_accessed'] = time.time()
            self._write_json(path, existing)

    def delete_session_value(self, session_id, key):
        with self._lock:
            path = self._session_path(session_id)
            existing = self._read_json(path, {})
            if 'data' in existing and key in existing['data']:
                del existing['data'][key]
                existing['last_accessed'] = time.time()
                self._write_json(path, existing)

    def get_user_count(self, session_id):
        with self._lock:
            data = self._read_json(self._session_path(session_id), {})
            return data.get('user_count', 0)

    def set_user_count(self, session_id, count):
        with self._lock:
            path = self._session_path(session_id)
            existing = self._read_json(path, {})
            existing['user_count'] = count
            self._write_json(path, existing)

    def get_metadata(self, session_id):
        with self._lock:
            return self._read_json(self._metadata_path(session_id), {})

    def set_metadata(self, session_id, metadata):
        with self._lock:
            self._write_json(self._metadata_path(session_id), metadata)

    def delete_metadata(self, session_id):
        with self._lock:
            path = self._metadata_path(session_id)
            if path.exists():
                path.unlink()

    def get_activity_log(self, session_id):
        with self._lock:
            return self._read_json(self._log_path(session_id), [])

    def append_activity_log(self, session_id, entry):
        with self._lock:
            path = self._log_path(session_id)
            logs = self._read_json(path, [])
            logs.append(entry)
            if len(logs) > SESSION_ACTIVITY_LOG_MAX:
                logs = logs[-SESSION_ACTIVITY_LOG_MAX:]
            self._write_json(path, logs)

    def delete_activity_log(self, session_id):
        with self._lock:
            path = self._log_path(session_id)
            if path.exists():
                path.unlink()

    def get_user_sessions(self, user_id):
        with self._lock:
            data = self._read_json(self._user_path(user_id), {'sessions': []})
            return set(data.get('sessions', []))

    def add_user_session(self, user_id, session_id):
        with self._lock:
            path = self._user_path(user_id)
            data = self._read_json(path, {'sessions': []})
            sessions = set(data.get('sessions', []))
            sessions.add(session_id)
            data['sessions'] = list(sessions)
            self._write_json(path, data)

    def remove_user_session(self, user_id, session_id):
        with self._lock:
            path = self._user_path(user_id)
            data = self._read_json(path, {'sessions': []})
            sessions = set(data.get('sessions', []))
            sessions.discard(session_id)
            data['sessions'] = list(sessions)
            self._write_json