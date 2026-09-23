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
import os
import json
import sqlite3
import logging
import threading
import uuid
import time
from collections import defaultdict
from functools import wraps

logger = logging.getLogger(__name__)

_session_store = {}
_session_store_lock = threading.RLock()
_file_locks = defaultdict(threading.RLock)
_db_pool_lock = threading.Semaphore(10)

def get_config():
    config = {
        "STORAGE_TYPE": os.environ.get("STORAGE_TYPE", "database"),
        "FILE_STORAGE_PATH": os.environ.get("FILE_STORAGE_PATH", "/tmp/benchmark_storage"),
        "COOKIE_MAX_AGE": int(os.environ.get("COOKIE_MAX_AGE", str(60 * 3))),
        "COOKIE_SECURE": os.environ.get("COOKIE_SECURE", "true").lower() == "true",
        "COOKIE_DOMAIN": os.environ.get("COOKIE_DOMAIN", "localhost"),
        "COOKIE_NAME": os.environ.get("COOKIE_NAME", "BenchmarkTest00011"),
        "COOKIE_DEFAULT_VALUE": os.environ.get("COOKIE_DEFAULT_VALUE", "noCookieValueSupplied"),
        "DB_DEFAULT_USERNAME": os.environ.get("DB_DEFAULT_USERNAME", "admin"),
        "DB_DEFAULT_PASSWORD": os.environ.get("DB_DEFAULT_PASSWORD", "admin123"),
        "ALLOW_STORAGE_OVERRIDE": os.environ.get("ALLOW_STORAGE_OVERRIDE", "true").lower() == "true",
        "MAX_WRITE_USERNAME_LENGTH": int(os.environ.get("MAX_WRITE_USERNAME_LENGTH", "255")),
        "MAX_WRITE_PASSWORD_LENGTH": int(os.environ.get("MAX_WRITE_PASSWORD_LENGTH", "255")),
        "USERS_FILENAME": os.environ.get("USERS_FILENAME", "users.json"),
        "BENCHMARK_ROUTE_PREFIX": os.environ.get("BENCHMARK_ROUTE_PREFIX", "/benchmark/sqli-00"),
        "BENCHMARK_TEST_NAME": os.environ.get("BENCHMARK_TEST_NAME", "BenchmarkTest00011"),
        "DB_PATH": os.environ.get("DB_PATH", "/tmp/benchmark_storage/benchmark.db"),
        "DB_POOL_SIZE": int(os.environ.get("DB_POOL_SIZE", "5")),
        "FILE_BACKUP_ENABLED": os.environ.get("FILE_BACKUP_ENABLED", "false").lower() == "true",
        "FILE_BACKUP_PATH": os.environ.get("FILE_BACKUP_PATH", "/tmp/benchmark_storage/backup"),
        "DB_SEED_USER1": os.environ.get("DB_SEED_USER1", "user1"),
        "DB_SEED_PASS1": os.environ.get("DB_SEED_PASS1", "password1"),
        "DB_SEED_USER2": os.environ.get("DB_SEED_USER2", "user2"),
        "DB_SEED_PASS2": os.environ.get("DB_SEED_PASS2", "password2"),
        "SESSION_TIMEOUT": int(os.environ.get("SESSION_TIMEOUT", str(60 * 30))),
        "MAX_CONCURRENT_SESSIONS": int(os.environ.get("MAX_CONCURRENT_SESSIONS", "100")),
    }
    return config

CONFIG = get_config()
STORAGE_TYPE = CONFIG["STORAGE_TYPE"]
FILE_STORAGE_PATH = CONFIG["FILE_STORAGE_PATH"]

class StorageError(Exception):
    pass

class FileStorageError(StorageError):
    pass

class DatabaseStorageError(StorageError):
    pass

class SessionError(Exception):
    pass

class MaxSessionsExceededError(SessionError):
    pass

class SessionExpiredError(SessionError):
    pass

class SessionNotFoundError(SessionError):
    pass

class Session:
    def __init__(self, session_id, user_id=None):
        self.session_id = session_id
        self.user_id = user_id
        self.created_at = time.time()
        self.last_accessed = time.time()
        self.data = {}
        self._lock = threading.RLock()

    def touch(self):
        with self._lock:
            self.last_accessed = time.time()

    def is_expired(self, timeout):
        with self._lock:
            return (time.time() - self.last_accessed) > timeout

    def get(self, key, default=None):
        with self._lock:
            return self.data.get(key, default)

    def set(self, key, value):
        with self._lock:
            self.data[key] = value

    def delete(self, key):
        with self._lock:
            self.data.pop(key, None)

    def to_dict(self):
        with self._lock:
            return {
                "session_id": self.session_id,
                "user_id": self.user_id,
                "created_at": self.created_at,
                "last_accessed": self.last_accessed,
                "data": dict(self.data),
            }

class SessionManager:
    def __init__(self, config):
        self.config = config
        self.sessions = {}
        self.lock = threading.RLock()
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()

    def create_session(self, user_id=None):
        with self.lock:
            active_sessions = [
                s for s in self.sessions.values()
                if not s.is_expired(self.config["SESSION_TIMEOUT"])
            ]
            if len(active_sessions) >= self.config["MAX_CONCURRENT_SESSIONS"]:
                raise MaxSessionsExceededError(
                    f"Maximum concurrent sessions ({self.config['MAX_CONCURRENT_SESSIONS']}) reached."
                )
            session_id = str(uuid.uuid4())
            while session_id in self.sessions:
                session_id = str(uuid.uuid4())
            session = Session(session_id, user_id)
            self.sessions[session_id] = session
            logger.debug(f"Session created: {session_id} for user: {user_id}")
            return session

    def get_session(self, session_id):
        with self.lock:
            session = self.sessions.get(session_id)
            if session is None:
                raise SessionNotFoundError(f"Session not found: {session_id}")
            if session.is_expired(self.config["SESSION_TIMEOUT"]):
                del self.sessions[session_id]
                raise SessionExpiredError(f"Session expired: {session_id}")
            session.touch()
            return session

    def destroy_session(self, session_id):
        with self.lock:
            if session_id in self.sessions:
                del self.sessions[session_id]
                logger.debug(f"Session destroyed: {session_id}")
                return True
            return False

    def get_active_session_count(self):
        with self.lock:
            return sum(
                1 for s in self.sessions.values()
                if not s.is_expired(self.config["SESSION_TIMEOUT"])
            )

    def get_all_active_sessions(self):
        with self.lock:
            return [
                s.to_dict() for s in self.sessions.values()
                if not s.is_expired(self.config["SESSION_TIMEOUT"])
            ]

    def _cleanup_expired_sessions(self):
        with self.lock:
            expired = [
                sid for sid, s in self.sessions.items()
                if s.is_expired(self.config["SESSION_TIMEOUT"])
            ]
            for sid in expired:
                del self.sessions[sid]
            if expired:
                logger.debug(f"Cleaned up {len(expired)} expired sessions.")

    def _cleanup_loop(self):
        while True:
            time.sleep(60)
            try:
                self._cleanup_expired_sessions()
            except Exception as e:
                logger.error(f"Session cleanup error: {e}")

_session_manager = SessionManager(CONFIG)

def get_session_manager():
    return _session_manager

def with_session(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        config = get_config()
        cookie_name = config["COOKIE_NAME"]
        session_id = request.cookies.get(cookie_name)
        session = None
        sm = get_session_manager()
        if session_id:
            try:
                session = sm.get_session(session_id)
            except (SessionNotFoundError, SessionExpiredError):
                session = None
        if session is None:
            try:
                session = sm.create_session()
            except MaxSessionsExceededError as e:
                logger.warning(str(e))
                return make_response("Service temporarily unavailable: too many active sessions.", 503)
        kwargs["session"] = session
        response = f(*args, **kwargs)
        if hasattr(response, "set_cookie"):
            response.set_cookie(
                cookie_name,
                session.session_id,
                max_age=config["COOKIE_MAX_AGE"],
                secure=config["COOKIE_SECURE"],
                httponly=True,
                samesite="Strict",
            )
        return response
    return decorated

def ensure_directory(path):
    if not os.path.exists(path):
        os.makedirs(path)

def get_default_seed_data(config):
    return [
        {"username": config["DB_DEFAULT_USERNAME"], "password": config["DB_DEFAULT_PASSWORD"]},
        {"username": config["DB_SEED_USER1"], "password": config["DB_SEED_PASS1"]},
        {"username": config["DB_SEED_USER2"], "password": config["DB_SEED_PASS2"]},
    ]

def load_file_data(file_path):
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            return json.load(f)
    return None

def save_file_data(file_path, data):
    with open(file_path, "w") as f:
        json.dump(data, f, indent=2)

def backup_file_data(file_path, backup_path, filename):
    import shutil
    ensure_directory(backup_path)
    timestamp = int(time.time())
    backup_file = os.path.join(backup_path, f"{timestamp}_{filename}")
    if os.path.exists(file_path):
        shutil.copy2(file_path, backup_file)

def _get_file_lock(file_path):
    with threading.Lock():
        return _file_locks[file_path]

def initialize_file_storage(config):
    storage_path = config["FILE_STORAGE_PATH"]
    ensure_directory(storage_path)
    file_path = os.path.join(storage_path, config["USERS_FILENAME"])
    lock = _get_file_lock(file_path)
    with lock:
        if not os.path.exists(file_path):
            default_data = get_default_seed_data(config)
            save_file_data(file_path, default_data)
            return True
    return False

def read_from_file(param, session=None):
    config = get_config()
    result = ""
    try:
        storage_path = config["FILE_STORAGE_PATH"]
        ensure_directory(storage_path)
        file_path = os.path.join(storage_path, config["USERS_FILENAME"])
        lock = _get_file_lock(file_path)
        with lock:
            data = load_file_data(file_path)
            if data is None:
                default_data = get_default_seed_data(config)
                save_file_data(file_path, default_data)
                result += "<br>File storage initialized with default data. No matching records found.<br>"
                return result
            matches = [entry["username"] for entry in data if entry.get("password") == param]
        if matches:
            result += f"<br>Results for query: SELECT username from USERS where password = '{param}'<br>"
            for username in matches:
                result += f"username: {username}<br>"
        else:
            result += f"<br>No results found for query: SELECT username from USERS where password = '{param}'<br>"
        if session is not None:
            session.set("last_read_param", param)
            session.set("last_read_time", time.time())
    except json.JSONDecodeError as e:
        raise FileStorageError(f"Corrupted file storage: {str(e)}")
    except PermissionError as e:
        raise FileStorageError(f"File permission error: {str(e)}")
    except Exception as e:
        raise FileStorageError(f"File storage error: {str(e)}")
    return result

def read_from_database(param, session=None):
    result = ""
    try:
        import helpers.db_sqlite
        sql = f'SELECT username from USERS where password = ?'
        with _db_pool_lock:
            con = helpers.db_sqlite.get_connection()
            cur = con.cursor()
            cur.execute(sql, (param,))
            result += helpers.db_sqlite.results(cur, sql)
            con.close()
        if session is not None:
            session.set("last_read_param", param)
            session.set("last_read_time", time.time())
    except Exception as e:
        raise DatabaseStorageError(f"Database read error: {str(e)}")
    return result

def write_to_file(username, password, session=None):
    config = get_config()
    result = ""
    try:
        storage_path = config["FILE_STORAGE_PATH"]
        ensure_directory(storage_path)
        file_path = os.path.join(storage_path, config["USERS_FILENAME"])
        lock = _get_file_lock(file_path)
        with lock:
            if config["FILE_BACKUP_ENABLED"]:
                backup_file_data(file_path, config["FILE_BACKUP_PATH"], config["USERS_FILENAME"])
            data = load_file_data(file_path)
            if data is None:
                data = get_default_seed_data(config)
            existing_usernames = [entry["username"] for entry in data]
            if username in existing_usernames:
                for entry in data:
                    if entry["username"] == username:
                        entry["password"] = password
                result += "<br>Record updated in file storage successfully.<br>"
            else:
                data.append({"username": username, "password": password})
                result += "<br>Record written to file storage successfully.<br>"
            save_file_data(file_path, data)
        if session is not None:
            session.set("last_write_username", username)
            session.set("last_write_time", time.time())
    except json.JSONDecodeError as e:
        raise FileStorageError(f"Corrupted file storage: {str(e)}")
    except PermissionError as e:
        raise FileStorageError(f"File permission error: {str(e)}")
    except Exception as e:
        raise FileStorage