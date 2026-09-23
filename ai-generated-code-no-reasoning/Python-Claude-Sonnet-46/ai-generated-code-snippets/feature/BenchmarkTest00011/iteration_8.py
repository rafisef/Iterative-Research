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
import queue
import contextlib
from collections import defaultdict
from functools import wraps
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

_session_store = {}
_session_store_lock = threading.RLock()
_file_locks = defaultdict(threading.RLock)
_file_locks_meta_lock = threading.Lock()

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
        "DB_POOL_ACQUIRE_TIMEOUT": int(os.environ.get("DB_POOL_ACQUIRE_TIMEOUT", "10")),
        "SESSION_CLEANUP_INTERVAL": int(os.environ.get("SESSION_CLEANUP_INTERVAL", "60")),
        "PER_USER_MAX_SESSIONS": int(os.environ.get("PER_USER_MAX_SESSIONS", "5")),
        "AUTH_PROVIDERS": os.environ.get("AUTH_PROVIDERS", "database").split(","),
        "AUTH_PROVIDER_PRIORITY": os.environ.get("AUTH_PROVIDER_PRIORITY", "database"),
        "OAUTH_CLIENT_ID": os.environ.get("OAUTH_CLIENT_ID", ""),
        "OAUTH_CLIENT_SECRET": os.environ.get("OAUTH_CLIENT_SECRET", ""),
        "OAUTH_REDIRECT_URI": os.environ.get("OAUTH_REDIRECT_URI", ""),
        "OAUTH_AUTH_URL": os.environ.get("OAUTH_AUTH_URL", ""),
        "OAUTH_TOKEN_URL": os.environ.get("OAUTH_TOKEN_URL", ""),
        "OAUTH_USERINFO_URL": os.environ.get("OAUTH_USERINFO_URL", ""),
        "LDAP_SERVER": os.environ.get("LDAP_SERVER", ""),
        "LDAP_PORT": int(os.environ.get("LDAP_PORT", "389")),
        "LDAP_BASE_DN": os.environ.get("LDAP_BASE_DN", ""),
        "LDAP_BIND_DN": os.environ.get("LDAP_BIND_DN", ""),
        "LDAP_BIND_PASSWORD": os.environ.get("LDAP_BIND_PASSWORD", ""),
        "LDAP_USER_SEARCH_FILTER": os.environ.get("LDAP_USER_SEARCH_FILTER", "(uid={username})"),
        "API_KEY_HEADER": os.environ.get("API_KEY_HEADER", "X-API-Key"),
        "API_KEYS_FILE": os.environ.get("API_KEYS_FILE", "/tmp/benchmark_storage/api_keys.json"),
        "AUTH_FALLBACK_ENABLED": os.environ.get("AUTH_FALLBACK_ENABLED", "true").lower() == "true",
        "AUTH_CACHE_ENABLED": os.environ.get("AUTH_CACHE_ENABLED", "false").lower() == "true",
        "AUTH_CACHE_TTL": int(os.environ.get("AUTH_CACHE_TTL", "300")),
        "SESSION_RENEWAL_THRESHOLD": int(os.environ.get("SESSION_RENEWAL_THRESHOLD", str(60 * 5))),
        "SESSION_MAX_LIFETIME": int(os.environ.get("SESSION_MAX_LIFETIME", str(60 * 60 * 8))),
        "CONCURRENT_SESSION_STRATEGY": os.environ.get("CONCURRENT_SESSION_STRATEGY", "allow"),
        "SESSION_STORE_BACKEND": os.environ.get("SESSION_STORE_BACKEND", "memory"),
        "SESSION_EVENTS_ENABLED": os.environ.get("SESSION_EVENTS_ENABLED", "true").lower() == "true",
        "SESSION_AUDIT_LOG_ENABLED": os.environ.get("SESSION_AUDIT_LOG_ENABLED", "false").lower() == "true",
        "SESSION_FINGERPRINT_ENABLED": os.environ.get("SESSION_FINGERPRINT_ENABLED", "false").lower() == "true",
        "SESSION_FINGERPRINT_FIELDS": os.environ.get("SESSION_FINGERPRINT_FIELDS", "user_agent,remote_addr"),
        "SESSION_IDLE_TIMEOUT": int(os.environ.get("SESSION_IDLE_TIMEOUT", str(60 * 15))),
        "SESSION_CONCURRENT_LOCK_TIMEOUT": int(os.environ.get("SESSION_CONCURRENT_LOCK_TIMEOUT", "5")),
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

class PerUserSessionLimitError(SessionError):
    pass

class DatabasePoolError(StorageError):
    pass

class AuthenticationError(Exception):
    pass

class AuthProviderError(AuthenticationError):
    pass

class AuthProviderNotFoundError(AuthenticationError):
    pass

class AllAuthProvidersFailedError(AuthenticationError):
    pass

class AuthCredentialsError(AuthenticationError):
    pass

class SessionFingerprintMismatchError(SessionError):
    pass

class SessionRenewalError(SessionError):
    pass

class ConcurrentSessionConflictError(SessionError):
    pass

class SessionEventType:
    CREATED = "created"
    DESTROYED = "destroyed"
    EXPIRED = "expired"
    RENEWED = "renewed"
    ACCESSED = "accessed"
    FINGERPRINT_MISMATCH = "fingerprint_mismatch"
    LIMIT_EXCEEDED = "limit_exceeded"
    CONCURRENT_CONFLICT = "concurrent_conflict"

class SessionEvent:
    def __init__(self, event_type, session_id, user_id=None, metadata=None):
        self.event_type = event_type
        self.session_id = session_id
        self.user_id = user_id
        self.timestamp = time.time()
        self.metadata = metadata or {}

    def to_dict(self):
        return {
            "event_type": self.event_type,
            "session_id": self.session_id,
            "user_id": self.user_id,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }

class SessionEventBus:
    def __init__(self):
        self._listeners = defaultdict(list)
        self._lock = threading.RLock()
        self._event_queue = queue.Queue()
        self._dispatch_thread = threading.Thread(target=self._dispatch_loop, daemon=True)
        self._dispatch_thread.start()

    def subscribe(self, event_type, listener):
        with self._lock:
            self._listeners[event_type].append(listener)

    def unsubscribe(self, event_type, listener):
        with self._lock:
            if event_type in self._listeners:
                try:
                    self._listeners[event_type].remove(listener)
                except ValueError:
                    pass

    def publish(self, event):
        self._event_queue.put(event)

    def _dispatch_loop(self):
        while True:
            try:
                event = self._event_queue.get(timeout=1)
                self._dispatch(event)
            except queue.Empty:
                continue
            except Exception:
                pass

    def _dispatch(self, event):
        with self._lock:
            listeners = list(self._listeners.get(event.event_type, []))
            listeners += list(self._listeners.get("*", []))
        for listener in listeners:
            try:
                listener(event)
            except Exception as e:
                logger.error(f"Session event listener error: {e}")

_session_event_bus = SessionEventBus()

class SessionAuditLogger:
    def __init__(self, enabled):
        self._enabled = enabled
        self._audit_logger = logging.getLogger("session.audit")

    def log(self, event):
        if not self._enabled:
            return
        self._audit_logger.info(json.dumps(event.to_dict()))

_session_audit_logger = None

def get_session_audit_logger():
    global _session_audit_logger
    if _session_audit_logger is None:
        config = get_config()
        _session_audit_logger = SessionAuditLogger(config["SESSION_AUDIT_LOG_ENABLED"])
    return _session_audit_logger

class SessionFingerprint:
    def __init__(self, fields):
        self._fields = [f.strip() for f in fields]

    def compute(self, request_context):
        parts = []
        for field in self._fields:
            parts.append(str(request_context.get(field, "")))
        return ":".join(parts)

    def verify(self, stored_fingerprint, request_context):
        current = self.compute(request_context)
        return stored_fingerprint == current

class DatabasePool:
    def __init__(self, db_path, pool_size, acquire_timeout):
        self._db_path = db_path
        self._pool_size = pool_size
        self._acquire_timeout = acquire_timeout
        self._pool = queue.Queue(maxsize=pool_size)
        self._all_connections = []
        self._lock = threading.Lock()
        self._initialize_pool()

    def _initialize_pool(self):
        for _ in range(self._pool_size):
            conn = self._create_connection()
            self._pool.put(conn)
            self._all_connections.append(conn)

    def _create_connection(self):
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    @contextlib.contextmanager
    def acquire(self):
        conn = None
        try:
            conn = self._pool.get(timeout=self._acquire_timeout)
            yield conn
        except queue.Empty:
            raise DatabasePoolError(
                f"Could not acquire a database connection within {self._acquire_timeout} seconds."
            )
        finally:
            if conn is not None:
                try:
                    conn.rollback()
                except Exception:
                    try:
                        conn.close()
                    except Exception:
                        pass
                    conn = self._create_connection()
                self._pool.put(conn)

    def close_all(self):
        with self._lock:
            while not self._pool.empty():
                try:
                    conn = self._pool.get_nowait()
                    conn.close()
                except queue.Empty:
                    break

_db_pool = None
_db_pool_init_lock = threading.Lock()

def get_db_pool():
    global _db_pool
    if _db_pool is None:
        with _db_pool_init_lock:
            if _db_pool is None:
                config = get_config()
                _db_pool = DatabasePool(
                    config["DB_PATH"],
                    config["DB_POOL_SIZE"],
                    config["DB_POOL_ACQUIRE_TIMEOUT"],
                )
    return _db_pool

class Session:
    def __init__(self, session_id, user_id=None, fingerprint=None):
        self.session_id = session_id
        self.user_id = user_id
        self.created_at = time.time()
        self.last_accessed = time.time()
        self.last_renewed = time.time()
        self.data = {}
        self._lock = threading.RLock()
        self.fingerprint = fingerprint
        self.access_count = 0
        self.renewal_count = 0
        self.metadata = {}

    def touch(self):
        with self._lock:
            self.last_accessed = time.time()
            self.access_count += 1

    def is_expired(self, timeout):
        with self._lock:
            return (time.time() - self.last_accessed) > timeout

    def is_idle_expired(self, idle_timeout):
        with self._lock:
            return (time.time() - self.last_accessed) > idle_timeout

    def is_absolute_expired(