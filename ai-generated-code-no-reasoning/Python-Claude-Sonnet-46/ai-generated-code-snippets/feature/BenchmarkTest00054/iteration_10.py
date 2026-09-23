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
import asyncio
import aiofiles
import hashlib
import base64
import io
import urllib.parse
import helpers.utils
import concurrent.futures
import os
import threading
import time
import logging
import hmac
import secrets
import json
import sqlite3
import queue
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List, Union, Callable, Awaitable, TypeVar
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

T = TypeVar('T')


def _get_env_bool(key: str, default: bool) -> bool:
    val = os.environ.get(key)
    if val is None:
        return default
    return val.lower() == 'true'


def _get_env_int(key: str, default: int) -> int:
    val = os.environ.get(key)
    if val is None:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def _get_env_float(key: str, default: float) -> float:
    val = os.environ.get(key)
    if val is None:
        return default
    try:
        return float(val)
    except (ValueError, TypeError):
        return default


def _get_env_str(key: str, default: str) -> str:
    return os.environ.get(key, default)


def _get_env_list(key: str, default: List[str], separator: str = ',') -> List[str]:
    val = os.environ.get(key)
    if val is None:
        return default
    return val.split(separator)


class StorageBackend(Enum):
    FILE = 'file'
    DATABASE = 'database'


class StorageError(Exception):
    pass


class StorageReadError(StorageError):
    pass


class StorageWriteError(StorageError):
    pass


class StorageConnectionError(StorageError):
    pass


class SessionError(Exception):
    pass


class SessionExpiredError(SessionError):
    pass


class SessionNotFoundError(SessionError):
    pass


class SessionConflictError(SessionError):
    pass


@dataclass
class StorageRecord:
    key: str
    value: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


@dataclass
class UserSession:
    session_id: str
    user_id: str
    data: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + 3600)
    is_active: bool = True
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def touch(self, extend_by: float = 3600) -> None:
        self.last_accessed = time.time()
        self.expires_at = time.time() + extend_by

    def to_dict(self) -> Dict[str, Any]:
        return {
            'session_id': self.session_id,
            'user_id': self.user_id,
            'data': self.data,
            'created_at': self.created_at,
            'last_accessed': self.last_accessed,
            'expires_at': self.expires_at,
            'is_active': self.is_active,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'metadata': self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'UserSession':
        return cls(
            session_id=data['session_id'],
            user_id=data['user_id'],
            data=data.get('data', {}),
            created_at=data.get('created_at', time.time()),
            last_accessed=data.get('last_accessed', time.time()),
            expires_at=data.get('expires_at', time.time() + 3600),
            is_active=data.get('is_active', True),
            ip_address=data.get('ip_address'),
            user_agent=data.get('user_agent'),
            metadata=data.get('metadata', {}),
        )


class SessionStore(ABC):

    @abstractmethod
    def create_session(self, user_id: str, ttl: float = 3600, ip_address: Optional[str] = None, user_agent: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> UserSession:
        pass

    @abstractmethod
    def get_session(self, session_id: str) -> Optional[UserSession]:
        pass

    @abstractmethod
    def update_session(self, session: UserSession) -> bool:
        pass

    @abstractmethod
    def delete_session(self, session_id: str) -> bool:
        pass

    @abstractmethod
    def get_user_sessions(self, user_id: str) -> List[UserSession]:
        pass

    @abstractmethod
    def invalidate_user_sessions(self, user_id: str) -> int:
        pass

    @abstractmethod
    def cleanup_expired_sessions(self) -> int:
        pass

    @abstractmethod
    def count_active_sessions(self) -> int:
        pass

    @abstractmethod
    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


class InMemorySessionStore(SessionStore):

    def __init__(
        self,
        max_sessions_per_user: int = 10,
        cleanup_interval: float = 300.0,
        default_ttl: float = 3600.0,
    ):
        self._sessions: Dict[str, UserSession] = {}
        self._user_sessions: Dict[str, List[str]] = {}
        self._lock = threading.RLock()
        self._max_sessions_per_user = max_sessions_per_user
        self._default_ttl = default_ttl
        self._cleanup_interval = cleanup_interval
        self._closed = False
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()

    def _cleanup_loop(self) -> None:
        while not self._closed:
            time.sleep(self._cleanup_interval)
            try:
                self.cleanup_expired_sessions()
            except Exception as e:
                logger.error(f'Session cleanup error: {e}')

    def _generate_session_id(self) -> str:
        return secrets.token_hex(32)

    def create_session(self, user_id: str, ttl: float = 3600, ip_address: Optional[str] = None, user_agent: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> UserSession:
        with self._lock:
            user_session_ids = self._user_sessions.get(user_id, [])
            active_sessions = [sid for sid in user_session_ids if sid in self._sessions and not self._sessions[sid].is_expired()]
            if len(active_sessions) >= self._max_sessions_per_user:
                oldest_id = min(active_sessions, key=lambda sid: self._sessions[sid].created_at)
                self.delete_session(oldest_id)
            session_id = self._generate_session_id()
            while session_id in self._sessions:
                session_id = self._generate_session_id()
            session = UserSession(
                session_id=session_id,
                user_id=user_id,
                created_at=time.time(),
                last_accessed=time.time(),
                expires_at=time.time() + ttl,
                ip_address=ip_address,
                user_agent=user_agent,
                metadata=metadata or {},
            )
            self._sessions[session_id] = session
            if user_id not in self._user_sessions:
                self._user_sessions[user_id] = []
            self._user_sessions[user_id].append(session_id)
            logger.info(f'Session created: {session_id} for user: {user_id}')
            return session

    def get_session(self, session_id: str) -> Optional[UserSession]:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            if session.is_expired() or not session.is_active:
                self.delete_session(session_id)
                return None
            session.touch()
            return session

    def update_session(self, session: UserSession) -> bool:
        with self._lock:
            if session.session_id not in self._sessions:
                return False
            if session.is_expired():
                raise SessionExpiredError(f'Session {session.session_id} has expired')
            self._sessions[session.session_id] = session
            return True

    def delete_session(self, session_id: str) -> bool:
        with self._lock:
            session = self._sessions.pop(session_id, None)
            if session is None:
                return False
            user_id = session.user_id
            if user_id in self._user_sessions:
                try:
                    self._user_sessions[user_id].remove(session_id)
                except ValueError:
                    pass
                if not self._user_sessions[user_id]:
                    del self._user_sessions[user_id]
            logger.info(f'Session deleted: {session_id}')
            return True

    def get_user_sessions(self, user_id: str) -> List[UserSession]:
        with self._lock:
            session_ids = self._user_sessions.get(user_id, [])
            sessions = []
            expired_ids = []
            for sid in session_ids:
                session = self._sessions.get(sid)
                if session is None:
                    expired_ids.append(sid)
                    continue
                if session.is_expired() or not session.is_active:
                    expired_ids.append(sid)
                    continue
                sessions.append(session)
            for sid in expired_ids:
                self.delete_session(sid)
            return sessions

    def invalidate_user_sessions(self, user_id: str) -> int:
        with self._lock:
            session_ids = list(self._user_sessions.get(user_id, []))
            count = 0
            for sid in session_ids:
                if self.delete_session(sid):
                    count += 1
            logger.info(f'Invalidated {count} sessions for user: {user_id}')
            return count

    def cleanup_expired_sessions(self) -> int:
        with self._lock:
            expired_ids = [
                sid for sid, session in self._sessions.items()
                if session.is_expired() or not session.is_active
            ]
            count = 0
            for sid in expired_ids:
                if self.delete_session(sid):
                    count += 1
            if count > 0:
                logger.info(f'Cleaned up {count} expired sessions')
            return count

    def count_active_sessions(self) -> int:
        with self._lock:
            return sum(
                1 for session in self._sessions.values()
                if not session.is_expired() and session.is_active
            )

    def close(self) -> None:
        self._closed = True


class PersistentSessionStore(SessionStore):

    _INIT_SQL = '''
        CREATE TABLE IF NOT EXISTS user_sessions (
            session_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            data TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL,
            last_accessed REAL NOT NULL,
            expires_at REAL NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            ip_address TEXT,
            user_agent TEXT,
            metadata TEXT NOT NULL DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON user_sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON user_sessions(expires_at);
        CREATE INDEX IF NOT EXISTS idx_sessions_is_active ON user_sessions(is_active);
    '''

    def __init__(
        self,
        db_path: str,
        pool_size: int = 5,
        pool_timeout: float = 30.0,
        max_sessions_per_user: int = 10,
        cleanup_interval: float = 300.0,
    ):
        self._db_path = db_path
        self._pool_size = pool_size
        self._pool_timeout = pool_timeout
        self._max_sessions_per_user = max_sessions_per_user
        self._cleanup_interval = cleanup_interval
        self._pool: queue.Queue = queue.Queue(maxsize=pool_size)
        self._closed = False
        self._initialize_pool()
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()

    def _create_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False, timeout=self._pool_timeout)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL')
        conn.execute('PRAGMA foreign_keys=ON')
        conn.executescript(self._INIT_SQL)
        conn.commit()
        return conn

    def _initialize_pool(self) -> None:
        for _ in range(self._pool_size):
            try:
                conn = self._create_connection()
                self._pool.put_nowait(conn)
            except sqlite3.Error as e:
                raise StorageConnectionError(f'Failed to initialize session database pool: {e}') from e

    def _acquire_connection(self) -> sqlite3.Connection:
        try:
            return self._pool.get(timeout=self._pool_timeout)
        except queue.Empty:
            raise StorageConnectionError('Session database connection pool exhausted')

    def _release_connection(self, conn: sqlite3.Connection) -> None:
        if not self._closed:
            try:
                self._pool.put_nowait(conn)
            except queue.Full:
                try:
                    conn.close()
                except Exception:
                    pass

    def _cleanup_loop(self) -> None:
        while not self._closed:
            time.sleep(self._cleanup_interval)
            try:
                self.cleanup_expired_sessions()
            except Exception as e:
                logger.error(f'Persistent session cleanup error: {e}')

    def _generate_session_id(self) -> str:
        return secrets.token_hex(32)

    def _row_to_session(self, row: sqlite3.