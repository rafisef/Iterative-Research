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


@dataclass
class StorageRecord:
    key: str
    value: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


class BaseStorageProvider(ABC):

    @abstractmethod
    def read(self, key: str) -> Optional[str]:
        pass

    @abstractmethod
    def write(self, key: str, value: str, metadata: Optional[Dict[str, Any]] = None) -> bool:
        pass

    @abstractmethod
    def delete(self, key: str) -> bool:
        pass

    @abstractmethod
    def exists(self, key: str) -> bool:
        pass

    @abstractmethod
    def list_keys(self, prefix: Optional[str] = None) -> List[str]:
        pass

    @abstractmethod
    def read_record(self, key: str) -> Optional[StorageRecord]:
        pass

    @abstractmethod
    def write_record(self, record: StorageRecord) -> bool:
        pass

    @abstractmethod
    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


class FileStorageProvider(BaseStorageProvider):

    def __init__(
        self,
        base_dir: str,
        encoding: str = 'utf-8',
        write_timeout: float = 5.0,
        retry_attempts: int = 3,
        retry_delay: float = 0.1,
        lock_timeout: float = 10.0,
    ):
        self._base_dir = base_dir
        self._encoding = encoding
        self._write_timeout = write_timeout
        self._retry_attempts = retry_attempts
        self._retry_delay = retry_delay
        self._lock_timeout = lock_timeout
        self._locks: Dict[str, threading.Lock] = {}
        self._locks_lock = threading.Lock()
        os.makedirs(self._base_dir, exist_ok=True)
        self._meta_dir = os.path.join(self._base_dir, '.metadata')
        os.makedirs(self._meta_dir, exist_ok=True)

    def _get_lock(self, key: str) -> threading.Lock:
        with self._locks_lock:
            if key not in self._locks:
                self._locks[key] = threading.Lock()
            return self._locks[key]

    def _key_to_path(self, key: str) -> str:
        safe_key = key.replace('/', '_').replace('\\', '_').replace('..', '_')
        return os.path.join(self._base_dir, safe_key)

    def _key_to_meta_path(self, key: str) -> str:
        safe_key = key.replace('/', '_').replace('\\', '_').replace('..', '_')
        return os.path.join(self._meta_dir, safe_key + '.json')

    def read(self, key: str) -> Optional[str]:
        path = self._key_to_path(key)
        lock = self._get_lock(key)
        acquired = lock.acquire(timeout=self._lock_timeout)
        if not acquired:
            raise StorageReadError(f'Could not acquire lock for key: {key}')
        try:
            if not os.path.exists(path):
                return None
            with open(path, 'r', encoding=self._encoding) as f:
                return f.read()
        except OSError as e:
            raise StorageReadError(f'Failed to read key {key}: {e}') from e
        finally:
            lock.release()

    def write(self, key: str, value: str, metadata: Optional[Dict[str, Any]] = None) -> bool:
        path = self._key_to_path(key)
        meta_path = self._key_to_meta_path(key)
        lock = self._get_lock(key)
        acquired = lock.acquire(timeout=self._lock_timeout)
        if not acquired:
            raise StorageWriteError(f'Could not acquire lock for key: {key}')
        try:
            for attempt in range(self._retry_attempts):
                try:
                    tmp_path = path + '.tmp'
                    with open(tmp_path, 'w', encoding=self._encoding) as f:
                        f.write(value)
                    os.replace(tmp_path, path)
                    if metadata is not None:
                        meta_data = {
                            'key': key,
                            'metadata': metadata,
                            'created_at': time.time(),
                            'updated_at': time.time(),
                        }
                        if os.path.exists(meta_path):
                            try:
                                with open(meta_path, 'r', encoding=self._encoding) as mf:
                                    existing = json.load(mf)
                                    meta_data['created_at'] = existing.get('created_at', meta_data['created_at'])
                            except (OSError, json.JSONDecodeError):
                                pass
                        tmp_meta = meta_path + '.tmp'
                        with open(tmp_meta, 'w', encoding=self._encoding) as mf:
                            json.dump(meta_data, mf)
                        os.replace(tmp_meta, meta_path)
                    return True
                except OSError as e:
                    if attempt < self._retry_attempts - 1:
                        time.sleep(self._retry_delay)
                    else:
                        raise StorageWriteError(f'Failed to write key {key} after {self._retry_attempts} attempts: {e}') from e
        finally:
            lock.release()
        return False

    def delete(self, key: str) -> bool:
        path = self._key_to_path(key)
        meta_path = self._key_to_meta_path(key)
        lock = self._get_lock(key)
        acquired = lock.acquire(timeout=self._lock_timeout)
        if not acquired:
            raise StorageError(f'Could not acquire lock for key: {key}')
        try:
            deleted = False
            if os.path.exists(path):
                os.remove(path)
                deleted = True
            if os.path.exists(meta_path):
                os.remove(meta_path)
            return deleted
        except OSError as e:
            raise StorageError(f'Failed to delete key {key}: {e}') from e
        finally:
            lock.release()

    def exists(self, key: str) -> bool:
        path = self._key_to_path(key)
        return os.path.exists(path)

    def list_keys(self, prefix: Optional[str] = None) -> List[str]:
        try:
            keys = []
            for fname in os.listdir(self._base_dir):
                if fname.startswith('.'):
                    continue
                full_path = os.path.join(self._base_dir, fname)
                if os.path.isfile(full_path):
                    if prefix is None or fname.startswith(prefix):
                        keys.append(fname)
            return keys
        except OSError as e:
            raise StorageReadError(f'Failed to list keys: {e}') from e

    def read_record(self, key: str) -> Optional[StorageRecord]:
        value = self.read(key)
        if value is None:
            return None
        meta_path = self._key_to_meta_path(key)
        metadata: Dict[str, Any] = {}
        created_at = time.time()
        updated_at = time.time()
        if os.path.exists(meta_path):
            try:
                with open(meta_path, 'r', encoding=self._encoding) as mf:
                    meta_data = json.load(mf)
                    metadata = meta_data.get('metadata', {})
                    created_at = meta_data.get('created_at', created_at)
                    updated_at = meta_data.get('updated_at', updated_at)
            except (OSError, json.JSONDecodeError):
                pass
        return StorageRecord(
            key=key,
            value=value,
            metadata=metadata,
            created_at=created_at,
            updated_at=updated_at,
        )

    def write_record(self, record: StorageRecord) -> bool:
        return self.write(record.key, record.value, record.metadata)

    def append(self, key: str, value: str) -> bool:
        path = self._key_to_path(key)
        lock = self._get_lock(key)
        acquired = lock.acquire(timeout=self._lock_timeout)
        if not acquired:
            raise StorageWriteError(f'Could not acquire lock for key: {key}')
        try:
            for attempt in range(self._retry_attempts):
                try:
                    with open(path, 'a', encoding=self._encoding) as f:
                        f.write(value)
                    return True
                except OSError as e:
                    if attempt < self._retry_attempts - 1:
                        time.sleep(self._retry_delay)
                    else:
                        raise StorageWriteError(f'Failed to append to key {key}: {e}') from e
        finally:
            lock.release()
        return False

    def read_lines(self, key: str) -> List[str]:
        path = self._key_to_path(key)
        lock = self._get_lock(key)
        acquired = lock.acquire(timeout=self._lock_timeout)
        if not acquired:
            raise StorageReadError(f'Could not acquire lock for key: {key}')
        try:
            if not os.path.exists(path):
                return []
            with open(path, 'r', encoding=self._encoding) as f:
                return f.readlines()
        except OSError as e:
            raise StorageReadError(f'Failed to read lines for key {key}: {e}') from e
        finally:
            lock.release()

    def close(self) -> None:
        pass


class DatabaseStorageProvider(BaseStorageProvider):

    _INIT_SQL = '''
        CREATE TABLE IF NOT EXISTS storage_records (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            metadata TEXT NOT NULL DEFAULT '{}',
            created_at REAL NOT NULL,
            updated_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_storage_key ON storage_records(key);
    '''

    def __init__(
        self,
        db_url: str,
        pool_size: int = 5,
        pool_timeout: float = 30.0,
        write_timeout: float = 5.0,
        retry_attempts: int = 3,
        retry_delay: float = 0.1,
    ):
        self._db_url = db_url
        self._pool_size = pool_size
        self._pool_timeout = pool_timeout
        self._write_timeout = write_timeout
        self._retry_attempts = retry_attempts
        self._retry_delay = retry_delay
        self._pool: queue.Queue = queue.Queue(maxsize=pool_size)
        self._pool_lock = threading.Lock()
        self._closed = False
        self._initialize_pool()

    def _get_db_path(self) -> str:
        if self._db_url.startswith('sqlite:///'):
            return self._db_url[len('sqlite:///'):]
        if self._db_url.startswith('sqlite://'):
            return self._db_url[len('sqlite://'):]
        return self._db_url

    def _create_connection(self) -> sqlite3.Connection:
        db_path = self._get_db_path()
        conn = sqlite3.connect(db_path, check_same_thread=False, timeout=self._pool_timeout)
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
                raise StorageConnectionError(f'Failed to initialize database connection pool: {e}') from e

    def _acquire_connection(self) -> sqlite3.Connection:
        try:
            return self._pool.get(timeout=self._pool_timeout)
        except queue.Empty:
            raise StorageConnectionError('Database connection pool exhausted')

    def _release_connection(self, conn: sqlite3.Connection) -> None:
        if not self._closed:
            try:
                self._pool.put_nowait(conn)
            except queue.Full:
                try:
                    conn.close()
                except Exception:
                    pass

    def read(self, key: str) -> Optional[str]:
        conn = self._acquire_connection()
        try:
            cursor = conn.execute(
                'SELECT value FROM storage_records WHERE key = ?',
                (key,)
            )
            row = cursor.fetchone()