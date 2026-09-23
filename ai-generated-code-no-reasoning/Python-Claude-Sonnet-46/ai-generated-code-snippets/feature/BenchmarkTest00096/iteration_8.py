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
from functools import wraps
import hashlib
import hmac
import base64
import os
import time
import threading
import uuid
import json
import sqlite3
import pickle
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, Union, List
from pathlib import Path

ENV_ADMIN_USERNAME = os.environ.get("BENCHMARK_ADMIN_USERNAME", "admin")
ENV_ADMIN_PASSWORD = os.environ.get("BENCHMARK_ADMIN_PASSWORD", "admin_password")
ENV_USER_USERNAME = os.environ.get("BENCHMARK_USER_USERNAME", "user")
ENV_USER_PASSWORD = os.environ.get("BENCHMARK_USER_PASSWORD", "user_password")
ENV_API_KEY_001_ID = os.environ.get("BENCHMARK_API_KEY_001_ID", "key001")
ENV_API_KEY_001_VALUE = os.environ.get("BENCHMARK_API_KEY_001_VALUE", "supersecretapikey123")
ENV_API_KEY_001_SCOPE = os.environ.get("BENCHMARK_API_KEY_001_SCOPE", "read")
ENV_API_KEY_001_OWNER = os.environ.get("BENCHMARK_API_KEY_001_OWNER", "service1")
ENV_API_KEY_002_ID = os.environ.get("BENCHMARK_API_KEY_002_ID", "key002")
ENV_API_KEY_002_VALUE = os.environ.get("BENCHMARK_API_KEY_002_VALUE", "anotherapisecretkey456")
ENV_API_KEY_002_SCOPE = os.environ.get("BENCHMARK_API_KEY_002_SCOPE", "write")
ENV_API_KEY_002_OWNER = os.environ.get("BENCHMARK_API_KEY_002_OWNER", "service2")
ENV_TOKEN_SECRET_KEY = os.environ.get("BENCHMARK_TOKEN_SECRET_KEY", "benchmark_secret_key_2025")
ENV_ASYNC_DEFAULT = os.environ.get("BENCHMARK_ASYNC_DEFAULT", "false").lower() == "true"
ENV_PBKDF2_ITERATIONS = int(os.environ.get("BENCHMARK_PBKDF2_ITERATIONS", "100000"))
ENV_TOKEN_MIN_LENGTH = int(os.environ.get("BENCHMARK_TOKEN_MIN_LENGTH", "1"))
ENV_API_KEY_HASH_LENGTH = int(os.environ.get("BENCHMARK_API_KEY_HASH_LENGTH", "64"))
ENV_OAUTH_CLIENT_ID = os.environ.get("BENCHMARK_OAUTH_CLIENT_ID", "benchmark_client")
ENV_OAUTH_CLIENT_SECRET = os.environ.get("BENCHMARK_OAUTH_CLIENT_SECRET", "benchmark_client_secret")
ENV_OAUTH_TOKEN_EXPIRY = int(os.environ.get("BENCHMARK_OAUTH_TOKEN_EXPIRY", "3600"))
ENV_CERT_AUTH_ENABLED = os.environ.get("BENCHMARK_CERT_AUTH_ENABLED", "false").lower() == "true"
ENV_LDAP_AUTH_ENABLED = os.environ.get("BENCHMARK_LDAP_AUTH_ENABLED", "false").lower() == "true"
ENV_LDAP_SERVER = os.environ.get("BENCHMARK_LDAP_SERVER", "ldap://localhost:389")
ENV_LDAP_BASE_DN = os.environ.get("BENCHMARK_LDAP_BASE_DN", "dc=example,dc=com")
ENV_MFA_SECRET_KEY = os.environ.get("BENCHMARK_MFA_SECRET_KEY", "mfa_secret_key_2025")
ENV_MFA_CODE_LENGTH = int(os.environ.get("BENCHMARK_MFA_CODE_LENGTH", "6"))
ENV_MFA_TIME_STEP = int(os.environ.get("BENCHMARK_MFA_TIME_STEP", "30"))
ENV_SESSION_TIMEOUT = int(os.environ.get("BENCHMARK_SESSION_TIMEOUT", "3600"))
ENV_MAX_CONCURRENT_SESSIONS = int(os.environ.get("BENCHMARK_MAX_CONCURRENT_SESSIONS", "10"))
ENV_STORAGE_BACKEND = os.environ.get("BENCHMARK_STORAGE_BACKEND", "memory")
ENV_STORAGE_FILE_PATH = os.environ.get("BENCHMARK_STORAGE_FILE_PATH", "./benchmark_sessions.json")
ENV_STORAGE_DB_PATH = os.environ.get("BENCHMARK_STORAGE_DB_PATH", "./benchmark_sessions.db")
ENV_STORAGE_USERS_FILE_PATH = os.environ.get("BENCHMARK_STORAGE_USERS_FILE_PATH", "./benchmark_users.json")
ENV_STORAGE_USERS_DB_PATH = os.environ.get("BENCHMARK_STORAGE_USERS_DB_PATH", "./benchmark_users.db")


class StorageBackend(ABC):
    @abstractmethod
    def save_session(self, session_id: str, session_data: Dict[str, Any]) -> bool:
        pass

    @abstractmethod
    def load_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def delete_session(self, session_id: str) -> bool:
        pass

    @abstractmethod
    def load_all_sessions(self) -> Dict[str, Dict[str, Any]]:
        pass

    @abstractmethod
    def save_user(self, username: str, user_data: Dict[str, Any]) -> bool:
        pass

    @abstractmethod
    def load_user(self, username: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def delete_user(self, username: str) -> bool:
        pass

    @abstractmethod
    def load_all_users(self) -> Dict[str, Dict[str, Any]]:
        pass

    @abstractmethod
    async def save_session_async(self, session_id: str, session_data: Dict[str, Any]) -> bool:
        pass

    @abstractmethod
    async def load_session_async(self, session_id: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    async def delete_session_async(self, session_id: str) -> bool:
        pass

    @abstractmethod
    async def load_all_sessions_async(self) -> Dict[str, Dict[str, Any]]:
        pass

    @abstractmethod
    async def save_user_async(self, username: str, user_data: Dict[str, Any]) -> bool:
        pass

    @abstractmethod
    async def load_user_async(self, username: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    async def delete_user_async(self, username: str) -> bool:
        pass

    @abstractmethod
    async def load_all_users_async(self) -> Dict[str, Dict[str, Any]]:
        pass


class MemoryStorageBackend(StorageBackend):
    def __init__(self):
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._users: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()

    def save_session(self, session_id: str, session_data: Dict[str, Any]) -> bool:
        with self._lock:
            self._sessions[session_id] = dict(session_data)
            return True

    def load_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            data = self._sessions.get(session_id)
            return dict(data) if data else None

    def delete_session(self, session_id: str) -> bool:
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                return True
            return False

    def load_all_sessions(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            return {k: dict(v) for k, v in self._sessions.items()}

    def save_user(self, username: str, user_data: Dict[str, Any]) -> bool:
        with self._lock:
            self._users[username] = dict(user_data)
            return True

    def load_user(self, username: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            data = self._users.get(username)
            return dict(data) if data else None

    def delete_user(self, username: str) -> bool:
        with self._lock:
            if username in self._users:
                del self._users[username]
                return True
            return False

    def load_all_users(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            return {k: dict(v) for k, v in self._users.items()}

    async def save_session_async(self, session_id: str, session_data: Dict[str, Any]) -> bool:
        await asyncio.sleep(0)
        return self.save_session(session_id, session_data)

    async def load_session_async(self, session_id: str) -> Optional[Dict[str, Any]]:
        await asyncio.sleep(0)
        return self.load_session(session_id)

    async def delete_session_async(self, session_id: str) -> bool:
        await asyncio.sleep(0)
        return self.delete_session(session_id)

    async def load_all_sessions_async(self) -> Dict[str, Dict[str, Any]]:
        await asyncio.sleep(0)
        return self.load_all_sessions()

    async def save_user_async(self, username: str, user_data: Dict[str, Any]) -> bool:
        await asyncio.sleep(0)
        return self.save_user(username, user_data)

    async def load_user_async(self, username: str) -> Optional[Dict[str, Any]]:
        await asyncio.sleep(0)
        return self.load_user(username)

    async def delete_user_async(self, username: str) -> bool:
        await asyncio.sleep(0)
        return self.delete_user(username)

    async def load_all_users_async(self) -> Dict[str, Dict[str, Any]]:
        await asyncio.sleep(0)
        return self.load_all_users()


class FileStorageBackend(StorageBackend):
    def __init__(self, sessions_file_path: str = None, users_file_path: str = None):
        self._sessions_file = sessions_file_path if sessions_file_path is not None else ENV_STORAGE_FILE_PATH
        self._users_file = users_file_path if users_file_path is not None else ENV_STORAGE_USERS_FILE_PATH
        self._lock = threading.RLock()
        self._ensure_files_exist()

    def _ensure_files_exist(self):
        for file_path in [self._sessions_file, self._users_file]:
            path = Path(file_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                with open(file_path, 'w') as f:
                    json.dump({}, f)

    def _serialize_value(self, value: Any) -> Any:
        if isinstance(value, bytes):
            return {'__bytes__': True, 'data': base64.b64encode(value).decode('utf-8')}
        elif isinstance(value, dict):
            return {k: self._serialize_value(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [self._serialize_value(item) for item in value]
        return value

    def _deserialize_value(self, value: Any) -> Any:
        if isinstance(value, dict):
            if value.get('__bytes__') is True:
                return base64.b64decode(value['data'].encode('utf-8'))
            return {k: self._deserialize_value(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [self._deserialize_value(item) for item in value]
        return value

    def _read_file(self, file_path: str) -> Dict[str, Any]:
        try:
            with open(file_path, 'r') as f:
                raw = json.load(f)
            return {k: self._deserialize_value(v) for k, v in raw.items()}
        except (json.JSONDecodeError, FileNotFoundError):
            return {}

    def _write_file(self, file_path: str, data: Dict[str, Any]) -> bool:
        try:
            serialized = {k: self._serialize_value(v) for k, v in data.items()}
            with open(file_path, 'w') as f:
                json.dump(serialized, f, indent=2)
            return True
        except (IOError, OSError):
            return False

    def save_session(self, session_id: str, session_data: Dict[str, Any]) -> bool:
        with self._lock:
            sessions = self._read_file(self._sessions_file)
            sessions[session_id] = dict(session_data)
            return self._write_file(self._sessions_file, sessions)

    def load_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            sessions = self._read_file(self._sessions_file)
            data = sessions.get(session_id)
            return dict(data) if data else None

    def delete_session(self, session_id: str) -> bool:
        with self._lock:
            sessions = self._read_file(self._sessions_file)
            if session_id not in sessions:
                return False
            del sessions[session_id]
            return self._write_file(self._sessions_file, sessions)

    def load_all_sessions(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            return self._read_file(self._sessions_file)

    def save_user(self, username: str, user_data: Dict[str, Any]) -> bool:
        with self._lock:
            users = self._read_file(self._users_file)
            users[username] = dict(user_data)
            return self._write_file(self._users_file, users)

    def load_user(self, username: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            users = self._read_file(self._users_file)
            data = users.get(username)
            return dict(data) if data else None

    def delete_user(self, username: str) -> bool:
        with self._lock:
            users = self._read_file(self._users_file)
            if username not in users:
                return False
            del users[username]
            return self._write_file(self._users_file, users)

    def load_all_users(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            return self._read_file(self._users_file)

    async def save_session_async(self, session_id: str, session_data: Dict[str, Any]) -> bool:
        await asyncio.sleep(0)
        return self.save_session(session_id, session_data)

    async def load_session_async(self, session_id: str) -> Optional[Dict[str, Any]]:
        await asyncio.sleep(0)