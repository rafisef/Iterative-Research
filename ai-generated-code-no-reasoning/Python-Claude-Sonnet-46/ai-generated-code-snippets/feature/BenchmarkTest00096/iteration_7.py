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
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, Union, List

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


class SessionManager:
    def __init__(self, session_timeout: int = None, max_sessions: int = None):
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._user_sessions: Dict[str, List[str]] = {}
        self._lock = threading.RLock()
        self._session_timeout = session_timeout if session_timeout is not None else ENV_SESSION_TIMEOUT
        self._max_sessions = max_sessions if max_sessions is not None else ENV_MAX_CONCURRENT_SESSIONS

    def create_session(self, user_id: str, metadata: Dict[str, Any] = None) -> Optional[str]:
        with self._lock:
            self._cleanup_expired_sessions()
            user_session_list = self._user_sessions.get(user_id, [])
            active = [s for s in user_session_list if s in self._sessions]
            if len(active) >= self._max_sessions:
                return None
            session_id = str(uuid.uuid4())
            self._sessions[session_id] = {
                'user_id': user_id,
                'created_at': time.time(),
                'last_accessed': time.time(),
                'metadata': metadata or {}
            }
            if user_id not in self._user_sessions:
                self._user_sessions[user_id] = []
            self._user_sessions[user_id].append(session_id)
            return session_id

    async def create_session_async(self, user_id: str, metadata: Dict[str, Any] = None) -> Optional[str]:
        await asyncio.sleep(0)
        return self.create_session(user_id, metadata)

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            if time.time() - session['last_accessed'] > self._session_timeout:
                self._remove_session(session_id)
                return None
            session['last_accessed'] = time.time()
            return dict(session)

    async def get_session_async(self, session_id: str) -> Optional[Dict[str, Any]]:
        await asyncio.sleep(0)
        return self.get_session(session_id)

    def update_session(self, session_id: str, metadata: Dict[str, Any]) -> bool:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return False
            if time.time() - session['last_accessed'] > self._session_timeout:
                self._remove_session(session_id)
                return False
            session['metadata'].update(metadata)
            session['last_accessed'] = time.time()
            return True

    async def update_session_async(self, session_id: str, metadata: Dict[str, Any]) -> bool:
        await asyncio.sleep(0)
        return self.update_session(session_id, metadata)

    def destroy_session(self, session_id: str) -> bool:
        with self._lock:
            return self._remove_session(session_id)

    async def destroy_session_async(self, session_id: str) -> bool:
        await asyncio.sleep(0)
        return self.destroy_session(session_id)

    def destroy_all_user_sessions(self, user_id: str) -> int:
        with self._lock:
            session_ids = list(self._user_sessions.get(user_id, []))
            count = 0
            for session_id in session_ids:
                if self._remove_session(session_id):
                    count += 1
            return count

    async def destroy_all_user_sessions_async(self, user_id: str) -> int:
        await asyncio.sleep(0)
        return self.destroy_all_user_sessions(user_id)

    def get_user_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            self._cleanup_expired_sessions()
            session_ids = self._user_sessions.get(user_id, [])
            result = []
            for session_id in session_ids:
                session = self._sessions.get(session_id)
                if session:
                    entry = dict(session)
                    entry['session_id'] = session_id
                    result.append(entry)
            return result

    async def get_user_sessions_async(self, user_id: str) -> List[Dict[str, Any]]:
        await asyncio.sleep(0)
        return self.get_user_sessions(user_id)

    def count_user_sessions(self, user_id: str) -> int:
        with self._lock:
            self._cleanup_expired_sessions()
            return len([s for s in self._user_sessions.get(user_id, []) if s in self._sessions])

    async def count_user_sessions_async(self, user_id: str) -> int:
        await asyncio.sleep(0)
        return self.count_user_sessions(user_id)

    def is_session_valid(self, session_id: str) -> bool:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return False
            if time.time() - session['last_accessed'] > self._session_timeout:
                self._remove_session(session_id)
                return False
            return True

    async def is_session_valid_async(self, session_id: str) -> bool:
        await asyncio.sleep(0)
        return self.is_session_valid(session_id)

    def _remove_session(self, session_id: str) -> bool:
        session = self._sessions.pop(session_id, None)
        if session is None:
            return False
        user_id = session.get('user_id')
        if user_id and user_id in self._user_sessions:
            try:
                self._user_sessions[user_id].remove(session_id)
            except ValueError:
                pass
            if not self._user_sessions[user_id]:
                del self._user_sessions[user_id]
        return True

    def _cleanup_expired_sessions(self):
        now = time.time()
        expired = [
            sid for sid, s in self._sessions.items()
            if now - s['last_accessed'] > self._session_timeout
        ]
        for session_id in expired:
            self._remove_session(session_id)

    def cleanup_expired_sessions(self) -> int:
        with self._lock:
            before = len(self._sessions)
            self._cleanup_expired_sessions()
            return before - len(self._sessions)

    async def cleanup_expired_sessions_async(self) -> int:
        await asyncio.sleep(0)
        return self.cleanup_expired_sessions()

    def list_all_sessions(self) -> List[Dict[str, Any]]:
        with self._lock:
            self._cleanup_expired_sessions()
            result = []
            for session_id, session in self._sessions.items():
                entry = dict(session)
                entry['session_id'] = session_id
                result.append(entry)
            return result

    async def list_all_sessions_async(self) -> List[Dict[str, Any]]:
        await asyncio.sleep(0)
        return self.list_all_sessions()

    def get_total_session_count(self) -> int:
        with self._lock:
            self._cleanup_expired_sessions()
            return len(self._sessions)

    async def get_total_session_count_async(self) -> int:
        await asyncio.sleep(0)
        return self.get_total_session_count()


def run_async(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(f(*args, **kwargs))
        finally:
            loop.close()
    return wrapper


async def process_param_async(param):
    await asyncio.sleep(0)
    possible = "ABC"
    guess = possible[0]

    match guess:
        case 'A':
            bar = param
        case 'B':
            bar = 'bob'
        case 'C' | 'D':
            bar = param
        case _:
            bar = 'bob\'s your uncle'

    return bar


def process_param_sync(param):
    possible = "ABC"
    guess = possible[0]

    match guess:
        case 'A':
            bar = param
        case 'B':
            bar = 'bob'
        case 'C' | 'D':
            bar = param
        case _:
            bar = 'bob\'s your uncle'

    return bar


class AuthProvider(ABC):
    @abstractmethod
    def authenticate(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    async def authenticate_async(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def get_provider_name(self) -> str:
        pass

    @abstractmethod
    def validate_token(self, token: str) -> bool:
        pass

    @abstractmethod
    async def validate_token_async(self, token: str) -> bool:
        pass

    def get_provider_metadata(self) -> Dict[str, Any]:
        return {
            'name': self.get_provider_name(),
            'type': self.__class__.__name__
        }

    async def get_provider_metadata_async(self) -> Dict[str, Any]:
        await asyncio.sleep(0)
        return self.get_provider_metadata()


class BasicAuthProvider(AuthProvider):
    def __init__(self, iterations: int = None, session_manager: SessionManager = None):
        self._users = {}
        self._lock = threading.RLock()
        self._iterations = iterations if iterations is not None else ENV_PBKDF2_ITERATIONS
        self._session_manager = session_manager if session_manager is not None else SessionManager()
        self._active_tokens: Dict[str, str] = {}

    def register_user(self, username: str, password: str):
        salt = os.urandom(16)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, self._iterations)
        with self._lock:
            self._users[username] = {
                'salt': salt,
                'hash': password_hash
            }

    async def register_user_async(self, username: str, password: str):
        await asyncio.sleep(0)
        self.register_user(username, password)

    def get_provider_name(self) -> str:
        return 'basic'

    def authenticate(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        username = credentials.get('username')
        password = credentials.get('password')

        if not username or not password:
            return None

        with self._lock:
            user_data = self._users.get(username)

        if not user_data:
            return None

        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            user_data['salt'],
            self._iterations
        )

        if