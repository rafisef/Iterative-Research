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
import asyncio
import uuid
import json
import os
import sqlite3
import aiosqlite
import time
import hashlib
import hmac
import aiofiles
import aiofiles.os
from contextlib import contextmanager, asynccontextmanager
from typing import Optional, Dict, Any, List, Callable, Set, Tuple
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import weakref
import logging
import queue
import concurrent.futures

logger = logging.getLogger(__name__)

session_store = {}
session_lock = threading.Lock()
async_session_lock = asyncio.Lock()
session_locks = {}
session_locks_lock = threading.Lock()
async_session_locks = {}
async_session_locks_lock = asyncio.Lock()
user_session_index = {}
user_session_index_lock = threading.Lock()
async_user_session_index = {}
async_user_session_index_lock = asyncio.Lock()

STORAGE_BACKEND = os.environ.get('SESSION_STORAGE_BACKEND', 'memory')
SESSION_FILE_DIR = os.environ.get('SESSION_FILE_DIR', '/tmp/sessions')
SESSION_DB_PATH = os.environ.get('SESSION_DB_PATH', '/tmp/sessions.db')
SESSION_MAX_AGE = int(os.environ.get('SESSION_MAX_AGE', 1800))
SESSION_SECRET = os.environ.get('SESSION_SECRET', os.urandom(32).hex())
MAX_SESSIONS_PER_USER = int(os.environ.get('MAX_SESSIONS_PER_USER', 10))
SESSION_ROTATION_INTERVAL = int(os.environ.get('SESSION_ROTATION_INTERVAL', 300))
MAX_CONCURRENT_REQUESTS_PER_SESSION = int(os.environ.get('MAX_CONCURRENT_REQUESTS_PER_SESSION', 10))
MAX_CONCURRENT_SESSIONS_GLOBAL = int(os.environ.get('MAX_CONCURRENT_SESSIONS_GLOBAL', 10000))
SESSION_CLEANUP_INTERVAL = int(os.environ.get('SESSION_CLEANUP_INTERVAL', 60))
SESSION_HEARTBEAT_INTERVAL = int(os.environ.get('SESSION_HEARTBEAT_INTERVAL', 30))
CONCURRENT_SESSION_POLICY = os.environ.get('CONCURRENT_SESSION_POLICY', 'allow')

session_request_counts = {}
session_request_counts_lock = threading.Lock()
async_session_request_counts = {}
async_session_request_counts_lock = asyncio.Lock()

session_active_requests = {}
session_active_requests_lock = threading.Lock()
async_session_active_requests = {}
async_session_active_requests_lock = asyncio.Lock()

session_semaphores = {}
session_semaphores_lock = threading.Lock()
async_session_semaphores = {}
async_session_semaphores_lock = asyncio.Lock()

session_heartbeats = {}
session_heartbeats_lock = threading.Lock()

concurrent_session_events = {}
concurrent_session_events_lock = threading.Lock()
async_concurrent_session_events = {}
async_concurrent_session_events_lock = asyncio.Lock()

global_session_semaphore = threading.Semaphore(MAX_CONCURRENT_SESSIONS_GLOBAL)
async_global_session_semaphore = None

db_pool = []
db_pool_lock = threading.Lock()
DB_POOL_SIZE = int(os.environ.get('DB_POOL_SIZE', 5))

thread_pool = concurrent.futures.ThreadPoolExecutor(
    max_workers=int(os.environ.get('SESSION_THREAD_POOL_SIZE', 20))
)

_cleanup_thread = None
_cleanup_thread_lock = threading.Lock()
_async_cleanup_task = None


class AuthProviderType(Enum):
    LOCAL = 'local'
    OAUTH2 = 'oauth2'
    SAML = 'saml'
    LDAP = 'ldap'
    OPENID_CONNECT = 'openid_connect'
    API_KEY = 'api_key'
    JWT = 'jwt'
    CUSTOM = 'custom'


@dataclass
class AuthProviderConfig:
    provider_id: str
    provider_type: AuthProviderType
    display_name: str
    enabled: bool = True
    priority: int = 0
    config: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthResult:
    success: bool
    user_id: Optional[str] = None
    provider_id: Optional[str] = None
    provider_type: Optional[AuthProviderType] = None
    claims: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    requires_mfa: bool = False
    mfa_token: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthProviderCredentials:
    provider_id: str
    credentials: Dict[str, Any] = field(default_factory=dict)
    raw_token: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)


class AuthProvider(ABC):
    def __init__(self, config: AuthProviderConfig):
        self.config = config
        self.provider_id = config.provider_id
        self.provider_type = config.provider_type
        self.enabled = config.enabled

    @abstractmethod
    def authenticate(self, credentials: AuthProviderCredentials) -> AuthResult:
        pass

    @abstractmethod
    async def async_authenticate(self, credentials: AuthProviderCredentials) -> AuthResult:
        pass

    def is_enabled(self) -> bool:
        return self.enabled

    def get_provider_id(self) -> str:
        return self.provider_id

    def get_provider_type(self) -> AuthProviderType:
        return self.provider_type

    def get_config(self) -> AuthProviderConfig:
        return self.config

    def validate_credentials(self, credentials: AuthProviderCredentials) -> bool:
        return credentials.provider_id == self.provider_id

    def refresh_token(self, token: str) -> Optional[str]:
        return None

    async def async_refresh_token(self, token: str) -> Optional[str]:
        return None

    def revoke_token(self, token: str) -> bool:
        return True

    async def async_revoke_token(self, token: str) -> bool:
        return True

    def get_user_info(self, token: str) -> Optional[Dict[str, Any]]:
        return None

    async def async_get_user_info(self, token: str) -> Optional[Dict[str, Any]]:
        return None


class LocalAuthProvider(AuthProvider):
    def __init__(self, config: AuthProviderConfig):
        super().__init__(config)
        self._user_store: Dict[str, Dict[str, Any]] = {}
        self._user_store_lock = threading.Lock()
        self._async_user_store_lock = asyncio.Lock()

    def _hash_password(self, password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        if salt is None:
            salt = os.urandom(32).hex()
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
        return hashed, salt

    def _verify_password(self, password: str, hashed: str, salt: str) -> bool:
        computed, _ = self._hash_password(password, salt)
        return hmac.compare_digest(computed, hashed)

    def register_user(self, user_id: str, password: str, metadata: Optional[Dict[str, Any]] = None) -> bool:
        hashed, salt = self._hash_password(password)
        with self._user_store_lock:
            if user_id in self._user_store:
                return False
            self._user_store[user_id] = {
                'user_id': user_id,
                'password_hash': hashed,
                'salt': salt,
                'created_at': time.time(),
                'metadata': metadata or {},
                'active': True,
                'failed_attempts': 0,
                'locked_until': None
            }
        return True

    async def async_register_user(self, user_id: str, password: str, metadata: Optional[Dict[str, Any]] = None) -> bool:
        hashed, salt = self._hash_password(password)
        async with self._async_user_store_lock:
            if user_id in self._user_store:
                return False
            self._user_store[user_id] = {
                'user_id': user_id,
                'password_hash': hashed,
                'salt': salt,
                'created_at': time.time(),
                'metadata': metadata or {},
                'active': True,
                'failed_attempts': 0,
                'locked_until': None
            }
        return True

    def authenticate(self, credentials: AuthProviderCredentials) -> AuthResult:
        if not self.validate_credentials(credentials):
            return AuthResult(success=False, error='Invalid provider')

        user_id = credentials.credentials.get('username') or credentials.credentials.get('user_id')
        password = credentials.credentials.get('password')

        if not user_id or not password:
            return AuthResult(success=False, error='Missing credentials')

        with self._user_store_lock:
            user = self._user_store.get(user_id)

        if user is None:
            return AuthResult(success=False, error='User not found')

        if not user.get('active'):
            return AuthResult(success=False, error='Account disabled')

        locked_until = user.get('locked_until')
        if locked_until and time.time() < locked_until:
            return AuthResult(success=False, error='Account temporarily locked')

        if not self._verify_password(password, user['password_hash'], user['salt']):
            with self._user_store_lock:
                if user_id in self._user_store:
                    self._user_store[user_id]['failed_attempts'] = self._user_store[user_id].get('failed_attempts', 0) + 1
                    if self._user_store[user_id]['failed_attempts'] >= 5:
                        self._user_store[user_id]['locked_until'] = time.time() + 300
            return AuthResult(success=False, error='Invalid credentials')

        with self._user_store_lock:
            if user_id in self._user_store:
                self._user_store[user_id]['failed_attempts'] = 0
                self._user_store[user_id]['locked_until'] = None

        return AuthResult(
            success=True,
            user_id=user_id,
            provider_id=self.provider_id,
            provider_type=self.provider_type,
            claims={'sub': user_id, 'metadata': user.get('metadata', {})}
        )

    async def async_authenticate(self, credentials: AuthProviderCredentials) -> AuthResult:
        if not self.validate_credentials(credentials):
            return AuthResult(success=False, error='Invalid provider')

        user_id = credentials.credentials.get('username') or credentials.credentials.get('user_id')
        password = credentials.credentials.get('password')

        if not user_id or not password:
            return AuthResult(success=False, error='Missing credentials')

        async with self._async_user_store_lock:
            user = self._user_store.get(user_id)

        if user is None:
            return AuthResult(success=False, error='User not found')

        if not user.get('active'):
            return AuthResult(success=False, error='Account disabled')

        locked_until = user.get('locked_until')
        if locked_until and time.time() < locked_until:
            return AuthResult(success=False, error='Account temporarily locked')

        if not self._verify_password(password, user['password_hash'], user['salt']):
            async with self._async_user_store_lock:
                if user_id in self._user_store:
                    self._user_store[user_id]['failed_attempts'] = self._user_store[user_id].get('failed_attempts', 0) + 1
                    if self._user_store[user_id]['failed_attempts'] >= 5:
                        self._user_store[user_id]['locked_until'] = time.time() + 300
            return AuthResult(success=False, error='Invalid credentials')

        async with self._async_user_store_lock:
            if user_id in self._user_store:
                self._user_store[user_id]['failed_attempts'] = 0
                self._user_store[user_id]['locked_until'] = None

        return AuthResult(
            success=True,
            user_id=user_id,
            provider_id=self.provider_id,
            provider_type=self.provider_type,
            claims={'sub': user_id, 'metadata': user.get('metadata', {})}
        )


class OAuth2AuthProvider(AuthProvider):
    def __init__(self, config: AuthProviderConfig):
        super().__init__(config)
        self._token_store: Dict[str, Dict[str, Any]] = {}
        self._token_store_lock = threading.Lock()
        self._async_token_store_lock = asyncio.Lock()

    def _validate_oauth2_token(self, token: str) -> Optional[Dict[str, Any]]:
        with self._token_store_lock:
            token_data = self._token_store.get(token)
        if token_data is None:
            return None
        if time.time() > token_data.get('expires_at', 0):
            return None
        return token_data

    async def _async_validate_oauth2_token(self, token: str) -> Optional[Dict[str, Any]]:
        async with self._async_token_store_lock:
            token_data = self._token_store.get(token)
        if token_data is None:
            return None
        if time.time() > token_data.get('expires_at', 0):
            return None
        return token_data

    def register_token(self, token: str, user_id: str, scopes: List[str], expires_in: int = 3600, claims: Optional[Dict[str, Any]] = None) -> bool:
        with self._token_store_lock:
            self._token_store[token] = {
                'token': token,
                'user_id': user_id,
                'scopes': scopes,
                'created_at': time.time(),
                'expires_at': time.time() + expires_in,
                'claims': claims or {}
            }
        return True

    async def async_register_token(self, token: str, user_id: str, scopes: List[str], expires_in: int = 3600, claims: Optional[Dict[str, Any]] = None) -> bool:
        async with self._async_token_store_lock:
            self._token_store[token] = {
                'token': token,
                'user_id': user_id,
                'scopes': scopes,
                'created_at': time.time(),