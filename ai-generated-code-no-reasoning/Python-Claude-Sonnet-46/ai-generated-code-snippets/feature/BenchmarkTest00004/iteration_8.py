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
from typing import Optional, Dict, Any, List, Callable
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum

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

session_request_counts = {}
session_request_counts_lock = threading.Lock()
async_session_request_counts = {}
async_session_request_counts_lock = asyncio.Lock()

db_pool = []
db_pool_lock = threading.Lock()
DB_POOL_SIZE = int(os.environ.get('DB_POOL_SIZE', 5))


class AuthProviderType(Enum):
    LOCAL = "local"
    OAUTH2 = "oauth2"
    SAML = "saml"
    LDAP = "ldap"
    OPENID_CONNECT = "openid_connect"
    API_KEY = "api_key"
    JWT = "jwt"
    CUSTOM = "custom"


@dataclass
class AuthCredentials:
    provider_type: AuthProviderType
    identifier: str
    secret: Optional[str] = None
    token: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthResult:
    success: bool
    user_id: Optional[str] = None
    provider_type: Optional[AuthProviderType] = None
    provider_name: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    requires_mfa: bool = False
    mfa_token: Optional[str] = None


@dataclass
class AuthProviderConfig:
    name: str
    provider_type: AuthProviderType
    enabled: bool = True
    priority: int = 0
    settings: Dict[str, Any] = field(default_factory=dict)


class AuthProvider(ABC):
    def __init__(self, config: AuthProviderConfig):
        self.config = config
        self.name = config.name
        self.provider_type = config.provider_type
        self.enabled = config.enabled
        self.priority = config.priority

    @abstractmethod
    def authenticate(self, credentials: AuthCredentials) -> AuthResult:
        pass

    @abstractmethod
    async def async_authenticate(self, credentials: AuthCredentials) -> AuthResult:
        pass

    @abstractmethod
    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    async def async_validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        pass

    def is_applicable(self, credentials: AuthCredentials) -> bool:
        return credentials.provider_type == self.provider_type

    def get_provider_info(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'type': self.provider_type.value,
            'enabled': self.enabled,
            'priority': self.priority
        }


class LocalAuthProvider(AuthProvider):
    def __init__(self, config: AuthProviderConfig, user_store: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._user_store = user_store or {}
        self._user_store_lock = threading.Lock()
        self._async_user_store_lock = asyncio.Lock()

    def _hash_password(self, password: str, salt: Optional[str] = None) -> tuple:
        if salt is None:
            salt = os.urandom(16).hex()
        hashed = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        ).hex()
        return hashed, salt

    def _verify_password(self, password: str, hashed: str, salt: str) -> bool:
        computed, _ = self._hash_password(password, salt)
        return hmac.compare_digest(computed, hashed)

    def register_user(self, user_id: str, password: str, attributes: Optional[Dict[str, Any]] = None) -> bool:
        with self._user_store_lock:
            if user_id in self._user_store:
                return False
            hashed, salt = self._hash_password(password)
            self._user_store[user_id] = {
                'password_hash': hashed,
                'salt': salt,
                'attributes': attributes or {},
                'created_at': time.time(),
                'last_login': None,
                'failed_attempts': 0,
                'locked_until': None
            }
            return True

    async def async_register_user(self, user_id: str, password: str, attributes: Optional[Dict[str, Any]] = None) -> bool:
        async with self._async_user_store_lock:
            if user_id in self._user_store:
                return False
            hashed, salt = self._hash_password(password)
            self._user_store[user_id] = {
                'password_hash': hashed,
                'salt': salt,
                'attributes': attributes or {},
                'created_at': time.time(),
                'last_login': None,
                'failed_attempts': 0,
                'locked_until': None
            }
            return True

    def _check_lockout(self, user_data: Dict[str, Any]) -> bool:
        locked_until = user_data.get('locked_until')
        if locked_until and time.time() < locked_until:
            return True
        return False

    def _record_failed_attempt(self, user_id: str, max_attempts: int = 5, lockout_duration: int = 300):
        with self._user_store_lock:
            if user_id in self._user_store:
                self._user_store[user_id]['failed_attempts'] = self._user_store[user_id].get('failed_attempts', 0) + 1
                if self._user_store[user_id]['failed_attempts'] >= max_attempts:
                    self._user_store[user_id]['locked_until'] = time.time() + lockout_duration

    def _record_successful_login(self, user_id: str):
        with self._user_store_lock:
            if user_id in self._user_store:
                self._user_store[user_id]['failed_attempts'] = 0
                self._user_store[user_id]['locked_until'] = None
                self._user_store[user_id]['last_login'] = time.time()

    def authenticate(self, credentials: AuthCredentials) -> AuthResult:
        user_id = credentials.identifier
        password = credentials.secret

        if not user_id or not password:
            return AuthResult(success=False, error="Missing credentials")

        with self._user_store_lock:
            user_data = self._user_store.get(user_id)

        if not user_data:
            return AuthResult(success=False, error="Invalid credentials")

        if self._check_lockout(user_data):
            return AuthResult(success=False, error="Account locked")

        if not self._verify_password(password, user_data['password_hash'], user_data['salt']):
            self._record_failed_attempt(user_id)
            return AuthResult(success=False, error="Invalid credentials")

        self._record_successful_login(user_id)
        return AuthResult(
            success=True,
            user_id=user_id,
            provider_type=self.provider_type,
            provider_name=self.name,
            attributes=user_data.get('attributes', {})
        )

    async def async_authenticate(self, credentials: AuthCredentials) -> AuthResult:
        user_id = credentials.identifier
        password = credentials.secret

        if not user_id or not password:
            return AuthResult(success=False, error="Missing credentials")

        async with self._async_user_store_lock:
            user_data = self._user_store.get(user_id)

        if not user_data:
            return AuthResult(success=False, error="Invalid credentials")

        if self._check_lockout(user_data):
            return AuthResult(success=False, error="Account locked")

        if not self._verify_password(password, user_data['password_hash'], user_data['salt']):
            self._record_failed_attempt(user_id)
            return AuthResult(success=False, error="Invalid credentials")

        self._record_successful_login(user_id)
        return AuthResult(
            success=True,
            user_id=user_id,
            provider_type=self.provider_type,
            provider_name=self.name,
            attributes=user_data.get('attributes', {})
        )

    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        return None

    async def async_validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        return None


class ApiKeyAuthProvider(AuthProvider):
    def __init__(self, config: AuthProviderConfig, api_key_store: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._api_key_store = api_key_store or {}
        self._api_key_store_lock = threading.Lock()
        self._async_api_key_store_lock = asyncio.Lock()

    def register_api_key(self, api_key: str, user_id: str, attributes: Optional[Dict[str, Any]] = None, expires_at: Optional[float] = None) -> bool:
        with self._api_key_store_lock:
            if api_key in self._api_key_store:
                return False
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            self._api_key_store[key_hash] = {
                'user_id': user_id,
                'attributes': attributes or {},
                'created_at': time.time(),
                'expires_at': expires_at,
                'last_used': None
            }
            return True

    async def async_register_api_key(self, api_key: str, user_id: str, attributes: Optional[Dict[str, Any]] = None, expires_at: Optional[float] = None) -> bool:
        async with self._async_api_key_store_lock:
            if api_key in self._api_key_store:
                return False
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            self._api_key_store[key_hash] = {
                'user_id': user_id,
                'attributes': attributes or {},
                'created_at': time.time(),
                'expires_at': expires_at,
                'last_used': None
            }
            return True

    def revoke_api_key(self, api_key: str) -> bool:
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        with self._api_key_store_lock:
            if key_hash in self._api_key_store:
                del self._api_key_store[key_hash]
                return True
        return False

    def authenticate(self, credentials: AuthCredentials) -> AuthResult:
        api_key = credentials.token or credentials.secret
        if not api_key:
            return AuthResult(success=False, error="Missing API key")

        key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        with self._api_key_store_lock:
            key_data = self._api_key_store.get(key_hash)

        if not key_data:
            return AuthResult(success=False, error="Invalid API key")

        expires_at = key_data.get('expires_at')
        if expires_at and time.time() > expires_at:
            return AuthResult(success=False, error="API key expired")

        with self._api_key_store_lock:
            if key_hash in self._api_key_store:
                self._api_key_store[key_hash]['last_used'] = time.time()

        return AuthResult(
            success=True,
            user_id=key_data['user_id'],
            provider_type=self.provider_type,
            provider_name=self.name,
            attributes=key_data.get('attributes', {})
        )

    async def async_authenticate(self, credentials: AuthCredentials) -> AuthResult:
        api_key = credentials.token or credentials.secret
        if not api_key:
            return AuthResult(success=False, error="Missing API key")

        key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        async with self._async_api_key_store_lock:
            key_data = self._api_key_store.get(key_hash)

        if not key_data:
            return AuthResult(success=False, error="Invalid API key")

        expires_at = key_data.get('expires_at')
        if expires_at and time.time() > expires_at:
            return AuthResult(success=False, error="API key expired")

        async with self._async_api_key_store_lock:
            if key_hash in self._api_key_store:
                self._api_key_store[key_hash]['last_used'] = time.time()

        return AuthResult(
            success=True,
            user_id=key_data['user_id'],
            provider_type=self.provider_type,
            provider_name=self.name,
            attributes=key_data.get('attributes', {})
        )

    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        key_hash = hashlib.sha256(token.encode()).hexdigest()
        with self._api_key_store_lock:
            key_data = self._api_key_store.get(key_hash)
        if not key_data:
            return None
        expires_at = key_data.get('expires_at')