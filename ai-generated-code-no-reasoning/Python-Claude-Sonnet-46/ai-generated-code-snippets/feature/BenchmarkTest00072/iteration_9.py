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
import hashlib
import hmac
import base64
import asyncio
import inspect
from collections import defaultdict
from abc import ABC, abstractmethod
from functools import wraps
from concurrent.futures import ThreadPoolExecutor

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

AUTH_PROVIDER = os.environ.get('AUTH_PROVIDER', 'local')
AUTH_PROVIDERS_ENABLED = os.environ.get('AUTH_PROVIDERS_ENABLED', 'local').split(',')
OAUTH2_CLIENT_ID = os.environ.get('OAUTH2_CLIENT_ID', '')
OAUTH2_CLIENT_SECRET = os.environ.get('OAUTH2_CLIENT_SECRET', '')
OAUTH2_REDIRECT_URI = os.environ.get('OAUTH2_REDIRECT_URI', '')
OAUTH2_AUTHORIZATION_URL = os.environ.get('OAUTH2_AUTHORIZATION_URL', '')
OAUTH2_TOKEN_URL = os.environ.get('OAUTH2_TOKEN_URL', '')
OAUTH2_USERINFO_URL = os.environ.get('OAUTH2_USERINFO_URL', '')
SAML_IDP_METADATA_URL = os.environ.get('SAML_IDP_METADATA_URL', '')
SAML_SP_ENTITY_ID = os.environ.get('SAML_SP_ENTITY_ID', '')
SAML_SP_ACS_URL = os.environ.get('SAML_SP_ACS_URL', '')
LDAP_SERVER_URL = os.environ.get('LDAP_SERVER_URL', '')
LDAP_BASE_DN = os.environ.get('LDAP_BASE_DN', '')
LDAP_BIND_DN = os.environ.get('LDAP_BIND_DN', '')
LDAP_BIND_PASSWORD = os.environ.get('LDAP_BIND_PASSWORD', '')
LDAP_USER_SEARCH_FILTER = os.environ.get('LDAP_USER_SEARCH_FILTER', '(uid={username})')
API_KEY_HEADER = os.environ.get('API_KEY_HEADER', 'X-API-Key')
API_KEY_HASH_ALGORITHM = os.environ.get('API_KEY_HASH_ALGORITHM', 'sha256')
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', '')
JWT_ALGORITHM = os.environ.get('JWT_ALGORITHM', 'HS256')
JWT_ISSUER = os.environ.get('JWT_ISSUER', '')
JWT_AUDIENCE = os.environ.get('JWT_AUDIENCE', '')

_executor = ThreadPoolExecutor(max_workers=int(os.environ.get('AUTH_THREAD_POOL_SIZE', 10)))


def run_sync_or_async(func, *args, **kwargs):
    if inspect.iscoroutinefunction(func):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(func(*args, **kwargs))
        finally:
            loop.close()
    return func(*args, **kwargs)


async def run_in_executor(func, *args, **kwargs):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_executor, lambda: func(*args, **kwargs))


def supports_async(method):
    @wraps(method)
    def wrapper(self, *args, **kwargs):
        result = method(self, *args, **kwargs)
        if inspect.iscoroutine(result):
            return result
        return result
    return wrapper


class AuthenticationError(Exception):
    pass


class AuthProviderNotFoundError(AuthenticationError):
    pass


class AuthCredentialsError(AuthenticationError):
    pass


class AuthProviderBase(ABC):

    @abstractmethod
    def authenticate(self, credentials):
        pass

    async def authenticate_async(self, credentials):
        return await run_in_executor(self.authenticate, credentials)

    @abstractmethod
    def get_provider_name(self):
        pass

    @abstractmethod
    def get_provider_type(self):
        pass

    @abstractmethod
    def validate_credentials_format(self, credentials):
        pass

    async def validate_credentials_format_async(self, credentials):
        return await run_in_executor(self.validate_credentials_format, credentials)

    @abstractmethod
    def get_user_info(self, auth_result):
        pass

    async def get_user_info_async(self, auth_result):
        return await run_in_executor(self.get_user_info, auth_result)

    @abstractmethod
    def supports_logout(self):
        pass

    @abstractmethod
    def logout(self, auth_result):
        pass

    async def logout_async(self, auth_result):
        return await run_in_executor(self.logout, auth_result)

    @abstractmethod
    def refresh_token(self, auth_result):
        pass

    async def refresh_token_async(self, auth_result):
        return await run_in_executor(self.refresh_token, auth_result)

    @abstractmethod
    def is_token_valid(self, token):
        pass

    async def is_token_valid_async(self, token):
        return await run_in_executor(self.is_token_valid, token)

    @abstractmethod
    def get_provider_metadata(self):
        pass

    async def get_provider_metadata_async(self):
        return await run_in_executor(self.get_provider_metadata)

    def call_method(self, method_name, *args, **kwargs):
        method = getattr(self, method_name)
        return method(*args, **kwargs)

    async def call_method_async(self, method_name, *args, **kwargs):
        method = getattr(self, method_name + '_async', None)
        if method is None:
            sync_method = getattr(self, method_name)
            return await run_in_executor(sync_method, *args, **kwargs)
        return await method(*args, **kwargs)


class LocalAuthProvider(AuthProviderBase):

    def __init__(self, user_store=None):
        self._user_store = user_store or {}
        self._lock = threading.RLock()
        self._async_lock = None
        self._failed_attempts = defaultdict(int)
        self._lockout_until = {}
        self._max_attempts = int(os.environ.get('LOCAL_AUTH_MAX_ATTEMPTS', 5))
        self._lockout_seconds = int(os.environ.get('LOCAL_AUTH_LOCKOUT_SECONDS', 300))

    def _get_async_lock(self):
        if self._async_lock is None:
            self._async_lock = asyncio.Lock()
        return self._async_lock

    def _hash_password(self, password, salt=None):
        if salt is None:
            salt = os.urandom(32)
        if isinstance(salt, str):
            salt = bytes.fromhex(salt)
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return salt.hex(), key.hex()

    def _verify_password(self, password, salt_hex, key_hex):
        _, computed_key = self._hash_password(password, salt_hex)
        return hmac.compare_digest(computed_key, key_hex)

    def register_user(self, username, password, roles=None, metadata=None):
        with self._lock:
            if username in self._user_store:
                raise AuthenticationError(f'User {username} already exists')
            salt, key = self._hash_password(password)
            self._user_store[username] = {
                'username': username,
                'salt': salt,
                'key': key,
                'roles': roles or ['user'],
                'metadata': metadata or {},
                'created_at': time.time(),
                'active': True
            }

    async def register_user_async(self, username, password, roles=None, metadata=None):
        return await run_in_executor(self.register_user, username, password, roles, metadata)

    def authenticate(self, credentials):
        username = credentials.get('username', '')
        password = credentials.get('password', '')
        with self._lock:
            now = time.time()
            lockout_until = self._lockout_until.get(username, 0)
            if now < lockout_until:
                raise AuthCredentialsError(f'Account locked until {lockout_until}')
            user = self._user_store.get(username)
            if not user or not user.get('active', False):
                self._failed_attempts[username] += 1
                if self._failed_attempts[username] >= self._max_attempts:
                    self._lockout_until[username] = now + self._lockout_seconds
                raise AuthCredentialsError('Invalid username or password')
            if not self._verify_password(password, user['salt'], user['key']):
                self._failed_attempts[username] += 1
                if self._failed_attempts[username] >= self._max_attempts:
                    self._lockout_until[username] = now + self._lockout_seconds
                raise AuthCredentialsError('Invalid username or password')
            self._failed_attempts[username] = 0
            self._lockout_until.pop(username, None)
            return {
                'username': username,
                'roles': user.get('roles', ['user']),
                'metadata': user.get('metadata', {}),
                'provider': self.get_provider_name(),
                'authenticated_at': now
            }

    async def authenticate_async(self, credentials):
        return await run_in_executor(self.authenticate, credentials)

    def get_provider_name(self):
        return 'local'

    def get_provider_type(self):
        return 'local'

    def validate_credentials_format(self, credentials):
        if not isinstance(credentials, dict):
            return False
        if 'username' not in credentials or 'password' not in credentials:
            return False
        if not isinstance(credentials['username'], str) or not isinstance(credentials['password'], str):
            return False
        if len(credentials['username']) == 0 or len(credentials['password']) == 0:
            return False
        return True

    def get_user_info(self, auth_result):
        username = auth_result.get('username', '')
        with self._lock:
            user = self._user_store.get(username, {})
            return {
                'username': username,
                'roles': user.get('roles', []),
                'metadata': user.get('metadata', {}),
                'provider': self.get_provider_name()
            }

    async def get_user_info_async(self, auth_result):
        return await run_in_executor(self.get_user_info, auth_result)

    def supports_logout(self):
        return True

    def logout(self, auth_result):
        return True

    async def logout_async(self, auth_result):
        return await run_in_executor(self.logout, auth_result)

    def refresh_token(self, auth_result):
        return auth_result

    async def refresh_token_async(self, auth_result):
        return await run_in_executor(self.refresh_token, auth_result)

    def is_token_valid(self, token):
        return True

    async def is_token_valid_async(self, token):
        return await run_in_executor(self.is_token_valid, token)

    def get_provider_metadata(self):
        return {
            'name': self.get_provider_name(),
            'type': self.get_provider_type(),
            'supports_logout': self.supports_logout(),
            'supports_refresh': False,
            'requires_mfa': False
        }

    async def get_provider_metadata_async(self):
        return await run_in_executor(self.get_provider_metadata)


class ApiKeyAuthProvider(AuthProviderBase):

    def __init__(self, key_store=None):
        self._key_store = key_store or {}
        self._lock = threading.RLock()
        self._algorithm = API_KEY_HASH_ALGORITHM

    def _hash_key(self, api_key):
        h = hashlib.new(self._algorithm)
        h.update(api_key.encode('utf-8'))
        return h.hexdigest()

    def register_api_key(self, api_key, user_id, roles=None, metadata=None, expiry=None):
        with self._lock:
            key_hash = self._hash_key(api_key)
            self._key_store[key_hash] = {
                'user_id': user_id,
                'roles': roles or ['api'],
                'metadata': metadata or {},
                'created_at': time.time(),
                'expiry': expiry,
                'active': True
            }
            return key_hash

    async def register_api_key_async(self, api_key, user_id, roles=None, metadata=None, expiry=None):
        return await run_in_executor(self.register_api_key, api_key, user_id, roles, metadata, expiry)

    def authenticate(self, credentials):
        api_key = credentials.get('api_key', '')
        if not api_key:
            api_key = credentials.get('token', '')
        with self._lock:
            key_hash = self._hash_key(api_key)
            key_data = self._key_store.get(key_hash)
            if not key_data or not key_data.get('active', False):
                raise AuthCredentialsError('Invalid API key')
            expiry = key_data.get('expiry')
            if expiry and time.time() > expiry:
                raise AuthCredentialsError('API key has expired')
            return {
                'user_id': key_data['user_id'],
                'roles': key_data.get('roles', ['api']),
                'metadata': key_data.get('metadata', {}),
                'provider': self.