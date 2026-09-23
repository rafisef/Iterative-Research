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


class SessionLimitExceededError(Exception):
    pass


class SessionNotFoundError(Exception):
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


class ConcurrentSessionManager:

    def __init__(self, max_sessions_per_user=MAX_CONCURRENT_SESSIONS_PER_USER,
                 session_expiry=SESSION_EXPIRY_SECONDS,
                 cleanup_interval=SESSION_CLEANUP_INTERVAL):
        self._sessions = {}
        self._user_sessions = defaultdict(dict)
        self._lock = threading.RLock()
        self._max_sessions_per_user = max_sessions_per_user
        self._session_expiry = session_expiry
        self._cleanup_interval = cleanup_interval
        self._activity_log = defaultdict(list)
        self._session_metadata = {}
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleanup_thread.start()
        self._async_locks = {}
        self._async_locks_lock = threading.Lock()

    def _get_async_lock(self, key):
        with self._async_locks_lock:
            if key not in self._async_locks:
                self._async_locks[key] = asyncio.Lock()
            return self._async_locks[key]

    def _cleanup_loop(self):
        while True:
            time.sleep(self._cleanup_interval)
            self._cleanup_expired_sessions()

    def _cleanup_expired_sessions(self):
        now = time.time()
        with self._lock:
            expired = [
                sid for sid, sess in self._sessions.items()
                if now - sess.get('last_activity', sess.get('created_at', 0)) > self._session_expiry
            ]
            for sid in expired:
                self._remove_session_internal(sid)

    def _remove_session_internal(self, session_id):
        session = self._sessions.pop(session_id, None)
        if session:
            user_id = session.get('user_id')
            if user_id and user_id in self._user_sessions:
                self._user_sessions[user_id].pop(session_id, None)
                if not self._user_sessions[user_id]:
                    del self._user_sessions[user_id]
        self._activity_log.pop(session_id, None)
        self._session_metadata.pop(session_id, None)

    def _generate_session_id(self):
        return str(uuid.uuid4())

    def _enforce_session_limit(self, user_id):
        user_sessions = self._user_sessions.get(user_id, {})
        if len(user_sessions) >= self._max_sessions_per_user:
            oldest_sid = min(
                user_sessions.keys(),
                key=lambda sid: self._sessions.get(sid, {}).get('created_at', float('inf'))
            )
            self._remove_session_internal(oldest_sid)

    def create_session(self, user_id, auth_result, metadata=None, device_info=None, ip_address=None):
        with self._lock:
            self._enforce_session_limit(user_id)
            session_id = self._generate_session_id()
            now = time.time()
            session = {
                'session_id': session_id,
                'user_id': user_id,
                'auth_result': auth_result,
                'created_at': now,
                'last_activity': now,
                'device_info': device_info or {},
                'ip_address': ip_address or '',
                'active': True,
                'metadata': metadata or {}
            }
            self._sessions[session_id] = session
            self._user_sessions[user_id][session_id] = now
            self._session_metadata[session_id] = metadata or {}
            self._log_activity(session_id, 'session_created', {'user_id': user_id, 'ip_address': ip_address})
            return session_id

    async def create_session_async(self, user_id, auth_result, metadata=None, device_info=None, ip_address=None):
        return await run_in_executor(self.create_session, user_id, auth_result, metadata, device_info, ip_address)

    def get_session(self, session_id):
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return None
            now = time.time()
            if now - session.get('last_activity', session.get('created_at', 0)) > self._session_expiry:
                self._remove_session_internal(session_id)
                return None
            if not session.get('active', False):
                return None
            return dict(session)

    async def get_session_async(self, session_id):
        return await run_in_executor(self.get_session, session_id)

    def touch_session(self, session_id, ip_address=None):
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                raise SessionNotFoundError(f'Session {session_id} not found')
            now = time.time()
            if now - session.get('last_activity', session.get('created_at', 0)) > self._session_expiry:
                self._remove_session_internal(session_id)
                raise SessionNotFoundError(f'Session {session_id} has expired')
            session['last_activity'] = now
            if ip_address:
                session['ip_address'] = ip_address
            self._log_activity(session_id, 'session_touched', {'ip_address': ip_address})

    async def touch_session_async(self, session_id, ip_address=None):
        return await run_in_executor(self.touch_session, session_id, ip_address)

    def invalidate_session(self, session_id):
        with self._lock:
            if session_id not in self._sessions:
                return False
            self._log_activity(session_id, 'session_invalidated', {})
            self._remove_session_internal(session_id)
            return True

    async def invalidate_session_async(self, session_id):
        return await run_in_executor(self.invalidate_session, session_id)

    def invalidate_all_user_sessions(self, user_id):
        with self._lock:
            session_ids = list(self._user_sessions.get(user_id, {}).keys())
            for sid in session_ids:
                self._log_activity(sid, 'session_invalidated_bulk', {'user_id': user_id})
                self._remove_session_internal(sid)
            return len(session_ids)

    async def invalidate_all_user_sessions_async(self, user_id):
        return await run_in_executor(self.invalidate_all_user_sessions, user_id)

    def invalidate_other_user_sessions(self, user_id, current_session_id):
        with self._lock:
            session_ids = [
                sid for sid in list(self._user_sessions.get(user_id, {}).keys())
                if sid != current_session_id
            ]
            for sid in session_ids:
                self._log_activity(sid, 'session_invalidated_other', {'user_id': user_id, 'kept_session': current_session_id})
                self._remove_session_internal(sid)
            return len(session_ids)

    async def invalidate_other_user_sessions_async(self, user_id, current_session_id):
        return await run_in_executor(self.invalidate_other_user_sessions, user_id, current_session_id)

    def get_user_sessions(self, user_id):
        with self._lock:
            now = time.time()
            result = []
            for sid in list(self._user_sessions.get(user_id, {}).keys()):
                session = self._sessions.get(sid)
                if session and now - session.get('last_activity', session