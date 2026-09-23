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

import os
import json
import sqlite3
import threading
import uuid
import time
import asyncio
import aiofiles
import aiosqlite
from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html


_file_lock = threading.Lock()
_db_lock = threading.Lock()
_session_store_lock = threading.RLock()
_async_file_lock = asyncio.Lock()
_async_db_lock = asyncio.Lock()
_async_session_store_lock = asyncio.Lock()
_in_memory_sessions = {}
_auth_provider_registry = {}
_auth_provider_registry_lock = threading.Lock()


def _get_config():
    return {
        'COOKIE_MAX_AGE': int(os.environ.get('BENCHMARK_COOKIE_MAX_AGE', 60 * 3)),
        'COOKIE_SECURE': os.environ.get('BENCHMARK_COOKIE_SECURE', 'true').lower() == 'true',
        'COOKIE_DOMAIN': os.environ.get('BENCHMARK_COOKIE_DOMAIN', 'localhost'),
        'BENCHMARK_PREFIX': os.environ.get('BENCHMARK_PREFIX', '90583'),
        'BENCHMARK_SUFFIX': os.environ.get('BENCHMARK_SUFFIX', 'abcd'),
        'USER_PREFIX': os.environ.get('BENCHMARK_USER_PREFIX', 'Nancy'),
        'STORAGE_TYPE': os.environ.get('BENCHMARK_STORAGE_TYPE', 'file'),
        'STORAGE_FILE_PATH': os.environ.get('BENCHMARK_STORAGE_FILE_PATH', 'benchmark_sessions.json'),
        'STORAGE_DB_PATH': os.environ.get('BENCHMARK_STORAGE_DB_PATH', 'benchmark_sessions.db'),
        'AUTH_PROVIDERS': os.environ.get('BENCHMARK_AUTH_PROVIDERS', 'local').split(','),
        'OAUTH_CLIENT_ID': os.environ.get('BENCHMARK_OAUTH_CLIENT_ID', ''),
        'OAUTH_CLIENT_SECRET': os.environ.get('BENCHMARK_OAUTH_CLIENT_SECRET', ''),
        'OAUTH_AUTH_URL': os.environ.get('BENCHMARK_OAUTH_AUTH_URL', ''),
        'OAUTH_TOKEN_URL': os.environ.get('BENCHMARK_OAUTH_TOKEN_URL', ''),
        'OAUTH_USERINFO_URL': os.environ.get('BENCHMARK_OAUTH_USERINFO_URL', ''),
        'LDAP_SERVER': os.environ.get('BENCHMARK_LDAP_SERVER', ''),
        'LDAP_PORT': int(os.environ.get('BENCHMARK_LDAP_PORT', 389)),
        'LDAP_BASE_DN': os.environ.get('BENCHMARK_LDAP_BASE_DN', ''),
        'SAML_IDP_METADATA_URL': os.environ.get('BENCHMARK_SAML_IDP_METADATA_URL', ''),
        'SAML_SP_ENTITY_ID': os.environ.get('BENCHMARK_SAML_SP_ENTITY_ID', ''),
        'SESSION_EXPIRY_SECONDS': int(os.environ.get('BENCHMARK_SESSION_EXPIRY_SECONDS', 60 * 30)),
        'MAX_SESSIONS_PER_USER': int(os.environ.get('BENCHMARK_MAX_SESSIONS_PER_USER', 10)),
    }


_config_overrides = {}


def configure(**kwargs):
    _config_overrides.update(kwargs)


def get_config_value(key):
    if key in _config_overrides:
        return _config_overrides[key]
    return _get_config().get(key)


COOKIE_MAX_AGE = int(os.environ.get('BENCHMARK_COOKIE_MAX_AGE', 60 * 3))
COOKIE_SECURE = os.environ.get('BENCHMARK_COOKIE_SECURE', 'true').lower() == 'true'
COOKIE_DOMAIN = os.environ.get('BENCHMARK_COOKIE_DOMAIN', 'localhost')
BENCHMARK_PREFIX = os.environ.get('BENCHMARK_PREFIX', '90583')
BENCHMARK_SUFFIX = os.environ.get('BENCHMARK_SUFFIX', 'abcd')
USER_PREFIX = os.environ.get('BENCHMARK_USER_PREFIX', 'Nancy')
STORAGE_TYPE = os.environ.get('BENCHMARK_STORAGE_TYPE', 'file')
STORAGE_FILE_PATH = os.environ.get('BENCHMARK_STORAGE_FILE_PATH', 'benchmark_sessions.json')
STORAGE_DB_PATH = os.environ.get('BENCHMARK_STORAGE_DB_PATH', 'benchmark_sessions.db')
AUTH_PROVIDERS = os.environ.get('BENCHMARK_AUTH_PROVIDERS', 'local').split(',')
OAUTH_CLIENT_ID = os.environ.get('BENCHMARK_OAUTH_CLIENT_ID', '')
OAUTH_CLIENT_SECRET = os.environ.get('BENCHMARK_OAUTH_CLIENT_SECRET', '')
OAUTH_AUTH_URL = os.environ.get('BENCHMARK_OAUTH_AUTH_URL', '')
OAUTH_TOKEN_URL = os.environ.get('BENCHMARK_OAUTH_TOKEN_URL', '')
OAUTH_USERINFO_URL = os.environ.get('BENCHMARK_OAUTH_USERINFO_URL', '')
LDAP_SERVER = os.environ.get('BENCHMARK_LDAP_SERVER', '')
LDAP_PORT = int(os.environ.get('BENCHMARK_LDAP_PORT', 389))
LDAP_BASE_DN = os.environ.get('BENCHMARK_LDAP_BASE_DN', '')
SAML_IDP_METADATA_URL = os.environ.get('BENCHMARK_SAML_IDP_METADATA_URL', '')
SAML_SP_ENTITY_ID = os.environ.get('BENCHMARK_SAML_SP_ENTITY_ID', '')


class AuthProviderBase:
    def __init__(self, provider_name, config=None):
        self.provider_name = provider_name
        self.config = config or {}
        self.enabled = True
        self._hooks = {
            'pre_authenticate': [],
            'post_authenticate': [],
            'pre_logout': [],
            'post_logout': [],
            'pre_get_user_info': [],
            'post_get_user_info': [],
        }
        self._metadata = {}

    def authenticate(self, credentials):
        raise NotImplementedError

    async def async_authenticate(self, credentials):
        raise NotImplementedError

    def get_user_info(self, token_or_identifier):
        raise NotImplementedError

    async def async_get_user_info(self, token_or_identifier):
        raise NotImplementedError

    def logout(self, session_data):
        pass

    async def async_logout(self, session_data):
        pass

    def is_enabled(self):
        return self.enabled

    def enable(self):
        self.enabled = True

    def disable(self):
        self.enabled = False

    def get_provider_name(self):
        return self.provider_name

    def get_config(self):
        return self.config

    def update_config(self, new_config):
        self.config.update(new_config)

    def register_hook(self, hook_name, callback):
        if hook_name in self._hooks:
            self._hooks[hook_name].append(callback)

    def unregister_hook(self, hook_name, callback):
        if hook_name in self._hooks and callback in self._hooks[hook_name]:
            self._hooks[hook_name].remove(callback)

    def _run_hooks(self, hook_name, *args, **kwargs):
        for callback in self._hooks.get(hook_name, []):
            callback(*args, **kwargs)

    async def _run_async_hooks(self, hook_name, *args, **kwargs):
        for callback in self._hooks.get(hook_name, []):
            if asyncio.iscoroutinefunction(callback):
                await callback(*args, **kwargs)
            else:
                callback(*args, **kwargs)

    def set_metadata(self, key, value):
        self._metadata[key] = value

    def get_metadata(self, key, default=None):
        return self._metadata.get(key, default)

    def get_all_metadata(self):
        return dict(self._metadata)

    def supports_feature(self, feature_name):
        return False

    def get_supported_features(self):
        return []

    def validate_credentials_schema(self, credentials):
        return True, None

    def refresh_token(self, token):
        return None

    async def async_refresh_token(self, token):
        return None

    def revoke_token(self, token):
        return False

    async def async_revoke_token(self, token):
        return False

    def get_provider_info(self):
        return {
            'name': self.provider_name,
            'enabled': self.enabled,
            'config_keys': list(self.config.keys()),
            'supported_features': self.get_supported_features(),
            'metadata': self.get_all_metadata(),
        }


class LocalAuthProvider(AuthProviderBase):
    def __init__(self, config=None):
        super().__init__('local', config)
        self._users = {}
        self._users_lock = threading.Lock()
        self._failed_attempts = {}
        self._failed_attempts_lock = threading.Lock()
        self._max_failed_attempts = self.config.get('max_failed_attempts', 5)
        self._lockout_duration = self.config.get('lockout_duration', 300)

    def register_user(self, username, password_hash):
        with self._users_lock:
            self._users[username] = password_hash

    def unregister_user(self, username):
        with self._users_lock:
            self._users.pop(username, None)

    def update_user_password(self, username, new_password_hash):
        with self._users_lock:
            if username in self._users:
                self._users[username] = new_password_hash
                return True
        return False

    def user_exists(self, username):
        with self._users_lock:
            return username in self._users

    def list_users(self):
        with self._users_lock:
            return list(self._users.keys())

    def _is_locked_out(self, username):
        with self._failed_attempts_lock:
            record = self._failed_attempts.get(username)
            if not record:
                return False
            attempts, lockout_time = record
            if attempts >= self._max_failed_attempts:
                if time.time() - lockout_time < self._lockout_duration:
                    return True
                else:
                    del self._failed_attempts[username]
                    return False
            return False

    def _record_failed_attempt(self, username):
        with self._failed_attempts_lock:
            record = self._failed_attempts.get(username, (0, 0))
            attempts = record[0] + 1
            self._failed_attempts[username] = (attempts, time.time())

    def _clear_failed_attempts(self, username):
        with self._failed_attempts_lock:
            self._failed_attempts.pop(username, None)

    def get_failed_attempts(self, username):
        with self._failed_attempts_lock:
            record = self._failed_attempts.get(username)
            if record:
                return record[0]
            return 0

    def authenticate(self, credentials):
        self._run_hooks('pre_authenticate', credentials)
        username = credentials.get('username', '')
        password_hash = credentials.get('password_hash', '')
        if self._is_locked_out(username):
            result = None
            self._run_hooks('post_authenticate', credentials, result)
            return result
        with self._users_lock:
            stored_hash = self._users.get(username)
        if stored_hash and stored_hash == password_hash:
            self._clear_failed_attempts(username)
            result = {'user_id': username, 'provider': 'local', 'username': username}
            self._run_hooks('post_authenticate', credentials, result)
            return result
        self._record_failed_attempt(username)
        self._run_hooks('post_authenticate', credentials, None)
        return None

    async def async_authenticate(self, credentials):
        await self._run_async_hooks('pre_authenticate', credentials)
        result = self.authenticate(credentials)
        await self._run_async_hooks('post_authenticate', credentials, result)
        return result

    def get_user_info(self, token_or_identifier):
        self._run_hooks('pre_get_user_info', token_or_identifier)
        with self._users_lock:
            if token_or_identifier in self._users:
                result = {'user_id': token_or_identifier, 'provider': 'local', 'username': token_or_identifier}
                self._run_hooks('post_get_user_info', token_or_identifier, result)
                return result
        self._run_hooks('post_get_user_info', token_or_identifier, None)
        return None

    async def async_get_user_info(self, token_or_identifier):
        return self.get_user_info(token_or_identifier)

    def validate_credentials_schema(self, credentials):
        if 'username' not in credentials:
            return False, "Missing 'username' field"
        if 'password_hash' not in credentials:
            return False, "Missing 'password_hash' field"
        return True, None

    def supports_feature(self, feature_name):
        return feature_name in self.get_supported_features()

    def get_supported_features(self):
        return ['lockout', 'password_update', 'user_management']

    def get_provider_info(self):
        info = super().get_provider_info()
        info['user_count'] = len(self._users)
        return info


class OAuthProvider(AuthProviderBase):
    def __init__(self, config=None):
        cfg = config or {}
        super().__init__('oauth', cfg)
        self.client_id = cfg.get('client_id', get_config_value('OAUTH_CLIENT_ID'))
        self.client_secret = cfg.get('client_secret', get_config_value('OAUTH_CLIENT_SECRET'))
        self.auth_url = cfg.get('auth_url', get_config_value('OAUTH_AUTH_URL'))
        self.token_url = cfg.get('token_url', get_config_value('OAUTH_TOKEN_URL'))
        self.userinfo_url = cfg.get('userinfo_url', get_config_value('OAUTH_USERINFO_URL'))
        self._token_cache = {}
        self._token_cache_lock = threading.Lock()
        self._scopes = cfg.get('scopes', ['openid', 'profile', 'email'])
        self._pkce_enabled = cfg.get('pkce_enabled', False)
        self._state_store = {}
        self._state_store_lock = threading.Lock()

    def authenticate(self, credentials):
        self._run_hooks('pre_authenticate', credentials)
        code = credentials.get('code', '')
        if not code:
            self._run_hooks('post_authenticate', credentials, None)
            return None
        result = {'user_id': None, 'provider': 'oauth', 'code': code, 'pending': True}
        self._run_hooks