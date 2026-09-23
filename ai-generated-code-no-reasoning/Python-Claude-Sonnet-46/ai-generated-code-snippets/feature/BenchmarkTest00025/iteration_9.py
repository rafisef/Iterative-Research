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


class LocalAuthProvider(AuthProviderBase):
    def __init__(self, config=None):
        super().__init__('local', config)
        self._users = {}
        self._users_lock = threading.Lock()

    def register_user(self, username, password_hash):
        with self._users_lock:
            self._users[username] = password_hash

    def authenticate(self, credentials):
        username = credentials.get('username', '')
        password_hash = credentials.get('password_hash', '')
        with self._users_lock:
            stored_hash = self._users.get(username)
        if stored_hash and stored_hash == password_hash:
            return {'user_id': username, 'provider': 'local', 'username': username}
        return None

    async def async_authenticate(self, credentials):
        return self.authenticate(credentials)

    def get_user_info(self, token_or_identifier):
        with self._users_lock:
            if token_or_identifier in self._users:
                return {'user_id': token_or_identifier, 'provider': 'local', 'username': token_or_identifier}
        return None

    async def async_get_user_info(self, token_or_identifier):
        return self.get_user_info(token_or_identifier)


class OAuthProvider(AuthProviderBase):
    def __init__(self, config=None):
        cfg = config or {}
        super().__init__('oauth', cfg)
        self.client_id = cfg.get('client_id', get_config_value('OAUTH_CLIENT_ID'))
        self.client_secret = cfg.get('client_secret', get_config_value('OAUTH_CLIENT_SECRET'))
        self.auth_url = cfg.get('auth_url', get_config_value('OAUTH_AUTH_URL'))
        self.token_url = cfg.get('token_url', get_config_value('OAUTH_TOKEN_URL'))
        self.userinfo_url = cfg.get('userinfo_url', get_config_value('OAUTH_USERINFO_URL'))

    def authenticate(self, credentials):
        code = credentials.get('code', '')
        if not code:
            return None
        return {'user_id': None, 'provider': 'oauth', 'code': code, 'pending': True}

    async def async_authenticate(self, credentials):
        return self.authenticate(credentials)

    def exchange_code_for_token(self, code):
        return None

    async def async_exchange_code_for_token(self, code):
        return None

    def get_user_info(self, token_or_identifier):
        return None

    async def async_get_user_info(self, token_or_identifier):
        return None

    def get_authorization_url(self, state=None, redirect_uri=None):
        params = {
            'client_id': self.client_id,
            'response_type': 'code',
        }
        if state:
            params['state'] = state
        if redirect_uri:
            params['redirect_uri'] = redirect_uri
        query_string = '&'.join(f'{k}={v}' for k, v in params.items())
        return f'{self.auth_url}?{query_string}'


class LDAPAuthProvider(AuthProviderBase):
    def __init__(self, config=None):
        cfg = config or {}
        super().__init__('ldap', cfg)
        self.server = cfg.get('server', get_config_value('LDAP_SERVER'))
        self.port = cfg.get('port', get_config_value('LDAP_PORT'))
        self.base_dn = cfg.get('base_dn', get_config_value('LDAP_BASE_DN'))

    def authenticate(self, credentials):
        username = credentials.get('username', '')
        password = credentials.get('password', '')
        if not username or not password:
            return None
        return None

    async def async_authenticate(self, credentials):
        return self.authenticate(credentials)

    def get_user_info(self, token_or_identifier):
        return None

    async def async_get_user_info(self, token_or_identifier):
        return None


class SAMLAuthProvider(AuthProviderBase):
    def __init__(self, config=None):
        cfg = config or {}
        super().__init__('saml', cfg)
        self.idp_metadata_url = cfg.get('idp_metadata_url', get_config_value('SAML_IDP_METADATA_URL'))
        self.sp_entity_id = cfg.get('sp_entity_id', get_config_value('SAML_SP_ENTITY_ID'))

    def authenticate(self, credentials):
        saml_response = credentials.get('SAMLResponse', '')
        if not saml_response:
            return None
        return None

    async def async_authenticate(self, credentials):
        return self.authenticate(credentials)

    def get_user_info(self, token_or_identifier):
        return None

    async def async_get_user_info(self, token_or_identifier):
        return None


_provider_class_map = {
    'local': LocalAuthProvider,
    'oauth': OAuthProvider,
    'ldap': LDAPAuthProvider,
    'saml': SAMLAuthProvider,
}


def register_auth_provider(provider_name, provider_instance):
    with _auth_provider_registry_lock:
        _auth_provider_registry[provider_name] = provider_instance


def unregister_auth_provider(provider_name):
    with _auth_provider_registry_lock:
        _auth_provider_registry.pop(provider_name, None)


def get_auth_provider(provider_name):
    with _auth_provider_registry_lock:
        return _auth_provider_registry.get(provider_name)


def get_all_auth_providers():
    with _auth_provider_registry_lock:
        return dict(_auth_provider_registry)


def get_enabled_auth_providers():
    with _auth_provider_registry_lock:
        return {k: v for k, v in _auth_provider_registry.items() if v.is_enabled()}


def enable_auth_provider(provider_name):
    with _auth_provider_registry_lock:
        provider = _auth_provider_registry.get(provider_name)
        if provider:
            provider.enable()
            return True
    return False


def disable_auth_provider(provider_name):
    with _auth_provider_registry_lock:
        provider = _auth_provider_registry.get(provider_name)
        if provider:
            provider.disable()
            return True
    return False


def init_auth_providers():
    configured_providers = get_config_value('AUTH_PROVIDERS')
    for provider_name in configured_providers:
        provider_name = provider_name.strip()
        if provider_name in _provider_class_map:
            provider_class = _provider_class_map[provider_name]
            instance = provider_class()
            register_auth_provider(provider_name, instance)


def register_custom_auth_provider(provider_name, provider_class, config=None):
    if not issubclass(provider_class, AuthProviderBase):
        raise ValueError(f"Provider class must extend AuthProviderBase")
    instance = provider_class(config=config) if config else provider_class()
    instance.provider_name = provider_name
    register_auth_provider(provider_name, instance)
    with _auth_provider_registry_lock:
        _provider_class_map[provider_name] = provider_class


def authenticate_with_provider(provider_name, credentials):
    provider = get_auth_provider(provider_name)
    if not provider:
        return None, f"Provider '{provider_name}' not found"
    if not provider.is_enabled():
        return None, f"Provider '{provider_name}' is disabled"
    result = provider.authenticate(credentials)
    return result, None


async def async_authenticate_with_provider(provider_name, credentials):
    provider = get_auth_provider(provider_name)
    if not provider:
        return None, f"Provider '{provider_name}' not found"
    if not provider.is_enabled():
        return None, f"Provider '{provider_name}' is disabled"
    result = await provider.async_authenticate(credentials)
    return result, None


def authenticate_with_any_provider(credentials, preferred_provider=None):
    if preferred_provider:
        result, error = authenticate_with_provider(preferred_provider, credentials)
        if result:
            return result, preferred_provider, None

    enabled_providers = get_enabled_auth_providers()
    for provider_name, provider in enabled_providers.items():
        if