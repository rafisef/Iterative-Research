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
from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html

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


def init_file_storage():
    if not os.path.exists(STORAGE_FILE_PATH):
        with open(STORAGE_FILE_PATH, 'w') as f:
            json.dump({}, f)


def init_db_storage():
    conn = sqlite3.connect(STORAGE_DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            cookie_name TEXT PRIMARY KEY,
            cookie_value TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS auth_providers (
            provider_name TEXT PRIMARY KEY,
            provider_config TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_auth_mappings (
            user_id TEXT NOT NULL,
            provider_name TEXT NOT NULL,
            provider_user_id TEXT NOT NULL,
            PRIMARY KEY (user_id, provider_name)
        )
    ''')
    conn.commit()
    conn.close()


def read_from_file(cookie_name):
    try:
        with open(STORAGE_FILE_PATH, 'r') as f:
            data = json.load(f)
        return data.get(cookie_name)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def write_to_file(cookie_name, cookie_value):
    try:
        with open(STORAGE_FILE_PATH, 'r') as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}
    data[cookie_name] = cookie_value
    with open(STORAGE_FILE_PATH, 'w') as f:
        json.dump(data, f)


def read_from_db(cookie_name):
    conn = sqlite3.connect(STORAGE_DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT cookie_value FROM sessions WHERE cookie_name = ?', (cookie_name,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0]
    return None


def write_to_db(cookie_name, cookie_value):
    conn = sqlite3.connect(STORAGE_DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO sessions (cookie_name, cookie_value)
        VALUES (?, ?)
        ON CONFLICT(cookie_name) DO UPDATE SET cookie_value = excluded.cookie_value
    ''', (cookie_name, cookie_value))
    conn.commit()
    conn.close()


def storage_read(cookie_name):
    if STORAGE_TYPE == 'database':
        return read_from_db(cookie_name)
    return read_from_file(cookie_name)


def storage_write(cookie_name, cookie_value):
    if STORAGE_TYPE == 'database':
        write_to_db(cookie_name, cookie_value)
    else:
        write_to_file(cookie_name, cookie_value)


class AuthProvider:
    def __init__(self, name):
        self.name = name

    def authenticate(self, credentials):
        raise NotImplementedError

    def get_user_info(self, token_or_session):
        raise NotImplementedError


class LocalAuthProvider(AuthProvider):
    def __init__(self):
        super().__init__('local')

    def authenticate(self, credentials):
        username = credentials.get('username', '')
        password = credentials.get('password', '')
        if username and password:
            return {'user_id': username, 'provider': self.name}
        return None

    def get_user_info(self, token_or_session):
        return {'user_id': token_or_session.get('user_id'), 'provider': self.name}


class OAuthProvider(AuthProvider):
    def __init__(self):
        super().__init__('oauth')
        self.client_id = OAUTH_CLIENT_ID
        self.client_secret = OAUTH_CLIENT_SECRET
        self.auth_url = OAUTH_AUTH_URL
        self.token_url = OAUTH_TOKEN_URL
        self.userinfo_url = OAUTH_USERINFO_URL

    def authenticate(self, credentials):
        import urllib.request
        import urllib.parse as urlparse
        code = credentials.get('code', '')
        redirect_uri = credentials.get('redirect_uri', '')
        if not code:
            return None
        data = urlparse.urlencode({
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
        }).encode()
        try:
            req = urllib.request.Request(self.token_url, data=data, method='POST')
            with urllib.request.urlopen(req) as resp:
                token_data = json.loads(resp.read().decode())
            return {'access_token': token_data.get('access_token'), 'provider': self.name}
        except Exception:
            return None

    def get_user_info(self, token_or_session):
        import urllib.request
        access_token = token_or_session.get('access_token', '')
        if not access_token:
            return None
        try:
            req = urllib.request.Request(
                self.userinfo_url,
                headers={'Authorization': f'Bearer {access_token}'}
            )
            with urllib.request.urlopen(req) as resp:
                user_data = json.loads(resp.read().decode())
            return {'user_id': user_data.get('sub', user_data.get('id', '')), 'provider': self.name, 'raw': user_data}
        except Exception:
            return None

    def get_authorization_url(self, redirect_uri, state=''):
        import urllib.parse as urlparse
        params = urlparse.urlencode({
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'state': state,
        })
        return f'{self.auth_url}?{params}'


class LDAPAuthProvider(AuthProvider):
    def __init__(self):
        super().__init__('ldap')
        self.server = LDAP_SERVER
        self.port = LDAP_PORT
        self.base_dn = LDAP_BASE_DN

    def authenticate(self, credentials):
        username = credentials.get('username', '')
        password = credentials.get('password', '')
        if not username or not password or not self.server:
            return None
        try:
            import ldap3
            server = ldap3.Server(self.server, port=self.port)
            user_dn = f'uid={username},{self.base_dn}'
            conn = ldap3.Connection(server, user=user_dn, password=password, auto_bind=True)
            if conn.bound:
                return {'user_id': username, 'provider': self.name}
        except Exception:
            return None
        return None

    def get_user_info(self, token_or_session):
        return {'user_id': token_or_session.get('user_id'), 'provider': self.name}


class SAMLAuthProvider(AuthProvider):
    def __init__(self):
        super().__init__('saml')
        self.idp_metadata_url = SAML_IDP_METADATA_URL
        self.sp_entity_id = SAML_SP_ENTITY_ID

    def authenticate(self, credentials):
        saml_response = credentials.get('SAMLResponse', '')
        if not saml_response:
            return None
        try:
            import base64
            import xml.etree.ElementTree as ET
            decoded = base64.b64decode(saml_response).decode('utf-8')
            root = ET.fromstring(decoded)
            ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'}
            name_id = root.find('.//saml:NameID', ns)
            if name_id is not None and name_id.text:
                return {'user_id': name_id.text, 'provider': self.name}
        except Exception:
            return None
        return None

    def get_user_info(self, token_or_session):
        return {'user_id': token_or_session.get('user_id'), 'provider': self.name}


_auth_provider_registry = {}


def register_auth_provider(provider):
    _auth_provider_registry[provider.name] = provider


def get_auth_provider(name):
    return _auth_provider_registry.get(name)


def get_all_auth_providers():
    return dict(_auth_provider_registry)


def init_auth_providers():
    provider_map = {
        'local': LocalAuthProvider,
        'oauth': OAuthProvider,
        'ldap': LDAPAuthProvider,
        'saml': SAMLAuthProvider,
    }
    for provider_name in AUTH_PROVIDERS:
        provider_name = provider_name.strip()
        if provider_name in provider_map:
            register_auth_provider(provider_map[provider_name]())
    if STORAGE_TYPE == 'database':
        conn = sqlite3.connect(STORAGE_DB_PATH)
        cursor = conn.cursor()
        for name, provider in _auth_provider_registry.items():
            cursor.execute('''
                INSERT INTO auth_providers (provider_name, provider_config, enabled)
                VALUES (?, ?, 1)
                ON CONFLICT(provider_name) DO UPDATE SET enabled = 1
            ''', (name, json.dumps({'name': name})))
        conn.commit()
        conn.close()


def authenticate_with_provider(provider_name, credentials):
    provider = get_auth_provider(provider_name)
    if provider is None:
        return None
    return provider.authenticate(credentials)


def get_user_info_from_provider(provider_name, token_or_session):
    provider = get_auth_provider(provider_name)
    if provider is None:
        return None
    return provider.get_user_info(token_or_session)


def store_user_auth_mapping(user_id, provider_name, provider_user_id):
    if STORAGE_TYPE == 'database':
        conn = sqlite3.connect(STORAGE_DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO user_auth_mappings (user_id, provider_name, provider_user_id)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id, provider_name) DO UPDATE SET provider_user_id = excluded.provider_user_id
        ''', (user_id, provider_name, provider_user_id))
        conn.commit()
        conn.close()
    else:
        try:
            with open(STORAGE_FILE_PATH, 'r') as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            data = {}
        if 'auth_mappings' not in data:
            data['auth_mappings'] = {}
        mapping_key = f'{user_id}:{provider_name}'
        data['auth_mappings'][mapping_key] = provider_user_id
        with open(STORAGE_FILE_PATH, 'w') as f:
            json.dump(data, f)


def get_user_auth_mapping(user_id, provider_name):
    if STORAGE_TYPE == 'database':
        conn = sqlite3.connect(STORAGE_DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            'SELECT provider_user_id FROM user_auth_mappings WHERE user_id = ? AND provider_name = ?',
            (user_id, provider_name)
        )
        row = cursor.fetchone()
        conn.close()
        if row:
            return row[0]
        return None
    else:
        try:
            with open(STORAGE_FILE_PATH, 'r') as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return None
        mappings = data.get('auth_mappings', {})
        return mappings.get(f'{user_id}:{provider_name}')


def init(app):

    if STORAGE_TYPE == 'database':
        init_db_storage()
    else:
        init_file_storage()

    init_auth_providers()

    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET'])
    def BenchmarkTest00025_get():
        response = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
        response.set_cookie('BenchmarkTest00025', 'whatever',
            max_age=COOKIE_MAX_AGE,
            secure=COOKIE_SECURE,
            path=request.path,
            domain=COOKIE_DOMAIN)
        return response

    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['POST'])
    def BenchmarkTest00025_post():
        RESPONSE