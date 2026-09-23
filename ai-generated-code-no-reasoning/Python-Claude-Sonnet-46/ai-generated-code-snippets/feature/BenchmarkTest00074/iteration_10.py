from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import os
import sqlite3
import configparser
import urllib.parse
import hashlib
import hmac
import base64
import json
import time
import asyncio
import aiofiles
import aiosqlite
from functools import wraps

STORAGE_BACKEND = os.environ.get('STORAGE_BACKEND', 'file')
DB_PATH = os.environ.get('BENCHMARK_DB_PATH', '/tmp/benchmark00074.db')
FILE_PATH = os.environ.get('BENCHMARK_FILE_PATH', '/tmp/benchmark00074.cfg')

AUTH_PROVIDERS = {
    'local': {
        'enabled': True,
        'secret': os.environ.get('LOCAL_AUTH_SECRET', 'default-local-secret'),
    },
    'oauth': {
        'enabled': os.environ.get('OAUTH_ENABLED', 'false').lower() == 'true',
        'client_id': os.environ.get('OAUTH_CLIENT_ID', ''),
        'client_secret': os.environ.get('OAUTH_CLIENT_SECRET', ''),
        'token_url': os.environ.get('OAUTH_TOKEN_URL', ''),
    },
    'saml': {
        'enabled': os.environ.get('SAML_ENABLED', 'false').lower() == 'true',
        'idp_url': os.environ.get('SAML_IDP_URL', ''),
        'sp_entity_id': os.environ.get('SAML_SP_ENTITY_ID', ''),
    },
    'ldap': {
        'enabled': os.environ.get('LDAP_ENABLED', 'false').lower() == 'true',
        'server': os.environ.get('LDAP_SERVER', ''),
        'base_dn': os.environ.get('LDAP_BASE_DN', ''),
        'bind_dn': os.environ.get('LDAP_BIND_DN', ''),
        'bind_password': os.environ.get('LDAP_BIND_PASSWORD', ''),
    },
    'api_key': {
        'enabled': os.environ.get('API_KEY_ENABLED', 'false').lower() == 'true',
        'header_name': os.environ.get('API_KEY_HEADER', 'X-API-Key'),
        'keys': os.environ.get('VALID_API_KEYS', '').split(','),
    }
}


def _init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS benchmark_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            section TEXT NOT NULL,
            key TEXT NOT NULL,
            value TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS auth_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_token TEXT NOT NULL,
            provider TEXT NOT NULL,
            user_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS auth_providers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider_name TEXT NOT NULL,
            provider_config TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1
        )
    ''')
    conn.commit()
    conn.close()


async def _async_init_db():
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS benchmark_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                section TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL
            )
        ''')
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS auth_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_token TEXT NOT NULL,
                provider TEXT NOT NULL,
                user_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            )
        ''')
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS auth_providers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider_name TEXT NOT NULL,
                provider_config TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1
            )
        ''')
        await conn.commit()


def _store_to_db(section, key, value):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO benchmark_config (section, key, value) VALUES (?, ?, ?)',
        (section, key, value)
    )
    conn.commit()
    conn.close()


async def _async_store_to_db(section, key, value):
    async with aiosqlite.connect(DB_PATH) as conn:
        await conn.execute(
            'INSERT INTO benchmark_config (section, key, value) VALUES (?, ?, ?)',
            (section, key, value)
        )
        await conn.commit()


def _retrieve_from_db(section, key):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        'SELECT value FROM benchmark_config WHERE section = ? AND key = ? ORDER BY id DESC LIMIT 1',
        (section, key)
    )
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0]
    return None


async def _async_retrieve_from_db(section, key):
    async with aiosqlite.connect(DB_PATH) as conn:
        async with conn.execute(
            'SELECT value FROM benchmark_config WHERE section = ? AND key = ? ORDER BY id DESC LIMIT 1',
            (section, key)
        ) as cursor:
            row = await cursor.fetchone()
    if row:
        return row[0]
    return None


def _store_session_to_db(session_token, provider, user_id, expires_in=3600):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    now = int(time.time())
    cursor.execute(
        'INSERT INTO auth_sessions (session_token, provider, user_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)',
        (session_token, provider, user_id, now, now + expires_in)
    )
    conn.commit()
    conn.close()


async def _async_store_session_to_db(session_token, provider, user_id, expires_in=3600):
    async with aiosqlite.connect(DB_PATH) as conn:
        now = int(time.time())
        await conn.execute(
            'INSERT INTO auth_sessions (session_token, provider, user_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)',
            (session_token, provider, user_id, now, now + expires_in)
        )
        await conn.commit()


def _retrieve_session_from_db(session_token):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    now = int(time.time())
    cursor.execute(
        'SELECT provider, user_id, expires_at FROM auth_sessions WHERE session_token = ? AND expires_at > ?',
        (session_token, now)
    )
    row = cursor.fetchone()
    conn.close()
    if row:
        return {'provider': row[0], 'user_id': row[1], 'expires_at': row[2]}
    return None


async def _async_retrieve_session_from_db(session_token):
    async with aiosqlite.connect(DB_PATH) as conn:
        now = int(time.time())
        async with conn.execute(
            'SELECT provider, user_id, expires_at FROM auth_sessions WHERE session_token = ? AND expires_at > ?',
            (session_token, now)
        ) as cursor:
            row = await cursor.fetchone()
    if row:
        return {'provider': row[0], 'user_id': row[1], 'expires_at': row[2]}
    return None


def _store_to_file(section, key_a, value_a, key_b, value_b):
    conf = configparser.ConfigParser()
    if os.path.exists(FILE_PATH):
        conf.read(FILE_PATH)
    if not conf.has_section(section):
        conf.add_section(section)
    conf.set(section, key_a, value_a)
    conf.set(section, key_b, value_b)
    with open(FILE_PATH, 'w') as f:
        conf.write(f)


async def _async_store_to_file(section, key_a, value_a, key_b, value_b):
    conf = configparser.ConfigParser()
    if os.path.exists(FILE_PATH):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, conf.read, FILE_PATH)
    if not conf.has_section(section):
        conf.add_section(section)
    conf.set(section, key_a, value_a)
    conf.set(section, key_b, value_b)
    import io
    buffer = io.StringIO()
    conf.write(buffer)
    content = buffer.getvalue()
    async with aiofiles.open(FILE_PATH, 'w') as f:
        await f.write(content)


def _retrieve_from_file(section, key):
    conf = configparser.ConfigParser()
    if os.path.exists(FILE_PATH):
        conf.read(FILE_PATH)
    if conf.has_section(section) and conf.has_option(section, key):
        return conf.get(section, key)
    return None


async def _async_retrieve_from_file(section, key):
    conf = configparser.ConfigParser()
    if os.path.exists(FILE_PATH):
        async with aiofiles.open(FILE_PATH, 'r') as f:
            content = await f.read()
        import io
        conf.read_file(io.StringIO(content))
    if conf.has_section(section) and conf.has_option(section, key):
        return conf.get(section, key)
    return None


def _store_auth_to_file(provider, token, user_id):
    conf = configparser.ConfigParser()
    if os.path.exists(FILE_PATH):
        conf.read(FILE_PATH)
    section = f'auth_{provider}'
    if not conf.has_section(section):
        conf.add_section(section)
    conf.set(section, 'token', token)
    conf.set(section, 'user_id', user_id)
    conf.set(section, 'timestamp', str(int(time.time())))
    with open(FILE_PATH, 'w') as f:
        conf.write(f)


async def _async_store_auth_to_file(provider, token, user_id):
    conf = configparser.ConfigParser()
    if os.path.exists(FILE_PATH):
        async with aiofiles.open(FILE_PATH, 'r') as f:
            content = await f.read()
        import io
        conf.read_file(io.StringIO(content))
    section = f'auth_{provider}'
    if not conf.has_section(section):
        conf.add_section(section)
    conf.set(section, 'token', token)
    conf.set(section, 'user_id', user_id)
    conf.set(section, 'timestamp', str(int(time.time())))
    import io
    buffer = io.StringIO()
    conf.write(buffer)
    content = buffer.getvalue()
    async with aiofiles.open(FILE_PATH, 'w') as f:
        await f.write(content)


def _retrieve_auth_from_file(provider, token):
    conf = configparser.ConfigParser()
    if os.path.exists(FILE_PATH):
        conf.read(FILE_PATH)
    section = f'auth_{provider}'
    if conf.has_section(section) and conf.has_option(section, 'token'):
        stored_token = conf.get(section, 'token')
        if stored_token == token:
            return {
                'user_id': conf.get(section, 'user_id', fallback='unknown'),
                'timestamp': conf.get(section, 'timestamp', fallback='0')
            }
    return None


async def _async_retrieve_auth_from_file(provider, token):
    conf = configparser.ConfigParser()
    if os.path.exists(FILE_PATH):
        async with aiofiles.open(FILE_PATH, 'r') as f:
            content = await f.read()
        import io
        conf.read_file(io.StringIO(content))
    section = f'auth_{provider}'
    if conf.has_section(section) and conf.has_option(section, 'token'):
        stored_token = conf.get(section, 'token')
        if stored_token == token:
            return {
                'user_id': conf.get(section, 'user_id', fallback='unknown'),
                'timestamp': conf.get(section, 'timestamp', fallback='0')
            }
    return None


def _generate_session_token(provider, user_id):
    secret = AUTH_PROVIDERS.get('local', {}).get('secret', 'fallback-secret')
    data = f"{provider}:{user_id}:{time.time()}"
    signature = hmac.new(
        secret.encode(),
        data.encode(),
        hashlib.sha256
    ).hexdigest()
    token_data = base64.b64encode(f"{data}:{signature}".encode()).decode()
    return token_data


async def _async_generate_session_token(provider, user_id):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _generate_session_token, provider, user_id)


def _validate_local_auth(username, password):
    if not AUTH_PROVIDERS['local']['enabled']:
        return None
    secret = AUTH_PROVIDERS['local']['secret']
    expected = hmac.new(secret.encode(), username.encode(), hashlib.sha256).hexdigest()
    provided = hmac.new(secret.encode(), password.encode(), hashlib.sha256).hexdigest()
    if hmac.compare_digest(expected, provided):
        return username
    return None


async def _async_validate_local_auth(username, password):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _validate_local_auth, username, password)


def _validate_api_key(api_key):
    if not AUTH_PROVIDERS['api_key']['enabled']:
        return None
    valid_keys = AUTH_PROVIDERS['api_key']['keys']
    for valid_key in valid_keys:
        if valid_key and hmac.compare_digest(api_key.strip(), valid_key.strip()):
            return f"api_user_{hashlib.sha256(api_key.encode()).hexdigest()[:8]}"
    return None


async def _async_validate_api_key(api_key):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _validate_api_key, api_key)


def _validate_oauth_token(token):
    if not AUTH_PROVIDERS['oauth']['enabled']:
        return None
    try:
        decoded = base64.b64decode(token.encode()).decode()
        parts = decoded.split(':')
        if len(parts) >= 2:
            return f"oauth_user_{hashlib.sha256(token.encode()).hexdigest()[:8]}"
    except Exception:
        pass
    return None


async def _async_validate_oauth_token(token):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _validate_oauth_token, token)


def _validate_saml_assertion(assertion):
    if not AUTH_PROVIDERS['saml']['enabled']:
        return None
    try