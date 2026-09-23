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


def _store_to_db(section, key, value):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO benchmark_config (section, key, value) VALUES (?, ?, ?)',
        (section, key, value)
    )
    conn.commit()
    conn.close()


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


def _retrieve_from_file(section, key):
    conf = configparser.ConfigParser()
    if os.path.exists(FILE_PATH):
        conf.read(FILE_PATH)
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


def _validate_local_auth(username, password):
    if not AUTH_PROVIDERS['local']['enabled']:
        return None
    secret = AUTH_PROVIDERS['local']['secret']
    expected = hmac.new(secret.encode(), username.encode(), hashlib.sha256).hexdigest()
    provided = hmac.new(secret.encode(), password.encode(), hashlib.sha256).hexdigest()
    if hmac.compare_digest(expected, provided):
        return username
    return None


def _validate_api_key(api_key):
    if not AUTH_PROVIDERS['api_key']['enabled']:
        return None
    valid_keys = AUTH_PROVIDERS['api_key']['keys']
    for valid_key in valid_keys:
        if valid_key and hmac.compare_digest(api_key.strip(), valid_key.strip()):
            return f"api_user_{hashlib.sha256(api_key.encode()).hexdigest()[:8]}"
    return None


def _get_active_providers():
    return [name for name, config in AUTH_PROVIDERS.items() if config.get('enabled', False)]


def _authenticate_request(req):
    api_key_header = AUTH_PROVIDERS['api_key'].get('header_name', 'X-API-Key')
    api_key = req.headers.get(api_key_header)
    if api_key and AUTH_PROVIDERS['api_key']['enabled']:
        user_id = _validate_api_key(api_key)
        if user_id:
            return {'provider': 'api_key', 'user_id': user_id, 'authenticated': True}

    auth_header = req.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        token = auth_header[7:]
        if STORAGE_BACKEND == 'database':
            session = _retrieve_session_from_db(token)
            if session:
                return {'provider': session['provider'], 'user_id': session['user_id'], 'authenticated': True}
        else:
            for provider in _get_active_providers():
                auth_data = _retrieve_auth_from_file(provider, token)
                if auth_data:
                    return {'provider': provider, 'user_id': auth_data['user_id'], 'authenticated': True}

    session_cookie = req.cookies.get('auth_session')
    if session_cookie:
        if STORAGE_BACKEND == 'database':
            session = _retrieve_session_from_db(session_cookie)
            if session:
                return {'provider': session['provider'], 'user_id': session['user_id'], 'authenticated': True}

    return {'provider': None, 'user_id': None, 'authenticated': False}


def _register_provider(provider_name, config_dict):
    if STORAGE_BACKEND == 'database':
        _init_db()
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO auth_providers (provider_name, provider_config, enabled) VALUES (?, ?, ?)',
            (provider_name, json.dumps(config_dict), 1)
        )
        conn.commit()
        conn.close()
    else:
        conf = configparser.ConfigParser()
        if os.path.exists(FILE_PATH):
            conf.read(FILE_PATH)
        section = f'provider_{provider_name}'
        if not conf.has_section(section):
            conf.add_section(section)
        for k, v in config_dict.items():
            conf.set(section, str(k), str(v))
        with open(FILE_PATH, 'w') as f:
            conf.write(f)


def _get_registered_providers():
    providers = []
    if STORAGE_BACKEND == 'database':
        _init_db()
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT provider_name, provider_config, enabled FROM auth_providers')
        rows = cursor.fetchall()
        conn.close()
        for row in rows:
            try:
                config = json.loads(row[1])
            except (json.JSONDecodeError, TypeError):
                config = {}
            providers.append({
                'name': row[0],
                'config': config,
                'enabled': bool(row[2])
            })
    else:
        conf = configparser.ConfigParser()
        if os.path.exists(FILE_PATH):
            conf.read(FILE_PATH)
        for section in conf.sections():
            if section.startswith('provider_'):
                provider_name = section[9:]
                config = dict(conf.items(section))
                providers.append({
                    'name': provider_name,
                    'config': config,
                    'enabled': config.get('enabled', 'true').lower() == 'true'
                })
    return providers


def init(app):

    @app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['GET'])
    def BenchmarkTest00074_get():
        response = make_response(render_template('web/codeinj-00/BenchmarkTest00074.html'))
        response.set_cookie('BenchmarkTest00074', '%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27',
            max_age=60*3,
            secure=True,
            path=request.path,
            domain=os.environ.get('BENCHMARK_DOMAIN', 'localhost'))
        return response

    @app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['POST'])
    def BenchmarkTest00074_post():
        RESPONSE = ""

        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00074", "noCookieValueSupplied"))

        bar = 'safe!'

        section = 'section90091'
        key_a = 'keyA-90091'
        key_b = 'keyB-90091'
        value_a = os.environ.get('BENCHMARK_KEY_A_90091', 'a-Value')
        value_b = os.environ.get('BENCHMARK_KEY_B_90091', param)

        if STORAGE_BACKEND == 'database':
            _init_db()
            _store_to_db(section, key_a, value_a)
            _store_to_db(section, key_b, value_b)
            retrieved = _retrieve_from_db(section, key_b)
            if retrieved is not None:
                bar = retrieved
        else:
            _store_to_file(section, key_a, value_a, key_b, value_b)
            retrieved = _retrieve_from_file(section, key_b)
            if retrieved is not None:
                bar = retrieved

        try:
            exec(bar)
        except:
            RESPONSE += (
                f'Error executing statement \'{escape_for_html(bar)}\''
            )

        return RESPONSE

    @app.route('/benchmark/codeinj-00/BenchmarkTest00074/auth/providers', methods=['GET'])
    def BenchmarkTest00074_get_providers():
        active_providers = _get_active_providers()
        registered_providers = _get_registered_providers()
        result = {
            'active_providers': active_providers,
            'registered_providers': [p['name'] for p in registered_providers if p['enabled']]
        }
        return json.dumps(result), 200, {'Content-Type': 'application/json'}

    @app.route('/benchmark/codeinj-00/BenchmarkTest00074/auth/login', methods=['POST'])
    def BenchmarkTest00074_auth_login():
        provider = request.form.get('provider', 'local')
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        if provider not in AUTH_PROVIDERS:
            return json.dumps({'error': 'Unknown provider'}), 400, {'Content-Type': 'application/json'}

        if not AUTH_PROVIDERS[provider].get('enabled', False):
            return json.dumps({'error': 'Provider not enabled'}), 403, {'Content-Type': 'application/json'}

        user_id = None
        if provider == 'local':
            user_id