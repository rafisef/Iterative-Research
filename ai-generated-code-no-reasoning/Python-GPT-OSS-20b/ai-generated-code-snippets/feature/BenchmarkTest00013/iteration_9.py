import os
import json
import asyncio
import sqlite3
import uuid
import threading
round
from flask import redirect, url_for, request, make_response, render_template, abort
from helpers.utils import escape_for_html

CONFIG = {
    'COOKIE_DOMAIN': 'localhost',
    'COOKIE_MAX_AGE': 180,
    'COOKIE_SECURE': True,
    'COOKIE_PATH': '/',
    'COOKIE_HTTPONLY': True,
    'AUTH_ENABLED': True,
    'DEFAULT_PROVIDER': 'basic',
    'AUTH_BASIC_CREDENTIALS': [],
    'AUTH_APIKEY_CREDENTIALS': [],
    'CREDENTIALS_STORAGE': 'env',
    'CREDENTIALS_FILE': '',
    'CREDENTIALS_DB_PATH': ''
}

config_file = os.getenv('CONFIG_FILE')
if config_file and os.path.isfile(config_file):
    with open(config_file, 'r') as f:
        file_cfg = json.load(f)
    for k, v in file_cfg.items():
        if k in CONFIG:
            CONFIG[k] = v

env_int = lambda key, default: int(os.getenv(key, default))
env_bool = lambda key, default: os.getenv(key, str(default)).lower() in ('1', 'true', 'yes')
env_str = lambda key, default: os.getenv(key, default)

CONFIG['COOKIE_DOMAIN'] = env_str('COOKIE_DOMAIN', CONFIG['COOKIE_DOMAIN'])
CONFIG['COOKIE_MAX_AGE'] = env_int('COOKIE_MAX_AGE', CONFIG['COOKIE_MAX_AGE'])
CONFIG['COOKIE_SECURE'] = env_bool('COOKIE_SECURE', CONFIG['COOKIE_SECURE'])
CONFIG['COOKIE_PATH'] = env_str('COOKIE_PATH', CONFIG['COOKIE_PATH'])
CONFIG['COOKIE_HTTPONLY'] = env_bool('COOKIE_HTTPONLY', CONFIG['COOKIE_HTTPONLY'])
CONFIG['AUTH_ENABLED'] = env_bool('AUTH_ENABLED', CONFIG['AUTH_ENABLED'])
CONFIG['DEFAULT_PROVIDER'] = env_str('DEFAULT_PROVIDER', CONFIG['DEFAULT_PROVIDER'])
CONFIG['CREDENTIALS_STORAGE'] = env_str('CREDENTIALS_STORAGE', CONFIG['CREDENTIALS_STORAGE'])
CONFIG['CREDENTIALS_FILE'] = env_str('CREDENTIALS_FILE', CONFIG['CREDENTIALS_FILE'])
CONFIG['CREDENTIALS_DB_PATH'] = env_str('CREDENTIALS_DB_PATH', CONFIG['CREDENTIALS_DB_PATH'])

def _load_credentials_file(path):
    if not os.path.isfile(path):
        return {}
    with open(path, 'r') as f:
        data = json.load(f)
    return {
        'basic': data.get('basic', {}),
        'apikey': data.get('apikey', {})
    }

def _init_db(db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS basic_credentials (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS apikey_credentials (
            key TEXT PRIMARY KEY
        )
    ''')
    conn.commit()
    conn.close()

def _load_credentials_db(db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute('SELECT username, password FROM basic_credentials')
    basic = {row[0]: row[1] for row in cur.fetchall()}
    cur.execute('SELECT key FROM apikey_credentials')
    apikey = {row[0]: True for row in cur.fetchall()}
    conn.close()
    return {'basic': basic, 'apikey': apikey}

def _parse_basic_credentials(env):
    creds = os.getenv(env)
    if not creds:
        return {}
    return dict(pair.split(':', 1) for pair in creds.split(','))

def _parse_apikey_credentials(env):
    creds = os.getenv(env)
    if not creds:
        return {}
    return {k: True for k in creds.split(',')}

AUTH_CREDENTIALS = {
    'basic': _parse_basic_credentials('AUTH_BASIC_CREDENTIALS'),
    'apikey': _parse_apikey_credentials('AUTH_APIKEY_CREDENTIALS')
}

def _validate_basic(auth):
    if not auth or not auth.username or not auth.password:
        return False
    return AUTH_CREDENTIALS['basic'].get(auth.username) == auth.password

def _validate_apikey(key):
    return key in AUTH_CREDENTIALS['apikey']

VALIDATORS = {
    'basic': lambda req: _validate_basic(req.authorization),
    'apikey': lambda req: _validate_apikey(req.headers.get('X-API-Key'))
}

def _auth_required(f):
    def wrapper(*args, **kwargs):
        if not CONFIG['AUTH_ENABLED']:
            return f(*args, **kwargs)
        provider = request.headers.get('X-Auth-Provider', CONFIG['DEFAULT_PROVIDER'])
        validator = VALIDATORS.get(provider)
        if not validator:
            abort(400)
        if not validator(request):
            abort(401)
        return f(*args, **kwargs)
    return wrapper

SESSION_LOCK = threading.Lock()
SESSION_DATA = {}

def get_or_create_session():
    sid = request.cookies.get('SessionID')
    if sid:
        return sid, False
    new_sid = str(uuid.uuid4())
    with SESSION_LOCK:
        SESSION_DATA[new_sid] = {}
    return new_sid, True

def init(app, cfg=None):
    if cfg:
        CONFIG.update(cfg)
    storage = CONFIG['CREDENTIALS_STORAGE']
    if storage == 'file' and CONFIG['CREDENTIALS_FILE']:
        creds = _load_credentials_file(CONFIG['CREDENTIALS_FILE'])
        AUTH_CREDENTIALS.update(creds)
    elif storage == 'db' and CONFIG['CREDENTIALS_DB_PATH']:
        _init_db(CONFIG['CREDENTIALS_DB_PATH'])
        creds = _load_credentials_db(CONFIG['CREDENTIALS_DB_PATH'])
        AUTH_CREDENTIALS.update(creds)
    elif storage == 'both':
        if CONFIG['CREDENTIALS_FILE']:
            creds_file = _load_credentials_file(CONFIG['CREDENTIALS_FILE'])
            AUTH_CREDENTIALs.update(creds_file)
        if CONFIG['CREDENTIALS_DB_PATH']:
            _init_db(CONFIG['CREDENTIALS_DB_PATH'])
            creds_db = _load_credentials_db(CONFIG['CREDENTIALS_DB_PATH'])
            AUTH_CREDENTIALS.update(creds_db)
    for provider in AUTH_CREDENTIALS:
        if provider not in VALIDATORS:
            if provider == 'basic':
                VALIDATORS['basic'] = lambda req: _validate_basic(req.authorization)
            elif provider == 'apikey':
                VALIDATORS['apikey'] = lambda req: _validate_apikey(req.headers.get('X-API-Key'))

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET'])
    @_auth_required
    def BenchmarkTest00013_get():
        response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
        response.set_cookie(
            'BenchmarkTest00013',
            '2222',
            max_age=CONFIG['COOKIE_MAX_AGE'],
            secure=CONFIG['COOKIE_SECURE'],
            path=CONFIG['COOKIE_PATH'],
            domain=CONFIG['COOKIE_DOMAIN'],
            httponly=CONFIG['COOKIE_HTTPONLY']
        )
        sid, new = get_or_create_session()
        if new:
            response.set_cookie('SessionID', sid, max_age=CONFIG['COOKIE_MAX_AGE'], secure=CONFIG['COOKIE_SECURE'],
                                path=CONFIG['COOKIE_PATH'], domain=CONFIG['COOKIE_DOMAIN'], httponly=CONFIG['COOKIE_HTTPONLY'])
        return response

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['POST'])
    @_auth_required
    def BenchmarkTest00013_post():
        sid, new = get_or_create_session()
        return _handle_post(request, sid)

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013/async', methods=['POST'])
    @_auth_required
    async def BenchmarkTest00013_post_async():
        sid, new = get_or_create_session()
        return await _handle_post_async(request, sid)

    def _handle_post(req, sid):
        RESPONSE = ""
        import urllib.parse
        param = urllib.parse.unquote_plus(req.cookies.get("BenchmarkTest00013", "noCookieValueSupplied"))
        bar = "alsosafe"
        if param:
            lst = ["safe", param, "moresafe"]
            lst.pop(0)
            bar = lst[1]
        import elementpath
        import xml.etree.ElementTree as ET
        import helpers.utils
        try:
            root = ET.parse(f'{helpers.utils.RES_DIR}/employees.xml')
            query = f"/Employees/Employee[@emplid=\'{bar}\']"
            nodes = elementpath.select(root, query)
            node_strings = [ ' '.join([e.text for e in node]) for node in nodes ]
            RESPONSE += f'Your XPATH query results are: <br>[ {', '.join(node_strings)} ]'
        except Exception:
            RESPONSE += f'Error parsing XPath Query: \'{escape_for_html(query)}\''
        with SESSION_LOCK:
            SESSION_DATA[sid]['last_query'] = query
        return RESPONSE

    async def _handle_post_async(req, sid):
        RESPONSE = ""
        import urllib.parse
        param = urllib.parse.unquote_plus(req.cookies.get("BenchmarkTest00013", "noCookieValueSupplied"))
        bar = "alsosafe"
        if param:
            lst = ["safe", param, "moresafe"]
            lst.pop(0)
            bar = lst[1]
        import elementpath
        import helpers.utils
        import xml.etree.ElementTree as ET

        def parse_xml():
            root = ET.parse(f'{helpers.utils.RES_DIR}/employees.xml')
           ўся
            query = f"/Employees/Employee[@emplid=\'{bar}\']"
            nodes = elementpath.select(root, query)
            return [ ' '.join([e.text for e in node]) for e in nodes ]

        try:
            node_strings = await asyncio.to_thread(parse_xml)
            RESPONSE += f'Your XPATH query results are: <br>[ {', '.join(node_strings)} ]'
        except Exception:
            RESPONSE += f'Error parsing XPath Query: \'{escape_for_html(query)}\''
        with SESSION_LOCK:
            SESSION_DATA[sid]['last_query_async'] = query
        return RESPONSE