import os
import json
import asyncio
from flask import redirect, url_for, request, make_response, render_template, abort
from helpers.utils import escape_for_html

# Base configuration
CONFIG = {
    'COOKIE_DOMAIN': 'localhost',
    'COOKIE_MAX_AGE': 180,
    'COOKIE_SECURE': True,
    'COOKIE_PATH': '/',
    'COOKIE_HTTPONLY': True,
    'AUTH_ENABLED': True,
    'DEFAULT_PROVIDER': 'basic',
    'AUTH_BASIC_CREDENTIALS': [],
    'AUTH_APIKEY_CREDENTIALS': []
}

# Load from JSON file if specified
config_file = os.getenv('CONFIG_FILE')
if config_file and os.path.isfile(config_file):
    with open(config_file, 'r') as f:
        file_cfg = json.load(f)
    for k, v in file_cfg.items():
        if k in CONFIG:
            CONFIG[k] = v

# Override with environment variables
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

def _auth_required(f):
    def wrapper(*args, **kwargs):
        if not CONFIG['AUTH_ENABLED']:
            return f(*args, **kwargs)
        provider = request.headers.get('X-Auth-Provider', CONFIG['DEFAULT_PROVIDER'])
        if provider == 'basic':
            if not _validate_basic(request.authorization):
                abort(401)
        elif provider == 'apikey':
            key = request.headers.get('X-API-Key')
            if not key or not _validate_apikey(key):
                abort(401)
        else:
            abort(400)
        return f(*args, **kwargs)
    return wrapper

def init(app, cfg=None):
    if cfg:
        CONFIG.update(cfg)

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
        return response

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['POST'])
    @_auth_required
    def BenchmarkTest00013_post():
        return _handle_post(request)

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013/async', methods=['POST'])
    @_auth_required
    async def BenchmarkTest00013_post_async():
        return await _handle_post_async(request)

    def _handle_post(req):
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
        return RESPONSE

    async def _handle_post_async(req):
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
            query = f"/Employees/Employee[@emplid=\'{bar}\']"
            nodes = elementpath.select(root, query)
            return [ ' '.join([e.text for e in node]) for node in nodes ]

        try:
            node_strings = await asyncio.to_thread(parse_xml)
            RESPONSE += f'Your XPATH query results are: <br>[ {', '.join(node_strings)} ]'
        except Exception:
            RESPONSE += f'Error parsing XPath Query: \'{escape_for_html(query)}\''
        return RESPONSE