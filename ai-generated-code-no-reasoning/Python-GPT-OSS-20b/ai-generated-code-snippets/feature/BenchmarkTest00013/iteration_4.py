import os
import json
import asyncio
from flask import redirect, url_for, request, make_response, render_template, abort
from helpers.utils import escape_for_html

COOKIE_DOMAIN = os.getenv('COOKIE_DOMAIN', 'localhost')
COOKIE_MAX_AGE = int(os.getenv('COOKIE_MAX_AGE', '180'))
COOKIE_SECURE = os.getenv('COOKIE_SECURE', 'True').lower() in ('1', 'true', 'yes')
COOKIE_PATH = os.getenv('COOKIE_PATH', '/')
COOKIE_HTTPONLY = os.getenv('COOKIE_HTTPONLY', 'True').lower() in ('1', 'true', 'yes')

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

AUTH_ENABLED = os.getenv('AUTH_ENABLED', 'True').lower() in ('1', 'true', 'yes')
DEFAULT_PROVIDER = os.getenv('DEFAULT_PROVIDER', 'basic')

def _validate_basic(auth):
    if not auth or not auth.username or not auth.password:
        return False
    return AUTH_CREDENTIALS['basic'].get(auth.username) == auth.password

def _validate_apikey(key):
    return key in AUTH_CREDENTIALS['apikey']

def _auth_required(f):
    def wrapper(*args, **kwargs):
        if not AUTH_ENABLED:
            return f(*args, **kwargs)
        provider = request.headers.get('X-Auth-Provider', DEFAULT_PROVIDER)
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

def init(app):

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET'])
    @_auth_required
    def BenchmarkTest00013_get():
        response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
        response.set_cookie(
            'BenchmarkTest00013',
            '2222',
            max_age=COOKIE_MAX_AGE,
            secure=COOKIE_SECURE,
            path=COOKIE_PATH,
            domain=COOKIE_DOMAIN,
            httponly=COOKIE_HTTPONLY
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