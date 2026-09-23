import os
from flask import redirect, url_for, request, make_response, render_template, abort
from helpers.utils import escape_for_html
import asyncio

COOKIE_DOMAIN = os.getenv('COOKIE_DOMAIN', 'localhost')
COOKIE_MAX_AGE = int(os.getenv('COOKIE_MAX_AGE', '180'))
COOKIE_SECURE = os.getenv('COOKIE_SECURE', 'True').lower() in ('1', 'true', 'yes')

AUTH_CREDENTIALS = {
    'basic': {'admin': 'secret'},
    'apikey': {'abcd1234': True}
}

def _validate_basic(auth):
    if not auth or not auth.username or not auth.password:
        return False
    return AUTH_CREDENTIALS['basic'].get(auth.username) == auth.password

def _validate_apikey(key):
    return key in AUTH_CREDENTIALS['apikey']

def _auth_required(f):
    def wrapper(*args, **kwargs):
        provider = request.headers.get('X-Auth-Provider', 'basic')
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
        response.set_cookie('BenchmarkTest00013', '2222',
            max_age=COOKIE_MAX_AGE,
            secure=COOKIE_SECURE,
            path=request.path,
            domain=COOKIE_DOMAIN)
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
            node_strings = []
            for node in nodes:
                node_strings.append(' '.join([e.text for e in node]))
            RESPONSE += (
                f'Your XPATH query results are: <br>[ {', '.join(node_strings)} ]'
            )
        except Exception:
            RESPONSE += (
                f'Error parsing XPath Query: \'{escape_for_html(query)}\''
            )
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
        async def parse_xml():
            root = ET.parse(f'{helpers.utils.RES_DIR}/employees.xml')
            query = f"/Employees/Employee[@emplid=\'{bar}\']"
            nodes = elementpath.select(root, query)
            node_strings = []
            for node in nodes:
                node_strings.append(' '.join([e.text for e in node]))
            return node_strings
        try:
            node_strings = await asyncio.to_thread(parse_xml)
            RESPONSE += (
                f'Your XPATH query results are: <br>[ {', '.join(node_strings)} ]'
            )
        except Exception:
            RESPONSE += (
                f'Error parsing XPath Query: \'{escape_for_html(query)}\''
            )
        return RESPONSE