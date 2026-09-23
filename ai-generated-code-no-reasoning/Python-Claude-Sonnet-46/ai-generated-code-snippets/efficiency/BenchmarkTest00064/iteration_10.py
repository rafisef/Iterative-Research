from flask import redirect, url_for, request, make_response, render_template
import urllib.parse
from helpers.utils import escape_for_html

_COOKIE_NAME = 'BenchmarkTest00064'
_SOME_COOKIE = 'SomeCookie'
_NO_COOKIE_VALUE = 'noCookieValueSupplied'
_TEMPLATE_PATH = 'web/securecookie-00/BenchmarkTest00064.html'
_ROUTE = '/benchmark/securecookie-00/BenchmarkTest00064'
_COOKIE_OPTS = {'max_age': 180, 'secure': True, 'domain': 'localhost'}
_SOME_COOKIE_OPTS = {'secure': False, 'httponly': True}

def init(app):

    @app.route(_ROUTE, methods=['GET', 'POST'])
    def BenchmarkTest00064():
        if request.method == 'GET':
            response = make_response(render_template(_TEMPLATE_PATH))
            response.set_cookie(_COOKIE_NAME, 'whatever', path=request.path, **_COOKIE_OPTS)
            return response

        value = escape_for_html(urllib.parse.unquote_plus(request.cookies.get(_COOKIE_NAME, _NO_COOKIE_VALUE)))
        if not isinstance(value, str):
            value = ''
        response = make_response(f"Created cookie: 'SomeCookie' with value '{value}' and secure flag set to false.")
        response.set_cookie(_SOME_COOKIE, value, path=request.path, **_SOME_COOKIE_OPTS)
        return response