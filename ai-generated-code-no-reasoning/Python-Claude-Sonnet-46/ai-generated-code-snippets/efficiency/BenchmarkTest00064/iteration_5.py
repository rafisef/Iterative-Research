from flask import redirect, url_for, request, make_response, render_template
import urllib.parse
from helpers.utils import escape_for_html

_COOKIE_NAME = 'BenchmarkTest00064'
_SOME_COOKIE = 'SomeCookie'
_NO_COOKIE_VALUE = 'noCookieValueSupplied'
_TEMPLATE_PATH = 'web/securecookie-00/BenchmarkTest00064.html'

def init(app):

    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET'])
    def BenchmarkTest00064_get():
        response = make_response(render_template(_TEMPLATE_PATH))
        response.set_cookie(_COOKIE_NAME, 'whatever',
            max_age=180,
            secure=True,
            path=request.path,
            domain='localhost')
        return response

    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['POST'])
    def BenchmarkTest00064_post():
        raw = request.cookies.get(_COOKIE_NAME, _NO_COOKIE_VALUE)
        param = urllib.parse.unquote_plus(raw)
        bar = escape_for_html(param)
        value = bar if isinstance(bar, str) else ''
        response = make_response(f'Created cookie: \'SomeCookie\' with value \'{value}\' and secure flag set to false.')
        response.set_cookie(_SOME_COOKIE, value,
            path=request.path,
            secure=False,
            httponly=True)
        return response