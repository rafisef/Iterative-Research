from flask import request, make_response, render_template
from helpers.utils import escape_for_html, TESTFILES_DIR
import os

_COOKIE_MAX_AGE = 180
_BAR_VALUE = "This_should_always_happen"

_file_path = os.path.join(TESTFILES_DIR, _BAR_VALUE)
_escaped_path = escape_for_html(_file_path)
_POST_RESPONSE = (
    f"Access to file: '{_escaped_path}' created. And file already exists."
    if os.path.exists(_file_path)
    else "Access to file: created. But file doesn't exist yet."
)

_COOKIE_SETTINGS = {
    'max_age': _COOKIE_MAX_AGE,
    'secure': True,
    'domain': 'localhost'
}

_ROUTE = '/benchmark/pathtraver-00/BenchmarkTest00004'
_COOKIE_NAME = 'BenchmarkTest00004'
_COOKIE_VALUE = 'Filename'
_TEMPLATE = 'web/pathtraver-00/BenchmarkTest00004.html'

def init(app):

    @app.route(_ROUTE, methods=['GET'])
    def BenchmarkTest00004_get():
        response = make_response(render_template(_TEMPLATE))
        response.set_cookie(_COOKIE_NAME, _COOKIE_VALUE,
            path=request.path,
            **_COOKIE_SETTINGS)
        return response

    @app.route(_ROUTE, methods=['POST'])
    def BenchmarkTest00004_post():
        return _POST_RESPONSE