from flask import request, make_response, render_template
from helpers.utils import escape_for_html, TESTFILES_DIR
import os

_COOKIE_MAX_AGE = 180
_BAR_VALUE = "This_should_always_happen"
_ROUTE = '/benchmark/pathtraver-00/BenchmarkTest00004'
_COOKIE_NAME = 'BenchmarkTest00004'
_COOKIE_VALUE = 'Filename'
_TEMPLATE = 'web/pathtraver-00/BenchmarkTest00004.html'
_FILE_PATH = os.path.join(TESTFILES_DIR, _BAR_VALUE)
_ESCAPED_PATH = escape_for_html(_FILE_PATH)

def _get_post_response():
    if os.path.exists(_FILE_PATH):
        return f"Access to file: '{_ESCAPED_PATH}' created. And file already exists."
    return "Access to file: created. But file doesn't exist yet."

def init(app):

    @app.route(_ROUTE, methods=['GET'])
    def BenchmarkTest00004_get():
        response = make_response(render_template(_TEMPLATE))
        response.set_cookie(_COOKIE_NAME, _COOKIE_VALUE,
            path=request.path,
            max_age=_COOKIE_MAX_AGE,
            secure=True,
            domain='localhost')
        return response

    @app.route(_ROUTE, methods=['POST'])
    def BenchmarkTest00004_post():
        return _get_post_response()