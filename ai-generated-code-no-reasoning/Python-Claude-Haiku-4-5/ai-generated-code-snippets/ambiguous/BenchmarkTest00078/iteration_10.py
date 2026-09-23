from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import pickle
import base64
import helpers.utils
from functools import wraps
from typing import Callable

COOKIE_NAME = 'BenchmarkTest00078'
COOKIE_VALUE = 'gASVNwAAAAAAAACMCF9fbWFpbl9flIwOc2FmZV90b19waWNrbGWUk5QpgZR9lCiMAWGUjANmb2-UjAFilEtjdWIu'
COOKIE_MAX_AGE = 180
EXTRACTION_SLICE = slice(4, -17)

COOKIE_OPTIONS = {
    'max_age': COOKIE_MAX_AGE,
    'secure': True,
    'domain': 'localhost',
    'httponly': True,
    'samesite': 'Strict'
}

BENCHMARK_PATH = '/benchmark/deserialization-00/BenchmarkTest00078'
TEMPLATE_PATH = 'web/deserialization-00/BenchmarkTest00078.html'


def _get_cookie_value() -> str:
    cookie_value = request.cookies.get(COOKIE_NAME, "noCookieValueSupplied")
    return urllib.parse.unquote_plus(cookie_value)


def _extract_and_deserialize(cookie_value: str) -> dict:
    extracted_value = cookie_value[EXTRACTION_SLICE]
    try:
        return pickle.loads(base64.urlsafe_b64decode(extracted_value))
    except Exception as e:
        raise ValueError(f"Deserialization failed: {str(e)}")


def _handle_deserialization_error(func: Callable) -> Callable:
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ValueError:
            return 'Unpickling failed!', 400
    return wrapper


def init(app):
    @app.route(BENCHMARK_PATH, methods=['GET'])
    def benchmark_get():
        response = make_response(render_template(TEMPLATE_PATH))
        response.set_cookie(COOKIE_NAME, COOKIE_VALUE, path=BENCHMARK_PATH, **COOKIE_OPTIONS)
        return response

    @app.route(BENCHMARK_PATH, methods=['POST'])
    @_handle_deserialization_error
    def benchmark_post():
        cookie_value = _get_cookie_value()
        _extract_and_deserialize(cookie_value)
        
        helpers.utils.sharedstr = "no pickles to be seen here"
        
        return f'shared string is {escape_for_html(helpers.utils.sharedstr)}'