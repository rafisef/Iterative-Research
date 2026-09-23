import base64
import binascii
import json
import urllib.parse

from flask import request, make_response, render_template
import helpers.utils

SAFE_COOKIE_VALUE = 'gASVNwAAAAAAAACMCF9fbWFpbl9flIwOc2FmZV90b19waWNrbGWUk5QpgZR9lCiMAWGUjANmb2-UjAFilEtjdWIu'
ALLOWED_KEYS = frozenset({'a', 'foo', 'b'})
COOKIE_NAME = 'BenchmarkTest00078'
ROUTE_PATH = '/benchmark/deserialization-00/BenchmarkTest00078'
COOKIE_PREFIX = 'help'
COOKIE_SUFFIX = 'snapes on a plane'
COOKIE_MAX_AGE = 180
MAX_COOKIE_LENGTH = 4096

_PREFIX_LEN = len(COOKIE_PREFIX)
_SUFFIX_LEN = len(COOKIE_SUFFIX)
_MIN_PARAM_LEN = _PREFIX_LEN + _SUFFIX_LEN + 1


def _safe_decode(encoded: str) -> dict:
    try:
        raw = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4))
    except binascii.Error as exc:
        raise ValueError("Invalid base64 encoding") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("Invalid JSON payload") from exc
    if not isinstance(data, dict):
        raise ValueError("Expected a JSON object")
    return {k: v for k, v in data.items() if k in ALLOWED_KEYS}


def _extract_bar(param: str) -> str | None:
    if (
        len(param) >= _MIN_PARAM_LEN
        and param.startswith(COOKIE_PREFIX)
        and param.endswith(COOKIE_SUFFIX)
    ):
        return param[_PREFIX_LEN: len(param) - _SUFFIX_LEN]
    return None


def _build_cookie_response(path: str) -> make_response:
    response = make_response(
        render_template('web/deserialization-00/BenchmarkTest00078.html')
    )
    response.set_cookie(
        COOKIE_NAME,
        SAFE_COOKIE_VALUE,
        max_age=COOKIE_MAX_AGE,
        secure=True,
        httponly=True,
        samesite='Strict',
        path=path,
        domain='localhost',
    )
    return response


def _handle_post() -> tuple[str, int] | str:
    raw_cookie = request.cookies.get(COOKIE_NAME, "")
    if not raw_cookie:
        return 'No cookie value supplied', 400
    if len(raw_cookie) > MAX_COOKIE_LENGTH:
        return 'Cookie value too large', 400

    bar = _extract_bar(urllib.parse.unquote_plus(raw_cookie))
    if bar is None:
        return 'Invalid cookie format', 400

    helpers.utils.sharedstr = "no pickles to be seen here"

    try:
        result = _safe_decode(bar)
    except ValueError:
        return 'Decoding failed!', 400

    helpers.utils.sharedstr = str(result)
    return f'shared string is {helpers.utils.sharedstr}'


def init(app):

    @app.route(ROUTE_PATH, methods=['GET'])
    def BenchmarkTest00078_get():
        return _build_cookie_response(request.path)

    @app.route(ROUTE_PATH, methods=['POST'])
    def BenchmarkTest00078_post():
        return _handle_post()