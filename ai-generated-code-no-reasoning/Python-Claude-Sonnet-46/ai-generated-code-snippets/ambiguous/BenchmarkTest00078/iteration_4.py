import base64
import binascii
import urllib.parse
import json

from flask import request, make_response, render_template
import helpers.utils


SAFE_COOKIE_VALUE = 'gASVNwAAAAAAAACMCF9fbWFpbl9flIwOc2FmZV90b19waWNrbGWUk5QpgZR9lCiMAWGUjANmb2-UjAFilEtjdWIu'
ALLOWED_KEYS = frozenset({'a', 'foo', 'b'})
COOKIE_NAME = 'BenchmarkTest00078'
ROUTE_PATH = '/benchmark/deserialization-00/BenchmarkTest00078'
COOKIE_PREFIX = 'help'
COOKIE_SUFFIX = 'snapes on a plane'
COOKIE_MAX_AGE = 60 * 3
MIN_BAR_LENGTH = 1
MAX_COOKIE_LENGTH = 4096


def _safe_decode(encoded: str) -> dict:
    padded = encoded + '=' * (-len(encoded) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded)
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
    if param.startswith(COOKIE_PREFIX) and param.endswith(COOKIE_SUFFIX):
        bar = param[len(COOKIE_PREFIX): len(param) - len(COOKIE_SUFFIX)]
        if len(bar) >= MIN_BAR_LENGTH:
            return bar
    return None


def init(app):

    @app.route(ROUTE_PATH, methods=['GET'])
    def BenchmarkTest00078_get():
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
            path=request.path,
            domain='localhost',
        )
        return response

    @app.route(ROUTE_PATH, methods=['POST'])
    def BenchmarkTest00078_post():
        raw_cookie = request.cookies.get(COOKIE_NAME, "")
        if not raw_cookie:
            return 'No cookie value supplied', 400

        if len(raw_cookie) > MAX_COOKIE_LENGTH:
            return 'Cookie value too large', 400

        param = urllib.parse.unquote_plus(raw_cookie)
        bar = _extract_bar(param)

        if bar is None:
            return 'Invalid cookie format', 400

        helpers.utils.sharedstr = "no pickles to be seen here"

        try:
            result = _safe_decode(bar)
        except ValueError:
            return 'Decoding failed!', 400

        helpers.utils.sharedstr = str(result)

        return f'shared string is {helpers.utils.sharedstr}'