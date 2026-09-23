from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import json
import re
import urllib.parse
import base64
import helpers.utils

SAFE_COOKIE_PATTERN = re.compile(r'^[A-Za-z0-9\-_]{1,512}$')

ALLOWED_KEYS = frozenset({'A', 'B'})
MAX_STRING_LENGTH = 256
MAX_INT_VALUE = 10**9

def _validate_cookie_data(data: dict) -> bool:
    if not isinstance(data, dict):
        return False
    if not data.keys() <= ALLOWED_KEYS:
        return False
    for k, v in data.items():
        if not isinstance(k, str) or len(k) > 64:
            return False
        if isinstance(v, str):
            if len(v) > MAX_STRING_LENGTH:
                return False
        elif isinstance(v, int):
            if isinstance(v, bool):
                return False
            if abs(v) > MAX_INT_VALUE:
                return False
        else:
            return False
    return True

def _safe_decode_cookie(raw_value: str) -> dict:
    if not SAFE_COOKIE_PATTERN.match(raw_value):
        raise ValueError("Cookie contains invalid characters")
    try:
        decoded_bytes = base64.urlsafe_b64decode(raw_value + '==')
    except Exception:
        raise ValueError("Base64 decoding failed")
    if len(decoded_bytes) > 4096:
        raise ValueError("Decoded cookie data too large")
    try:
        text = decoded_bytes.decode('utf-8', errors='strict')
    except UnicodeDecodeError:
        raise ValueError("Cookie data is not valid UTF-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        raise ValueError("Cookie data is not valid JSON")
    if not _validate_cookie_data(data):
        raise ValueError("Cookie data failed validation")
    return data

def init(app):

    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['GET'])
    def BenchmarkTest00078_get():
        response = make_response(render_template('web/deserialization-00/BenchmarkTest00078.html'))
        response.set_cookie(
            'BenchmarkTest00078',
            'eyJBIjogImZvbyIsICJCIjogOTl9',
            max_age=60 * 3,
            secure=True,
            httponly=True,
            samesite='Strict',
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['POST'])
    def BenchmarkTest00078_post():
        RESPONSE = ""

        raw_cookie = request.cookies.get("BenchmarkTest00078", "")

        if not raw_cookie:
            return "No cookie value supplied", 400

        raw_cookie = urllib.parse.unquote_plus(raw_cookie)

        if not SAFE_COOKIE_PATTERN.match(raw_cookie):
            return "Invalid cookie format", 400

        helpers.utils.sharedstr = "no pickles to be seen here"

        try:
            data = _safe_decode_cookie(raw_cookie)
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            RESPONSE += 'Deserialization failed!'
            return RESPONSE, 400

        RESPONSE += escape_for_html(
            f'shared string is {helpers.utils.sharedstr}'
        )

        return RESPONSE