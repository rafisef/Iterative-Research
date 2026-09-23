from flask import request, make_response, render_template
from helpers.utils import escape_for_html
import json
import re
import base64
import helpers.utils
import hmac
import hashlib
import os
import secrets

SAFE_COOKIE_PATTERN = re.compile(r'^[A-Za-z0-9\-_]{1,512}$')

ALLOWED_KEYS = frozenset({'A', 'B'})
MAX_STRING_LENGTH = 256
MAX_INT_VALUE = 10**9

_COOKIE_SECRET_HEX = os.environ.get('COOKIE_SECRET')
if _COOKIE_SECRET_HEX:
    _COOKIE_SECRET = bytes.fromhex(_COOKIE_SECRET_HEX)
    if len(_COOKIE_SECRET) < 32:
        raise RuntimeError("COOKIE_SECRET must be at least 32 bytes")
else:
    _COOKIE_SECRET = secrets.token_bytes(32)


def _sign_cookie(value: str) -> str:
    sig = hmac.new(_COOKIE_SECRET, value.encode('utf-8'), hashlib.sha256).hexdigest()
    return f"{value}.{sig}"


def _verify_and_strip_signature(signed_value: str) -> str:
    if '.' not in signed_value:
        raise ValueError("Cookie missing signature")
    value, _, sig = signed_value.rpartition('.')
    if not value or not sig:
        raise ValueError("Cookie signature malformed")
    if len(sig) != 64:
        raise ValueError("Cookie signature has unexpected length")
    expected_sig = hmac.new(_COOKIE_SECRET, value.encode('utf-8'), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, sig):
        raise ValueError("Cookie signature invalid")
    return value


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
        padding = (4 - len(raw_value) % 4) % 4
        decoded_bytes = base64.urlsafe_b64decode(raw_value + '=' * padding)
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
    if not isinstance(data, dict):
        raise ValueError("Cookie data must be a JSON object")
    if not _validate_cookie_data(data):
        raise ValueError("Cookie data failed validation")
    return data


def init(app):

    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['GET'])
    def BenchmarkTest00078_get():
        raw_cookie_value = 'eyJBIjogImZvbyIsICJCIjogOTl9'
        signed_value = _sign_cookie(raw_cookie_value)
        response = make_response(render_template('web/deserialization-00/BenchmarkTest00078.html'))
        response.set_cookie(
            'BenchmarkTest00078',
            signed_value,
            max_age=60 * 3,
            secure=True,
            httponly=True,
            samesite='Strict',
            path=request.path,
            domain='localhost'
        )
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = "default-src 'none'"
        response.headers['Cache-Control'] = 'no-store'
        return response

    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['POST'])
    def BenchmarkTest00078_post():
        RESPONSE = ""

        raw_cookie = request.cookies.get("BenchmarkTest00078", "")

        if not raw_cookie:
            return "No cookie value supplied", 400

        if len(raw_cookie) > 1024:
            return "Cookie value too long", 400

        if not re.match(r'^[A-Za-z0-9\-_.]{1,1024}$', raw_cookie):
            return "Cookie contains invalid characters", 400

        try:
            raw_cookie = _verify_and_strip_signature(raw_cookie)
        except ValueError:
            return "Invalid cookie signature", 400

        if not SAFE_COOKIE_PATTERN.match(raw_cookie):
            return "Invalid cookie format", 400

        shared_str = "no pickles to be seen here"

        try:
            data = _safe_decode_cookie(raw_cookie)
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            RESPONSE += 'Deserialization failed!'
            return RESPONSE, 400

        _ = data

        RESPONSE += escape_for_html(
            f'shared string is {shared_str}'
        )

        response = make_response(RESPONSE, 200)
        response.headers['Content-Type'] = 'text/plain; charset=utf-8'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Content-Security-Policy'] = "default-src 'none'"
        response.headers['Cache-Control'] = 'no-store'
        return response