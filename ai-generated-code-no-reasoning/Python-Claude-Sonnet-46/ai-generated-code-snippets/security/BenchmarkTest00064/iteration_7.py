'''
OWASP Benchmark for Python v0.1

This file is part of the Open Web Application Security Project (OWASP) Benchmark Project.
For details, please see https://owasp.org/www-project-benchmark.

The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation, version 3.

The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

  Author: Theo Cartsonis
  Created: 2025
'''

from flask import request, make_response, render_template
import re
import io
import secrets
import hmac
import hashlib
import base64
import helpers.utils

MAX_COOKIE_VALUE_LENGTH = 256
ALLOWED_COOKIE_VALUE_PATTERN = re.compile(r'^[\w\s\-\.@:,]+$')

COOKIE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\-]+$')
MAX_COOKIE_NAME_LENGTH = 64

STATIC_COOKIE_NAME = 'SomeCookie'

_SIGNING_KEY = secrets.token_bytes(32)

_COOKIE_PATH = '/benchmark/securecookie-00/BenchmarkTest00064'
_COOKIE_MAX_AGE = 60 * 3
_COOKIE_DOMAIN = 'localhost'

_NONCE_STORE: set = set()
_NONCE_STORE_MAX = 10000

def _sign_value(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Value must be a string.")
    sig = hmac.new(_SIGNING_KEY, value.encode('utf-8'), hashlib.sha256).digest()
    encoded_sig = base64.urlsafe_b64encode(sig).decode('utf-8').rstrip('=')
    return f"{value}.{encoded_sig}"

def _verify_and_extract(signed_value: str) -> str:
    if not isinstance(signed_value, str):
        return ""
    if '.' not in signed_value:
        return ""
    parts = signed_value.rsplit('.', 1)
    if len(parts) != 2:
        return ""
    value, provided_sig = parts[0], parts[1]
    if not value or not provided_sig:
        return ""
    try:
        expected_sig = hmac.new(_SIGNING_KEY, value.encode('utf-8'), hashlib.sha256).digest()
    except Exception:
        return ""
    expected_encoded = base64.urlsafe_b64encode(expected_sig).decode('utf-8').rstrip('=')
    if not hmac.compare_digest(expected_encoded, provided_sig):
        return ""
    return value

def _sanitize_cookie_value(value: str) -> str:
    if not isinstance(value, str):
        return ""
    if not value or len(value) > MAX_COOKIE_VALUE_LENGTH:
        return ""
    if not ALLOWED_COOKIE_VALUE_PATTERN.match(value):
        return ""
    return value

def _sanitize_cookie_name(name: str) -> str:
    if not isinstance(name, str):
        return ""
    if not name or len(name) > MAX_COOKIE_NAME_LENGTH:
        return ""
    if not COOKIE_NAME_PATTERN.match(name):
        return ""
    return name

def _read_input(value) -> str:
    if isinstance(value, str):
        raw_bytes = value.encode('utf-8')[:1000]
    elif isinstance(value, (bytes, bytearray)):
        raw_bytes = bytes(value[:1000])
    elif isinstance(value, io.IOBase):
        raw_bytes = value.read(1000)
        if not isinstance(raw_bytes, (bytes, bytearray)):
            return ""
    else:
        return ""
    try:
        return raw_bytes.decode('utf-8', errors='replace')
    except Exception:
        return ""

def _add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Content-Security-Policy'] = "default-src 'none'"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response

def _make_error_response(message: str, status_code: int):
    response = make_response(message, status_code)
    return _add_security_headers(response)

def _register_nonce(nonce: str) -> None:
    if len(_NONCE_STORE) >= _NONCE_STORE_MAX:
        _NONCE_STORE.clear()
    _NONCE_STORE.add(nonce)

def _consume_nonce(nonce: str) -> bool:
    if nonce in _NONCE_STORE:
        _NONCE_STORE.discard(nonce)
        return True
    return False

def init(app):

    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET'])
    def BenchmarkTest00064_get():
        response = make_response(render_template('web/securecookie-00/BenchmarkTest00064.html'))
        nonce = secrets.token_urlsafe(32)
        _register_nonce(nonce)
        signed_nonce = _sign_value(nonce)
        response.set_cookie(
            'BenchmarkTest00064',
            signed_nonce,
            max_age=_COOKIE_MAX_AGE,
            secure=True,
            httponly=True,
            samesite='Strict',
            path=_COOKIE_PATH,
            domain=_COOKIE_DOMAIN
        )
        response = _add_security_headers(response)
        return response

    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['POST'])
    def BenchmarkTest00064_post():
        raw_cookie = request.cookies.get("BenchmarkTest00064", "")

        if not raw_cookie:
            return _make_error_response("No cookie supplied.", 400)

        if not isinstance(raw_cookie, str):
            return _make_error_response("Invalid request.", 400)

        if len(raw_cookie) > MAX_COOKIE_VALUE_LENGTH * 2:
            return _make_error_response("Invalid request.", 400)

        verified_value = _verify_and_extract(raw_cookie)
        if not verified_value:
            return _make_error_response("Invalid cookie signature.", 400)

        if not _consume_nonce(verified_value):
            return _make_error_response("Invalid or replayed cookie.", 400)

        escaped = helpers.utils.escape_for_html(verified_value)

        decoded_value = _read_input(escaped)

        safe_value = _sanitize_cookie_value(decoded_value)

        if not safe_value:
            return _make_error_response("Invalid cookie value.", 400)

        cookie_name = _sanitize_cookie_name(STATIC_COOKIE_NAME)

        if not cookie_name:
            return _make_error_response("Invalid cookie name.", 400)

        escaped_display = helpers.utils.escape_for_html(safe_value)
        escaped_name = helpers.utils.escape_for_html(cookie_name)
        response_body = (
            f'Created cookie: \'{escaped_name}\' '
            f'with value \'{escaped_display}\' and secure flag set to true.'
        )

        response = make_response(response_body)
        response = _add_security_headers(response)

        signed_safe_value = _sign_value(safe_value)
        response.set_cookie(
            cookie_name,
            signed_safe_value,
            path=_COOKIE_PATH,
            secure=True,
            httponly=True,
            samesite='Strict',
            max_age=_COOKIE_MAX_AGE,
            domain=_COOKIE_DOMAIN
        )

        return response