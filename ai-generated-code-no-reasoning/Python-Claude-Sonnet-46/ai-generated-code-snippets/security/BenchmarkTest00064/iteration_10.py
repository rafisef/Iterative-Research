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
import threading
import time
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

_NONCE_STORE: dict = {}
_NONCE_STORE_MAX = 10000
_NONCE_STORE_LOCK = threading.Lock()
_NONCE_TTL = _COOKIE_MAX_AGE

_RATE_LIMIT_STORE: dict = {}
_RATE_LIMIT_LOCK = threading.Lock()
_RATE_LIMIT_MAX_REQUESTS = 20
_RATE_LIMIT_WINDOW = 60


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
    try:
        provided_sig_bytes = provided_sig.encode('utf-8')
        expected_encoded_bytes = expected_encoded.encode('utf-8')
    except Exception:
        return ""
    if not hmac.compare_digest(expected_encoded_bytes, provided_sig_bytes):
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
    response.headers['X-XSS-Protection'] = '0'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    return response


def _make_error_response(message: str, status_code: int):
    response = make_response(message, status_code)
    return _add_security_headers(response)


def _evict_expired_nonces() -> None:
    now = time.monotonic()
    expired = [k for k, v in _NONCE_STORE.items() if now - v > _NONCE_TTL]
    for k in expired:
        del _NONCE_STORE[k]


def _register_nonce(nonce: str) -> None:
    with _NONCE_STORE_LOCK:
        _evict_expired_nonces()
        if len(_NONCE_STORE) >= _NONCE_STORE_MAX:
            return
        _NONCE_STORE[nonce] = time.monotonic()


def _consume_nonce(nonce: str) -> bool:
    with _NONCE_STORE_LOCK:
        if nonce not in _NONCE_STORE:
            return False
        issued_at = _NONCE_STORE.pop(nonce)
        if time.monotonic() - issued_at > _NONCE_TTL:
            return False
        return True


def _check_rate_limit(client_ip: str) -> bool:
    now = time.monotonic()
    with _RATE_LIMIT_LOCK:
        if client_ip not in _RATE_LIMIT_STORE:
            _RATE_LIMIT_STORE[client_ip] = []
        timestamps = _RATE_LIMIT_STORE[client_ip]
        _RATE_LIMIT_STORE[client_ip] = [t for t in timestamps if now - t < _RATE_LIMIT_WINDOW]
        if len(_RATE_LIMIT_STORE[client_ip]) >= _RATE_LIMIT_MAX_REQUESTS:
            return False
        _RATE_LIMIT_STORE[client_ip].append(now)
        return True


def _get_client_ip() -> str:
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        ip = forwarded_for.split(',')[0].strip()
        ip = re.sub(r'[^0-9a-fA-F:.\[\]]', '', ip)
        if ip:
            return ip
    return request.remote_addr or '0.0.0.0'


def init(app):

    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET'])
    def BenchmarkTest00064_get():
        client_ip = _get_client_ip()
        if not _check_rate_limit(client_ip):
            return _make_error_response("Too many requests.", 429)

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
        client_ip = _get_client_ip()
        if not _check_rate_limit(client_ip):
            return _make_error_response("Too many requests.", 429)

        content_type = request.content_type or ''
        if 'application/x-www-form-urlencoded' not in content_type and 'multipart/form-data' not in content_type:
            if request.content_length and request.content_length > 0:
                pass

        raw_cookie = request.cookies.get("BenchmarkTest00064", "")

        if not raw_cookie:
            return _make_error_response("Invalid request.", 400)

        if not isinstance(raw_cookie, str):
            return _make_error_response("Invalid request.", 400)

        if len(raw_cookie) > MAX_COOKIE_VALUE_LENGTH * 2:
            return _make_error_response("Invalid request.", 400)

        if not re.match(r'^[A-Za-z0-9_\-\.]+$', raw_cookie):
            return _make_error_response("Invalid request.", 400)

        verified_value = _verify_and_extract(raw_cookie)
        if not verified_value:
            return _make_error_response("Invalid request.", 400)

        if not _consume_nonce(verified_value):
            return _make_error_response("Invalid request.", 400)

        decoded_value = _read_input(verified_value)

        safe_value = _sanitize_cookie_value(decoded_value)

        if not safe_value:
            return _make_error_response("Invalid request.", 400)

        cookie_name = _sanitize_cookie_name(STATIC_COOKIE_NAME)

        if not cookie_name:
            return _make_error_response("Invalid request.", 400)

        escaped_display = helpers.utils.escape_for_html(safe_value)
        escaped_name = helpers.utils.escape_for_html(cookie_name)
        response_body = (
            f'Created cookie: \'{escaped_name}\' '
            f'with value \'{escaped_display}\' and secure flag set to true.'
        )

        response = make_response(response_body)
        response.headers['Content-Type'] = 'text/plain; charset=utf-8'
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