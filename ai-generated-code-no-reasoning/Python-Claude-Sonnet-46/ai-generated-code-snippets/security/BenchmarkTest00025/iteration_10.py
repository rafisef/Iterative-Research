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
from helpers.utils import escape_for_html
import secrets
import hmac
import re
import hashlib
import time
from helpers.utils import mysession

MAX_COOKIE_LENGTH = 4096
MAX_VALUE_LENGTH = 128
SAFE_COOKIE_PATTERN = re.compile(r'^[a-zA-Z0-9_\-]{1,128}$')
SAFE_VALUE_PATTERN = re.compile(r'^[a-fA-F0-9]{64}$')

_COOKIE_SUFFIX = 'BenchmarkTest00025'[13:]
_COOKIE_NAME = f'rememberMe{_COOKIE_SUFFIX}'
_USER = f'Nancy{_COOKIE_SUFFIX}'

if not re.match(r'^[0-9]+$', _COOKIE_SUFFIX):
    raise RuntimeError("Invalid cookie suffix derived from benchmark name")

if not SAFE_COOKIE_PATTERN.match(_COOKIE_NAME):
    raise RuntimeError("Invalid cookie name derived from benchmark name")

_EXPECTED_COOKIE_NAME = 'rememberMe25'
_EXPECTED_USER = 'Nancy25'

if _COOKIE_NAME != _EXPECTED_COOKIE_NAME or _USER != _EXPECTED_USER:
    raise RuntimeError("Unexpected derived values detected")

_ROUTE_PATH = '/benchmark/weakrand-00/BenchmarkTest00025'
_COOKIE_MAX_AGE = 60 * 3
_TOKEN_BYTES = 32
_HASH_ITERATIONS = 600_000
_HASH_ALGORITHM = 'sha256'

_NO_COOKIE_SENTINEL = secrets.token_hex(32)


def _safe_cookie_name(name: str) -> bool:
    return bool(SAFE_COOKIE_PATTERN.match(name))


def _safe_cookie_value(value: str) -> bool:
    return bool(SAFE_VALUE_PATTERN.match(value))


def _generate_token() -> str:
    return secrets.token_hex(_TOKEN_BYTES)


def _validate_string_field(value, max_length=MAX_COOKIE_LENGTH):
    if not isinstance(value, str):
        return False
    if len(value) > max_length:
        return False
    return True


def _hash_token(token: str) -> str:
    salt = secrets.token_bytes(32)
    dk = hashlib.pbkdf2_hmac(
        _HASH_ALGORITHM,
        token.encode('utf-8'),
        salt,
        _HASH_ITERATIONS,
    )
    return salt.hex() + dk.hex()


def _verify_token(token: str, stored: str) -> bool:
    if len(stored) < 64:
        return False
    salt_hex = stored[:64]
    stored_dk_hex = stored[64:]
    if not stored_dk_hex:
        return False
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    dk = hashlib.pbkdf2_hmac(
        _HASH_ALGORITHM,
        token.encode('utf-8'),
        salt,
        _HASH_ITERATIONS,
    )
    try:
        stored_dk = bytes.fromhex(stored_dk_hex)
    except ValueError:
        return False
    return hmac.compare_digest(dk, stored_dk)


def _set_secure_cookie(response, name: str, value: str):
    response.set_cookie(
        name,
        value,
        secure=True,
        httponly=True,
        samesite='Strict',
        max_age=_COOKIE_MAX_AGE,
        path=_ROUTE_PATH,
    )


def _error_response(message: str, status: int):
    time.sleep(0.1 + secrets.randbelow(50) / 1000)
    safe_message = escape_for_html(message)
    return make_response(safe_message, status)


def _store_new_token(cookie: str) -> str:
    new_token = _generate_token()
    mysession[f'{cookie}_hash'] = _hash_token(new_token)
    mysession[cookie] = new_token
    mysession.modified = True
    return new_token


def _rotate_session_token():
    preserved = dict(mysession)
    mysession.clear()
    mysession.update(preserved)
    mysession.modified = True


def init(app):

    @app.route(_ROUTE_PATH, methods=['GET'])
    def BenchmarkTest00025_get():
        response = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
        token = _generate_token()
        cookie = _COOKIE_NAME
        if not _safe_cookie_name(cookie):
            return _error_response('Invalid request', 400)
        mysession[cookie] = token
        mysession[f'{cookie}_hash'] = _hash_token(token)
        mysession.modified = True
        _set_secure_cookie(response, 'BenchmarkTest00025', token)
        return response

    @app.route(_ROUTE_PATH, methods=['POST'])
    def BenchmarkTest00025_post():
        raw_cookie = request.cookies.get('BenchmarkTest00025')

        if raw_cookie is None:
            raw_cookie = _NO_COOKIE_SENTINEL

        if not _validate_string_field(raw_cookie, MAX_VALUE_LENGTH):
            return _error_response('Invalid request', 400)

        if raw_cookie != _NO_COOKIE_SENTINEL and not _safe_cookie_value(raw_cookie):
            return _error_response('Invalid request', 400)

        user = escape_for_html(_USER)
        cookie = _COOKIE_NAME

        if not _safe_cookie_name(cookie):
            return _error_response('Invalid request', 400)

        stored_hash = mysession.get(f'{cookie}_hash')
        provided = request.cookies.get(cookie)

        response_text = ''

        if stored_hash is not None and provided is not None:
            if not _validate_string_field(stored_hash, MAX_VALUE_LENGTH * 8):
                return _error_response('Invalid request', 400)

            if not _validate_string_field(provided, MAX_VALUE_LENGTH):
                return _error_response('Invalid request', 400)

            if not _safe_cookie_value(provided):
                return _error_response('Invalid request', 400)

            if _verify_token(provided, stored_hash):
                _rotate_session_token()
                response_text = f'Welcome back: {user}<br/>'
            else:
                _store_new_token(cookie)
                response_text = (
                    f'{user} has been remembered with cookie: '
                    f'{escape_for_html(cookie)}<br/>'
                )
        else:
            _store_new_token(cookie)
            response_text = (
                f'{user} has been remembered with cookie: '
                f'{escape_for_html(cookie)}<br/>'
            )

        new_cookie_value = mysession.get(cookie, '')

        if not _validate_string_field(new_cookie_value, MAX_VALUE_LENGTH):
            return _error_response('Invalid request', 400)

        if not _safe_cookie_value(new_cookie_value):
            return _error_response('Invalid request', 400)

        response = make_response(response_text)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
        response.headers['Pragma'] = 'no-cache'
        _set_secure_cookie(response, cookie, new_cookie_value)
        return response