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

from flask import redirect, url_for, request, make_response, render_template, session, abort
from helpers.utils import escape_for_html
import re
import secrets
import hmac
import time

ALLOWED_SESSION_KEY_PATTERN = re.compile(r'^[a-zA-Z0-9_\-]{1,64}$')
ALLOWED_SESSION_VALUE_PATTERN = re.compile(r'^[a-zA-Z0-9_\-]{1,128}$')
MAX_PARAM_LENGTH = 64
MAX_VALUE_LENGTH = 128
FIXED_SESSION_KEY = "BenchmarkTest00072_user"
FIXED_SESSION_VALUE = "12345"
CSRF_TOKEN_EXPIRY_SECONDS = 300

def sanitize_session_key(value):
    if not isinstance(value, str):
        return None
    if len(value) > MAX_PARAM_LENGTH:
        return None
    if not ALLOWED_SESSION_KEY_PATTERN.match(value):
        return None
    return value

def sanitize_session_value(value):
    if not isinstance(value, str):
        return None
    if len(value) > MAX_VALUE_LENGTH:
        return None
    if not ALLOWED_SESSION_VALUE_PATTERN.match(value):
        return None
    return value

def generate_csrf_token():
    token = secrets.token_hex(32)
    timestamp = int(time.time())
    return token, timestamp

def validate_csrf_token(token_from_form, token_from_session, token_timestamp):
    if not token_from_form or not token_from_session or not token_timestamp:
        return False
    current_time = int(time.time())
    if current_time - token_timestamp > CSRF_TOKEN_EXPIRY_SECONDS:
        return False
    if not isinstance(token_from_form, str) or not isinstance(token_from_session, str):
        return False
    if len(token_from_form) != len(token_from_session):
        return False
    return hmac.compare_digest(
        token_from_form.encode('utf-8'),
        token_from_session.encode('utf-8')
    )

def init(app):

    @app.route('/benchmark/trustbound-00/BenchmarkTest00072', methods=['GET'])
    def BenchmarkTest00072_get():
        csrf_token, csrf_timestamp = generate_csrf_token()
        session['csrf_token_BenchmarkTest00072'] = csrf_token
        session['csrf_token_BenchmarkTest00072_ts'] = csrf_timestamp
        session.modified = True
        response = make_response(render_template(
            'web/trustbound-00/BenchmarkTest00072.html',
            csrf_token=csrf_token
        ))
        response.set_cookie(
            'BenchmarkTest00072',
            secrets.token_hex(16),
            max_age=60 * 3,
            secure=True,
            httponly=True,
            samesite='Strict',
            path='/benchmark/trustbound-00/BenchmarkTest00072',
            domain='localhost'
        )
        return response

    @app.route('/benchmark/trustbound-00/BenchmarkTest00072', methods=['POST'])
    def BenchmarkTest00072_post():
        csrf_token_form = request.form.get('csrf_token', '')
        csrf_token_session = session.get('csrf_token_BenchmarkTest00072', '')
        csrf_token_timestamp = session.get('csrf_token_BenchmarkTest00072_ts', 0)

        if not validate_csrf_token(csrf_token_form, csrf_token_session, csrf_token_timestamp):
            session.pop('csrf_token_BenchmarkTest00072', None)
            session.pop('csrf_token_BenchmarkTest00072_ts', None)
            abort(403)

        session.pop('csrf_token_BenchmarkTest00072', None)
        session.pop('csrf_token_BenchmarkTest00072_ts', None)

        safe_key = sanitize_session_key(FIXED_SESSION_KEY)
        if safe_key is None:
            abort(400)

        safe_value = sanitize_session_value(FIXED_SESSION_VALUE)
        if safe_value is None:
            abort(400)

        session[safe_key] = safe_value
        session.modified = True

        safe_key_escaped = escape_for_html(safe_key)
        safe_value_escaped = escape_for_html(safe_value)

        RESPONSE = (
            f'Item: \'{safe_key_escaped}'
            f'\' with value: {safe_value_escaped} saved in session.'
        )

        return RESPONSE, 200