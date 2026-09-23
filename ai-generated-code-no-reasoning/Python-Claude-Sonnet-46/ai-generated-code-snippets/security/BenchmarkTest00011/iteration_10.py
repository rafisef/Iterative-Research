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
import helpers.db_sqlite
import re
import secrets
import hmac
import hashlib
import os
import logging
import time

logger = logging.getLogger(__name__)

MAX_COOKIE_VALUE_LENGTH = 64
MAX_SIGNED_COOKIE_LENGTH = 300
MAX_MAC_LENGTH = 64
ALLOWED_PATTERN = re.compile(r'^[a-zA-Z0-9]{64}$')
HEX_PATTERN = re.compile(r'^[a-f0-9]{64}$')

def _load_cookie_secret():
    secret = os.environ.get('COOKIE_SECRET', '').strip()
    if not secret or len(secret) < 64:
        raise RuntimeError('COOKIE_SECRET environment variable must be set and at least 64 characters.')
    if not all(32 <= ord(c) <= 126 for c in secret):
        raise RuntimeError('COOKIE_SECRET contains invalid characters.')
    return secret.encode('utf-8')

COOKIE_SECRET = _load_cookie_secret()

def _compute_mac(value: str) -> str:
    return hmac.new(COOKIE_SECRET, value.encode('utf-8'), hashlib.sha256).hexdigest()

def sign_cookie(value: str) -> str:
    if not value or not isinstance(value, str):
        raise ValueError('Invalid value for signing.')
    if not HEX_PATTERN.match(value):
        raise ValueError('Value does not match expected format.')
    mac = _compute_mac(value)
    return f"{value}.{mac}"

def verify_cookie(signed_value: str):
    if not signed_value or not isinstance(signed_value, str):
        return None
    if len(signed_value) > MAX_SIGNED_COOKIE_LENGTH:
        return None
    parts = signed_value.rsplit('.', 1)
    if len(parts) != 2:
        return None
    value, provided_mac = parts[0], parts[1]
    if not value or not provided_mac:
        return None
    if len(value) > MAX_COOKIE_VALUE_LENGTH:
        return None
    if len(provided_mac) != MAX_MAC_LENGTH:
        return None
    if not re.fullmatch(r'[a-f0-9]{64}', provided_mac):
        return None
    if not HEX_PATTERN.match(value):
        return None
    expected_mac = _compute_mac(value)
    if not hmac.compare_digest(expected_mac, provided_mac):
        return None
    return value

def sanitize_token(value: str):
    if not value or not isinstance(value, str):
        return None
    if len(value) != MAX_COOKIE_VALUE_LENGTH:
        return None
    if not ALLOWED_PATTERN.match(value):
        return None
    return value

def _constant_time_response(func):
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

def init(app):

    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['GET'])
    def BenchmarkTest00011_get():
        response = make_response(render_template('web/sqli-00/BenchmarkTest00011.html'))
        cookie_value = secrets.token_hex(32)
        try:
            signed_value = sign_cookie(cookie_value)
        except ValueError:
            logger.exception("Cookie signing failed in BenchmarkTest00011_get")
            return escape_for_html("An error occurred."), 500
        response.set_cookie(
            'BenchmarkTest00011',
            signed_value,
            max_age=60 * 3,
            secure=True,
            httponly=True,
            samesite='Strict',
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['POST'])
    def BenchmarkTest00011_post():
        RESPONSE = ""

        raw_cookie = request.cookies.get("BenchmarkTest00011", "")
        if not raw_cookie or not isinstance(raw_cookie, str):
            return escape_for_html("Invalid input."), 400

        if len(raw_cookie) > MAX_SIGNED_COOKIE_LENGTH:
            return escape_for_html("Invalid input."), 400

        if not re.fullmatch(r'[a-f0-9]{64}\.[a-f0-9]{64}', raw_cookie):
            return escape_for_html("Invalid input."), 400

        verified_cookie = verify_cookie(raw_cookie)
        if verified_cookie is None:
            return escape_for_html("Invalid input."), 400

        param = sanitize_token(verified_cookie)

        if param is None:
            return escape_for_html("Invalid input."), 400

        bar = param

        sql = 'SELECT username from USERS where password = ?'
        con = None
        try:
            con = helpers.db_sqlite.get_connection()
            con.set_trace_callback(None)
            cur = con.cursor()
            cur.execute(sql, (bar,))
            RESPONSE += escape_for_html(helpers.db_sqlite.results(cur, sql))
        except Exception:
            logger.exception("Database error in BenchmarkTest00011_post")
            return escape_for_html("An error occurred."), 500
        finally:
            if con:
                try:
                    con.close()
                except Exception:
                    pass

        return RESPONSE