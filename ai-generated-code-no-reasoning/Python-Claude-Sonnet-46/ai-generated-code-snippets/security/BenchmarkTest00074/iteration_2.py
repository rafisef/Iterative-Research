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

from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import re
import urllib.parse
import configparser
import secrets
import hmac
import hashlib
import os

ALLOWED_PATTERN = re.compile(r'^[a-zA-Z0-9_\-\.\ ]+$')
MAX_PARAM_LENGTH = 256
COOKIE_NAME = 'BenchmarkTest00074'
HMAC_SECRET = os.environ.get('COOKIE_HMAC_SECRET', secrets.token_hex(32))

def sign_cookie_value(value: str) -> str:
    sig = hmac.new(HMAC_SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()
    return f"{value}|{sig}"

def verify_cookie_value(signed_value: str):
    if '|' not in signed_value:
        return None
    value, _, sig = signed_value.rpartition('|')
    expected_sig = hmac.new(HMAC_SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return None
    return value

def init(app):

    @app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['GET'])
    def BenchmarkTest00074_get():
        response = make_response(render_template('web/codeinj-00/BenchmarkTest00074.html'))
        raw_cookie_value = '%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27'
        signed_value = sign_cookie_value(raw_cookie_value)
        response.set_cookie(
            COOKIE_NAME,
            signed_value,
            max_age=60 * 3,
            secure=True,
            httponly=True,
            samesite='Strict',
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['POST'])
    def BenchmarkTest00074_post():
        RESPONSE = ""

        raw_signed = request.cookies.get(COOKIE_NAME, "")

        if not raw_signed:
            return escape_for_html("Missing cookie."), 400

        verified_raw = verify_cookie_value(raw_signed)
        if verified_raw is None:
            return escape_for_html("Cookie integrity check failed."), 400

        param = urllib.parse.unquote_plus(verified_raw)

        if len(param) > MAX_PARAM_LENGTH:
            return escape_for_html("Input exceeds maximum allowed length."), 400

        if not ALLOWED_PATTERN.match(param):
            return escape_for_html("Invalid input detected."), 400

        conf90091 = configparser.ConfigParser()
        conf90091.read_dict({
            'section90091': {
                'keyA-90091': 'a-Value',
                'keyB-90091': param
            }
        })

        bar = conf90091.get('section90091', 'keyB-90091')

        if len(bar) > MAX_PARAM_LENGTH:
            return escape_for_html("Retrieved value exceeds maximum allowed length."), 400

        if not ALLOWED_PATTERN.match(bar):
            return escape_for_html("Invalid value retrieved from config."), 400

        RESPONSE += escape_for_html(bar)

        return RESPONSE