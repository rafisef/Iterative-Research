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
from helpers.utils import mysession

MAX_COOKIE_LENGTH = 4096
SAFE_COOKIE_PATTERN = re.compile(r'^[a-zA-Z0-9_\-]{1,128}$')
SAFE_VALUE_PATTERN = re.compile(r'^[a-zA-Z0-9_\-]{1,256}$')

def _safe_cookie_name(name: str) -> bool:
    return bool(SAFE_COOKIE_PATTERN.match(name))

def _safe_cookie_value(value: str) -> bool:
    return bool(SAFE_VALUE_PATTERN.match(value))

def init(app):

    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET'])
    def BenchmarkTest00025_get():
        response = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
        response.set_cookie(
            'BenchmarkTest00025',
            'whatever',
            max_age=60 * 3,
            secure=True,
            httponly=True,
            samesite='Strict',
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['POST'])
    def BenchmarkTest00025_post():
        RESPONSE = ""

        raw_cookie = request.cookies.get("BenchmarkTest00025", "noCookieValueSupplied")

        if not isinstance(raw_cookie, str):
            return make_response("Invalid request", 400)

        if len(raw_cookie) > MAX_COOKIE_LENGTH:
            return make_response("Invalid request", 400)

        if not _safe_cookie_value(raw_cookie) and raw_cookie != "noCookieValueSupplied":
            return make_response("Invalid request", 400)

        param = escape_for_html(raw_cookie)

        suffix = 'BenchmarkTest00025'[13:]
        if not re.match(r'^[0-9]+$', suffix):
            return make_response("Invalid request", 400)

        user = escape_for_html(f'Nancy{suffix}')
        cookie = f'rememberMe{suffix}'

        if not _safe_cookie_name(cookie):
            return make_response("Invalid request", 400)

        value = secrets.token_hex(32)

        if cookie in mysession and request.cookies.get(cookie) is not None:
            stored = mysession[cookie]
            provided = request.cookies.get(cookie)

            if not isinstance(stored, str) or not isinstance(provided, str):
                return make_response("Invalid request", 400)

            if len(provided) > MAX_COOKIE_LENGTH:
                return make_response("Invalid request", 400)

            if not _safe_cookie_value(stored) or not _safe_cookie_value(provided):
                return make_response("Invalid request", 400)

            stored_bytes = stored.encode('utf-8')
            provided_bytes = provided.encode('utf-8')

            if len(stored_bytes) != len(provided_bytes):
                mysession[cookie] = value
                RESPONSE += (
                    f'{user} has been remembered with cookie: '
                    f'{escape_for_html(cookie)} whose value is: {escape_for_html(mysession[cookie])}<br/>'
                )
            elif hmac.compare_digest(stored_bytes, provided_bytes):
                RESPONSE += (
                    f'Welcome back: {user}<br/>'
                )
            else:
                mysession[cookie] = value
                RESPONSE += (
                    f'{user} has been remembered with cookie: '
                    f'{escape_for_html(cookie)} whose value is: {escape_for_html(mysession[cookie])}<br/>'
                )
        else:
            mysession[cookie] = value
            RESPONSE += (
                f'{user} has been remembered with cookie: '
                f'{escape_for_html(cookie)} whose value is: {escape_for_html(mysession[cookie])}<br/>'
            )

        new_cookie_value = mysession.get(cookie, "")
        if not isinstance(new_cookie_value, str) or not _safe_cookie_value(new_cookie_value):
            return make_response("Invalid request", 400)

        response = make_response(RESPONSE)
        response.set_cookie(
            cookie,
            new_cookie_value,
            secure=True,
            httponly=True,
            samesite='Strict',
            max_age=60 * 3,
            path='/'
        )
        return response