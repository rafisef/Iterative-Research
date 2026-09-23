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
import io
import helpers.utils

MAX_COOKIE_VALUE_LENGTH = 256
ALLOWED_COOKIE_VALUE_PATTERN = None

import re
ALLOWED_COOKIE_VALUE_PATTERN = re.compile(r'^[\w\s\-\.@:,]+$')

def _sanitize_cookie_value(value: str) -> str:
    if not value or len(value) > MAX_COOKIE_VALUE_LENGTH:
        return ""
    if not ALLOWED_COOKIE_VALUE_PATTERN.match(value):
        return ""
    return value

def init(app):

    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET'])
    def BenchmarkTest00064_get():
        response = make_response(render_template('web/securecookie-00/BenchmarkTest00064.html'))
        response.set_cookie(
            'BenchmarkTest00064',
            'whatever',
            max_age=60 * 3,
            secure=True,
            httponly=True,
            samesite='Strict',
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['POST'])
    def BenchmarkTest00064_post():
        raw_cookie = request.cookies.get("BenchmarkTest00064", "noCookieValueSupplied")

        escaped = helpers.utils.escape_for_html(raw_cookie)

        input_data = b''
        if isinstance(escaped, str):
            input_data = escaped.encode('utf-8')
        elif isinstance(escaped, io.IOBase):
            input_data = escaped.read(1000)

        decoded_value = input_data.decode('utf-8', errors='replace')

        safe_value = _sanitize_cookie_value(decoded_value)

        cookie_name = 'SomeCookie'

        escaped_display = helpers.utils.escape_for_html(safe_value)
        response_body = (
            f'Created cookie: \'{helpers.utils.escape_for_html(cookie_name)}\' '
            f'with value \'{escaped_display}\' and secure flag set to true.'
        )

        response = make_response(response_body)

        if safe_value:
            response.set_cookie(
                cookie_name,
                safe_value,
                path=request.path,
                secure=True,
                httponly=True,
                samesite='Strict',
                max_age=60 * 3
            )

        return response