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

import urllib.parse
from flask import request, make_response, render_template, session
from helpers.utils import escape_for_html

COOKIE_NAME = 'BenchmarkTest00072'
ROUTE = '/benchmark/trustbound-00/BenchmarkTest00072'
DEFAULT_COOKIE_VALUE = 'noCookieValueSupplied'
SESSION_KEY = 'benchmark_test_00072_key'
SESSION_VALUE = '12345'
COOKIE_MAX_AGE = 180


def init(app):

    @app.route(ROUTE, methods=['GET'])
    def BenchmarkTest00072_get():
        response = make_response(render_template('web/trustbound-00/BenchmarkTest00072.html'))
        response.set_cookie(
            COOKIE_NAME,
            'my-user-id',
            max_age=COOKIE_MAX_AGE,
            secure=True,
            httponly=True,
            samesite='Strict',
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route(ROUTE, methods=['POST'])
    def BenchmarkTest00072_post():
        raw_cookie = request.cookies.get(COOKIE_NAME, DEFAULT_COOKIE_VALUE)
        urllib.parse.unquote_plus(raw_cookie)

        session[SESSION_KEY] = SESSION_VALUE

        return f"Item: '{escape_for_html(SESSION_KEY)}' with value: {SESSION_VALUE} saved in session."