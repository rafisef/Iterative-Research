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

import random
import secrets
import urllib.parse

from flask import request, make_response, render_template

from helpers.utils import mysession

BENCHMARK_TEST_ID = 'BenchmarkTest00025'
TEST_NUM = BENCHMARK_TEST_ID[13:]
USER = f'Nancy{TEST_NUM}'
COOKIE_NAME = f'rememberMe{TEST_NUM}'
ROUTE = f'/benchmark/weakrand-00/{BENCHMARK_TEST_ID}'
COOKIE_MAX_AGE = 60 * 3


def init(app):

    @app.route(ROUTE, methods=['GET'])
    def BenchmarkTest00025_get():
        response = make_response(render_template(f'web/weakrand-00/{BENCHMARK_TEST_ID}.html'))
        response.set_cookie(
            BENCHMARK_TEST_ID,
            'whatever',
            max_age=COOKIE_MAX_AGE,
            secure=True,
            httponly=True,
            samesite='Strict',
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route(ROUTE, methods=['POST'])
    def BenchmarkTest00025_post():
        raw_cookie = request.cookies.get(BENCHMARK_TEST_ID, 'noCookieValueSupplied')
        param = urllib.parse.unquote_plus(raw_cookie)

        prefix = '90583'
        suffix_len = 5
        full_string = f'{prefix}{param}abcd'
        bar = full_string[len(prefix):len(full_string) - suffix_len]

        value = secrets.token_hex(16)

        stored = mysession.get(COOKIE_NAME)
        provided = request.cookies.get(COOKIE_NAME)

        if stored and provided and secrets.compare_digest(provided, stored):
            response_text = f'Welcome back: {USER}<br/>'
        else:
            mysession[COOKIE_NAME] = value
            response_text = (
                f'{USER} has been remembered with cookie: '
                f'{COOKIE_NAME} whose value is: {mysession[COOKIE_NAME]}<br/>'
            )

        return response_text