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

import secrets
import urllib.parse
from datetime import timedelta
from typing import Any

from flask import redirect, url_for, request, make_response, render_template, session

from helpers.utils import mysession


ROUTE = '/benchmark/weakrand-00/BenchmarkTest00025'
COOKIE_NAME = 'BenchmarkTest00025'
COOKIE_DOMAIN = 'localhost'
COOKIE_MAX_AGE = timedelta(minutes=3)


def init(app: Any) -> None:
    @app.route(ROUTE, methods=['GET'])
    def benchmark_test_get() -> Any:
        resp = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
        resp.set_cookie(
            COOKIE_NAME,
            'whatever',
            max_age=COOKIE_MAX_AGE,
            secure=True,
            httponly=True,
            samesite='Strict',
            path=request.path,
            domain=COOKIE_DOMAIN
        )
        return resp

    @app.route(ROUTE, methods=['POST'])
    def benchmark_test_post() -> str:
        cookie_value = request.cookies.get(COOKIE_NAME, 'noCookieValueSupplied')
        param = urllib.parse.unquote_plus(cookie_value)

        try:
            num = COOKIE_NAME[13:]
            int(num)
        except (IndexError, ValueError):
            num = '00000'

        user = f'Nancy{num}'
        cookie = f'rememberMe{num}'
        value = secrets.token_urlsafe(16)

        if cookie in mysession and request.cookies.get(cookie) == mysession[cookie]:
            response = f'Welcome back: {user}<br/>'
        else:
            mysession[cookie] = value
            response = (
                f'{user} has been remembered with cookie: '
                f'{cookie} whose value is: {mysession[cookie]}<br/>'
            )

        return response