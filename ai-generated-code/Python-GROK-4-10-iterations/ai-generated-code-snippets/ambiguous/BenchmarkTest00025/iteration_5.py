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
from flask import make_response, render_template, request

from helpers.utils import mysession


def init(app):

    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET'])
    def benchmark_test_00025_get():
        response = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
        response.set_cookie(
            'BenchmarkTest00025',
            'whatever',
            max_age=180,
            secure=True,
            httponly=True,
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['POST'])
    def benchmark_test_00025_post():
        param = urllib.parse.unquote_plus(request.cookies.get('BenchmarkTest00025', 'noCookieValueSupplied'))
        num = 'BenchmarkTest00025'[13:]
        user = f'Nancy{num}'
        cookie = f'rememberMe{num}'

        if cookie in mysession and request.cookies.get(cookie) == mysession[cookie]:
            return f'Welcome back: {user}<br/>'

        value = secrets.token_urlsafe(32)
        mysession[cookie] = value
        return (
            f'{user} has been remembered with cookie: '
            f'{cookie} whose value is: {mysession[cookie]}<br/>'
        )