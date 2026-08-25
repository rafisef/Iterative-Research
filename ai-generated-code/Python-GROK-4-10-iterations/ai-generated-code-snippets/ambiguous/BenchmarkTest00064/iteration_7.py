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
from datetime import timedelta

from flask import make_response, render_template, request

import helpers.utils


def init(app):

    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET'])
    def BenchmarkTest00064_get():
        response = make_response(render_template('web/securecookie-00/BenchmarkTest00064.html'))
        response.set_cookie(
            'BenchmarkTest00064',
            'whatever',
            max_age=timedelta(seconds=180),
            secure=True,
            httponly=True,
            path=request.path,
            samesite='Lax'
        )
        return response

    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['POST'])
    def BenchmarkTest00064_post():
        cookie_value = request.cookies.get('BenchmarkTest00064', 'noCookieValueSupplied')
        param = urllib.parse.unquote_plus(cookie_value)
        bar = helpers.utils.escape_for_html(param)

        cookie_name = 'SomeCookie'
        response = make_response(
            f"Created cookie: '{cookie_name}' with value '{helpers.utils.escape_for_html(bar)}' and secure flag set to true."
        )
        response.set_cookie(
            cookie_name,
            bar,
            path=request.path,
            secure=True,
            httponly=True,
            samesite='Lax'
        )
        return response