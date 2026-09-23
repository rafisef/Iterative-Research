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
import flask
from flask import redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html

COOKIE_NAME = 'BenchmarkTest00072'
ROUTE = '/benchmark/trustbound-00/BenchmarkTest00072'
DEFAULT_COOKIE_VALUE = 'noCookieValueSupplied'

def init(app):

    @app.route(ROUTE, methods=['GET'])
    def BenchmarkTest00072_get():
        response = make_response(render_template('web/trustbound-00/BenchmarkTest00072.html'))
        response.set_cookie(
            COOKIE_NAME,
            'my-user-id',
            max_age=60 * 3,
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
        param = urllib.parse.unquote_plus(raw_cookie)

        test_param = "This should never happen"
        bar = param if 'should' in test_param else "If not case passed"

        session[bar] = '12345'

        response_text = f"Item: '{escape_for_html(bar)}' with value: 12345 saved in session."

        return response_text