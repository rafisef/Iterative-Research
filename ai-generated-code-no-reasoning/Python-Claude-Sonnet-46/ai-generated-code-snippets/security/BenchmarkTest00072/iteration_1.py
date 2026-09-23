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

ALLOWED_SESSION_KEY_PATTERN = re.compile(r'^[a-zA-Z0-9_\-]{1,64}$')
MAX_PARAM_LENGTH = 256

def sanitize_session_key(value):
    if not isinstance(value, str):
        return None
    if len(value) > MAX_PARAM_LENGTH:
        return None
    if ALLOWED_SESSION_KEY_PATTERN.match(value):
        return value
    return None

def init(app):

    @app.route('/benchmark/trustbound-00/BenchmarkTest00072', methods=['GET'])
    def BenchmarkTest00072_get():
        response = make_response(render_template('web/trustbound-00/BenchmarkTest00072.html'))
        response.set_cookie('BenchmarkTest00072', 'my-user-id',
            max_age=60*3,
            secure=True,
            httponly=True,
            samesite='Strict',
            path=request.path,
            domain='localhost')
        return response

    @app.route('/benchmark/trustbound-00/BenchmarkTest00072', methods=['POST'])
    def BenchmarkTest00072_post():
        RESPONSE = ""

        import urllib.parse
        import flask

        raw_param = request.cookies.get("BenchmarkTest00072", "noCookieValueSupplied")
        param = urllib.parse.unquote_plus(raw_param)

        TestParam = "This should never happen"
        if 'should' not in TestParam:
            bar = "Ifnot case passed"
        else:
            bar = param

        safe_key = sanitize_session_key(bar)
        if safe_key is None:
            return "Invalid session key.", 400

        flask.session[safe_key] = '12345'

        RESPONSE += (
            f'Item: \'{escape_for_html(safe_key)}'
            '\' with value: 12345 saved in session.'
        )

        return RESPONSE