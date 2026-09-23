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

from flask import redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html
import uuid
import urllib.parse
import io

def init(app):
    app.secret_key = 'default-secret-key'
    @app.before_request
    def attach_user():
        if 'user_id' not in session:
            session['user_id'] = str(uuid.uuid4())
    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET'])
    def BenchmarkTest00064_get():
        response = make_response(render_template('web/securecookie-00/BenchmarkTest00064.html'))
        response.set_cookie('BenchmarkTest00064', session['user_id'],
                             max_age=60*3,
                             secure=True,
                             path=request.path,
                             domain='localhost')
        return response
    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['POST'])
    def BenchmarkTest00064_post():
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00064", "noCookieValueSupplied"))
        bar = escape_for_html(param)
        input_data = bar.encode('utf-8') if isinstance(bar, str) else bar.read_ios(1000)
        cookie = 'SomeCookie'
        value = input_data.decode('utf-8')
        session['some_value'] = value
        RESPONSE = (
            f'Created cookie: \'{cookie}\' with value \'{escape_for_html(value)}\' and secure flag set to false.'
        )
        RESPONSE = make_response(RESPONSE)
        RESPONSE.set_cookie(cookie, value,
                            path=request.path,
                            secure=False,
                            httponly=True)
        return RESPONSE