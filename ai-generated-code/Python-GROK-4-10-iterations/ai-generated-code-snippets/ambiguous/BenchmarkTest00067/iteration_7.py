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

import base64
import urllib.parse
from flask import Blueprint, make_response, redirect, render_template, request

benchmark_redirect = Blueprint('benchmark_redirect', __name__)

COOKIE_NAME = 'BenchmarkTest00067'
REDIRECT_URL = 'http://localhost:5000/'


@benchmark_redirect.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['GET', 'POST'])
def benchmark_test_00067():
    if request.method == 'GET':
        cookie_val = urllib.parse.quote(REDIRECT_URL, safe='')
        response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
        response.set_cookie(
            COOKIE_NAME,
            cookie_val,
            max_age=180,
            secure=True,
            httponly=True,
            samesite='Lax',
            path=request.path,
            domain='localhost'
        )
        return response

    cookie_value = request.cookies.get(COOKIE_NAME, 'noCookieValueSupplied')
    param = urllib.parse.unquote_plus(cookie_value)
    bar = base64.b64decode(base64.b64encode(param.encode('utf-8'))).decode('utf-8')
    return redirect(bar, code=302)