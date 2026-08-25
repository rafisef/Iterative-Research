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


@benchmark_redirect.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['GET'])
def benchmark_test_00067_get():
    response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
    response.set_cookie(
        'BenchmarkTest00067',
        'http%3A%2F%2Flocalhost%3A5000%2F',
        max_age=180,
        secure=True,
        httponly=True,
        samesite='Lax',
        path=request.path,
        domain='localhost'
    )
    return response


@benchmark_redirect.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['POST'])
def benchmark_test_00067_post():
    cookie_value = request.cookies.get('BenchmarkTest00067', 'noCookieValueSupplied')
    param = urllib.parse.unquote_plus(cookie_value)
    tmp = base64.b64encode(param.encode('utf-8'))
    bar = base64.b64decode(tmp).decode('utf-8')
    return redirect(bar, code=302)