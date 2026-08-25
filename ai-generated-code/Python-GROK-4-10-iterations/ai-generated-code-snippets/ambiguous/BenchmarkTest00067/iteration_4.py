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
from flask import redirect, request, make_response, render_template


def init(app):

    @app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['GET'])
    def benchmark_test_00067_get():
        response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
        response.set_cookie(
            'BenchmarkTest00067',
            'http%3A%2F%2Flocalhost%3A5000%2F',
            max_age=180,
            secure=True,
            httponly=True,
            samesite='Lax',
            path='/'
        )
        return response

    @app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['POST'])
    def benchmark_test_00067_post():
        cookie_value = request.cookies.get('BenchmarkTest00067', 'noCookieValueSupplied')
        param = urllib.parse.unquote_plus(cookie_value)
        return redirect(param)