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

from flask import request, make_response
from helpers.utils import escape_for_html

POSSIBLE = "ABC"
ROUTE = '/benchmark/xss-00/BenchmarkTest00096'
SAFE_CASES = frozenset({'A', 'C', 'D'})
FIRST_CHAR = POSSIBLE[0]

def init(app):

    @app.route(ROUTE, methods=['GET', 'POST'])
    def BenchmarkTest00096():
        param = request.form.get("BenchmarkTest00096", "")
        bar = escape_for_html(param) if FIRST_CHAR in SAFE_CASES else "bob"
        response = make_response(f"bar is '{bar}' and otherarg is 'static text'")
        response.headers['Content-Type'] = 'text/plain; charset=utf-8'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response