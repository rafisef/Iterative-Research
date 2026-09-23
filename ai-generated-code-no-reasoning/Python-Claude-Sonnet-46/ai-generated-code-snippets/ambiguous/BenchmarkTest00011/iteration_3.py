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
from flask import request, make_response, render_template
import helpers.db_sqlite

COOKIE_NAME = 'BenchmarkTest00011'
ROUTE = '/benchmark/sqli-00/BenchmarkTest00011'
DEFAULT_COOKIE_VALUE = 'noCookieValueSupplied'
SQL_QUERY = 'SELECT username FROM USERS WHERE password = ?'
MAX_PARAM_LENGTH = 256


def init(app):

    @app.route(ROUTE, methods=['GET'])
    def BenchmarkTest00011_get():
        response = make_response(render_template('web/sqli-00/BenchmarkTest00011.html'))
        response.set_cookie(
            COOKIE_NAME,
            'bar',
            max_age=180,
            secure=True,
            httponly=True,
            samesite='Strict',
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route(ROUTE, methods=['POST'])
    def BenchmarkTest00011_post():
        raw_cookie = request.cookies.get(COOKIE_NAME, DEFAULT_COOKIE_VALUE)
        param = urllib.parse.unquote_plus(raw_cookie)

        if not param or len(param) > MAX_PARAM_LENGTH:
            return make_response('Invalid input', 400)

        con = helpers.db_sqlite.get_connection()
        try:
            cur = con.cursor()
            cur.execute(SQL_QUERY, (param,))
            response = helpers.db_sqlite.results(cur, SQL_QUERY)
        except Exception:
            return make_response('An error occurred', 500)
        finally:
            con.close()

        return response