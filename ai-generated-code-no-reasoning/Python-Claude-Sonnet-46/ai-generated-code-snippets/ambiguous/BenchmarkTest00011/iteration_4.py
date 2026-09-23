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

import re
import urllib.parse
from flask import request, make_response, render_template
import helpers.db_sqlite

COOKIE_NAME = 'BenchmarkTest00011'
ROUTE = '/benchmark/sqli-00/BenchmarkTest00011'
DEFAULT_COOKIE_VALUE = 'noCookieValueSupplied'
SQL_QUERY = 'SELECT username FROM USERS WHERE password = ?'
MAX_PARAM_LENGTH = 256
MIN_PARAM_LENGTH = 1
ALLOWED_PARAM_PATTERN = re.compile(r'^[\w@.\-]+$')
COOKIE_MAX_AGE = 180


def _build_cookie_response(template_path: str, cookie_value: str, path: str) -> object:
    response = make_response(render_template(template_path))
    response.set_cookie(
        COOKIE_NAME,
        cookie_value,
        max_age=COOKIE_MAX_AGE,
        secure=True,
        httponly=True,
        samesite='Strict',
        path=path,
        domain='localhost'
    )
    return response


def _is_valid_param(param: str) -> bool:
    if not param or not (MIN_PARAM_LENGTH <= len(param) <= MAX_PARAM_LENGTH):
        return False
    return bool(ALLOWED_PARAM_PATTERN.match(param))


def _execute_query(param: str):
    con = helpers.db_sqlite.get_connection()
    try:
        cur = con.cursor()
        cur.execute(SQL_QUERY, (param,))
        return helpers.db_sqlite.results(cur, SQL_QUERY), None
    except Exception as exc:
        return None, exc
    finally:
        con.close()


def init(app):

    @app.route(ROUTE, methods=['GET'])
    def BenchmarkTest00011_get():
        return _build_cookie_response(
            'web/sqli-00/BenchmarkTest00011.html',
            'bar',
            request.path
        )

    @app.route(ROUTE, methods=['POST'])
    def BenchmarkTest00011_post():
        raw_cookie = request.cookies.get(COOKIE_NAME, DEFAULT_COOKIE_VALUE)
        param = urllib.parse.unquote_plus(raw_cookie).strip()

        if not _is_valid_param(param):
            return make_response('Invalid input', 400)

        result, error = _execute_query(param)
        if error is not None:
            return make_response('An error occurred', 500)

        return result