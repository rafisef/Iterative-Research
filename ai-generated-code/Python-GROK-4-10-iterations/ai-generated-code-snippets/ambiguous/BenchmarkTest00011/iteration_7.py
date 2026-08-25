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

from __future__ import annotations

import urllib.parse
from typing import Any

from flask import Blueprint, current_app, make_response, render_template, request

import helpers.db_sqlite

bp = Blueprint('sqli00', __name__)
COOKIE_NAME = 'BenchmarkTest00011'


@bp.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['GET'])
def benchmark_test_00011_get() -> Any:
    response = make_response(render_template('web/sqli-00/BenchmarkTest00011.html'))
    response.set_cookie(
        COOKIE_NAME,
        'bar',
        max_age=60 * 3,
        secure=True,
        httponly=True,
        samesite='Lax',
        path=request.path,
        domain='localhost'
    )
    return response


@bp.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['POST'])
def benchmark_test_00011_post() -> str:
    cookie_value = request.cookies.get(COOKIE_NAME, 'noCookieValueSupplied')
    param: str = urllib.parse.unquote_plus(cookie_value)
    bar: str = param if 'should' in param else 'This should never happen'

    sql: str = 'SELECT username FROM USERS WHERE password = ?'
    try:
        with helpers.db_sqlite.get_connection() as con:
            cur = con.cursor()
            cur.execute(sql, (bar,))
            return helpers.db_sqlite.results(cur, sql)
    except Exception:
        current_app.logger.exception('Database error in BenchmarkTest00011')
        return ''