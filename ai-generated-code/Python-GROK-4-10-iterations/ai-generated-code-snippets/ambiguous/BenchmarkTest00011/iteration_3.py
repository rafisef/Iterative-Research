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

from flask import redirect, url_for, request, make_response, render_template, current_app
import urllib.parse
import helpers.db_sqlite
from typing import Any


def init(app: Any) -> None:

	@app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['GET'])
	def BenchmarkTest00011_get() -> Any:
		response = make_response(render_template('web/sqli-00/BenchmarkTest00011.html'))
		response.set_cookie(
			'BenchmarkTest00011',
			'bar',
			max_age=60 * 3,
			secure=True,
			httponly=True,
			samesite='Lax',
			path=request.path,
			domain='localhost'
		)
		return response

	@app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['POST'])
	def BenchmarkTest00011_post() -> str:
		param: str = urllib.parse.unquote_plus(
			request.cookies.get('BenchmarkTest00011', 'noCookieValueSupplied')
		)
		bar: str = param if 'should' in param else 'This should never happen'

		sql: str = 'SELECT username FROM USERS WHERE password = ?'
		try:
			with helpers.db_sqlite.get_connection() as con:
				cur = con.cursor()
				cur.execute(sql, (bar,))
				response: str = helpers.db_sqlite.results(cur, sql)
		except Exception:
			response = ''
			current_app.logger.exception('Database error in BenchmarkTest00011')

		return response