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
import urllib.parse
import helpers.db_sqlite

def init(app):

	@app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['GET'])
	def BenchmarkTest00011_get():
		response = make_response(render_template('web/sqli-00/BenchmarkTest00011.html'))
		response.set_cookie('BenchmarkTest00011', 'bar',
			max_age=60*3,
			secure=True,
			httponly=True,
			samesite='Strict',
			path=request.path)
		return response

	@app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['POST'])
	def BenchmarkTest00011_post():
		RESPONSE = ""

		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00011", "noCookieValueSupplied"))

		bar = "This will never happen"
		if 'should' in bar:
			bar = param

		sql = 'SELECT username from USERS where password = ?'
		with helpers.db_sqlite.get_connection() as con:
			cur = con.cursor()
			cur.execute(sql, (bar,))
			RESPONSE += (
				helpers.db_sqlite.results(cur, sql)
			)

		return RESPONSE