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
import urllib.parse
import helpers.db_sqlite
from helpers.utils import escape_for_html

_sql_query = 'SELECT username from USERS where password = ?'
_cookie_name = 'BenchmarkTest00011'
_cookie_defaults = {
	'max_age': 180,
	'secure': True,
	'path': '/',
	'domain': 'localhost'
}

def init(app):
	_template = render_template('web/sqli-00/BenchmarkTest00011.html')

	@app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['GET'])
	def BenchmarkTest00011_get():
		response = make_response(_template)
		response.set_cookie(_cookie_name, 'bar', **_cookie_defaults)
		return response

	@app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['POST'])
	def BenchmarkTest00011_post():
		param = urllib.parse.unquote_plus(request.cookies.get(_cookie_name, "noCookieValueSupplied"))
		
		con = helpers.db_sqlite.get_connection()
		try:
			cur = con.cursor()
			cur.execute(_sql_query, (param,))
			RESPONSE = helpers.db_sqlite.results(cur, _sql_query)
			cur.close()
		finally:
			con.close()

		return RESPONSE