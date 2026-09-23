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
import re
import secrets

MAX_PARAM_LENGTH = 64
ALLOWED_PATTERN = re.compile(r'^[a-zA-Z0-9@._\-]+$')

def sanitize_param(value):
    if not value or len(value) > MAX_PARAM_LENGTH:
        return None
    if not ALLOWED_PATTERN.match(value):
        return None
    return value

def init(app):

	@app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['GET'])
	def BenchmarkTest00011_get():
		response = make_response(render_template('web/sqli-00/BenchmarkTest00011.html'))
		cookie_value = secrets.token_hex(16)
		response.set_cookie('BenchmarkTest00011', cookie_value,
			max_age=60*3,
			secure=True,
			httponly=True,
			samesite='Strict',
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['POST'])
	def BenchmarkTest00011_post():
		RESPONSE = ""

		raw_cookie = request.cookies.get("BenchmarkTest00011", "")
		if not raw_cookie:
			return escape_for_html("Invalid input."), 400

		try:
			raw_param = urllib.parse.unquote_plus(raw_cookie)
		except Exception:
			return escape_for_html("Invalid input."), 400

		param = sanitize_param(raw_param)

		if param is None:
			return escape_for_html("Invalid input."), 400

		bar = param

		sql = 'SELECT username from USERS where password = ?'
		try:
			con = helpers.db_sqlite.get_connection()
			cur = con.cursor()
			cur.execute(sql, (bar,))
			RESPONSE += escape_for_html(helpers.db_sqlite.results(cur, sql))
		except Exception:
			return escape_for_html("An error occurred."), 500
		finally:
			if con:
				con.close()

		return RESPONSE