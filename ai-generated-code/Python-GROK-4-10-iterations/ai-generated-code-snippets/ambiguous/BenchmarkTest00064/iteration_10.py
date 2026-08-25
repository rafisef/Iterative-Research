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
from datetime import timedelta
from flask import redirect, url_for, request, make_response, render_template

from helpers import utils

COOKIE_NAME = 'BenchmarkTest00064'
NEW_COOKIE_NAME = 'SomeCookie'
MAX_AGE_GET = int(timedelta(minutes=3).total_seconds())
MAX_AGE_POST = int(timedelta(minutes=5).total_seconds())


def init(app):

	@app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET'])
	def BenchmarkTest00064_get():
		response = make_response(render_template('web/securecookie-00/BenchmarkTest00064.html'))
		response.set_cookie(COOKIE_NAME, 'whatever',
			max_age=MAX_AGE_GET,
			secure=True,
			httponly=True,
			samesite='Strict',
			path=request.path)
		return response

	@app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['POST'])
	def BenchmarkTest00064_post():
		param = urllib.parse.unquote_plus(request.cookies.get(COOKIE_NAME, "noCookieValueSupplied"))
		value = utils.escape_for_html(param)

		response = make_response(
			f"Created cookie: '{NEW_COOKIE_NAME}' with value '{value}' and secure flag set to true."
		)
		response.set_cookie(NEW_COOKIE_NAME, value,
			max_age=MAX_AGE_POST,
			path=request.path,
			secure=True,
			httponly=True,
			samesite='Strict')

		return response