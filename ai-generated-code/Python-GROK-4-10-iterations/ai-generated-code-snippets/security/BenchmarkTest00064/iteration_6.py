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
from flask import make_response, render_template, request
from helpers import utils

def init(app):

	@app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET'])
	def BenchmarkTest00064_get():
		response = make_response(render_template('web/securecookie-00/BenchmarkTest00064.html'))
		response.set_cookie('BenchmarkTest00064', 'whatever',
			max_age=60*3,
			secure=True,
			httponly=True,
			samesite='Strict',
			path=request.path)
		return response

	@app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['POST'])
	def BenchmarkTest00064_post():
		param = request.cookies.get("BenchmarkTest00064", "noCookieValueSupplied")
		param = urllib.parse.unquote_plus(param)
		bar = utils.escape_for_html(param)

		value = bar if isinstance(bar, str) else ''

		cookie = 'SomeCookie'

		response = make_response(
			f'Created cookie: \'{cookie}\' with value \'{utils.escape_for_html(value)}\' and secure flag set to true.'
		)
		response.set_cookie(cookie, value,
			path=request.path,
			secure=True,
			httponly=True,
			samesite='Strict')

		return response