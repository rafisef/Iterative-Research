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
import random
import secrets
from helpers.utils import escape_for_html, mysession


def init(app):

	@app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET', 'POST'])
	def BenchmarkTest00025():
		if request.method == 'GET':
			return _handle_get()
		else:
			return _handle_post()


	def _handle_get():
		response = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
		response.set_cookie(
			'BenchmarkTest00025',
			'whatever',
			max_age=180,
			secure=True,
			path=request.path,
			domain='localhost',
			httponly=True,
			samesite='Strict'
		)
		return response


	def _handle_post():
		param = urllib.parse.unquote_plus(
			request.cookies.get("BenchmarkTest00025", "noCookieValueSupplied")
		)

		superstring = f'90583{param}abcd'
		bar = superstring[6:-5]

		num = '25'
		user = f'Nancy{num}'
		cookie = f'rememberMe{num}'
		value = secrets.token_hex(16)

		if cookie in mysession and request.cookies.get(cookie) == mysession[cookie]:
			response_text = f'Welcome back: {user}<br/>'
		else:
			mysession[cookie] = value
			response_text = (
				f'{user} has been remembered with cookie: '
				f'{cookie} whose value is: {mysession[cookie]}<br/>'
			)

		return response_text