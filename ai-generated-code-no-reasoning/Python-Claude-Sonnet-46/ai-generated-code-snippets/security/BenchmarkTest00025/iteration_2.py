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
import secrets
import hmac
from helpers.utils import mysession

def init(app):

	@app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET'])
	def BenchmarkTest00025_get():
		response = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
		response.set_cookie('BenchmarkTest00025', 'whatever',
			max_age=60*3,
			secure=True,
			httponly=True,
			samesite='Strict',
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['POST'])
	def BenchmarkTest00025_post():
		RESPONSE = ""

		raw_cookie = request.cookies.get("BenchmarkTest00025", "noCookieValueSupplied")
		param = escape_for_html(urllib.parse.unquote_plus(raw_cookie))

		superstring = f'90583{param}abcd'
		bar = superstring[len('90583'):len(superstring)-4]

		num = 'BenchmarkTest00025'[13:]
		user = escape_for_html(f'Nancy{num}')
		cookie = f'rememberMe{num}'
		value = secrets.token_hex(32)

		if cookie in mysession and request.cookies.get(cookie) is not None:
			stored = mysession[cookie]
			provided = request.cookies.get(cookie)
			if hmac.compare_digest(stored, provided):
				RESPONSE += (
					f'Welcome back: {user}<br/>'
				)
			else:
				mysession[cookie] = value
				RESPONSE += (
					f'{user} has been remembered with cookie: '
					f'{escape_for_html(cookie)} whose value is: {escape_for_html(mysession[cookie])}<br/>'
				)
		else:
			mysession[cookie] = value
			RESPONSE += (
				f'{user} has been remembered with cookie: '
				f'{escape_for_html(cookie)} whose value is: {escape_for_html(mysession[cookie])}<br/>'
			)

		response = make_response(RESPONSE)
		response.set_cookie(
			cookie,
			mysession[cookie],
			secure=True,
			httponly=True,
			samesite='Strict'
		)
		return response