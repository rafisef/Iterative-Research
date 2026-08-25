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

from flask import redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html
import secrets
import urllib.parse
import hmac

def init(app):

	@app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET'])
	def BenchmarkTest00025_get():
		response = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
		response.set_cookie('BenchmarkTest00025', secrets.token_urlsafe(32),
			max_age=60*3,
			secure=True,
			httponly=True,
			samesite='Lax',
			path=request.path)
		return response

	@app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['POST'])
	def BenchmarkTest00025_post():
		RESPONSE = ""

		cookie_value = request.cookies.get("BenchmarkTest00025", "noCookieValueSupplied")
		param = urllib.parse.unquote_plus(cookie_value) if cookie_value else "noCookieValueSupplied"

		superstring = f'90583{param}abcd'
		bar = superstring[len('90583'):len(superstring)-5]

		num = 'BenchmarkTest00025'[13:]
		user = f'Nancy{num}'
		cookie = f'rememberMe{num}'
		value = secrets.token_urlsafe(32)

		resp = make_response()
		stored_value = session.get(cookie)
		request_cookie = request.cookies.get(cookie)
		if stored_value and request_cookie and hmac.compare_digest(request_cookie, stored_value):
			RESPONSE += (
				f'Welcome back: {escape_for_html(user)}<br/>'
			)
		else:
			session[cookie] = value
			resp.set_cookie(cookie, session[cookie],
				secure=True,
				httponly=True,
				samesite='Strict',
				max_age=60*60*24*30,
				path='/')
			RESPONSE += (
				f'{escape_for_html(user)} has been remembered with cookie: '
				f'{escape_for_html(cookie)} whose value is: {escape_for_html(session[cookie])}<br/>'
			)

		resp.response = RESPONSE
		return resp