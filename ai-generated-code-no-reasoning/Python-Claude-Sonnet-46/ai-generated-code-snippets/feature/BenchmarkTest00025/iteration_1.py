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

import os
from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html

COOKIE_MAX_AGE = int(os.environ.get('BENCHMARK_COOKIE_MAX_AGE', 60 * 3))
COOKIE_SECURE = os.environ.get('BENCHMARK_COOKIE_SECURE', 'true').lower() == 'true'
COOKIE_DOMAIN = os.environ.get('BENCHMARK_COOKIE_DOMAIN', 'localhost')
BENCHMARK_PREFIX = os.environ.get('BENCHMARK_PREFIX', '90583')
BENCHMARK_SUFFIX = os.environ.get('BENCHMARK_SUFFIX', 'abcd')
USER_PREFIX = os.environ.get('BENCHMARK_USER_PREFIX', 'Nancy')

def init(app):

	@app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET'])
	def BenchmarkTest00025_get():
		response = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
		response.set_cookie('BenchmarkTest00025', 'whatever',
			max_age=COOKIE_MAX_AGE,
			secure=COOKIE_SECURE,
			path=request.path,
			domain=COOKIE_DOMAIN)
		return response
		return BenchmarkTest00025_post()

	@app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['POST'])
	def BenchmarkTest00025_post():
		RESPONSE = ""

		import urllib.parse
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00025", "noCookieValueSupplied"))

		superstring = f'{BENCHMARK_PREFIX}{param}{BENCHMARK_SUFFIX}'
		bar = superstring[len(BENCHMARK_PREFIX):len(superstring)-len(BENCHMARK_SUFFIX)+1]

		import random
		from helpers.utils import mysession

		num = 'BenchmarkTest00025'[13:]
		user = f'{USER_PREFIX}{num}'
		cookie = f'rememberMe{num}'
		value = str(random.normalvariate())[2:]

		if cookie in mysession and request.cookies.get(cookie) == mysession[cookie]:
			RESPONSE += (
				f'Welcome back: {user}<br/>'
			)
		else:
			mysession[cookie] = value
			RESPONSE += (
				f'{user} has been remembered with cookie: '
				f'{cookie} whose value is: {mysession[cookie]}<br/>'
			)

		return RESPONSE