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

class Config:
	def __init__(self):
		self.cookie_max_age = int(os.getenv('BENCHMARK_COOKIE_MAX_AGE', 180))
		self.cookie_secure = os.getenv('BENCHMARK_COOKIE_SECURE', 'True').lower() == 'true'
		self.cookie_domain = os.getenv('BENCHMARK_COOKIE_DOMAIN', 'localhost')
		self.cookie_path = os.getenv('BENCHMARK_COOKIE_PATH', '/benchmark/weakrand-00/BenchmarkTest00025')
		self.route_prefix = os.getenv('BENCHMARK_ROUTE_PREFIX', '/benchmark/weakrand-00')
		self.template_path = os.getenv('BENCHMARK_TEMPLATE_PATH', 'web/weakrand-00/BenchmarkTest00025.html')

def init(app):
	config = Config()

	@app.route(f'{config.route_prefix}/BenchmarkTest00025', methods=['GET'])
	def BenchmarkTest00025_get():
		response = make_response(render_template(config.template_path))
		response.set_cookie('BenchmarkTest00025', 'whatever',
			max_age=config.cookie_max_age,
			secure=config.cookie_secure,
			path=config.cookie_path,
			domain=config.cookie_domain)
		return response

	@app.route(f'{config.route_prefix}/BenchmarkTest00025', methods=['POST'])
	def BenchmarkTest00025_post():
		RESPONSE = ""

		import urllib.parse
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00025", "noCookieValueSupplied"))

		superstring = f'90583{param}abcd'
		bar = superstring[len('90583'):len(superstring)-5]

		import random
		from helpers.utils import mysession

		num = 'BenchmarkTest00025'[13:]
		user = f'Nancy{num}'
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