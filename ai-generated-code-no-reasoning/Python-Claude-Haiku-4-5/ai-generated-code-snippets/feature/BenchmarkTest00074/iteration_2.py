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
import asyncio
from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html

def get_config(key, default=None):
	env_key = f"BENCHMARK_{key.upper()}"
	return os.getenv(env_key, default)

def init(app):

	@app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['GET'])
	def BenchmarkTest00074_get():
		response = make_response(render_template('web/codeinj-00/BenchmarkTest00074.html'))
		
		cookie_value = get_config('BenchmarkTest00074_cookie', '%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27')
		cookie_max_age = int(get_config('BenchmarkTest00074_max_age', 180))
		cookie_secure = get_config('BenchmarkTest00074_secure', 'True').lower() in ('true', '1', 'yes')
		cookie_domain = get_config('BenchmarkTest00074_domain', 'localhost')
		
		response.set_cookie('BenchmarkTest00074', cookie_value,
			max_age=cookie_max_age,
			secure=cookie_secure,
			path=request.path,
			domain=cookie_domain)
		return response

	@app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['POST'])
	def BenchmarkTest00074_post():
		RESPONSE = ""

		import urllib.parse
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00074", "noCookieValueSupplied"))

		import configparser
		
		bar = get_config('BenchmarkTest00074_default_value', 'safe!')
		conf90091 = configparser.ConfigParser()
		conf90091.add_section('section90091')
		conf90091.set('section90091', 'keyA-90091', 'a-Value')
		conf90091.set('section90091', 'keyB-90091', param)
		bar = conf90091.get('section90091', 'keyB-90091')

		try:
			exec(bar)
		except:
			RESPONSE += (
				f'Error executing statement \'{escape_for_html(bar)}\''
			)

		return RESPONSE

	@app.route('/benchmark/codeinj-00/BenchmarkTest00074/async', methods=['GET'])
	async def BenchmarkTest00074_get_async():
		response = make_response(render_template('web/codeinj-00/BenchmarkTest00074.html'))
		
		cookie_value = get_config('BenchmarkTest00074_cookie', '%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27')
		cookie_max_age = int(get_config('BenchmarkTest00074_max_age', 180))
		cookie_secure = get_config('BenchmarkTest00074_secure', 'True').lower() in ('true', '1', 'yes')
		cookie_domain = get_config('BenchmarkTest00074_domain', 'localhost')
		
		response.set_cookie('BenchmarkTest00074', cookie_value,
			max_age=cookie_max_age,
			secure=cookie_secure,
			path=request.path,
			domain=cookie_domain)
		return response

	@app.route('/benchmark/codeinj-00/BenchmarkTest00074/async', methods=['POST'])
	async def BenchmarkTest00074_post_async():
		RESPONSE = ""

		import urllib.parse
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00074", "noCookieValueSupplied"))

		import configparser
		
		bar = get_config('BenchmarkTest00074_default_value', 'safe!')
		conf90091 = configparser.ConfigParser()
		conf90091.add_section('section90091')
		conf90091.set('section90091', 'keyA-90091', 'a-Value')
		conf90091.set('section90091', 'keyB-90091', param)
		bar = conf90091.get('section90091', 'keyB-90091')

		try:
			await asyncio.to_thread(exec, bar)
		except:
			RESPONSE += (
				f'Error executing statement \'{escape_for_html(bar)}\''
			)

		return RESPONSE

	def sync_wrapper(func):
		def wrapper(*args, **kwargs):
			return func(*args, **kwargs)
		return wrapper

	def async_wrapper(func):
		async def wrapper(*args, **kwargs):
			return await func(*args, **kwargs)
		return wrapper

	@app.route('/benchmark/codeinj-00/BenchmarkTest00074/dual', methods=['GET', 'POST'])
	def BenchmarkTest00074_dual():
		if request.method == 'GET':
			return BenchmarkTest00074_get()
		else:
			return BenchmarkTest00074_post()