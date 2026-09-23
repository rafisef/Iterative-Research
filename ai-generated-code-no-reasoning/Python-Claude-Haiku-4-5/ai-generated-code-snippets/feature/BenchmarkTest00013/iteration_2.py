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
import asyncio
import inspect
import os

def _get_config(key, default=None):
	env_key = f"BENCHMARK_{key.upper()}"
	return os.getenv(env_key, default)

def init(app):

	def _process_xpath_query(param):
		RESPONSE = ""

		import urllib.parse
		bar = "alsosafe"
		if param:
			lst = []
			lst.append('safe')
			lst.append(param)
			lst.append('moresafe')
			lst.pop(0)
			bar = lst[1]

		import elementpath
		import xml.etree.ElementTree as ET
		import helpers.utils

		try:
			root = ET.parse(f'{helpers.utils.RES_DIR}/employees.xml')
			query = f"/Employees/Employee[@emplid=\'{bar}\']"
			nodes = elementpath.select(root, query)
			node_strings = []
			for node in nodes:
				node_strings.append(' '.join([e.text for e in node]))

			RESPONSE += (
				f'Your XPATH query results are: <br>[ {', '.join(node_strings)} ]'
			)
		except:
			RESPONSE += (
				f'Error parsing XPath Query: \'{escape_for_html(query)}\''
			)

		return RESPONSE

	async def _process_xpath_query_async(param):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, _process_xpath_query, param)

	cookie_max_age = int(_get_config('cookie_max_age', 60*3))
	cookie_secure = _get_config('cookie_secure', 'True').lower() == 'true'
	cookie_domain = _get_config('cookie_domain', 'localhost')
	cookie_name = _get_config('cookie_name', 'BenchmarkTest00013')

	@app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET'])
	def BenchmarkTest00013_get():
		response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
		response.set_cookie(cookie_name, '2222',
			max_age=cookie_max_age,
			secure=cookie_secure,
			path=request.path,
			domain=cookie_domain)
		return response

	@app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['POST'])
	def BenchmarkTest00013_post():
		import urllib.parse
		param = urllib.parse.unquote_plus(request.cookies.get(cookie_name, "noCookieValueSupplied"))

		return _process_xpath_query(param)

	@app.route('/benchmark/xpathi-00/BenchmarkTest00013/async', methods=['GET'])
	async def BenchmarkTest00013_get_async():
		response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
		response.set_cookie(cookie_name, '2222',
			max_age=cookie_max_age,
			secure=cookie_secure,
			path=request.path,
			domain=cookie_domain)
		return response

	@app.route('/benchmark/xpathi-00/BenchmarkTest00013/async', methods=['POST'])
	async def BenchmarkTest00013_post_async():
		import urllib.parse
		param = urllib.parse.unquote_plus(request.cookies.get(cookie_name, "noCookieValueSupplied"))

		return await _process_xpath_query_async(param)

	def _sync_or_async_route(sync_func, async_func):
		def wrapper(*args, **kwargs):
			if asyncio.iscoroutinefunction(async_func):
				try:
					loop = asyncio.get_event_loop()
					if loop.is_running():
						return async_func(*args, **kwargs)
					else:
						return loop.run_until_complete(async_func(*args, **kwargs))
				except RuntimeError:
					loop = asyncio.new_event_loop()
					asyncio.set_event_loop(loop)
					return loop.run_until_complete(async_func(*args, **kwargs))
			return sync_func(*args, **kwargs)
		return wrapper

	original_post = BenchmarkTest00013_post
	BenchmarkTest00013_post = _sync_or_async_route(original_post, BenchmarkTest00013_post_async)