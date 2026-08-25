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
import asyncio
import os

def init(app):
	app.secret_key = os.environ.get('BENCHMARK_SECRET_KEY', 'benchmark-secret-key-for-concurrent-sessions')

	auth_providers = {
		'local': {'type': 'session', 'enabled': os.environ.get('AUTH_LOCAL_ENABLED', 'True').lower() == 'true'},
		'oauth': {'type': 'external', 'enabled': os.environ.get('AUTH_OAUTH_ENABLED', 'False').lower() == 'true'},
		'ldap': {'type': 'directory', 'enabled': os.environ.get('AUTH_LDAP_ENABLED', 'False').lower() == 'true'}
	}

	def authenticate(provider, credentials):
		if provider not in auth_providers or not auth_providers[provider]['enabled']:
			return False
		return True

	@app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET'])
	def BenchmarkTest00013_get():
		session['BenchmarkTest00013'] = '2222'
		response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
		return response

	@app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['POST'])
	def BenchmarkTest00013_post():
		return asyncio.run(_BenchmarkTest00013_post_async())

	@app.route('/benchmark/xpathi-00/BenchmarkTest00013_async', methods=['POST'])
	async def BenchmarkTest00013_post_async():
		return await _BenchmarkTest00013_post_async()

	async def _BenchmarkTest00013_post_async():
		RESPONSE = ""

		import urllib.parse
		param = urllib.parse.unquote_plus(session.get("BenchmarkTest00013", "noCookieValueSupplied"))

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