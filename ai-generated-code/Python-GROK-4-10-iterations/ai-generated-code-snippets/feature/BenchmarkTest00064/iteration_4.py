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

AUTH_PROVIDERS = {
    'local': lambda creds: True,
    'oauth': lambda creds: 'access_token' in creds,
    'saml': lambda creds: creds.get('saml_response') is not None
}

def authenticate(provider, credentials):
    if provider in AUTH_PROVIDERS:
        return AUTH_PROVIDERS[provider](credentials)
    return False

async def async_authenticate(provider, credentials):
    if provider in AUTH_PROVIDERS:
        if asyncio.iscoroutinefunction(AUTH_PROVIDERS[provider]):
            return await AUTH_PROVIDERS[provider](credentials)
        return AUTH_PROVIDERS[provider](credentials)
    return False

def init(app):

	@app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET'])
	def BenchmarkTest00064_get():
		response = make_response(render_template('web/securecookie-00/BenchmarkTest00064.html'))
		response.set_cookie('BenchmarkTest00064', 'whatever',
			max_age=60*3,
			secure=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['POST'])
	def BenchmarkTest00064_post():
		RESPONSE = ""

		import urllib.parse
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00064", "noCookieValueSupplied"))

		import helpers.utils
		bar = helpers.utils.escape_for_html(param)

		from flask import make_response
		import io
		import helpers.utils

		input = ''
		if isinstance(bar, str):
			input = bar.encode('utf-8')
		elif isinstance(bar, io.IOBase):
			input = bar.read(1000)

		cookie = 'SomeCookie'
		value = input.decode('utf-8')

		RESPONSE += (
			f'Created cookie: \'{cookie}\' with value \'{helpers.utils.escape_for_html(value)}\' and secure flag set to false.'
		)

		RESPONSE = make_response(RESPONSE)
		RESPONSE.set_cookie(cookie, value,
			path=request.path,
			secure=False,
			httponly=True)

		return RESPONSE

	@app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET'])
	async def async_BenchmarkTest00064_get():
		response = make_response(render_template('web/securecookie-00/BenchmarkTest00064.html'))
		response.set_cookie('BenchmarkTest00064', 'whatever',
			max_age=60*3,
			secure=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['POST'])
	async def async_BenchmarkTest00064_post():
		RESPONSE = ""

		import urllib.parse
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00064", "noCookieValueSupplied"))

		import helpers.utils
		bar = helpers.utils.escape_for_html(param)

		from flask import make_response
		import io
		import helpers.utils

		input = ''
		if isinstance(bar, str):
			input = bar.encode('utf-8')
		elif isinstance(bar, io.IOBase):
			input = bar.read(1000)

		cookie = 'SomeCookie'
		value = input.decode('utf-8')

		RESPONSE += (
			f'Created cookie: \'{cookie}\' with value \'{helpers.utils.escape_for_html(value)}\' and secure flag set to false.'
		)

		RESPONSE = make_response(RESPONSE)
		RESPONSE.set_cookie(cookie, value,
			path=request.path,
			secure=False,
			httponly=True)

		return RESPONSE