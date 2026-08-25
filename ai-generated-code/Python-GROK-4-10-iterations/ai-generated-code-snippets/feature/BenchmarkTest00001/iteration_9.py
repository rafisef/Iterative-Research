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
import uuid
import threading
import asyncio

_session_store = {}
_session_lock = threading.Lock()
_async_session_lock = asyncio.Lock()

auth_providers = {
    'local': lambda u, p: True,
    'oauth': lambda u, p: False,
    'ldap': lambda u, p: True
}

def authenticate(provider, username, password):
    if provider in auth_providers:
        return auth_providers[provider](username, password)
    return False

async def async_authenticate(provider, username, password):
    if provider in auth_providers:
        return auth_providers[provider](username, password)
    return False

def init(app):
	app.secret_key = 'benchmark-secret-key-for-sessions'
	app.config['SESSION_COOKIE_SECURE'] = True
	app.config['SESSION_COOKIE_HTTPONLY'] = True

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00001', methods=['GET'])
	def BenchmarkTest00001_get():
		with _session_lock:
			session_id = session.get('session_id', str(uuid.uuid4()))
			session['session_id'] = session_id
			_session_store[session_id] = {'created': True}
		response = make_response(render_template('web/pathtraver-00/BenchmarkTest00001.html'))
		response.set_cookie('BenchmarkTest00001', session_id,
			max_age=60*3,
			secure=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00001', methods=['POST'])
	def BenchmarkTest00001_post():
		RESPONSE = ""

		import urllib.parse
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00001", "noCookieValueSupplied"))

		bar = param

		import codecs
		import helpers.utils

		try:
			fileTarget = codecs.open(f'{helpers.utils.TESTFILES_DIR}/{bar}','r','utf-8')

			RESPONSE += (
				f"Access to file: \'{escape_for_html(fileTarget.name)}\' created."
			)

			RESPONSE += (
				" And file already exists."
			)

		except FileNotFoundError:
			RESPONSE += (
				" But file doesn't exist yet."
			)

		return RESPONSE

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00001/async', methods=['GET'])
	async def BenchmarkTest00001_get_async():
		async with _async_session_lock:
			session_id = session.get('session_id', str(uuid.uuid4()))
			session['session_id'] = session_id
			_session_store[session_id] = {'created': True}
		response = make_response(render_template('web/pathtraver-00/BenchmarkTest00001.html'))
		response.set_cookie('BenchmarkTest00001', session_id,
			max_age=60*3,
			secure=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00001/async', methods=['POST'])
	async def BenchmarkTest00001_post_async():
		RESPONSE = ""

		import urllib.parse
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00001", "noCookieValueSupplied"))

		bar = param

		import codecs
		import helpers.utils

		try:
			fileTarget = codecs.open(f'{helpers.utils.TESTFILES_DIR}/{bar}','r','utf-8')

			RESPONSE += (
				f"Access to file: \'{escape_for_html(fileTarget.name)}\' created."
			)

			RESPONSE += (
				" And file already exists."
			)

		except FileNotFoundError:
			RESPONSE += (
				" But file doesn't exist yet."
			)

		return RESPONSE