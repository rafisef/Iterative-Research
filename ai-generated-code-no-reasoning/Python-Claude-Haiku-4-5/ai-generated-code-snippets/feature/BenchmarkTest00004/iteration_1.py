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
from functools import wraps
from uuid import uuid4
import threading

_session_store = {}
_session_lock = threading.RLock()

def _get_or_create_session():
	session_id = session.get('session_id')
	
	if not session_id:
		session_id = str(uuid4())
		session['session_id'] = session_id
	
	with _session_lock:
		if session_id not in _session_store:
			_session_store[session_id] = {
				'data': {},
				'lock': threading.RLock()
			}
	
	return session_id, _session_store[session_id]

def _get_session_data(session_id):
	with _session_lock:
		return _session_store.get(session_id, {})

def _update_session_data(session_id, key, value):
	with _session_lock:
		if session_id in _session_store:
			with _session_store[session_id]['lock']:
				_session_store[session_id]['data'][key] = value

def _get_session_value(session_id, key, default=None):
	with _session_lock:
		if session_id in _session_store:
			with _session_store[session_id]['lock']:
				return _session_store[session_id]['data'].get(key, default)
	return default

def _cleanup_session(session_id):
	with _session_lock:
		if session_id in _session_store:
			del _session_store[session_id]

def init(app):
	app.secret_key = str(uuid4())

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['GET'])
	def BenchmarkTest00004_get():
		session_id, session_data = _get_or_create_session()
		
		response = make_response(render_template('web/pathtraver-00/BenchmarkTest00004.html'))
		response.set_cookie('BenchmarkTest00004', 'Filename',
			max_age=60*3,
			secure=True,
			path=request.path,
			domain='localhost')
		
		_update_session_data(session_id, 'test_00004_init', True)
		
		return response

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['POST'])
	def BenchmarkTest00004_post():
		session_id, session_data = _get_or_create_session()
		
		with session_data['lock']:
			RESPONSE = ""

			import urllib.parse
			param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00004", "noCookieValueSupplied"))

			num = 106
			
			bar = "This_should_always_happen" if 7 * 18 + num > 200 else param

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

			_update_session_data(session_id, 'test_00004_response', RESPONSE)
			
			return RESPONSE