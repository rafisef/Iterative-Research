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
from threading import Lock
from datetime import datetime, timedelta
import uuid

user_sessions = {}
session_lock = Lock()

def cleanup_expired_sessions():
	with session_lock:
		current_time = datetime.now()
		expired_sessions = [sid for sid, sdata in user_sessions.items() 
						   if sdata['expires'] < current_time]
		for sid in expired_sessions:
			del user_sessions[sid]

def get_or_create_session():
	cleanup_expired_sessions()
	
	session_id = request.cookies.get('session_id')
	
	if session_id and session_id in user_sessions:
		with session_lock:
			if session_id in user_sessions:
				user_sessions[session_id]['last_accessed'] = datetime.now()
				user_sessions[session_id]['expires'] = datetime.now() + timedelta(hours=1)
				return session_id, user_sessions[session_id]
	
	new_session_id = str(uuid.uuid4())
	new_session_data = {
		'created': datetime.now(),
		'last_accessed': datetime.now(),
		'expires': datetime.now() + timedelta(hours=1),
		'data': {}
	}
	
	with session_lock:
		user_sessions[new_session_id] = new_session_data
	
	return new_session_id, new_session_data

def require_session(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		session_id, session_data = get_or_create_session()
		kwargs['session_id'] = session_id
		kwargs['session_data'] = session_data
		return f(*args, **kwargs)
	return decorated_function

def init(app):

	@app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET'])
	@require_session
	def BenchmarkTest00064_get(session_id=None, session_data=None):
		response = make_response(render_template('web/securecookie-00/BenchmarkTest00064.html'))
		response.set_cookie('BenchmarkTest00064', 'whatever',
			max_age=60*3,
			secure=True,
			path=request.path,
			domain='localhost')
		response.set_cookie('session_id', session_id,
			max_age=3600,
			secure=True,
			httponly=True,
			path='/')
		return response

	@app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['POST'])
	@require_session
	def BenchmarkTest00064_post(session_id=None, session_data=None):
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

		with session_lock:
			if session_id in user_sessions:
				user_sessions[session_id]['data'][cookie] = value

		RESPONSE += (
			f'Created cookie: \'{cookie}\' with value \'{helpers.utils.escape_for_html(value)}\' and secure flag set to false.'
		)

		RESPONSE = make_response(RESPONSE)
		RESPONSE.set_cookie(cookie, value,
			path=request.path,
			secure=False,
			httponly=True)
		RESPONSE.set_cookie('session_id', session_id,
			max_age=3600,
			secure=True,
			httponly=True,
			path='/')

		return RESPONSE