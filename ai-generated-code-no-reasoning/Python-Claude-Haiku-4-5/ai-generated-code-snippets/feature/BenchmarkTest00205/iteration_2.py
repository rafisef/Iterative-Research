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
import uuid
import threading
import os

_session_lock = threading.RLock()
_sessions = {}

_config = {
	'SESSION_TYPE': os.getenv('BENCHMARK_SESSION_TYPE', 'filesystem'),
	'SESSION_TIMEOUT': int(os.getenv('BENCHMARK_SESSION_TIMEOUT', '3600')),
	'ENABLE_XXE_PARSING': os.getenv('BENCHMARK_ENABLE_XXE_PARSING', 'true').lower() == 'true',
	'LOG_RESPONSES': os.getenv('BENCHMARK_LOG_RESPONSES', 'false').lower() == 'true',
	'PARSER_EXTERNAL_GES': os.getenv('BENCHMARK_PARSER_EXTERNAL_GES', 'true').lower() == 'true',
}

def get_config(key, default=None):
	return _config.get(key, default)

def set_config(key, value):
	_config[key] = value

def _get_or_create_session():
	session_id = session.get('_benchmark_session_id')
	if not session_id:
		session_id = str(uuid.uuid4())
		session['_benchmark_session_id'] = session_id
	
	with _session_lock:
		if session_id not in _sessions:
			_sessions[session_id] = {
				'data': {},
				'lock': threading.RLock()
			}
	
	return session_id, _sessions[session_id]

def _require_session(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		session_id, session_data = _get_or_create_session()
		return f(session_id=session_id, session_data=session_data, *args, **kwargs)
	return decorated_function

def init(app):
	app.config['SESSION_TYPE'] = get_config('SESSION_TYPE')
	
	@app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET'])
	@_require_session
	def BenchmarkTest00205_get(session_id, session_data):
		return BenchmarkTest00205_post(session_id=session_id, session_data=session_data)

	@app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['POST'])
	@_require_session
	def BenchmarkTest00205_post(session_id, session_data):
		RESPONSE = ""

		values = request.form.getlist("BenchmarkTest00205")
		param = ""
		if values:
			param = values[0]

		import configparser
		
		with session_data['lock']:
			bar = 'safe!'
			conf60568 = configparser.ConfigParser()
			conf60568.add_section('section60568')
			conf60568.set('section60568', 'keyA-60568', 'a-Value')
			conf60568.set('section60568', 'keyB-60568', param)
			bar = conf60568.get('section60568', 'keyB-60568')

			session_data['data']['last_bar'] = bar
			session_data['data']['last_param'] = param

		import xml.dom.minidom
		import xml.sax.handler

		try:
			parser = xml.sax.make_parser()
			parser.setFeature(xml.sax.handler.feature_external_ges, get_config('PARSER_EXTERNAL_GES'))

			doc = xml.dom.minidom.parseString(bar, parser)

			out = ''
			processing = [doc.documentElement]
			while processing:
				e = processing.pop(0)
				if e.nodeType == xml.dom.Node.TEXT_NODE:
					out += e.data
				else:
					processing[:0] = e.childNodes

			RESPONSE += (
				f'Your XML doc results are: <br>{escape_for_html(out)}'
			)
		except:
			RESPONSE += (
				f'There was an error reading your XML doc:<br>{escape_for_html(bar)}'
			)

		with session_data['lock']:
			session_data['data']['last_response'] = RESPONSE

		if get_config('LOG_RESPONSES'):
			print(f"Session {session_id}: Response logged - {RESPONSE[:100]}")

		return RESPONSE