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
from threading import RLock, Condition
from datetime import datetime, timedelta
import uuid
from collections import defaultdict
import asyncio
from concurrent.futures import ThreadPoolExecutor

class SessionManager:
	def __init__(self, max_workers=10):
		self.sessions = {}
		self.lock = RLock()
		self.condition = Condition(self.lock)
		self.session_timeout = 180
		self.user_sessions = defaultdict(list)
		self.executor = ThreadPoolExecutor(max_workers=max_workers)
		self.session_activity = {}

	def create_session(self, user_id=None):
		session_id = str(uuid.uuid4())
		with self.lock:
			self.sessions[session_id] = {
				'data': {},
				'created_at': datetime.now(),
				'last_accessed': datetime.now(),
				'user_id': user_id,
				'activity_log': []
			}
			if user_id:
				self.user_sessions[user_id].append(session_id)
			self.session_activity[session_id] = {
				'requests': 0,
				'last_request_time': datetime.now()
			}
			self.condition.notify_all()
		return session_id

	def get_session(self, session_id):
		with self.lock:
			if session_id in self.sessions:
				session_data = self.sessions[session_id]
				session_data['last_accessed'] = datetime.now()
				if session_id in self.session_activity:
					self.session_activity[session_id]['requests'] += 1
					self.session_activity[session_id]['last_request_time'] = datetime.now()
				self._cleanup_expired()
				return session_data['data']
		return None

	def set_session_value(self, session_id, key, value):
		with self.lock:
			if session_id in self.sessions:
				self.sessions[session_id]['data'][key] = value
				self.sessions[session_id]['last_accessed'] = datetime.now()
				self.sessions[session_id]['activity_log'].append({
					'action': 'set',
					'key': key,
					'timestamp': datetime.now()
				})
				self.condition.notify_all()

	def get_user_sessions(self, user_id):
		with self.lock:
			return self.user_sessions.get(user_id, [])

	def invalidate_session(self, session_id):
		with self.lock:
			if session_id in self.sessions:
				user_id = self.sessions[session_id].get('user_id')
				del self.sessions[session_id]
				if session_id in self.session_activity:
					del self.session_activity[session_id]
				if user_id and session_id in self.user_sessions[user_id]:
					self.user_sessions[user_id].remove(session_id)
				self.condition.notify_all()

	def invalidate_user_sessions(self, user_id):
		with self.lock:
			sessions_to_remove = self.user_sessions.get(user_id, []).copy()
			for session_id in sessions_to_remove:
				if session_id in self.sessions:
					del self.sessions[session_id]
					if session_id in self.session_activity:
						del self.session_activity[session_id]
			if user_id in self.user_sessions:
				self.user_sessions[user_id].clear()
			self.condition.notify_all()

	def get_session_activity(self, session_id):
		with self.lock:
			return self.session_activity.get(session_id, {})

	def _cleanup_expired(self):
		current_time = datetime.now()
		expired_sessions = []
		for sid, session_data in self.sessions.items():
			if (current_time - session_data['last_accessed']).seconds > self.session_timeout:
				expired_sessions.append(sid)
		for sid in expired_sessions:
			user_id = self.sessions[sid].get('user_id')
			del self.sessions[sid]
			if sid in self.session_activity:
				del self.session_activity[sid]
			if user_id and sid in self.user_sessions[user_id]:
				self.user_sessions[user_id].remove(sid)

	def cleanup_expired_async(self):
		def cleanup():
			with self.lock:
				self._cleanup_expired()
		self.executor.submit(cleanup)

	def get_all_sessions_count(self):
		with self.lock:
			return len(self.sessions)

	def get_user_session_count(self, user_id):
		with self.lock:
			return len(self.user_sessions.get(user_id, []))

session_manager = SessionManager()

def init(app):
	app.config['SECRET_KEY'] = 'benchmark-secret-key-change-in-production'

	@app.route('/benchmark/trustbound-00/BenchmarkTest00072', methods=['GET'])
	def BenchmarkTest00072_get():
		session_id = session.get('session_id')
		if not session_id:
			session_id = session_manager.create_session()
			session['session_id'] = session_id

		response = make_response(render_template('web/trustbound-00/BenchmarkTest00072.html'))
		response.set_cookie('BenchmarkTest00072', 'my-user-id',
			max_age=60*3,
			secure=True,
			path=request.path,
			domain='localhost')
		response.set_cookie('session_id', session_id,
			max_age=60*3,
			secure=True,
			httponly=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/trustbound-00/BenchmarkTest00072', methods=['POST'])
	def BenchmarkTest00072_post():
		RESPONSE = ""

		session_id = session.get('session_id')
		if not session_id:
			session_id = session_manager.create_session()
			session['session_id'] = session_id

		import urllib.parse
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00072", "noCookieValueSupplied"))

		TestParam = "This should never happen"
		if 'should' not in TestParam:
			bar = "Ifnot case passed"
		else:
			bar = param

		session_manager.set_session_value(session_id, bar, '12345')

		RESPONSE += (
			f'Item: \'{escape_for_html(bar)}'
			'\' with value: 12345 saved in session.'
		)

		return RESPONSE

	@app.route('/benchmark/session/invalidate', methods=['POST'])
	def invalidate_session_route():
		session_id = session.get('session_id')
		if session_id:
			session_manager.invalidate_session(session_id)
			session.pop('session_id', None)
		return "Session invalidated"

	@app.route('/benchmark/session/activity', methods=['GET'])
	def get_session_activity():
		session_id = session.get('session_id')
		if session_id:
			activity = session_manager.get_session_activity(session_id)
			return {
				'session_id': session_id,
				'requests': activity.get('requests', 0),
				'last_request_time': str(activity.get('last_request_time', ''))
			}
		return {}

	@app.route('/benchmark/session/count', methods=['GET'])
	def get_session_count():
		return {
			'total_sessions': session_manager.get_all_sessions_count()
		}