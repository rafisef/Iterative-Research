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
from threading import RLock, Condition, Thread
from datetime import datetime, timedelta
import uuid
from collections import defaultdict
import asyncio
from concurrent.futures import ThreadPoolExecutor
import time
import os

class SessionManager:
	def __init__(self, max_workers=None, cleanup_interval=None, session_timeout=None, secret_key=None):
		self.sessions = {}
		self.lock = RLock()
		self.condition = Condition(self.lock)
		
		self.max_workers = max_workers or int(os.getenv('SESSION_MAX_WORKERS', '10'))
		self.cleanup_interval = cleanup_interval or int(os.getenv('SESSION_CLEANUP_INTERVAL', '60'))
		self.session_timeout = session_timeout or int(os.getenv('SESSION_TIMEOUT', '180'))
		self.secret_key = secret_key or os.getenv('SESSION_SECRET_KEY', 'benchmark-secret-key-change-in-production')
		
		self.user_sessions = defaultdict(list)
		self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
		self.session_activity = {}
		self.cleanup_thread = None
		self.running = True
		self._start_cleanup_thread()

	def _start_cleanup_thread(self):
		self.cleanup_thread = Thread(target=self._cleanup_loop, daemon=True)
		self.cleanup_thread.start()

	def _cleanup_loop(self):
		while self.running:
			time.sleep(self.cleanup_interval)
			self.cleanup_expired_async()

	def create_session(self, user_id=None):
		session_id = str(uuid.uuid4())
		with self.lock:
			self.sessions[session_id] = {
				'data': {},
				'created_at': datetime.now(),
				'last_accessed': datetime.now(),
				'user_id': user_id,
				'activity_log': [],
				'concurrent_requests': 0
			}
			if user_id:
				self.user_sessions[user_id].append(session_id)
			self.session_activity[session_id] = {
				'requests': 0,
				'last_request_time': datetime.now(),
				'concurrent_count': 0,
				'peak_concurrent': 0
			}
			self.condition.notify_all()
		return session_id

	def get_session(self, session_id):
		with self.lock:
			if session_id in self.sessions:
				session_data = self.sessions[session_id]
				session_data['last_accessed'] = datetime.now()
				session_data['concurrent_requests'] += 1
				if session_id in self.session_activity:
					self.session_activity[session_id]['requests'] += 1
					self.session_activity[session_id]['last_request_time'] = datetime.now()
					self.session_activity[session_id]['concurrent_count'] += 1
					current_concurrent = self.session_activity[session_id]['concurrent_count']
					if current_concurrent > self.session_activity[session_id]['peak_concurrent']:
						self.session_activity[session_id]['peak_concurrent'] = current_concurrent
				self._cleanup_expired()
				return session_data['data']
		return None

	def release_session(self, session_id):
		with self.lock:
			if session_id in self.sessions:
				self.sessions[session_id]['concurrent_requests'] = max(0, self.sessions[session_id]['concurrent_requests'] - 1)
				if session_id in self.session_activity:
					self.session_activity[session_id]['concurrent_count'] = max(0, self.session_activity[session_id]['concurrent_count'] - 1)

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
			return self.user_sessions.get(user_id, []).copy()

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
			activity = self.session_activity.get(session_id, {}).copy()
			return activity

	def _cleanup_expired(self):
		current_time = datetime.now()
		expired_sessions = []
		for sid, session_data in list(self.sessions.items()):
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

	def get_concurrent_sessions_info(self):
		with self.lock:
			info = {
				'total_sessions': len(self.sessions),
				'total_concurrent_requests': sum(s.get('concurrent_requests', 0) for s in self.sessions.values()),
				'sessions_by_user': {uid: len(sids) for uid, sids in self.user_sessions.items() if sids}
			}
			return info

	def shutdown(self):
		self.running = False
		if self.cleanup_thread:
			self.cleanup_thread.join(timeout=5)
		self.executor.shutdown(wait=True)

session_manager = SessionManager()

def init(app):
	app.config['SECRET_KEY'] = session_manager.secret_key

	@app.before_request
	def track_session_start():
		session_id = session.get('session_id')
		if session_id:
			session_manager.get_session(session_id)

	@app.teardown_request
	def track_session_end(exception=None):
		session_id = session.get('session_id')
		if session_id:
			session_manager.release_session(session_id)

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
				'last_request_time': str(activity.get('last_request_time', '')),
				'concurrent_requests': activity.get('concurrent_count', 0),
				'peak_concurrent': activity.get('peak_concurrent', 0)
			}
		return {}

	@app.route('/benchmark/session/count', methods=['GET'])
	def get_session_count():
		info = session_manager.get_concurrent_sessions_info()
		return {
			'total_sessions': info['total_sessions'],
			'total_concurrent_requests': info['total_concurrent_requests'],
			'sessions_by_user': info['sessions_by_user']
		}

	@app.teardown_appcontext
	def shutdown_session_manager(exception=None):
		session_manager.shutdown()