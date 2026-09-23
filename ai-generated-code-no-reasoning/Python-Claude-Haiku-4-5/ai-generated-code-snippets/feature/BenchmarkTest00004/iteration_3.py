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
import sqlite3
import json
import os
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
import queue

class SessionStore(ABC):
	@abstractmethod
	def get_or_create_session(self):
		pass
	
	@abstractmethod
	def get_session_data(self, session_id):
		pass
	
	@abstractmethod
	def update_session_data(self, session_id, key, value):
		pass
	
	@abstractmethod
	def get_session_value(self, session_id, key, default=None):
		pass
	
	@abstractmethod
	def cleanup_session(self, session_id):
		pass
	
	@abstractmethod
	def cleanup_expired_sessions(self, max_age_seconds=3600):
		pass

class FileSessionStore(SessionStore):
	def __init__(self, max_age_seconds=3600):
		self._session_store = {}
		self._session_lock = threading.RLock()
		self.max_age_seconds = max_age_seconds
	
	def get_or_create_session(self):
		session_id = session.get('session_id')
		
		if not session_id:
			session_id = str(uuid4())
			session['session_id'] = session_id
		
		with self._session_lock:
			if session_id not in self._session_store:
				self._session_store[session_id] = {
					'data': {},
					'lock': threading.RLock(),
					'created_at': datetime.now(),
					'updated_at': datetime.now()
				}
		
		return session_id, self._session_store[session_id]
	
	def get_session_data(self, session_id):
		with self._session_lock:
			if session_id in self._session_store:
				return self._session_store[session_id].copy()
			return {}
	
	def update_session_data(self, session_id, key, value):
		with self._session_lock:
			if session_id in self._session_store:
				with self._session_store[session_id]['lock']:
					self._session_store[session_id]['data'][key] = value
					self._session_store[session_id]['updated_at'] = datetime.now()
	
	def get_session_value(self, session_id, key, default=None):
		with self._session_lock:
			if session_id in self._session_store:
				with self._session_store[session_id]['lock']:
					return self._session_store[session_id]['data'].get(key, default)
		return default
	
	def cleanup_session(self, session_id):
		with self._session_lock:
			if session_id in self._session_store:
				del self._session_store[session_id]
	
	def cleanup_expired_sessions(self, max_age_seconds=3600):
		now = datetime.now()
		expired_sessions = []
		
		with self._session_lock:
			for session_id, session_data in list(self._session_store.items()):
				age = (now - session_data['updated_at']).total_seconds()
				if age > max_age_seconds:
					expired_sessions.append(session_id)
		
		for session_id in expired_sessions:
			self.cleanup_session(session_id)

class DatabaseSessionStore(SessionStore):
	def __init__(self, db_path='sessions.db', max_age_seconds=3600):
		self.db_path = db_path
		self._lock = threading.RLock()
		self.max_age_seconds = max_age_seconds
		self._init_db()
	
	def _init_db(self):
		with sqlite3.connect(self.db_path) as conn:
			conn.execute('''
				CREATE TABLE IF NOT EXISTS sessions (
					session_id TEXT PRIMARY KEY,
					data TEXT NOT NULL,
					created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
					updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
				)
			''')
			conn.execute('''
				CREATE INDEX IF NOT EXISTS idx_updated_at ON sessions(updated_at)
			''')
			conn.commit()
	
	def _get_connection(self):
		conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
		conn.row_factory = sqlite3.Row
		conn.execute('PRAGMA journal_mode=WAL')
		return conn
	
	def get_or_create_session(self):
		session_id = session.get('session_id')
		
		if not session_id:
			session_id = str(uuid4())
			session['session_id'] = session_id
		
		with self._lock:
			conn = self._get_connection()
			cursor = conn.cursor()
			cursor.execute('SELECT data FROM sessions WHERE session_id = ?', (session_id,))
			row = cursor.fetchone()
			
			if not row:
				cursor.execute(
					'INSERT INTO sessions (session_id, data) VALUES (?, ?)',
					(session_id, json.dumps({}))
				)
				conn.commit()
			
			conn.close()
		
		return session_id, {'lock': threading.RLock()}
	
	def get_session_data(self, session_id):
		with self._lock:
			conn = self._get_connection()
			cursor = conn.cursor()
			cursor.execute('SELECT data FROM sessions WHERE session_id = ?', (session_id,))
			row = cursor.fetchone()
			conn.close()
			
			if row:
				return json.loads(row['data'])
			return {}
	
	def update_session_data(self, session_id, key, value):
		with self._lock:
			conn = self._get_connection()
			cursor = conn.cursor()
			
			cursor.execute('SELECT data FROM sessions WHERE session_id = ?', (session_id,))
			row = cursor.fetchone()
			
			if row:
				data = json.loads(row['data'])
				data[key] = value
				cursor.execute(
					'UPDATE sessions SET data = ?, updated_at = CURRENT_TIMESTAMP WHERE session_id = ?',
					(json.dumps(data), session_id)
				)
				conn.commit()
			
			conn.close()
	
	def get_session_value(self, session_id, key, default=None):
		with self._lock:
			conn = self._get_connection()
			cursor = conn.cursor()
			cursor.execute('SELECT data FROM sessions WHERE session_id = ?', (session_id,))
			row = cursor.fetchone()
			conn.close()
			
			if row:
				data = json.loads(row['data'])
				return data.get(key, default)
			return default
	
	def cleanup_session(self, session_id):
		with self._lock:
			conn = self._get_connection()
			cursor = conn.cursor()
			cursor.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
			conn.commit()
			conn.close()
	
	def cleanup_expired_sessions(self, max_age_seconds=3600):
		with self._lock:
			conn = self._get_connection()
			cursor = conn.cursor()
			cursor.execute(
				'DELETE FROM sessions WHERE datetime(updated_at) < datetime("now", "-' + str(max_age_seconds) + ' seconds")'
			)
			conn.commit()
			conn.close()

class ConcurrentSessionManager:
	def __init__(self, session_store, max_workers=10):
		self.session_store = session_store
		self.executor = ThreadPoolExecutor(max_workers=max_workers)
		self.cleanup_queue = queue.Queue()
	
	def async_update_session(self, session_id, key, value):
		self.executor.submit(self.session_store.update_session_data, session_id, key, value)
	
	def async_cleanup_session(self, session_id):
		self.executor.submit(self.session_store.cleanup_session, session_id)
	
	def cleanup_expired(self, max_age_seconds=3600):
		self.executor.submit(self.session_store.cleanup_expired_sessions, max_age_seconds)
	
	def shutdown(self):
		self.executor.shutdown(wait=True)

_session_store = None
_session_manager = None

def init(app, storage_type='file', db_path='sessions.db', max_workers=10, max_session_age=3600):
	global _session_store, _session_manager
	
	if storage_type == 'database':
		_session_store = DatabaseSessionStore(db_path, max_session_age)
	else:
		_session_store = FileSessionStore(max_session_age)
	
	_session_manager = ConcurrentSessionManager(_session_store, max_workers)
	
	app.secret_key = str(uuid4())

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['GET'])
	def BenchmarkTest00004_get():
		session_id, session_data = _session_store.get_or_create_session()
		
		response = make_response(render_template('web/pathtraver-00/BenchmarkTest00004.html'))
		response.set_cookie('BenchmarkTest00004', 'Filename',
			max_age=60*3,
			secure=True,
			path=request.path,
			domain='localhost')
		
		_session_manager.async_update_session(session_id, 'test_00004_init', True)
		
		return response

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['POST'])
	def BenchmarkTest00004_post():
		session_id, session_data = _session_store.get_or_create_session()
		
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

			_session_manager.async_update_session(session_id, 'test_00004_response', RESPONSE)
			
			return RESPONSE
	
	@app.before_request
	def cleanup_sessions():
		_session_manager.cleanup_expired(max_session_age)
	
	@app.teardown_appcontext
	def shutdown_session_manager(exception=None):
		_session_manager.shutdown()