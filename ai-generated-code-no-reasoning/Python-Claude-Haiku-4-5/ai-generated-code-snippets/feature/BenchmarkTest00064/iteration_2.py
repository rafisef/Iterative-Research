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
import json
import os
import sqlite3
from abc import ABC, abstractmethod

class SessionStorage(ABC):
	@abstractmethod
	def get(self, session_id):
		pass
	
	@abstractmethod
	def set(self, session_id, session_data):
		pass
	
	@abstractmethod
	def delete(self, session_id):
		pass
	
	@abstractmethod
	def exists(self, session_id):
		pass
	
	@abstractmethod
	def cleanup_expired(self):
		pass

class FileSessionStorage(SessionStorage):
	def __init__(self, storage_dir='sessions'):
		self.storage_dir = storage_dir
		self.lock = Lock()
		if not os.path.exists(storage_dir):
			os.makedirs(storage_dir)
	
	def _get_file_path(self, session_id):
		return os.path.join(self.storage_dir, f'{session_id}.json')
	
	def get(self, session_id):
		with self.lock:
			file_path = self._get_file_path(session_id)
			if os.path.exists(file_path):
				try:
					with open(file_path, 'r') as f:
						return json.load(f)
				except (json.JSONDecodeError, IOError):
					return None
		return None
	
	def set(self, session_id, session_data):
		with self.lock:
			file_path = self._get_file_path(session_id)
			try:
				with open(file_path, 'w') as f:
					json.dump(session_data, f, default=str)
			except IOError:
				pass
	
	def delete(self, session_id):
		with self.lock:
			file_path = self._get_file_path(session_id)
			if os.path.exists(file_path):
				try:
					os.remove(file_path)
				except OSError:
					pass
	
	def exists(self, session_id):
		with self.lock:
			file_path = self._get_file_path(session_id)
			return os.path.exists(file_path)
	
	def cleanup_expired(self):
		with self.lock:
			current_time = datetime.now()
			for filename in os.listdir(self.storage_dir):
				if filename.endswith('.json'):
					file_path = os.path.join(self.storage_dir, filename)
					try:
						with open(file_path, 'r') as f:
							data = json.load(f)
							expires = datetime.fromisoformat(data.get('expires', ''))
							if expires < current_time:
								os.remove(file_path)
					except (json.JSONDecodeError, IOError, ValueError):
						pass

class DatabaseSessionStorage(SessionStorage):
	def __init__(self, db_path='sessions.db'):
		self.db_path = db_path
		self.lock = Lock()
		self._init_db()
	
	def _init_db(self):
		with self.lock:
			conn = sqlite3.connect(self.db_path)
			cursor = conn.cursor()
			cursor.execute('''
				CREATE TABLE IF NOT EXISTS sessions (
					session_id TEXT PRIMARY KEY,
					created TEXT NOT NULL,
					last_accessed TEXT NOT NULL,
					expires TEXT NOT NULL,
					data TEXT NOT NULL
				)
			''')
			conn.commit()
			conn.close()
	
	def get(self, session_id):
		with self.lock:
			try:
				conn = sqlite3.connect(self.db_path)
				cursor = conn.cursor()
				cursor.execute('SELECT created, last_accessed, expires, data FROM sessions WHERE session_id = ?', (session_id,))
				row = cursor.fetchone()
				conn.close()
				if row:
					return {
						'created': row[0],
						'last_accessed': row[1],
						'expires': row[2],
						'data': json.loads(row[3])
					}
			except (sqlite3.Error, json.JSONDecodeError):
				pass
		return None
	
	def set(self, session_id, session_data):
		with self.lock:
			try:
				conn = sqlite3.connect(self.db_path)
				cursor = conn.cursor()
				data_json = json.dumps(session_data['data'], default=str)
				cursor.execute('''
					INSERT OR REPLACE INTO sessions (session_id, created, last_accessed, expires, data)
					VALUES (?, ?, ?, ?, ?)
				''', (session_id, session_data['created'], session_data['last_accessed'], session_data['expires'], data_json))
				conn.commit()
				conn.close()
			except sqlite3.Error:
				pass
	
	def delete(self, session_id):
		with self.lock:
			try:
				conn = sqlite3.connect(self.db_path)
				cursor = conn.cursor()
				cursor.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
				conn.commit()
				conn.close()
			except sqlite3.Error:
				pass
	
	def exists(self, session_id):
		with self.lock:
			try:
				conn = sqlite3.connect(self.db_path)
				cursor = conn.cursor()
				cursor.execute('SELECT 1 FROM sessions WHERE session_id = ?', (session_id,))
				result = cursor.fetchone() is not None
				conn.close()
				return result
			except sqlite3.Error:
				pass
		return False
	
	def cleanup_expired(self):
		with self.lock:
			try:
				conn = sqlite3.connect(self.db_path)
				cursor = conn.cursor()
				current_time = datetime.now().isoformat()
				cursor.execute('DELETE FROM sessions WHERE expires < ?', (current_time,))
				conn.commit()
				conn.close()
			except sqlite3.Error:
				pass

session_storage = None
session_lock = Lock()

def set_storage(storage):
	global session_storage
	session_storage = storage

def cleanup_expired_sessions():
	if session_storage:
		session_storage.cleanup_expired()

def get_or_create_session():
	cleanup_expired_sessions()
	
	session_id = request.cookies.get('session_id')
	
	if session_id and session_storage.exists(session_id):
		with session_lock:
			session_data = session_storage.get(session_id)
			if session_data:
				session_data['last_accessed'] = datetime.now().isoformat()
				session_data['expires'] = (datetime.now() + timedelta(hours=1)).isoformat()
				session_storage.set(session_id, session_data)
				return session_id, session_data
	
	new_session_id = str(uuid.uuid4())
	new_session_data = {
		'created': datetime.now().isoformat(),
		'last_accessed': datetime.now().isoformat(),
		'expires': (datetime.now() + timedelta(hours=1)).isoformat(),
		'data': {}
	}
	
	with session_lock:
		session_storage.set(new_session_id, new_session_data)
	
	return new_session_id, new_session_data

def require_session(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		session_id, session_data = get_or_create_session()
		kwargs['session_id'] = session_id
		kwargs['session_data'] = session_data
		return f(*args, **kwargs)
	return decorated_function

def init(app, storage_type='file', storage_config=None):
	global session_storage
	
	if storage_type == 'file':
		storage_dir = storage_config.get('storage_dir', 'sessions') if storage_config else 'sessions'
		session_storage = FileSessionStorage(storage_dir)
	elif storage_type == 'database':
		db_path = storage_config.get('db_path', 'sessions.db') if storage_config else 'sessions.db'
		session_storage = DatabaseSessionStorage(db_path)
	else:
		raise ValueError(f"Unknown storage type: {storage_type}")

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
			if session_storage.exists(session_id):
				session_data = session_storage.get(session_id)
				session_data['data'][cookie] = value
				session_storage.set(session_id, session_data)

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