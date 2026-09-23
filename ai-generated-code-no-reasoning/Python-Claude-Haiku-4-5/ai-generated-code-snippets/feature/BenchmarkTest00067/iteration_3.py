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

import asyncio
import urllib.parse
import base64
import os
import json
import sqlite3
import uuid
import threading
from abc import ABC, abstractmethod
from flask import redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html
from threading import RLock
from collections import defaultdict


class SessionManager:
	def __init__(self):
		self.sessions = {}
		self.lock = RLock()
		self.cleanup_interval = 3600

	def create_session(self):
		session_id = str(uuid.uuid4())
		with self.lock:
			self.sessions[session_id] = {
				'id': session_id,
				'data': {},
				'created_at': asyncio.get_event_loop().time() if asyncio.get_event_loop() else 0
			}
		return session_id

	def get_session(self, session_id):
		with self.lock:
			return self.sessions.get(session_id)

	def set_session_data(self, session_id, key, value):
		with self.lock:
			if session_id in self.sessions:
				self.sessions[session_id]['data'][key] = value

	def get_session_data(self, session_id, key):
		with self.lock:
			if session_id in self.sessions:
				return self.sessions[session_id]['data'].get(key)
		return None

	def delete_session(self, session_id):
		with self.lock:
			if session_id in self.sessions:
				del self.sessions[session_id]


class StorageBackend(ABC):
	@abstractmethod
	def save_redirect_url(self, test_id, url, session_id=None):
		pass

	@abstractmethod
	def get_redirect_url(self, test_id, session_id=None):
		pass


class FileStorageBackend(StorageBackend):
	def __init__(self, storage_dir='./benchmark_storage'):
		self.storage_dir = storage_dir
		os.makedirs(storage_dir, exist_ok=True)
		self.data_file = os.path.join(storage_dir, 'redirect_urls.json')
		self.lock = RLock()
		if not os.path.exists(self.data_file):
			with open(self.data_file, 'w') as f:
				json.dump({}, f)

	def save_redirect_url(self, test_id, url, session_id=None):
		with self.lock:
			with open(self.data_file, 'r') as f:
				data = json.load(f)
			key = f"{session_id}:{test_id}" if session_id else test_id
			data[key] = url
			with open(self.data_file, 'w') as f:
				json.dump(data, f)

	def get_redirect_url(self, test_id, session_id=None):
		with self.lock:
			with open(self.data_file, 'r') as f:
				data = json.load(f)
			key = f"{session_id}:{test_id}" if session_id else test_id
			return data.get(key, None)


class DatabaseStorageBackend(StorageBackend):
	def __init__(self, db_path='./benchmark_storage/benchmark.db'):
		self.db_path = db_path
		os.makedirs(os.path.dirname(db_path), exist_ok=True)
		self.lock = RLock()
		self._init_db()

	def _init_db(self):
		conn = sqlite3.connect(self.db_path)
		cursor = conn.cursor()
		cursor.execute('''
			CREATE TABLE IF NOT EXISTS redirect_urls (
				test_id TEXT NOT NULL,
				session_id TEXT,
				url TEXT NOT NULL,
				PRIMARY KEY (test_id, session_id)
			)
		''')
		conn.commit()
		conn.close()

	def save_redirect_url(self, test_id, url, session_id=None):
		with self.lock:
			conn = sqlite3.connect(self.db_path)
			cursor = conn.cursor()
			cursor.execute('INSERT OR REPLACE INTO redirect_urls (test_id, session_id, url) VALUES (?, ?, ?)',
						   (test_id, session_id, url))
			conn.commit()
			conn.close()

	def get_redirect_url(self, test_id, session_id=None):
		with self.lock:
			conn = sqlite3.connect(self.db_path)
			cursor = conn.cursor()
			cursor.execute('SELECT url FROM redirect_urls WHERE test_id = ? AND session_id = ?', (test_id, session_id))
			result = cursor.fetchone()
			conn.close()
			return result[0] if result else None


def init(app, storage_type='file', storage_config=None):
	if storage_config is None:
		storage_config = {}

	session_manager = SessionManager()

	if storage_type == 'file':
		storage_dir = storage_config.get('storage_dir', './benchmark_storage')
		storage = FileStorageBackend(storage_dir)
	elif storage_type == 'database':
		db_path = storage_config.get('db_path', './benchmark_storage/benchmark.db')
		storage = DatabaseStorageBackend(db_path)
	else:
		raise ValueError(f"Unknown storage type: {storage_type}")

	def get_or_create_session():
		session_id = session.get('benchmark_session_id')
		if not session_id:
			session_id = session_manager.create_session()
			session['benchmark_session_id'] = session_id
		return session_id

	@app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['GET'])
	def BenchmarkTest00067_get():
		session_id = get_or_create_session()
		response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
		response.set_cookie('BenchmarkTest00067', 'http%3A%2F%2Flocalhost%3A5000%2F',
			max_age=60*3,
			secure=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['POST'])
	def BenchmarkTest00067_post():
		session_id = get_or_create_session()
		RESPONSE = ""
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00067", "noCookieValueSupplied"))
		tmp = base64.b64encode(param.encode('utf-8'))
		bar = base64.b64decode(tmp).decode('utf-8')
		storage.save_redirect_url('BenchmarkTest00067', bar, session_id)
		return redirect(bar)

	@app.route('/benchmark/redirect-00/BenchmarkTest00067/async', methods=['GET'])
	async def BenchmarkTest00067_get_async():
		session_id = get_or_create_session()
		response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
		response.set_cookie('BenchmarkTest00067', 'http%3A%2F%2Flocalhost%3A5000%2F',
			max_age=60*3,
			secure=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/redirect-00/BenchmarkTest00067/async', methods=['POST'])
	async def BenchmarkTest00067_post_async():
		session_id = get_or_create_session()
		RESPONSE = ""
		param = await asyncio.to_thread(urllib.parse.unquote_plus, request.cookies.get("BenchmarkTest00067", "noCookieValueSupplied"))
		tmp = await asyncio.to_thread(base64.b64encode, param.encode('utf-8'))
		bar = await asyncio.to_thread(base64.b64decode, tmp)
		bar = bar.decode('utf-8')
		await asyncio.to_thread(storage.save_redirect_url, 'BenchmarkTest00067_async', bar, session_id)
		return redirect(bar)

	def sync_wrapper(func):
		def wrapper(*args, **kwargs):
			return func(*args, **kwargs)
		return wrapper

	def async_wrapper(func):
		def wrapper(*args, **kwargs):
			try:
				loop = asyncio.get_event_loop()
			except RuntimeError:
				loop = asyncio.new_event_loop()
				asyncio.set_event_loop(loop)
			return loop.run_until_complete(func(*args, **kwargs))
		return wrapper

	@app.route('/benchmark/redirect-00/BenchmarkTest00067/hybrid', methods=['GET'])
	def BenchmarkTest00067_get_hybrid():
		session_id = get_or_create_session()
		response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
		response.set_cookie('BenchmarkTest00067', 'http%3A%2F%2Flocalhost%3A5000%2F',
			max_age=60*3,
			secure=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/redirect-00/BenchmarkTest00067/hybrid', methods=['POST'])
	def BenchmarkTest00067_post_hybrid():
		session_id = get_or_create_session()
		RESPONSE = ""
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00067", "noCookieValueSupplied"))
		tmp = base64.b64encode(param.encode('utf-8'))
		bar = base64.b64decode(tmp).decode('utf-8')
		storage.save_redirect_url('BenchmarkTest00067_hybrid', bar, session_id)
		return redirect(bar)

	@app.route('/benchmark/redirect-00/BenchmarkTest00067/retrieve', methods=['GET'])
	def BenchmarkTest00067_retrieve():
		session_id = get_or_create_session()
		test_id = request.args.get('test_id', 'BenchmarkTest00067')
		url = storage.get_redirect_url(test_id, session_id)
		if url:
			return {'test_id': test_id, 'url': url, 'session_id': session_id}
		return {'error': 'URL not found'}, 404

	@app.route('/benchmark/session/info', methods=['GET'])
	def get_session_info():
		session_id = get_or_create_session()
		session_data = session_manager.get_session(session_id)
		if session_data:
			return {'session_id': session_id, 'data': session_data['data']}
		return {'error': 'Session not found'}, 404

	@app.route('/benchmark/session/clear', methods=['POST'])
	def clear_session():
		session_id = session.get('benchmark_session_id')
		if session_id:
			session_manager.delete_session(session_id)
			session.clear()
			return {'message': 'Session cleared'}
		return {'error': 'No session to clear'}, 404