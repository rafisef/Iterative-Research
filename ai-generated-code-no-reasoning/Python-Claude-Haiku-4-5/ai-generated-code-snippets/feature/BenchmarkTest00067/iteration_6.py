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
import time
from abc import ABC, abstractmethod
from flask import redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html
from threading import RLock, Thread
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor


class Config:
	def __init__(self, env_override=None):
		if env_override is None:
			env_override = {}
		
		self.storage_type = env_override.get('storage_type') or os.getenv('BENCHMARK_STORAGE_TYPE', 'file')
		self.storage_dir = env_override.get('storage_dir') or os.getenv('BENCHMARK_STORAGE_DIR', './benchmark_storage')
		self.db_path = env_override.get('db_path') or os.getenv('BENCHMARK_DB_PATH', './benchmark_storage/benchmark.db')
		self.session_cleanup_interval = env_override.get('session_cleanup_interval') or int(os.getenv('BENCHMARK_SESSION_CLEANUP_INTERVAL', '3600'))
		self.cookie_max_age = env_override.get('cookie_max_age') or int(os.getenv('BENCHMARK_COOKIE_MAX_AGE', '180'))
		self.cookie_secure = env_override.get('cookie_secure') if env_override.get('cookie_secure') is not None else os.getenv('BENCHMARK_COOKIE_SECURE', 'True').lower() == 'true'
		self.cookie_domain = env_override.get('cookie_domain') or os.getenv('BENCHMARK_COOKIE_DOMAIN', 'localhost')
		self.log_level = env_override.get('log_level') or os.getenv('BENCHMARK_LOG_LEVEL', 'INFO')
		self.debug_mode = env_override.get('debug_mode') if env_override.get('debug_mode') is not None else os.getenv('BENCHMARK_DEBUG_MODE', 'False').lower() == 'true'
		self.max_concurrent_sessions = env_override.get('max_concurrent_sessions') or int(os.getenv('BENCHMARK_MAX_CONCURRENT_SESSIONS', '1000'))
		self.session_timeout = env_override.get('session_timeout') or int(os.getenv('BENCHMARK_SESSION_TIMEOUT', '1800'))

	def to_dict(self):
		return {
			'storage_type': self.storage_type,
			'storage_dir': self.storage_dir,
			'db_path': self.db_path,
			'session_cleanup_interval': self.session_cleanup_interval,
			'cookie_max_age': self.cookie_max_age,
			'cookie_secure': self.cookie_secure,
			'cookie_domain': self.cookie_domain,
			'log_level': self.log_level,
			'debug_mode': self.debug_mode,
			'max_concurrent_sessions': self.max_concurrent_sessions,
			'session_timeout': self.session_timeout
		}


class SessionManager:
	def __init__(self, cleanup_interval=3600, session_timeout=1800, max_sessions=1000):
		self.sessions = {}
		self.lock = RLock()
		self.cleanup_interval = cleanup_interval
		self.session_timeout = session_timeout
		self.max_sessions = max_sessions
		self.cleanup_thread = None
		self.running = False
		self._start_cleanup_thread()

	def _start_cleanup_thread(self):
		self.running = True
		self.cleanup_thread = Thread(target=self._cleanup_expired_sessions, daemon=True)
		self.cleanup_thread.start()

	def _cleanup_expired_sessions(self):
		while self.running:
			time.sleep(self.cleanup_interval)
			current_time = time.time()
			with self.lock:
				expired_sessions = [
					sid for sid, data in self.sessions.items()
					if current_time - data['last_activity'] > self.session_timeout
				]
				for sid in expired_sessions:
					del self.sessions[sid]

	def create_session(self):
		session_id = str(uuid.uuid4())
		current_time = time.time()
		with self.lock:
			if len(self.sessions) >= self.max_sessions:
				oldest_session = min(self.sessions.items(), key=lambda x: x[1]['last_activity'])
				del self.sessions[oldest_session[0]]
			
			self.sessions[session_id] = {
				'id': session_id,
				'data': {},
				'created_at': current_time,
				'last_activity': current_time,
				'thread_id': threading.get_ident()
			}
		return session_id

	def get_session(self, session_id):
		with self.lock:
			if session_id in self.sessions:
				self.sessions[session_id]['last_activity'] = time.time()
				return self.sessions[session_id]
		return None

	def set_session_data(self, session_id, key, value):
		with self.lock:
			if session_id in self.sessions:
				self.sessions[session_id]['data'][key] = value
				self.sessions[session_id]['last_activity'] = time.time()

	def get_session_data(self, session_id, key):
		with self.lock:
			if session_id in self.sessions:
				self.sessions[session_id]['last_activity'] = time.time()
				return self.sessions[session_id]['data'].get(key)
		return None

	def delete_session(self, session_id):
		with self.lock:
			if session_id in self.sessions:
				del self.sessions[session_id]

	def get_active_sessions_count(self):
		with self.lock:
			return len(self.sessions)

	def stop_cleanup(self):
		self.running = False
		if self.cleanup_thread:
			self.cleanup_thread.join(timeout=5)


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
		self.executor = ThreadPoolExecutor(max_workers=5)
		if not os.path.exists(self.data_file):
			with open(self.data_file, 'w') as f:
				json.dump({}, f)

	def save_redirect_url(self, test_id, url, session_id=None):
		def _save():
			with self.lock:
				with open(self.data_file, 'r') as f:
					data = json.load(f)
				key = f"{session_id}:{test_id}" if session_id else test_id
				data[key] = url
				with open(self.data_file, 'w') as f:
					json.dump(data, f)
		return self.executor.submit(_save)

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
		self.executor = ThreadPoolExecutor(max_workers=10)
		self._init_db()

	def _init_db(self):
		conn = sqlite3.connect(self.db_path, check_same_thread=False)
		cursor = conn.cursor()
		cursor.execute('''
			CREATE TABLE IF NOT EXISTS redirect_urls (
				test_id TEXT NOT NULL,
				session_id TEXT,
				url TEXT NOT NULL,
				created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
				PRIMARY KEY (test_id, session_id)
			)
		''')
		conn.commit()
		conn.close()

	def save_redirect_url(self, test_id, url, session_id=None):
		def _save():
			with self.lock:
				conn = sqlite3.connect(self.db_path, check_same_thread=False)
				cursor = conn.cursor()
				cursor.execute('INSERT OR REPLACE INTO redirect_urls (test_id, session_id, url) VALUES (?, ?, ?)',
							   (test_id, session_id, url))
				conn.commit()
				conn.close()
		return self.executor.submit(_save)

	def get_redirect_url(self, test_id, session_id=None):
		with self.lock:
			conn = sqlite3.connect(self.db_path, check_same_thread=False)
			cursor = conn.cursor()
			cursor.execute('SELECT url FROM redirect_urls WHERE test_id = ? AND session_id = ?', (test_id, session_id))
			result = cursor.fetchone()
			conn.close()
			return result[0] if result else None


def init(app, storage_type=None, storage_config=None, env_override=None):
	if storage_config is None:
		storage_config = {}
	if env_override is None:
		env_override = {}

	config = Config(env_override=env_override)

	if storage_type is None:
		storage_type = config.storage_type

	if not storage_config:
		storage_config = {
			'storage_dir': config.storage_dir,
			'db_path': config.db_path
		}
	else:
		if 'storage_dir' not in storage_config:
			storage_config['storage_dir'] = config.storage_dir
		if 'db_path' not in storage_config:
			storage_config['db_path'] = config.db_path

	session_manager = SessionManager(
		cleanup_interval=config.session_cleanup_interval,
		session_timeout=config.session_timeout,
		max_sessions=config.max_concurrent_sessions
	)

	if storage_type == 'file':
		storage_dir = storage_config.get('storage_dir', config.storage_dir)
		storage = FileStorageBackend(storage_dir)
	elif storage_type == 'database':
		db_path = storage_config.get('db_path', config.db_path)
		storage = DatabaseStorageBackend(db_path)
	else:
		raise ValueError(f"Unknown storage type: {storage_type}")

	def get_or_create_session():
		session_id = session.get('benchmark_session_id')
		if not session_id:
			session_id = session_manager.create_session()
			session['benchmark_session_id'] = session_id
		else:
			session_manager.get_session(session_id)
		return session_id

	@app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['GET'])
	def BenchmarkTest00067_get():
		session_id = get_or_create_session()
		response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
		response.set_cookie('BenchmarkTest00067', 'http%3A%2F%2Flocalhost%3A5000%2F',
			max_age=config.cookie_max_age,
			secure=config.cookie_secure,
			path=request.path,
			domain=config.cookie_domain)
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
			max_age=config.cookie_max_age,
			secure=config.cookie_secure,
			path=request.path,
			domain=config.cookie_domain)
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
			max_age=config.cookie_max_age,
			secure=config.cookie_secure,
			path=request.path,
			domain=config.cookie_domain)
		return response

	@app.route('/benchmark/redirect-00/Benchmark