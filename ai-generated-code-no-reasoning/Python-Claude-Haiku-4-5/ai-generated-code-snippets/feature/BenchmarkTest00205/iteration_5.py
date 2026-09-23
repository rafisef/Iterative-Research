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
import json
import time
import sqlite3
import pickle
from concurrent.futures import ThreadPoolExecutor
from collections import OrderedDict
from abc import ABC, abstractmethod
from contextlib import contextmanager

_session_lock = threading.RLock()
_sessions = OrderedDict()
_session_cleanup_lock = threading.RLock()
_session_access_times = {}
_executor = ThreadPoolExecutor(max_workers=10)
_cleanup_thread = None
_storage_backend = None


class StorageBackend(ABC):
	@abstractmethod
	def get_session(self, session_id):
		pass
	
	@abstractmethod
	def set_session(self, session_id, session_data):
		pass
	
	@abstractmethod
	def delete_session(self, session_id):
		pass
	
	@abstractmethod
	def session_exists(self, session_id):
		pass
	
	@abstractmethod
	def get_all_session_ids(self):
		pass
	
	@abstractmethod
	def update_access_time(self, session_id, access_time):
		pass
	
	@abstractmethod
	def get_access_time(self, session_id):
		pass


class FileStorageBackend(StorageBackend):
	def __init__(self, storage_dir='./sessions'):
		self.storage_dir = storage_dir
		os.makedirs(storage_dir, exist_ok=True)
		self.lock = threading.RLock()
	
	def _get_session_path(self, session_id):
		return os.path.join(self.storage_dir, f"{session_id}.json")
	
	def _get_metadata_path(self, session_id):
		return os.path.join(self.storage_dir, f"{session_id}_meta.json")
	
	def get_session(self, session_id):
		with self.lock:
			try:
				path = self._get_session_path(session_id)
				if os.path.exists(path):
					with open(path, 'r') as f:
						data = json.load(f)
						return {
							'data': data,
							'lock': threading.RLock(),
							'created_at': data.get('_created_at', time.time())
						}
			except (FileNotFoundError, json.JSONDecodeError):
				pass
		return None
	
	def set_session(self, session_id, session_data):
		with self.lock:
			try:
				path = self._get_session_path(session_id)
				data_to_save = session_data['data'].copy()
				data_to_save['_created_at'] = session_data['created_at']
				with open(path, 'w') as f:
					json.dump(data_to_save, f)
			except Exception:
				pass
	
	def delete_session(self, session_id):
		with self.lock:
			try:
				path = self._get_session_path(session_id)
				meta_path = self._get_metadata_path(session_id)
				if os.path.exists(path):
					os.remove(path)
				if os.path.exists(meta_path):
					os.remove(meta_path)
			except Exception:
				pass
	
	def session_exists(self, session_id):
		with self.lock:
			return os.path.exists(self._get_session_path(session_id))
	
	def get_all_session_ids(self):
		with self.lock:
			try:
				files = os.listdir(self.storage_dir)
				return [f.replace('.json', '') for f in files if f.endswith('.json') and not f.endswith('_meta.json')]
			except Exception:
				return []
	
	def update_access_time(self, session_id, access_time):
		with self.lock:
			try:
				meta_path = self._get_metadata_path(session_id)
				with open(meta_path, 'w') as f:
					json.dump({'access_time': access_time}, f)
			except Exception:
				pass
	
	def get_access_time(self, session_id):
		with self.lock:
			try:
				meta_path = self._get_metadata_path(session_id)
				if os.path.exists(meta_path):
					with open(meta_path, 'r') as f:
						data = json.load(f)
						return data.get('access_time', time.time())
			except Exception:
				pass
		return time.time()


class DatabaseStorageBackend(StorageBackend):
	def __init__(self, db_path='./benchmark_sessions.db'):
		self.db_path = db_path
		self.lock = threading.RLock()
		self._init_db()
	
	def _init_db(self):
		with self.lock:
			try:
				conn = sqlite3.connect(self.db_path)
				cursor = conn.cursor()
				cursor.execute('''
					CREATE TABLE IF NOT EXISTS sessions (
						session_id TEXT PRIMARY KEY,
						session_data TEXT NOT NULL,
						created_at REAL NOT NULL,
						access_time REAL NOT NULL
					)
				''')
				conn.commit()
				conn.close()
			except Exception:
				pass
	
	@contextmanager
	def _get_connection(self):
		conn = sqlite3.connect(self.db_path)
		try:
			yield conn
		finally:
			conn.close()
	
	def get_session(self, session_id):
		with self.lock:
			try:
				with self._get_connection() as conn:
					cursor = conn.cursor()
					cursor.execute('SELECT session_data, created_at FROM sessions WHERE session_id = ?', (session_id,))
					row = cursor.fetchone()
					if row:
						data = json.loads(row[0])
						return {
							'data': data,
							'lock': threading.RLock(),
							'created_at': row[1]
						}
			except Exception:
				pass
		return None
	
	def set_session(self, session_id, session_data):
		with self.lock:
			try:
				with self._get_connection() as conn:
					cursor = conn.cursor()
					data_json = json.dumps(session_data['data'])
					cursor.execute('''
						INSERT OR REPLACE INTO sessions (session_id, session_data, created_at, access_time)
						VALUES (?, ?, ?, ?)
					''', (session_id, data_json, session_data['created_at'], time.time()))
					conn.commit()
			except Exception:
				pass
	
	def delete_session(self, session_id):
		with self.lock:
			try:
				with self._get_connection() as conn:
					cursor = conn.cursor()
					cursor.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
					conn.commit()
			except Exception:
				pass
	
	def session_exists(self, session_id):
		with self.lock:
			try:
				with self._get_connection() as conn:
					cursor = conn.cursor()
					cursor.execute('SELECT 1 FROM sessions WHERE session_id = ?', (session_id,))
					return cursor.fetchone() is not None
			except Exception:
				return False
	
	def get_all_session_ids(self):
		with self.lock:
			try:
				with self._get_connection() as conn:
					cursor = conn.cursor()
					cursor.execute('SELECT session_id FROM sessions')
					return [row[0] for row in cursor.fetchall()]
			except Exception:
				return []
	
	def update_access_time(self, session_id, access_time):
		with self.lock:
			try:
				with self._get_connection() as conn:
					cursor = conn.cursor()
					cursor.execute('UPDATE sessions SET access_time = ? WHERE session_id = ?', (access_time, session_id))
					conn.commit()
			except Exception:
				pass
	
	def get_access_time(self, session_id):
		with self.lock:
			try:
				with self._get_connection() as conn:
					cursor = conn.cursor()
					cursor.execute('SELECT access_time FROM sessions WHERE session_id = ?', (session_id,))
					row = cursor.fetchone()
					if row:
						return row[0]
			except Exception:
				pass
		return time.time()


def _load_config_from_file(config_file):
	try:
		with open(config_file, 'r') as f:
			return json.load(f)
	except (FileNotFoundError, json.JSONDecodeError):
		return {}

def _parse_env_value(value):
	if isinstance(value, str):
		if value.lower() == 'true':
			return True
		elif value.lower() == 'false':
			return False
		elif value.isdigit():
			return int(value)
	return value

def _initialize_config():
	config = {}
	
	config_file = os.getenv('BENCHMARK_CONFIG_FILE')
	if config_file:
		config.update(_load_config_from_file(config_file))
	
	env_config = {
		'SESSION_TYPE': os.getenv('BENCHMARK_SESSION_TYPE'),
		'SESSION_TIMEOUT': os.getenv('BENCHMARK_SESSION_TIMEOUT'),
		'ENABLE_XXE_PARSING': os.getenv('BENCHMARK_ENABLE_XXE_PARSING'),
		'LOG_RESPONSES': os.getenv('BENCHMARK_LOG_RESPONSES'),
		'PARSER_EXTERNAL_GES': os.getenv('BENCHMARK_PARSER_EXTERNAL_GES'),
		'MAX_CONCURRENT_SESSIONS': os.getenv('BENCHMARK_MAX_CONCURRENT_SESSIONS'),
		'SESSION_CLEANUP_INTERVAL': os.getenv('BENCHMARK_SESSION_CLEANUP_INTERVAL'),
		'STORAGE_TYPE': os.getenv('BENCHMARK_STORAGE_TYPE'),
		'STORAGE_PATH': os.getenv('BENCHMARK_STORAGE_PATH'),
	}
	
	for key, value in env_config.items():
		if value is not None:
			config[key] = _parse_env_value(value)
	
	defaults = {
		'SESSION_TYPE': 'filesystem',
		'SESSION_TIMEOUT': 3600,
		'ENABLE_XXE_PARSING': True,
		'LOG_RESPONSES': False,
		'PARSER_EXTERNAL_GES': True,
		'MAX_CONCURRENT_SESSIONS': 1000,
		'SESSION_CLEANUP_INTERVAL': 300,
		'STORAGE_TYPE': 'file',
		'STORAGE_PATH': './sessions',
	}
	
	for key, default_value in defaults.items():
		if key not in config:
			config[key] = default_value
	
	return config

_config = _initialize_config()

def get_config(key, default=None):
	return _config.get(key, default)

def set_config(key, value):
	_config[key] = value

def reload_config():
	global _config
	_config = _initialize_config()

def _initialize_storage_backend():
	global _storage_backend
	storage_type = get_config('STORAGE_TYPE', 'file').lower()
	storage_path = get_config('STORAGE_PATH', './sessions')
	
	if storage_type == 'database' or storage_type == 'db':
		_storage_backend = DatabaseStorageBackend(storage_path)
	else:
		_storage_backend = FileStorageBackend(storage_path)

def _cleanup_expired_sessions():
	global _cleanup_thread
	while True:
		try:
			time.sleep(get_config('SESSION_CLEANUP_INTERVAL'))
			current_time = time.time()
			session_timeout = get_config('SESSION_TIMEOUT')
			
			with _session_cleanup_lock:
				session_ids = _storage_backend.get_all_session_ids()
				for session_id in session_ids:
					access_time = _storage_backend.get_access_time(session_id)
					if current_time - access_time > session_timeout:
						_storage_backend.delete_session(session_id)
						with _session_lock:
							if session_id in _sessions:
								del _sessions[session_id]
							if session_id in _session_access_times:
								del _session_access_times[session_id]
		except Exception:
			pass

def _start_cleanup_thread():
	global _cleanup_thread
	if _cleanup_thread is None or not _cleanup_thread.is_alive():
		_cleanup_thread = threading.Thread(target=_cleanup_expired_sessions, daemon=True)
		_cleanup_thread.start()

def _get_or_create_session():
	session_id = session.get('_benchmark_session_id')
	if not session_id:
		session_id = str(uuid.uuid4())
		session['_benchmark_session_id'] = session_id
	
	current_time = time.time()
	
	with _session_lock:
		if session_id not in _sessions:
			stored_session = _storage_backend.get_session(session_id)
			if stored_session:
				_sessions[session_id] = stored_session
			else:
				if len(_sessions) >= get_config('MAX_CONCURRENT_SESSIONS'):
					oldest_id = next(iter(_sessions))
					_storage_backend.delete_session(oldest_id)
					del _sessions[oldest_id]
					if oldest_id in _session_access_times:
						del _session_access_times[oldest_id]
				
				_sessions[session_id] = {
					'data': {},
					'lock': threading.RLock(),
					'created_at': current_time
				}
		
		_session_access_times[session_id] = current_time
		_storage_backend.update_access_time(session_id, current_time)
	
	return session_id, _sessions[session_id]

def _require_session(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		session_id, session_data = _get_or_create_session()
		return f(session_id=session_id, session_data=session_data, *args, **kwargs)
	return decorated_function

def init(app):
	_initialize_storage_backend()
	app.config['SESSION_TYPE'] = get_config('SESSION_TYPE')
	_start_cleanup_thread()
	
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