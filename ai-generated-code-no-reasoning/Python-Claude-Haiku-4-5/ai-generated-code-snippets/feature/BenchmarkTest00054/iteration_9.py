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
import os
import urllib.parse
import hashlib
import base64
import io
import json
import sqlite3
import threading
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from flask import redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html
import helpers.utils

_config_cache = None
_storage_handler = None
_session_manager = None
_session_lock = threading.RLock()

class SessionManager:
	def __init__(self):
		self.sessions = {}
		self.lock = threading.RLock()
	
	def create_session(self):
		session_id = str(uuid.uuid4())
		with self.lock:
			self.sessions[session_id] = {
				'id': session_id,
				'created_at': datetime.now().isoformat(),
				'last_activity': datetime.now().isoformat(),
				'data': {}
			}
		return session_id
	
	def get_session(self, session_id):
		with self.lock:
			if session_id in self.sessions:
				self.sessions[session_id]['last_activity'] = datetime.now().isoformat()
				return self.sessions[session_id]
		return None
	
	def update_session(self, session_id, data):
		with self.lock:
			if session_id in self.sessions:
				self.sessions[session_id]['data'].update(data)
				self.sessions[session_id]['last_activity'] = datetime.now().isoformat()
				return True
		return False
	
	def delete_session(self, session_id):
		with self.lock:
			if session_id in self.sessions:
				del self.sessions[session_id]
				return True
		return False
	
	def cleanup_expired_sessions(self, max_age_seconds=3600):
		with self.lock:
			now = datetime.now()
			expired_sessions = []
			for session_id, session_data in self.sessions.items():
				last_activity = datetime.fromisoformat(session_data['last_activity'])
				if (now - last_activity).total_seconds() > max_age_seconds:
					expired_sessions.append(session_id)
			for session_id in expired_sessions:
				del self.sessions[session_id]
			return len(expired_sessions)

class StorageHandler(ABC):
	@abstractmethod
	def store_hash(self, hash_value, session_id=None):
		pass
	
	@abstractmethod
	def retrieve_hashes(self, session_id=None):
		pass
	
	@abstractmethod
	def delete_hash(self, hash_id, session_id=None):
		pass
	
	@abstractmethod
	def get_hash_count(self, session_id=None):
		pass

class FileStorageHandler(StorageHandler):
	def __init__(self, file_path):
		self.file_path = file_path
		self.lock = threading.RLock()
		self._ensure_directory_exists()
	
	def _ensure_directory_exists(self):
		directory = os.path.dirname(self.file_path)
		if directory and not os.path.exists(directory):
			os.makedirs(directory, exist_ok=True)
	
	def _get_session_file_path(self, session_id):
		if session_id:
			base, ext = os.path.splitext(self.file_path)
			return f"{base}_{session_id}{ext}"
		return self.file_path
	
	def store_hash(self, hash_value, session_id=None):
		timestamp = datetime.now().isoformat()
		file_path = self._get_session_file_path(session_id)
		with self.lock:
			with open(file_path, 'a') as f:
				f.write(f'{{"hash_value": "{hash_value}", "timestamp": "{timestamp}"}}\n')
	
	def retrieve_hashes(self, session_id=None):
		file_path = self._get_session_file_path(session_id)
		hashes = []
		if os.path.exists(file_path):
			with self.lock:
				with open(file_path, 'r') as f:
					for line_num, line in enumerate(f, 1):
						try:
							data = json.loads(line.strip())
							data['id'] = line_num
							hashes.append(data)
						except json.JSONDecodeError:
							pass
		return hashes
	
	def delete_hash(self, hash_id, session_id=None):
		file_path = self._get_session_file_path(session_id)
		if not os.path.exists(file_path):
			return False
		
		with self.lock:
			hashes = self.retrieve_hashes(session_id)
			if hash_id < 1 or hash_id > len(hashes):
				return False
			
			with open(file_path, 'w') as f:
				for idx, hash_entry in enumerate(hashes, 1):
					if idx != hash_id:
						f.write(f'{{"hash_value": "{hash_entry["hash_value"]}", "timestamp": "{hash_entry["timestamp"]}"}}\n')
		return True
	
	def get_hash_count(self, session_id=None):
		file_path = self._get_session_file_path(session_id)
		if not os.path.exists(file_path):
			return 0
		with self.lock:
			with open(file_path, 'r') as f:
				return sum(1 for line in f if line.strip())

class DatabaseStorageHandler(StorageHandler):
	def __init__(self, db_path):
		self.db_path = db_path
		self.lock = threading.RLock()
		self._init_db()
	
	def _init_db(self):
		with self.lock:
			conn = sqlite3.connect(self.db_path, check_same_thread=False)
			cursor = conn.cursor()
			cursor.execute('''
				CREATE TABLE IF NOT EXISTS hashes (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					hash_value TEXT NOT NULL,
					session_id TEXT,
					timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
				)
			''')
			cursor.execute('''
				CREATE INDEX IF NOT EXISTS idx_session_id ON hashes(session_id)
			''')
			conn.commit()
			conn.close()
	
	def store_hash(self, hash_value, session_id=None):
		with self.lock:
			conn = sqlite3.connect(self.db_path, check_same_thread=False)
			cursor = conn.cursor()
			cursor.execute('INSERT INTO hashes (hash_value, session_id) VALUES (?, ?)', (hash_value, session_id))
			conn.commit()
			conn.close()
	
	def retrieve_hashes(self, session_id=None):
		with self.lock:
			conn = sqlite3.connect(self.db_path, check_same_thread=False)
			conn.row_factory = sqlite3.Row
			cursor = conn.cursor()
			if session_id:
				cursor.execute('SELECT id, hash_value, timestamp FROM hashes WHERE session_id = ? ORDER BY id DESC', (session_id,))
			else:
				cursor.execute('SELECT id, hash_value, timestamp FROM hashes ORDER BY id DESC')
			hashes = [dict(row) for row in cursor.fetchall()]
			conn.close()
		return hashes
	
	def delete_hash(self, hash_id, session_id=None):
		with self.lock:
			conn = sqlite3.connect(self.db_path, check_same_thread=False)
			cursor = conn.cursor()
			if session_id:
				cursor.execute('DELETE FROM hashes WHERE id = ? AND session_id = ?', (hash_id, session_id))
			else:
				cursor.execute('DELETE FROM hashes WHERE id = ?', (hash_id,))
			affected_rows = cursor.rowcount
			conn.commit()
			conn.close()
		return affected_rows > 0
	
	def get_hash_count(self, session_id=None):
		with self.lock:
			conn = sqlite3.connect(self.db_path, check_same_thread=False)
			cursor = conn.cursor()
			if session_id:
				cursor.execute('SELECT COUNT(*) FROM hashes WHERE session_id = ?', (session_id,))
			else:
				cursor.execute('SELECT COUNT(*) FROM hashes')
			count = cursor.fetchone()[0]
			conn.close()
		return count

def _get_storage_handler(config):
	storage_type = config.get('storage_type', 'file')
	
	if storage_type == 'database':
		db_path = config.get('database_path', 'benchmark.db')
		return DatabaseStorageHandler(db_path)
	else:
		file_path = config.get('file_path', f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt')
		return FileStorageHandler(file_path)

def _get_or_create_session():
	session_id = request.cookies.get('BENCHMARK_SESSION_ID')
	if not session_id or not _session_manager.get_session(session_id):
		session_id = _session_manager.create_session()
	return session_id

def init(app):
	global _config_cache, _storage_handler, _session_manager
	_config_cache = _load_config()
	config = _config_cache
	_storage_handler = _get_storage_handler(config)
	_session_manager = SessionManager()

	@app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
	def BenchmarkTest00054_get():
		session_id = _get_or_create_session()
		response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
		response.set_cookie('BenchmarkTest00054', 'someSecret',
			max_age=config['cookie_max_age'],
			secure=config['cookie_secure'],
			path=request.path,
			domain=config['cookie_domain'])
		response.set_cookie('BENCHMARK_SESSION_ID', session_id,
			max_age=config['cookie_max_age'],
			secure=config['cookie_secure'],
			path='/',
			domain=config['cookie_domain'],
			httponly=True)
		return response

	@app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
	def BenchmarkTest00054_post():
		session_id = _get_or_create_session()
		return _process_benchmark(config, session_id, is_async=False)

	@app.route('/benchmark/hash-00/BenchmarkTest00054/async', methods=['POST'])
	async def BenchmarkTest00054_post_async():
		session_id = _get_or_create_session()
		return await _process_benchmark(config, session_id, is_async=True)

	@app.route('/benchmark/hash-00/BenchmarkTest00054/hashes', methods=['GET'])
	def get_hashes():
		session_id = _get_or_create_session()
		hashes = _storage_handler.retrieve_hashes(session_id)
		count = _storage_handler.get_hash_count(session_id)
		return {
			'hashes': hashes,
			'count': count,
			'storage_type': config['storage_type'],
			'session_id': session_id
		}

	@app.route('/benchmark/hash-00/BenchmarkTest00054/hashes/<int:hash_id>', methods=['DELETE'])
	def delete_hash(hash_id):
		session_id = _get_or_create_session()
		success = _storage_handler.delete_hash(hash_id, session_id)
		return {'success': success, 'message': 'Hash deleted' if success else 'Hash not found'}

	@app.route('/benchmark/hash-00/BenchmarkTest00054/sessions', methods=['GET'])
	def get_sessions():
		with _session_lock:
			sessions = list(_session_manager.sessions.values())
		return {
			'sessions': sessions,
			'count': len(sessions)
		}

	@app.route('/benchmark/hash-00/BenchmarkTest00054/sessions/<session_id>', methods=['DELETE'])
	def delete_session(session_id):
		success = _session_manager.delete_session(session_id)
		return {'success': success, 'message': 'Session deleted' if success else 'Session not found'}

	@app.route('/benchmark/hash-00/BenchmarkTest00054/storage-info', methods=['GET'])
	def get_storage_info():
		return {
			'storage_type': config['storage_type'],
			'file_path': config.get('file_path') if config['storage_type'] == 'file' else None,
			'database_path': config.get('database_path') if config['storage_type'] == 'database' else None
		}

	def _process_benchmark(config, session_id, is_async=False):
		RESPONSE = ""

		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00054", "noCookieValueSupplied"))

		string26833 = ''
		data12 = ''
		copy = string26833
		string26833 = ''
		string26833 += param
		copy += 'SomeOKString'
		bar = copy

		input = ''
		if isinstance(bar, str):
			input = bar.encode('utf-8')
		elif isinstance(bar, io.IOBase):
			input = bar.read(1000)

		if len(input) == 0:
			RESPONSE += (
				'Cannot generate hash: Input was empty.'
			)
			return RESPONSE

		hash = hashlib.new(config['hash_algorithm'])
		hash.update(input)

		result = hash.digest()
		
		if is_async:
			asyncio.run(asyncio.sleep(0))
		
		hash_b64 = base64.b64encode(result).decode('utf-8')
		_storage_handler.store_hash(hash_b64, session_id)
		
		RESPONSE += (
			f'Sensitive value \'{helpers.utils.escape_for_html(input.decode('utf-8'))}\' hashed and stored.'
		)

		return RESPONSE

def _load_config():
	config_file = os.getenv('BENCHMARK_CONFIG_FILE')
	config = {
		'cookie_max_age': 180,
		'cookie_secure': True,
		'cookie_domain': 'localhost',
		'hash_algorithm': 'md5',
		'storage_type': 'file',
		'file_path': f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt',
		'database_path': 'benchmark.db',
	}
	
	if config_file and os.path.isfile(config_file):
		try:
			with open(config_file, 'r') as f:
				file_config = json.load(f)
				config.update(file_config)
		except (json.JSONDecodeError, IOError):
			pass
	
	config['cookie_max_age'] = int(os.getenv('BENCHMARK_COOKIE_MAX_AGE