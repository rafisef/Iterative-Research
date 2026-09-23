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
from abc import ABC, abstractmethod
from datetime import datetime
from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import helpers.utils

_config_cache = None
_storage_handler = None

class StorageHandler(ABC):
	@abstractmethod
	def store_hash(self, hash_value):
		pass
	
	@abstractmethod
	def retrieve_hashes(self):
		pass
	
	@abstractmethod
	def delete_hash(self, hash_id):
		pass
	
	@abstractmethod
	def get_hash_count(self):
		pass

class FileStorageHandler(StorageHandler):
	def __init__(self, file_path):
		self.file_path = file_path
		self._ensure_directory_exists()
	
	def _ensure_directory_exists(self):
		directory = os.path.dirname(self.file_path)
		if directory and not os.path.exists(directory):
			os.makedirs(directory, exist_ok=True)
	
	def store_hash(self, hash_value):
		timestamp = datetime.now().isoformat()
		with open(self.file_path, 'a') as f:
			f.write(f'{{"hash_value": "{hash_value}", "timestamp": "{timestamp}"}}\n')
	
	def retrieve_hashes(self):
		hashes = []
		if os.path.exists(self.file_path):
			with open(self.file_path, 'r') as f:
				for line_num, line in enumerate(f, 1):
					try:
						data = json.loads(line.strip())
						data['id'] = line_num
						hashes.append(data)
					except json.JSONDecodeError:
						pass
		return hashes
	
	def delete_hash(self, hash_id):
		if not os.path.exists(self.file_path):
			return False
		
		hashes = self.retrieve_hashes()
		if hash_id < 1 or hash_id > len(hashes):
			return False
		
		with open(self.file_path, 'w') as f:
			for idx, hash_entry in enumerate(hashes, 1):
				if idx != hash_id:
					f.write(f'{{"hash_value": "{hash_entry["hash_value"]}", "timestamp": "{hash_entry["timestamp"]}"}}\n')
		return True
	
	def get_hash_count(self):
		if not os.path.exists(self.file_path):
			return 0
		with open(self.file_path, 'r') as f:
			return sum(1 for line in f if line.strip())

class DatabaseStorageHandler(StorageHandler):
	def __init__(self, db_path):
		self.db_path = db_path
		self._init_db()
	
	def _init_db(self):
		conn = sqlite3.connect(self.db_path)
		cursor = conn.cursor()
		cursor.execute('''
			CREATE TABLE IF NOT EXISTS hashes (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				hash_value TEXT NOT NULL,
				timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
			)
		''')
		conn.commit()
		conn.close()
	
	def store_hash(self, hash_value):
		conn = sqlite3.connect(self.db_path)
		cursor = conn.cursor()
		cursor.execute('INSERT INTO hashes (hash_value) VALUES (?)', (hash_value,))
		conn.commit()
		conn.close()
	
	def retrieve_hashes(self):
		conn = sqlite3.connect(self.db_path)
		conn.row_factory = sqlite3.Row
		cursor = conn.cursor()
		cursor.execute('SELECT id, hash_value, timestamp FROM hashes ORDER BY id DESC')
		hashes = [dict(row) for row in cursor.fetchall()]
		conn.close()
		return hashes
	
	def delete_hash(self, hash_id):
		conn = sqlite3.connect(self.db_path)
		cursor = conn.cursor()
		cursor.execute('DELETE FROM hashes WHERE id = ?', (hash_id,))
		affected_rows = cursor.rowcount
		conn.commit()
		conn.close()
		return affected_rows > 0
	
	def get_hash_count(self):
		conn = sqlite3.connect(self.db_path)
		cursor = conn.cursor()
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

def init(app):
	global _config_cache, _storage_handler
	_config_cache = _load_config()
	config = _config_cache
	_storage_handler = _get_storage_handler(config)

	@app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
	def BenchmarkTest00054_get():
		response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
		response.set_cookie('BenchmarkTest00054', 'someSecret',
			max_age=config['cookie_max_age'],
			secure=config['cookie_secure'],
			path=request.path,
			domain=config['cookie_domain'])
		return response

	@app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
	def BenchmarkTest00054_post():
		return _process_benchmark(config, is_async=False)

	@app.route('/benchmark/hash-00/BenchmarkTest00054/async', methods=['POST'])
	async def BenchmarkTest00054_post_async():
		return await _process_benchmark(config, is_async=True)

	@app.route('/benchmark/hash-00/BenchmarkTest00054/hashes', methods=['GET'])
	def get_hashes():
		hashes = _storage_handler.retrieve_hashes()
		count = _storage_handler.get_hash_count()
		return {
			'hashes': hashes,
			'count': count,
			'storage_type': config['storage_type']
		}

	@app.route('/benchmark/hash-00/BenchmarkTest00054/hashes/<int:hash_id>', methods=['DELETE'])
	def delete_hash(hash_id):
		success = _storage_handler.delete_hash(hash_id)
		return {'success': success, 'message': 'Hash deleted' if success else 'Hash not found'}

	def _process_benchmark(config, is_async=False):
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
		_storage_handler.store_hash(hash_b64)
		
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
	
	config['cookie_max_age'] = int(os.getenv('BENCHMARK_COOKIE_MAX_AGE', config['cookie_max_age']))
	config['cookie_secure'] = os.getenv('BENCHMARK_COOKIE_SECURE', str(config['cookie_secure'])).lower() == 'true'
	config['cookie_domain'] = os.getenv('BENCHMARK_COOKIE_DOMAIN', config['cookie_domain'])
	config['hash_algorithm'] = os.getenv('BENCHMARK_HASH_ALGORITHM', config['hash_algorithm'])
	config['storage_type'] = os.getenv('BENCHMARK_STORAGE_TYPE', config['storage_type'])
	config['file_path'] = os.getenv('BENCHMARK_FILE_PATH', config['file_path'])
	config['database_path'] = os.getenv('BENCHMARK_DATABASE_PATH', config['database_path'])
	
	return config