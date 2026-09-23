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

import os
import json
import sqlite3
from abc import ABC, abstractmethod
from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html

class StorageBackend(ABC):
	@abstractmethod
	def get(self, key):
		pass

	@abstractmethod
	def set(self, key, value):
		pass

	@abstractmethod
	def exists(self, key):
		pass

class FileStorage(StorageBackend):
	def __init__(self, storage_dir):
		self.storage_dir = storage_dir
		os.makedirs(storage_dir, exist_ok=True)

	def _get_path(self, key):
		return os.path.join(self.storage_dir, f'{key}.json')

	def get(self, key):
		path = self._get_path(key)
		if os.path.exists(path):
			try:
				with open(path, 'r') as f:
					data = json.load(f)
					return data.get('value')
			except (json.JSONDecodeError, IOError):
				return None
		return None

	def set(self, key, value):
		path = self._get_path(key)
		try:
			with open(path, 'w') as f:
				json.dump({'value': value}, f)
		except IOError:
			pass

	def exists(self, key):
		return os.path.exists(self._get_path(key))

class DatabaseStorage(StorageBackend):
	def __init__(self, db_path):
		self.db_path = db_path
		self._init_db()

	def _init_db(self):
		try:
			conn = sqlite3.connect(self.db_path)
			cursor = conn.cursor()
			cursor.execute('''
				CREATE TABLE IF NOT EXISTS storage (
					key TEXT PRIMARY KEY,
					value TEXT NOT NULL
				)
			''')
			conn.commit()
			conn.close()
		except sqlite3.Error:
			pass

	def get(self, key):
		try:
			conn = sqlite3.connect(self.db_path)
			cursor = conn.cursor()
			cursor.execute('SELECT value FROM storage WHERE key = ?', (key,))
			result = cursor.fetchone()
			conn.close()
			return result[0] if result else None
		except sqlite3.Error:
			return None

	def set(self, key, value):
		try:
			conn = sqlite3.connect(self.db_path)
			cursor = conn.cursor()
			cursor.execute(
				'INSERT OR REPLACE INTO storage (key, value) VALUES (?, ?)',
				(key, value)
			)
			conn.commit()
			conn.close()
		except sqlite3.Error:
			pass

	def exists(self, key):
		try:
			conn = sqlite3.connect(self.db_path)
			cursor = conn.cursor()
			cursor.execute('SELECT 1 FROM storage WHERE key = ?', (key,))
			result = cursor.fetchone()
			conn.close()
			return result is not None
		except sqlite3.Error:
			return False

class Config:
	def __init__(self):
		self.cookie_max_age = int(os.getenv('BENCHMARK_COOKIE_MAX_AGE', 180))
		self.cookie_secure = os.getenv('BENCHMARK_COOKIE_SECURE', 'True').lower() == 'true'
		self.cookie_domain = os.getenv('BENCHMARK_COOKIE_DOMAIN', 'localhost')
		self.cookie_path = os.getenv('BENCHMARK_COOKIE_PATH', '/benchmark/weakrand-00/BenchmarkTest00025')
		self.route_prefix = os.getenv('BENCHMARK_ROUTE_PREFIX', '/benchmark/weakrand-00')
		self.template_path = os.getenv('BENCHMARK_TEMPLATE_PATH', 'web/weakrand-00/BenchmarkTest00025.html')
		self.storage_type = os.getenv('BENCHMARK_STORAGE_TYPE', 'file').lower()
		self.storage_path = os.getenv('BENCHMARK_STORAGE_PATH', './benchmark_storage')

	def get_storage(self):
		if self.storage_type == 'database':
			db_path = os.getenv('BENCHMARK_DB_PATH', os.path.join(self.storage_path, 'benchmark.db'))
			return DatabaseStorage(db_path)
		else:
			return FileStorage(self.storage_path)

def init(app):
	config = Config()
	storage = config.get_storage()

	@app.route(f'{config.route_prefix}/BenchmarkTest00025', methods=['GET'])
	def BenchmarkTest00025_get():
		response = make_response(render_template(config.template_path))
		response.set_cookie('BenchmarkTest00025', 'whatever',
			max_age=config.cookie_max_age,
			secure=config.cookie_secure,
			path=config.cookie_path,
			domain=config.cookie_domain)
		return response

	@app.route(f'{config.route_prefix}/BenchmarkTest00025', methods=['POST'])
	def BenchmarkTest00025_post():
		RESPONSE = ""

		import urllib.parse
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00025", "noCookieValueSupplied"))

		superstring = f'90583{param}abcd'
		bar = superstring[len('90583'):len(superstring)-5]

		import random
		from helpers.utils import mysession

		num = 'BenchmarkTest00025'[13:]
		user = f'Nancy{num}'
		cookie = f'rememberMe{num}'
		value = str(random.normalvariate())[2:]

		if storage.exists(cookie) and request.cookies.get(cookie) == storage.get(cookie):
			RESPONSE += (
				f'Welcome back: {user}<br/>'
			)
		else:
			storage.set(cookie, value)
			RESPONSE += (
				f'{user} has been remembered with cookie: '
				f'{cookie} whose value is: {storage.get(cookie)}<br/>'
			)

		return RESPONSE