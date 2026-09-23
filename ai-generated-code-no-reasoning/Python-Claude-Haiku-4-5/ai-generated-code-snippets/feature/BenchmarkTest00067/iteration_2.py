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
from abc import ABC, abstractmethod
from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html


class StorageBackend(ABC):
	@abstractmethod
	def save_redirect_url(self, test_id, url):
		pass

	@abstractmethod
	def get_redirect_url(self, test_id):
		pass


class FileStorageBackend(StorageBackend):
	def __init__(self, storage_dir='./benchmark_storage'):
		self.storage_dir = storage_dir
		os.makedirs(storage_dir, exist_ok=True)
		self.data_file = os.path.join(storage_dir, 'redirect_urls.json')
		if not os.path.exists(self.data_file):
			with open(self.data_file, 'w') as f:
				json.dump({}, f)

	def save_redirect_url(self, test_id, url):
		with open(self.data_file, 'r') as f:
			data = json.load(f)
		data[test_id] = url
		with open(self.data_file, 'w') as f:
			json.dump(data, f)

	def get_redirect_url(self, test_id):
		with open(self.data_file, 'r') as f:
			data = json.load(f)
		return data.get(test_id, None)


class DatabaseStorageBackend(StorageBackend):
	def __init__(self, db_path='./benchmark_storage/benchmark.db'):
		self.db_path = db_path
		os.makedirs(os.path.dirname(db_path), exist_ok=True)
		self._init_db()

	def _init_db(self):
		conn = sqlite3.connect(self.db_path)
		cursor = conn.cursor()
		cursor.execute('''
			CREATE TABLE IF NOT EXISTS redirect_urls (
				test_id TEXT PRIMARY KEY,
				url TEXT NOT NULL
			)
		''')
		conn.commit()
		conn.close()

	def save_redirect_url(self, test_id, url):
		conn = sqlite3.connect(self.db_path)
		cursor = conn.cursor()
		cursor.execute('INSERT OR REPLACE INTO redirect_urls (test_id, url) VALUES (?, ?)',
					   (test_id, url))
		conn.commit()
		conn.close()

	def get_redirect_url(self, test_id):
		conn = sqlite3.connect(self.db_path)
		cursor = conn.cursor()
		cursor.execute('SELECT url FROM redirect_urls WHERE test_id = ?', (test_id,))
		result = cursor.fetchone()
		conn.close()
		return result[0] if result else None


def init(app, storage_type='file', storage_config=None):
	if storage_config is None:
		storage_config = {}

	if storage_type == 'file':
		storage_dir = storage_config.get('storage_dir', './benchmark_storage')
		storage = FileStorageBackend(storage_dir)
	elif storage_type == 'database':
		db_path = storage_config.get('db_path', './benchmark_storage/benchmark.db')
		storage = DatabaseStorageBackend(db_path)
	else:
		raise ValueError(f"Unknown storage type: {storage_type}")

	@app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['GET'])
	def BenchmarkTest00067_get():
		response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
		response.set_cookie('BenchmarkTest00067', 'http%3A%2F%2Flocalhost%3A5000%2F',
			max_age=60*3,
			secure=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['POST'])
	def BenchmarkTest00067_post():
		RESPONSE = ""
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00067", "noCookieValueSupplied"))
		tmp = base64.b64encode(param.encode('utf-8'))
		bar = base64.b64decode(tmp).decode('utf-8')
		storage.save_redirect_url('BenchmarkTest00067', bar)
		return redirect(bar)

	@app.route('/benchmark/redirect-00/BenchmarkTest00067/async', methods=['GET'])
	async def BenchmarkTest00067_get_async():
		response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
		response.set_cookie('BenchmarkTest00067', 'http%3A%2F%2Flocalhost%3A5000%2F',
			max_age=60*3,
			secure=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/redirect-00/BenchmarkTest00067/async', methods=['POST'])
	async def BenchmarkTest00067_post_async():
		RESPONSE = ""
		param = await asyncio.to_thread(urllib.parse.unquote_plus, request.cookies.get("BenchmarkTest00067", "noCookieValueSupplied"))
		tmp = await asyncio.to_thread(base64.b64encode, param.encode('utf-8'))
		bar = await asyncio.to_thread(base64.b64decode, tmp)
		bar = bar.decode('utf-8')
		await asyncio.to_thread(storage.save_redirect_url, 'BenchmarkTest00067_async', bar)
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
		response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
		response.set_cookie('BenchmarkTest00067', 'http%3A%2F%2Flocalhost%3A5000%2F',
			max_age=60*3,
			secure=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/redirect-00/BenchmarkTest00067/hybrid', methods=['POST'])
	def BenchmarkTest00067_post_hybrid():
		RESPONSE = ""
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00067", "noCookieValueSupplied"))
		tmp = base64.b64encode(param.encode('utf-8'))
		bar = base64.b64decode(tmp).decode('utf-8')
		storage.save_redirect_url('BenchmarkTest00067_hybrid', bar)
		return redirect(bar)

	@app.route('/benchmark/redirect-00/BenchmarkTest00067/retrieve', methods=['GET'])
	def BenchmarkTest00067_retrieve():
		test_id = request.args.get('test_id', 'BenchmarkTest00067')
		url = storage.get_redirect_url(test_id)
		if url:
			return {'test_id': test_id, 'url': url}
		return {'error': 'URL not found'}, 404