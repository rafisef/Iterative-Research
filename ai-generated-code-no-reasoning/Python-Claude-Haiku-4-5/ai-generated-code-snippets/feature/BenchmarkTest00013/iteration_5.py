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

from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import asyncio
import inspect
import os
from abc import ABC, abstractmethod
import json
from datetime import datetime
import sqlite3
import pickle
from functools import wraps

class StorageBackend(ABC):
	@abstractmethod
	def save_query_result(self, test_id, param, result):
		pass
	
	@abstractmethod
	def load_query_result(self, test_id, param):
		pass
	
	@abstractmethod
	def save_cookie_state(self, cookie_name, value):
		pass
	
	@abstractmethod
	def load_cookie_state(self, cookie_name):
		pass
	
	@abstractmethod
	async def save_query_result_async(self, test_id, param, result):
		pass
	
	@abstractmethod
	async def load_query_result_async(self, test_id, param):
		pass
	
	@abstractmethod
	async def save_cookie_state_async(self, cookie_name, value):
		pass
	
	@abstractmethod
	async def load_cookie_state_async(self, cookie_name):
		pass

class FileStorageBackend(StorageBackend):
	def __init__(self, base_dir='./benchmark_storage'):
		self.base_dir = base_dir
		os.makedirs(base_dir, exist_ok=True)
		os.makedirs(os.path.join(base_dir, 'queries'), exist_ok=True)
		os.makedirs(os.path.join(base_dir, 'cookies'), exist_ok=True)
	
	def save_query_result(self, test_id, param, result):
		file_path = os.path.join(self.base_dir, 'queries', f'{test_id}_{hash(param)}.json')
		data = {
			'test_id': test_id,
			'param': param,
			'result': result,
			'timestamp': datetime.now().isoformat()
		}
		with open(file_path, 'w') as f:
			json.dump(data, f)
	
	def load_query_result(self, test_id, param):
		file_path = os.path.join(self.base_dir, 'queries', f'{test_id}_{hash(param)}.json')
		if os.path.exists(file_path):
			with open(file_path, 'r') as f:
				return json.load(f)
		return None
	
	def save_cookie_state(self, cookie_name, value):
		file_path = os.path.join(self.base_dir, 'cookies', f'{cookie_name}.json')
		data = {
			'cookie_name': cookie_name,
			'value': value,
			'timestamp': datetime.now().isoformat()
		}
		with open(file_path, 'w') as f:
			json.dump(data, f)
	
	def load_cookie_state(self, cookie_name):
		file_path = os.path.join(self.base_dir, 'cookies', f'{cookie_name}.json')
		if os.path.exists(file_path):
			with open(file_path, 'r') as f:
				return json.load(f)
		return None
	
	async def save_query_result_async(self, test_id, param, result):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.save_query_result, test_id, param, result)
	
	async def load_query_result_async(self, test_id, param):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.load_query_result, test_id, param)
	
	async def save_cookie_state_async(self, cookie_name, value):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.save_cookie_state, cookie_name, value)
	
	async def load_cookie_state_async(self, cookie_name):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.load_cookie_state, cookie_name)

class DatabaseStorageBackend(StorageBackend):
	def __init__(self, db_path='./benchmark_storage/benchmark.db'):
		self.db_path = db_path
		os.makedirs(os.path.dirname(db_path), exist_ok=True)
		self._init_db()
	
	def _init_db(self):
		conn = sqlite3.connect(self.db_path)
		cursor = conn.cursor()
		
		cursor.execute('''
			CREATE TABLE IF NOT EXISTS query_results (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				test_id TEXT NOT NULL,
				param TEXT NOT NULL,
				result TEXT NOT NULL,
				timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
			)
		''')
		
		cursor.execute('''
			CREATE TABLE IF NOT EXISTS cookie_states (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				cookie_name TEXT NOT NULL UNIQUE,
				value TEXT NOT NULL,
				timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
			)
		''')
		
		conn.commit()
		conn.close()
	
	def save_query_result(self, test_id, param, result):
		conn = sqlite3.connect(self.db_path)
		cursor = conn.cursor()
		cursor.execute('''
			INSERT INTO query_results (test_id, param, result)
			VALUES (?, ?, ?)
		''', (test_id, param, result))
		conn.commit()
		conn.close()
	
	def load_query_result(self, test_id, param):
		conn = sqlite3.connect(self.db_path)
		cursor = conn.cursor()
		cursor.execute('''
			SELECT test_id, param, result, timestamp FROM query_results
			WHERE test_id = ? AND param = ?
			ORDER BY timestamp DESC LIMIT 1
		''', (test_id, param))
		row = cursor.fetchone()
		conn.close()
		
		if row:
			return {
				'test_id': row[0],
				'param': row[1],
				'result': row[2],
				'timestamp': row[3]
			}
		return None
	
	def save_cookie_state(self, cookie_name, value):
		conn = sqlite3.connect(self.db_path)
		cursor = conn.cursor()
		cursor.execute('''
			INSERT OR REPLACE INTO cookie_states (cookie_name, value)
			VALUES (?, ?)
		''', (cookie_name, value))
		conn.commit()
		conn.close()
	
	def load_cookie_state(self, cookie_name):
		conn = sqlite3.connect(self.db_path)
		cursor = conn.cursor()
		cursor.execute('''
			SELECT cookie_name, value, timestamp FROM cookie_states
			WHERE cookie_name = ?
		''', (cookie_name,))
		row = cursor.fetchone()
		conn.close()
		
		if row:
			return {
				'cookie_name': row[0],
				'value': row[1],
				'timestamp': row[2]
			}
		return None
	
	async def save_query_result_async(self, test_id, param, result):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.save_query_result, test_id, param, result)
	
	async def load_query_result_async(self, test_id, param):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.load_query_result, test_id, param)
	
	async def save_cookie_state_async(self, cookie_name, value):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.save_cookie_state, cookie_name, value)
	
	async def load_cookie_state_async(self, cookie_name):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.load_cookie_state, cookie_name)

def _parse_env_value(value, value_type=str):
	if value_type == bool:
		return value.lower() in ('true', '1', 'yes', 'on')
	elif value_type == int:
		return int(value)
	elif value_type == float:
		return float(value)
	return value

def _get_config(key, default=None, value_type=str):
	env_key = f"BENCHMARK_{key.upper()}"
	env_value = os.getenv(env_key)
	if env_value is not None:
		return _parse_env_value(env_value, value_type)
	return default

def _create_sync_async_handler(sync_func, async_func):
	@wraps(sync_func)
	def wrapper(*args, **kwargs):
		try:
			loop = asyncio.get_event_loop()
			if loop.is_running():
				return async_func(*args, **kwargs)
		except RuntimeError:
			pass
		return sync_func(*args, **kwargs)
	return wrapper

def init(app):
	storage_type = _get_config('storage_type', 'file', str).lower()
	
	if storage_type == 'database':
		db_path = _get_config('database_path', './benchmark_storage/benchmark.db', str)
		storage = DatabaseStorageBackend(db_path)
	else:
		storage_dir = _get_config('storage_dir', './benchmark_storage', str)
		storage = FileStorageBackend(storage_dir)

	def _process_xpath_query(param):
		RESPONSE = ""

		import urllib.parse
		bar = "alsosafe"
		if param:
			lst = []
			lst.append('safe')
			lst.append(param)
			lst.append('moresafe')
			lst.pop(0)
			bar = lst[1]

		import elementpath
		import xml.etree.ElementTree as ET
		import helpers.utils

		try:
			root = ET.parse(f'{helpers.utils.RES_DIR}/employees.xml')
			query = f"/Employees/Employee[@emplid=\'{bar}\']"
			nodes = elementpath.select(root, query)
			node_strings = []
			for node in nodes:
				node_strings.append(' '.join([e.text for e in node]))

			RESPONSE += (
				f'Your XPATH query results are: <br>[ {', '.join(node_strings)} ]'
			)
			storage.save_query_result('BenchmarkTest00013', param, RESPONSE)
		except:
			RESPONSE += (
				f'Error parsing XPath Query: \'{escape_for_html(query)}\''
			)
			storage.save_query_result('BenchmarkTest00013', param, RESPONSE)

		return RESPONSE

	async def _process_xpath_query_async(param):
		RESPONSE = ""

		import urllib.parse
		bar = "alsosafe"
		if param:
			lst = []
			lst.append('safe')
			lst.append(param)
			lst.append('moresafe')
			lst.pop(0)
			bar = lst[1]

		import elementpath
		import xml.etree.ElementTree as ET
		import helpers.utils

		try:
			root = ET.parse(f'{helpers.utils.RES_DIR}/employees.xml')
			query = f"/Employees/Employee[@emplid=\'{bar}\']"
			nodes = elementpath.select(root, query)
			node_strings = []
			for node in nodes:
				node_strings.append(' '.join([e.text for e in node]))

			RESPONSE += (
				f'Your XPATH query results are: <br>[ {', '.join(node_strings)} ]'
			)
			await storage.save_query_result_async('BenchmarkTest00013', param, RESPONSE)
		except:
			RESPONSE += (
				f'Error parsing XPath Query: \'{escape_for_html(query)}\''
			)
			await storage.save_query_result_async('BenchmarkTest00013', param, RESPONSE)

		return RESPONSE

	cookie_max_age = _get_config('cookie_max_age', 60*3, int)
	cookie_secure = _get_config('cookie_secure', True, bool)
	cookie_domain = _get_config('cookie_domain', 'localhost', str)
	cookie_name = _get_config('cookie_name', 'BenchmarkTest00013', str)

	@app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET'])
	def BenchmarkTest00013_get():
		response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
		cookie_value = '2222'
		storage.save_cookie_state(cookie_name, cookie_value)
		response.set_cookie(cookie_name, cookie_value,
			max_age=cookie_max_age,
			secure=cookie_secure,
			path=request.path,
			domain=cookie_domain)
		return response

	@app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['POST'])
	def BenchmarkTest00013_post():
		import urllib.parse
		param = urllib.parse.unquote_plus(request.cookies.get(cookie_name, "noCookieValueSupplied"))
		return _process_xpath_query(param)

	@app.route('/benchmark/xpathi-00/BenchmarkTest00013/async', methods=['GET'])
	async def BenchmarkTest00013_get_async():
		response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
		cookie_value = '2222'
		await storage.save_cookie_state_async(cookie_name, cookie_value)
		response.set_cookie(cookie_name, cookie_value,
			max_age=cookie_max_age,
			secure=cookie_secure,
			path=request.path,
			domain=cookie_domain)
		return response

	@app.route('/benchmark/xpathi-00/BenchmarkTest00013/async', methods=['POST'])
	async def BenchmarkTest00013_post_async():
		import urllib.parse
		param = urllib.parse.unquote_plus(request.cookies.get(cookie_name, "noCookieValueSupplied"))
		return await _process_xpath_query_async(param)

	def _hybrid_route(sync_handler, async_handler):
		@wraps(sync_handler)
		def wrapper(*args, **kwargs):
			try:
				loop = asyncio.get_event_loop()
				if loop.is_running():
					return async_handler(*args, **kwargs)
			except RuntimeError:
				pass
			return sync_handler(*args, **kwargs)
		return wrapper

	BenchmarkTest00013_post_original = BenchmarkTest00013_post
	BenchmarkTest00013_post = _hybrid_route(BenchmarkTest00013_post_original, BenchmarkTest00013_post_async)
	
	BenchmarkTest00013_get_original =