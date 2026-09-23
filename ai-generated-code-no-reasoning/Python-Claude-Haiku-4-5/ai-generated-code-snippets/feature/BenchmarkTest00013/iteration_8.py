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
import asyncio
import inspect
import os
from abc import ABC, abstractmethod
import json
from datetime import datetime
import sqlite3
import pickle
from functools import wraps
from typing import Optional, Dict, Any, Callable
import mysql.connector
from mysql.connector import Error as MySQLError
import psycopg2
from psycopg2 import Error as PostgresError

def _get_config(key: str, default: Any = None) -> Any:
	return os.getenv(key, default)

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
	def __init__(self, base_dir=None):
		self.base_dir = base_dir or _get_config('storage_file_base_dir', './benchmark_storage')
		os.makedirs(self.base_dir, exist_ok=True)
		os.makedirs(os.path.join(self.base_dir, 'queries'), exist_ok=True)
		os.makedirs(os.path.join(self.base_dir, 'cookies'), exist_ok=True)
	
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

class SQLiteStorageBackend(StorageBackend):
	def __init__(self, db_path=None):
		self.db_path = db_path or _get_config('storage_db_path', './benchmark_storage/benchmark.db')
		os.makedirs(os.path.dirname(self.db_path) or '.', exist_ok=True)
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

class MySQLStorageBackend(StorageBackend):
	def __init__(self, host=None, user=None, password=None, database=None, port=3306):
		self.host = host or _get_config('storage_mysql_host', 'localhost')
		self.user = user or _get_config('storage_mysql_user', 'root')
		self.password = password or _get_config('storage_mysql_password', '')
		self.database = database or _get_config('storage_mysql_database', 'benchmark')
		self.port = port or int(_get_config('storage_mysql_port', '3306'))
		self._init_db()
	
	def _get_connection(self):
		return mysql.connector.connect(
			host=self.host,
			user=self.user,
			password=self.password,
			database=self.database,
			port=self.port
		)
	
	def _init_db(self):
		try:
			conn = mysql.connector.connect(
				host=self.host,
				user=self.user,
				password=self.password,
				port=self.port
			)
			cursor = conn.cursor()
			cursor.execute(f'CREATE DATABASE IF NOT EXISTS {self.database}')
			conn.commit()
			conn.close()
		except MySQLError:
			pass
		
		conn = self._get_connection()
		cursor = conn.cursor()
		
		cursor.execute('''
			CREATE TABLE IF NOT EXISTS query_results (
				id INT AUTO_INCREMENT PRIMARY KEY,
				test_id VARCHAR(255) NOT NULL,
				param LONGTEXT NOT NULL,
				result LONGTEXT NOT NULL,
				timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
				INDEX idx_test_param (test_id, param(100))
			)
		''')
		
		cursor.execute('''
			CREATE TABLE IF NOT EXISTS cookie_states (
				id INT AUTO_INCREMENT PRIMARY KEY,
				cookie_name VARCHAR(255) NOT NULL UNIQUE,
				value LONGTEXT NOT NULL,
				timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
			)
		''')
		
		conn.commit()
		conn.close()
	
	def save_query_result(self, test_id, param, result):
		conn = self._get_connection()
		cursor = conn.cursor()
		cursor.execute('''
			INSERT INTO query_results (test_id, param, result)
			VALUES (%s, %s, %s)
		''', (test_id, param, result))
		conn.commit()
		conn.close()
	
	def load_query_result(self, test_id, param):
		conn = self._get_connection()
		cursor = conn.cursor()
		cursor.execute('''
			SELECT test_id, param, result, timestamp FROM query_results
			WHERE test_id = %s AND param = %s
			ORDER BY timestamp DESC LIMIT 1
		''', (test_id, param))
		row = cursor.fetchone()
		conn.close()
		
		if row:
			return {
				'test_id': row[0],
				'param': row[1],
				'result': row[2],
				'timestamp': str(row[3])
			}
		return None
	
	def save_cookie_state(self, cookie_name, value):
		conn = self._get_connection()
		cursor = conn.cursor()
		cursor.execute('''
			INSERT INTO cookie_states (cookie_name, value)
			VALUES (%s, %s)
			ON DUPLICATE KEY UPDATE value = %s
		''', (cookie_name, value, value))
		conn.commit()
		conn.close()
	
	def load_cookie_state(self, cookie_name):
		conn = self._get_connection()
		cursor = conn.cursor()
		cursor.execute('''
			SELECT cookie_name, value, timestamp FROM cookie_states
			WHERE cookie_name = %s
		''', (cookie_name,))
		row = cursor.fetchone()
		conn.close()
		
		if row:
			return {
				'cookie_name': row[0],
				'value': row[1],
				'timestamp': str(row[2])
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

class PostgresStorageBackend(StorageBackend):
	def __init__(self, host=None, user=None, password=None, database=None, port=5432):
		self.host = host or _get_config('storage_postgres_host', 'localhost')
		self.user = user or _get_config('storage_postgres_user', 'postgres')
		self.password = password or _get_config('storage_postgres_password', '')
		self.database = database or _get_config('storage_postgres_database', 'benchmark')
		self.port = port or int(_get_config('storage_postgres_port', '5432'))
		self._init_db()
	
	def _get_connection(self):
		return psycopg2.connect(
			host=self.host,
			user=self.user,
			password=self.password,
			database=self.database,
			port=self.port
		)
	
	def _init_db(self):
		try:
			conn = psycopg2.connect(
				host=self.host,
				user=self.user,
				password=self.password,
				port=self.port,
				database='postgres'
			)
			conn.autocommit = True
			cursor = conn.cursor()
			cursor.execute(f'CREATE DATABASE IF NOT EXISTS {self.database}')
			conn.close()
		except PostgresError:
			pass
		
		conn = self._get_connection()
		cursor = conn.cursor()
		
		cursor.execute('''