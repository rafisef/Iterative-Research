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
import threading
import uuid
from collections import defaultdict

def _get_config(key: str, default: Any = None) -> Any:
	return os.getenv(key, default)

class SessionManager:
	def __init__(self):
		self.sessions = {}
		self.session_lock = threading.RLock()
	
	def create_session(self, user_id: str = None) -> str:
		session_id = str(uuid.uuid4())
		with self.session_lock:
			self.sessions[session_id] = {
				'user_id': user_id or session_id,
				'created_at': datetime.now(),
				'data': {},
				'lock': threading.RLock()
			}
		return session_id
	
	def get_session(self, session_id: str) -> Optional[Dict]:
		with self.session_lock:
			return self.sessions.get(session_id)
	
	def set_session_data(self, session_id: str, key: str, value: Any) -> None:
		session = self.get_session(session_id)
		if session:
			with session['lock']:
				session['data'][key] = value
	
	def get_session_data(self, session_id: str, key: str) -> Any:
		session = self.get_session(session_id)
		if session:
			with session['lock']:
				return session['data'].get(key)
		return None
	
	def delete_session(self, session_id: str) -> None:
		with self.session_lock:
			if session_id in self.sessions:
				del self.sessions[session_id]
	
	def get_all_sessions_for_user(self, user_id: str) -> list:
		with self.session_lock:
			return [sid for sid, sdata in self.sessions.items() if sdata['user_id'] == user_id]

_session_manager = SessionManager()

class StorageBackend(ABC):
	@abstractmethod
	def save_query_result(self, test_id, param, result, session_id=None):
		pass
	
	@abstractmethod
	def load_query_result(self, test_id, param, session_id=None):
		pass
	
	@abstractmethod
	def save_cookie_state(self, cookie_name, value, session_id=None):
		pass
	
	@abstractmethod
	def load_cookie_state(self, cookie_name, session_id=None):
		pass
	
	@abstractmethod
	async def save_query_result_async(self, test_id, param, result, session_id=None):
		pass
	
	@abstractmethod
	async def load_query_result_async(self, test_id, param, session_id=None):
		pass
	
	@abstractmethod
	async def save_cookie_state_async(self, cookie_name, value, session_id=None):
		pass
	
	@abstractmethod
	async def load_cookie_state_async(self, cookie_name, session_id=None):
		pass

class FileStorageBackend(StorageBackend):
	def __init__(self, base_dir=None):
		self.base_dir = base_dir or _get_config('storage_file_base_dir', './benchmark_storage')
		os.makedirs(self.base_dir, exist_ok=True)
		os.makedirs(os.path.join(self.base_dir, 'queries'), exist_ok=True)
		os.makedirs(os.path.join(self.base_dir, 'cookies'), exist_ok=True)
		self.lock = threading.RLock()
	
	def _get_file_path(self, base_path, key, session_id=None):
		if session_id:
			return os.path.join(self.base_dir, base_path, f'{session_id}_{key}.json')
		return os.path.join(self.base_dir, base_path, f'{key}.json')
	
	def save_query_result(self, test_id, param, result, session_id=None):
		file_key = f'{test_id}_{hash(param)}'
		file_path = self._get_file_path('queries', file_key, session_id)
		data = {
			'test_id': test_id,
			'param': param,
			'result': result,
			'session_id': session_id,
			'timestamp': datetime.now().isoformat()
		}
		with self.lock:
			with open(file_path, 'w') as f:
				json.dump(data, f)
	
	def load_query_result(self, test_id, param, session_id=None):
		file_key = f'{test_id}_{hash(param)}'
		file_path = self._get_file_path('queries', file_key, session_id)
		with self.lock:
			if os.path.exists(file_path):
				with open(file_path, 'r') as f:
					return json.load(f)
		return None
	
	def save_cookie_state(self, cookie_name, value, session_id=None):
		cookie_key = cookie_name if not session_id else f'{session_id}_{cookie_name}'
		file_path = self._get_file_path('cookies', cookie_key, session_id)
		data = {
			'cookie_name': cookie_name,
			'value': value,
			'session_id': session_id,
			'timestamp': datetime.now().isoformat()
		}
		with self.lock:
			with open(file_path, 'w') as f:
				json.dump(data, f)
	
	def load_cookie_state(self, cookie_name, session_id=None):
		cookie_key = cookie_name if not session_id else f'{session_id}_{cookie_name}'
		file_path = self._get_file_path('cookies', cookie_key, session_id)
		with self.lock:
			if os.path.exists(file_path):
				with open(file_path, 'r') as f:
					return json.load(f)
		return None
	
	async def save_query_result_async(self, test_id, param, result, session_id=None):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.save_query_result, test_id, param, result, session_id)
	
	async def load_query_result_async(self, test_id, param, session_id=None):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.load_query_result, test_id, param, session_id)
	
	async def save_cookie_state_async(self, cookie_name, value, session_id=None):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.save_cookie_state, cookie_name, value, session_id)
	
	async def load_cookie_state_async(self, cookie_name, session_id=None):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.load_cookie_state, cookie_name, session_id)

class SQLiteStorageBackend(StorageBackend):
	def __init__(self, db_path=None):
		self.db_path = db_path or _get_config('storage_db_path', './benchmark_storage/benchmark.db')
		os.makedirs(os.path.dirname(self.db_path) or '.', exist_ok=True)
		self.lock = threading.RLock()
		self._init_db()
	
	def _init_db(self):
		with self.lock:
			conn = sqlite3.connect(self.db_path, check_same_thread=False)
			cursor = conn.cursor()
			
			cursor.execute('''
				CREATE TABLE IF NOT EXISTS query_results (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					test_id TEXT NOT NULL,
					param TEXT NOT NULL,
					result TEXT NOT NULL,
					session_id TEXT,
					timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
				)
			''')
			
			cursor.execute('''
				CREATE TABLE IF NOT EXISTS cookie_states (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					cookie_name TEXT NOT NULL,
					value TEXT NOT NULL,
					session_id TEXT,
					timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
					UNIQUE(cookie_name, session_id)
				)
			''')
			
			cursor.execute('CREATE INDEX IF NOT EXISTS idx_query_session ON query_results(session_id)')
			cursor.execute('CREATE INDEX IF NOT EXISTS idx_cookie_session ON cookie_states(session_id)')
			
			conn.commit()
			conn.close()
	
	def save_query_result(self, test_id, param, result, session_id=None):
		with self.lock:
			conn = sqlite3.connect(self.db_path, check_same_thread=False)
			cursor = conn.cursor()
			cursor.execute('''
				INSERT INTO query_results (test_id, param, result, session_id)
				VALUES (?, ?, ?, ?)
			''', (test_id, param, result, session_id))
			conn.commit()
			conn.close()
	
	def load_query_result(self, test_id, param, session_id=None):
		with self.lock:
			conn = sqlite3.connect(self.db_path, check_same_thread=False)
			cursor = conn.cursor()
			if session_id:
				cursor.execute('''
					SELECT test_id, param, result, timestamp FROM query_results
					WHERE test_id = ? AND param = ? AND session_id = ?
					ORDER BY timestamp DESC LIMIT 1
				''', (test_id, param, session_id))
			else:
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
	
	def save_cookie_state(self, cookie_name, value, session_id=None):
		with self.lock:
			conn = sqlite3.connect(self.db_path, check_same_thread=False)
			cursor = conn.cursor()
			cursor.execute('''
				INSERT OR REPLACE INTO cookie_states (cookie_name, value, session_id)
				VALUES (?, ?, ?)
			''', (cookie_name, value, session_id))
			conn.commit()
			conn.close()
	
	def load_cookie_state(self, cookie_name, session_id=None):
		with self.lock:
			conn = sqlite3.connect(self.db_path, check_same_thread=False)
			cursor = conn.cursor()
			if session_id:
				cursor.execute('''
					SELECT cookie_name, value, timestamp FROM cookie_states
					WHERE cookie_name = ? AND session_id = ?
				''', (cookie_name, session_id))
			else:
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
	
	async def save_query_result_async(self, test_id, param, result, session_id=None):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.save_query_result, test_id, param, result, session_id)
	
	async def load_query_result_async(self, test_id, param, session_id=None):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.load_query_result, test_id, param, session_id)
	
	async def save_cookie_state_async(self, cookie_name, value, session_id=None):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.save_cookie_state, cookie_name, value, session_id)
	
	async def load_cookie_state_async(self, cookie_name, session_id=None):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.load_cookie_state, cookie_name, session_id)

class MySQLStorageBackend(StorageBackend):
	def __init__(self, host=None, user=None, password=None, database=None, port=3306):
		self.host = host or _get_config('storage_mysql_host', 'localhost')
		self.user = user or _get_config('storage_mysql_user', 'root')
		self.password = password or _get_config('storage_mysql_password', '')
		self.database = database or _get_config('storage_mysql_database', 'benchmark')
		self.port = port or int(_get_config('storage_mysql_port', '3306'))
		self.lock = threading.RLock()
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
		
		with self.lock:
			conn = self._get_connection()
			cursor = conn.cursor()
			
			cursor.execute('''
				CREATE TABLE IF NOT EXISTS query_results (
					id INT AUTO_INCREMENT PRIMARY KEY,
					test_id VARCHAR(255) NOT NULL,
					param LONGTEXT NOT NULL,
					result LONGTEXT NOT NULL,
					session_id VARCHAR(255),
					timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
					INDEX idx_test_param (test_id, param(100)),
					INDEX idx_session (session_id)
				)
			''')
			
			cursor.execute('''
				CREATE TABLE IF NOT EXISTS cookie_states (
					id INT AUTO_INCREMENT PRIMARY KEY,