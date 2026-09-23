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
from uuid import uuid4
import threading
import sqlite3
import json
import os
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
import queue
import asyncio
from typing import Optional, Dict, Any, Callable, Awaitable, Union
import pickle

class SessionStore(ABC):
	@abstractmethod
	def get_or_create_session(self):
		pass
	
	@abstractmethod
	def get_session_data(self, session_id):
		pass
	
	@abstractmethod
	def update_session_data(self, session_id, key, value):
		pass
	
	@abstractmethod
	def get_session_value(self, session_id, key, default=None):
		pass
	
	@abstractmethod
	def cleanup_session(self, session_id):
		pass
	
	@abstractmethod
	def cleanup_expired_sessions(self, max_age_seconds=3600):
		pass
	
	@abstractmethod
	async def async_get_or_create_session(self):
		pass
	
	@abstractmethod
	async def async_get_session_data(self, session_id):
		pass
	
	@abstractmethod
	async def async_update_session_data(self, session_id, key, value):
		pass
	
	@abstractmethod
	async def async_get_session_value(self, session_id, key, default=None):
		pass
	
	@abstractmethod
	async def async_cleanup_session(self, session_id):
		pass
	
	@abstractmethod
	async def async_cleanup_expired_sessions(self, max_age_seconds=3600):
		pass

class FileSessionStore(SessionStore):
	def __init__(self, storage_path='sessions', max_age_seconds=3600):
		self._session_store = {}
		self._session_lock = threading.RLock()
		self._async_lock = asyncio.Lock()
		self.max_age_seconds = max_age_seconds
		self.storage_path = storage_path
		if not os.path.exists(self.storage_path):
			os.makedirs(self.storage_path)
	
	def _get_file_path(self, session_id):
		return os.path.join(self.storage_path, f'{session_id}.json')
	
	def _load_session_from_file(self, session_id):
		file_path = self._get_file_path(session_id)
		if os.path.exists(file_path):
			try:
				with open(file_path, 'r') as f:
					return json.load(f)
			except (json.JSONDecodeError, IOError):
				return None
		return None
	
	def _save_session_to_file(self, session_id, data):
		file_path = self._get_file_path(session_id)
		try:
			with open(file_path, 'w') as f:
				json.dump(data, f)
		except IOError:
			pass
	
	def get_or_create_session(self):
		session_id = session.get('session_id')
		
		if not session_id:
			session_id = str(uuid4())
			session['session_id'] = session_id
		
		with self._session_lock:
			if session_id not in self._session_store:
				file_data = self._load_session_from_file(session_id)
				if file_data:
					self._session_store[session_id] = {
						'data': file_data.get('data', {}),
						'lock': threading.RLock(),
						'created_at': datetime.fromisoformat(file_data.get('created_at', datetime.now().isoformat())),
						'updated_at': datetime.fromisoformat(file_data.get('updated_at', datetime.now().isoformat()))
					}
				else:
					self._session_store[session_id] = {
						'data': {},
						'lock': threading.RLock(),
						'created_at': datetime.now(),
						'updated_at': datetime.now()
					}
					self._save_session_to_file(session_id, {
						'data': {},
						'created_at': datetime.now().isoformat(),
						'updated_at': datetime.now().isoformat()
					})
		
		return session_id, self._session_store[session_id]
	
	def get_session_data(self, session_id):
		with self._session_lock:
			if session_id in self._session_store:
				return self._session_store[session_id].copy()
			file_data = self._load_session_from_file(session_id)
			if file_data:
				return file_data.get('data', {})
			return {}
	
	def update_session_data(self, session_id, key, value):
		with self._session_lock:
			if session_id in self._session_store:
				with self._session_store[session_id]['lock']:
					self._session_store[session_id]['data'][key] = value
					self._session_store[session_id]['updated_at'] = datetime.now()
					self._save_session_to_file(session_id, {
						'data': self._session_store[session_id]['data'],
						'created_at': self._session_store[session_id]['created_at'].isoformat(),
						'updated_at': self._session_store[session_id]['updated_at'].isoformat()
					})
	
	def get_session_value(self, session_id, key, default=None):
		with self._session_lock:
			if session_id in self._session_store:
				with self._session_store[session_id]['lock']:
					return self._session_store[session_id]['data'].get(key, default)
			file_data = self._load_session_from_file(session_id)
			if file_data:
				return file_data.get('data', {}).get(key, default)
		return default
	
	def cleanup_session(self, session_id):
		with self._session_lock:
			if session_id in self._session_store:
				del self._session_store[session_id]
			file_path = self._get_file_path(session_id)
			if os.path.exists(file_path):
				try:
					os.remove(file_path)
				except OSError:
					pass
	
	def cleanup_expired_sessions(self, max_age_seconds=3600):
		now = datetime.now()
		expired_sessions = []
		
		with self._session_lock:
			for session_id, session_data in list(self._session_store.items()):
				age = (now - session_data['updated_at']).total_seconds()
				if age > max_age_seconds:
					expired_sessions.append(session_id)
		
		for session_id in expired_sessions:
			self.cleanup_session(session_id)
		
		for filename in os.listdir(self.storage_path):
			if filename.endswith('.json'):
				file_path = os.path.join(self.storage_path, filename)
				try:
					file_time = os.path.getmtime(file_path)
					file_age = (datetime.now() - datetime.fromtimestamp(file_time)).total_seconds()
					if file_age > max_age_seconds:
						os.remove(file_path)
				except OSError:
					pass
	
	async def async_get_or_create_session(self):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.get_or_create_session)
	
	async def async_get_session_data(self, session_id):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.get_session_data, session_id)
	
	async def async_update_session_data(self, session_id, key, value):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.update_session_data, session_id, key, value)
	
	async def async_get_session_value(self, session_id, key, default=None):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.get_session_value, session_id, key, default)
	
	async def async_cleanup_session(self, session_id):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.cleanup_session, session_id)
	
	async def async_cleanup_expired_sessions(self, max_age_seconds=3600):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.cleanup_expired_sessions, max_age_seconds)

class DatabaseSessionStore(SessionStore):
	def __init__(self, db_path='sessions.db', max_age_seconds=3600):
		self.db_path = db_path
		self._lock = threading.RLock()
		self._async_lock = asyncio.Lock()
		self.max_age_seconds = max_age_seconds
		self._init_db()
	
	def _init_db(self):
		with sqlite3.connect(self.db_path) as conn:
			conn.execute('''
				CREATE TABLE IF NOT EXISTS sessions (
					session_id TEXT PRIMARY KEY,
					data TEXT NOT NULL,
					created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
					updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
				)
			''')
			conn.execute('''
				CREATE INDEX IF NOT EXISTS idx_updated_at ON sessions(updated_at)
			''')
			conn.commit()
	
	def _get_connection(self):
		conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
		conn.row_factory = sqlite3.Row
		conn.execute('PRAGMA journal_mode=WAL')
		return conn
	
	def get_or_create_session(self):
		session_id = session.get('session_id')
		
		if not session_id:
			session_id = str(uuid4())
			session['session_id'] = session_id
		
		with self._lock:
			conn = self._get_connection()
			cursor = conn.cursor()
			cursor.execute('SELECT data FROM sessions WHERE session_id = ?', (session_id,))
			row = cursor.fetchone()
			
			if not row:
				cursor.execute(
					'INSERT INTO sessions (session_id, data) VALUES (?, ?)',
					(session_id, json.dumps({}))
				)
				conn.commit()
			
			conn.close()
		
		return session_id, {'lock': threading.RLock()}
	
	def get_session_data(self, session_id):
		with self._lock:
			conn = self._get_connection()
			cursor = conn.cursor()
			cursor.execute('SELECT data FROM sessions WHERE session_id = ?', (session_id,))
			row = cursor.fetchone()
			conn.close()
			
			if row:
				return json.loads(row['data'])
			return {}
	
	def update_session_data(self, session_id, key, value):
		with self._lock:
			conn = self._get_connection()
			cursor = conn.cursor()
			
			cursor.execute('SELECT data FROM sessions WHERE session_id = ?', (session_id,))
			row = cursor.fetchone()
			
			if row:
				data = json.loads(row['data'])
				data[key] = value
				cursor.execute(
					'UPDATE sessions SET data = ?, updated_at = CURRENT_TIMESTAMP WHERE session_id = ?',
					(json.dumps(data), session_id)
				)
				conn.commit()
			
			conn.close()
	
	def get_session_value(self, session_id, key, default=None):
		with self._lock:
			conn = self._get_connection()
			cursor = conn.cursor()
			cursor.execute('SELECT data FROM sessions WHERE session_id = ?', (session_id,))
			row = cursor.fetchone()
			conn.close()
			
			if row:
				data = json.loads(row['data'])
				return data.get(key, default)
			return default
	
	def cleanup_session(self, session_id):
		with self._lock:
			conn = self._get_connection()
			cursor = conn.cursor()
			cursor.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
			conn.commit()
			conn.close()
	
	def cleanup_expired_sessions(self, max_age_seconds=3600):
		with self._lock:
			conn = self._get_connection()
			cursor = conn.cursor()
			cursor.execute(
				'DELETE FROM sessions WHERE datetime(updated_at) < datetime("now", "-' + str(max_age_seconds) + ' seconds")'
			)
			conn.commit()
			conn.close()
	
	async def async_get_or_create_session(self):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.get_or_create_session)
	
	async def async_get_session_data(self, session_id):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.get_session_data, session_id)
	
	async def async_update_session_data(self, session_id, key, value):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.update_session_data, session_id, key, value)
	
	async def async_get_session_value(self, session_id, key, default=None):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.get_session_value, session_id, key, default)
	
	async def async_cleanup_session(self, session_id):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.cleanup_session, session_id)
	
	async def async_cleanup_expired_sessions(self, max_age_seconds=3600):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.cleanup_expired_sessions, max_age_seconds)

class ConcurrentSessionManager:
	def __init__(self, session_store, max_workers=10):
		self.session_store = session_store
		self.executor = ThreadPoolExecutor(max_workers=max_workers)
		self.cleanup_queue = queue.Queue()
	
	def sync_update_session(self, session_id, key, value):
		self.session_store.update_session_data(session_id, key, value)
	
	def async_update_session(self, session_id, key, value):
		self.executor.submit(self.session_store.update_session_data, session_id, key, value)
	
	def sync_cleanup_session(self, session_id