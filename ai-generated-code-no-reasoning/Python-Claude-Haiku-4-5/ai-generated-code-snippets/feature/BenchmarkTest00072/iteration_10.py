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
from threading import RLock, Condition, Thread, Semaphore
from datetime import datetime, timedelta
import uuid
from collections import defaultdict
import asyncio
from concurrent.futures import ThreadPoolExecutor
import time
import os
import json
import sqlite3
import pickle
import queue
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Union, Coroutine, Set
from abc import ABC, abstractmethod
import hashlib
import hmac
import inspect

@dataclass
class SessionRequest:
	session_id: str
	user_id: Optional[str] = None
	request_time: datetime = field(default_factory=datetime.now)
	request_count: int = 0
	concurrent_count: int = 0

@dataclass
class ConcurrentUserSession:
	session_id: str
	user_id: str
	created_at: datetime = field(default_factory=datetime.now)
	last_accessed: datetime = field(default_factory=datetime.now)
	concurrent_requests: int = 0
	max_concurrent_requests: int = 10
	active_request_ids: Set[str] = field(default_factory=set)
	session_lock: RLock = field(default_factory=RLock)
	semaphore: Semaphore = field(default_factory=lambda: Semaphore(10))
	metadata: Dict[str, Any] = field(default_factory=dict)
	
	def acquire_request_slot(self, request_id: str) -> bool:
		with self.session_lock:
			if self.concurrent_requests < self.max_concurrent_requests:
				self.concurrent_requests += 1
				self.active_request_ids.add(request_id)
				self.last_accessed = datetime.now()
				return True
			return False
	
	def release_request_slot(self, request_id: str):
		with self.session_lock:
			if request_id in self.active_request_ids:
				self.active_request_ids.remove(request_id)
				self.concurrent_requests = max(0, self.concurrent_requests - 1)
				self.last_accessed = datetime.now()
	
	def is_active(self, timeout_seconds: int = 3600) -> bool:
		elapsed = (datetime.now() - self.last_accessed).total_seconds()
		return elapsed < timeout_seconds

class StorageBackend(ABC):
	@abstractmethod
	def save_session(self, session_id, session_data):
		raise NotImplementedError
	
	@abstractmethod
	async def save_session_async(self, session_id, session_data):
		raise NotImplementedError
	
	@abstractmethod
	def load_session(self, session_id):
		raise NotImplementedError
	
	@abstractmethod
	async def load_session_async(self, session_id):
		raise NotImplementedError
	
	@abstractmethod
	def delete_session(self, session_id):
		raise NotImplementedError
	
	@abstractmethod
	async def delete_session_async(self, session_id):
		raise NotImplementedError
	
	@abstractmethod
	def get_all_session_ids(self):
		raise NotImplementedError
	
	@abstractmethod
	async def get_all_session_ids_async(self):
		raise NotImplementedError
	
	@abstractmethod
	def session_exists(self, session_id):
		raise NotImplementedError
	
	@abstractmethod
	async def session_exists_async(self, session_id):
		raise NotImplementedError
	
	@abstractmethod
	def cleanup_expired_sessions(self, expiry_time):
		raise NotImplementedError
	
	@abstractmethod
	async def cleanup_expired_sessions_async(self, expiry_time):
		raise NotImplementedError

class FileStorageBackend(StorageBackend):
	def __init__(self, storage_dir=None):
		self.storage_dir = storage_dir or os.getenv('SESSION_STORAGE_DIR', './sessions')
		os.makedirs(self.storage_dir, exist_ok=True)
		self.lock = RLock()
		self.executor = ThreadPoolExecutor(max_workers=8)
	
	def _get_file_path(self, session_id):
		return os.path.join(self.storage_dir, f'{session_id}.json')
	
	def save_session(self, session_id, session_data):
		with self.lock:
			file_path = self._get_file_path(session_id)
			serializable_data = self._make_serializable(session_data)
			with open(file_path, 'w') as f:
				json.dump(serializable_data, f)
	
	async def save_session_async(self, session_id, session_data):
		loop = asyncio.get_event_loop()
		await loop.run_in_executor(self.executor, self.save_session, session_id, session_data)
	
	def load_session(self, session_id):
		with self.lock:
			file_path = self._get_file_path(session_id)
			if os.path.exists(file_path):
				with open(file_path, 'r') as f:
					data = json.load(f)
					return self._restore_datetime(data)
			return None
	
	async def load_session_async(self, session_id):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(self.executor, self.load_session, session_id)
	
	def delete_session(self, session_id):
		with self.lock:
			file_path = self._get_file_path(session_id)
			if os.path.exists(file_path):
				os.remove(file_path)
	
	async def delete_session_async(self, session_id):
		loop = asyncio.get_event_loop()
		await loop.run_in_executor(self.executor, self.delete_session, session_id)
	
	def get_all_session_ids(self):
		with self.lock:
			session_ids = []
			if os.path.exists(self.storage_dir):
				for filename in os.listdir(self.storage_dir):
					if filename.endswith('.json'):
						session_ids.append(filename[:-5])
			return session_ids
	
	async def get_all_session_ids_async(self):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(self.executor, self.get_all_session_ids)
	
	def session_exists(self, session_id):
		with self.lock:
			return os.path.exists(self._get_file_path(session_id))
	
	async def session_exists_async(self, session_id):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(self.executor, self.session_exists, session_id)
	
	def cleanup_expired_sessions(self, expiry_time):
		with self.lock:
			deleted_count = 0
			if os.path.exists(self.storage_dir):
				for filename in os.listdir(self.storage_dir):
					if filename.endswith('.json'):
						file_path = os.path.join(self.storage_dir, filename)
						try:
							with open(file_path, 'r') as f:
								data = json.load(f)
								last_accessed = data.get('last_accessed')
								if last_accessed:
									last_accessed_dt = datetime.fromisoformat(last_accessed)
									if last_accessed_dt < expiry_time:
										os.remove(file_path)
										deleted_count += 1
						except (json.JSONDecodeError, IOError):
							pass
			return deleted_count
	
	async def cleanup_expired_sessions_async(self, expiry_time):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(self.executor, self.cleanup_expired_sessions, expiry_time)
	
	def _make_serializable(self, obj):
		if isinstance(obj, datetime):
			return {'__datetime__': True, 'value': obj.isoformat()}
		elif isinstance(obj, dict):
			return {k: self._make_serializable(v) for k, v in obj.items()}
		elif isinstance(obj, list):
			return [self._make_serializable(item) for item in obj]
		return obj
	
	def _restore_datetime(self, obj):
		if isinstance(obj, dict):
			if obj.get('__datetime__'):
				return datetime.fromisoformat(obj['value'])
			return {k: self._restore_datetime(v) for k, v in obj.items()}
		elif isinstance(obj, list):
			return [self._restore_datetime(item) for item in obj]
		return obj

class DatabaseStorageBackend(StorageBackend):
	def __init__(self, db_path=None, db_type='sqlite'):
		self.db_path = db_path or os.getenv('SESSION_DB_PATH', './sessions.db')
		self.db_type = db_type or os.getenv('SESSION_DB_TYPE', 'sqlite')
		self.lock = RLock()
		self.executor = ThreadPoolExecutor(max_workers=8)
		self._init_db()
	
	def _init_db(self):
		with self.lock:
			if self.db_type == 'sqlite':
				conn = sqlite3.connect(self.db_path, check_same_thread=False)
				cursor = conn.cursor()
				cursor.execute('''
					CREATE TABLE IF NOT EXISTS sessions (
						session_id TEXT PRIMARY KEY,
						session_data BLOB,
						created_at TEXT,
						last_accessed TEXT,
						user_id TEXT,
						concurrent_requests INTEGER DEFAULT 0
					)
				''')
				cursor.execute('CREATE INDEX IF NOT EXISTS idx_last_accessed ON sessions(last_accessed)')
				cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_id ON sessions(user_id)')
				conn.commit()
				conn.close()
	
	def save_session(self, session_id, session_data):
		with self.lock:
			if self.db_type == 'sqlite':
				conn = sqlite3.connect(self.db_path, check_same_thread=False)
				cursor = conn.cursor()
				serialized = pickle.dumps(session_data)
				cursor.execute('''
					INSERT OR REPLACE INTO sessions 
					(session_id, session_data, created_at, last_accessed, user_id, concurrent_requests)
					VALUES (?, ?, ?, ?, ?, ?)
				''', (
					session_id,
					serialized,
					session_data.get('created_at', datetime.now()).isoformat(),
					session_data.get('last_accessed', datetime.now()).isoformat(),
					session_data.get('user_id'),
					session_data.get('concurrent_requests', 0)
				))
				conn.commit()
				conn.close()
	
	async def save_session_async(self, session_id, session_data):
		loop = asyncio.get_event_loop()
		await loop.run_in_executor(self.executor, self.save_session, session_id, session_data)
	
	def load_session(self, session_id):
		with self.lock:
			if self.db_type == 'sqlite':
				conn = sqlite3.connect(self.db_path, check_same_thread=False)
				cursor = conn.cursor()
				cursor.execute('SELECT session_data FROM sessions WHERE session_id = ?', (session_id,))
				row = cursor.fetchone()
				conn.close()
				if row:
					return pickle.loads(row[0])
			return None
	
	async def load_session_async(self, session_id):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(self.executor, self.load_session, session_id)
	
	def delete_session(self, session_id):
		with self.lock:
			if self.db_type == 'sqlite':
				conn = sqlite3.connect(self.db_path, check_same_thread=False)
				cursor = conn.cursor()
				cursor.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
				conn.commit()
				conn.close()
	
	async def delete_session_async(self, session_id):
		loop = asyncio.get_event_loop()
		await loop.run_in_executor(self.executor, self.delete_session, session_id)
	
	def get_all_session_ids(self):
		with self.lock:
			if self.db_type == 'sqlite':
				conn = sqlite3.connect(self.db_path, check_same_thread=False)
				cursor = conn.cursor()
				cursor.execute('SELECT session_id FROM sessions')
				rows = cursor.fetchall()
				conn.close()
				return [row[0] for row in rows]
			return []
	
	async def get_all_session_ids_async(self):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(self.executor, self.get_all_session_ids)
	
	def session_exists(self, session_id):
		with self.lock:
			if self.db_type == 'sqlite':
				conn = sqlite3.connect(self.db_path, check_same_thread=False)
				cursor = conn.cursor()
				cursor.execute('SELECT 1 FROM sessions WHERE session_id = ?', (session_id,))
				exists = cursor.fetchone() is not None
				conn.close()
				return exists
			return False
	
	async def session_exists_async(self, session_id):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(self.executor, self.session_exists, session_id)
	
	def cleanup_expired_sessions(self, expiry_time):
		with self.lock:
			deleted_count = 0
			if self.db_type == 'sqlite':
				conn = sqlite3.connect(self.db_path, check_same_thread=False)
				cursor = conn.cursor()
				cursor.execute(
					'DELETE FROM sessions WHERE last_accessed < ?',
					(expiry_time.isoformat(),)
				)
				deleted_count = cursor.rowcount
				conn.commit()
				conn.close()
			return deleted_count
	
	async def cleanup_expired_sessions_async(self, expiry_time):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(self.executor, self.cleanup_expired_sessions, expiry_time)

class ConcurrentSessionManager:
	def __init__(self, storage_backend: StorageBackend, max_sessions_per_user: int = 5, session_timeout_seconds: int = 3600):
		self.storage_backend = storage_backend
		self.max_sessions_per_user = max_sessions_per_user
		self.session_timeout_seconds = session_timeout_seconds
		self.active_sessions: Dict[str, ConcurrentUserSession] = {}
		self.user_sessions: Dict[str, Set[str]] = default