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
from threading import RLock, Condition, Thread
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
from typing import Dict, List, Optional, Any
from abc import ABC, abstractmethod

@dataclass
class SessionRequest:
	session_id: str
	user_id: Optional[str] = None
	request_time: datetime = field(default_factory=datetime.now)
	request_count: int = 0
	concurrent_count: int = 0

class StorageBackend(ABC):
	@abstractmethod
	def save_session(self, session_id, session_data):
		raise NotImplementedError
	
	@abstractmethod
	def load_session(self, session_id):
		raise NotImplementedError
	
	@abstractmethod
	def delete_session(self, session_id):
		raise NotImplementedError
	
	@abstractmethod
	def get_all_session_ids(self):
		raise NotImplementedError
	
	@abstractmethod
	def session_exists(self, session_id):
		raise NotImplementedError
	
	@abstractmethod
	def cleanup_expired_sessions(self, expiry_time):
		raise NotImplementedError

class FileStorageBackend(StorageBackend):
	def __init__(self, storage_dir=None):
		self.storage_dir = storage_dir or os.getenv('SESSION_STORAGE_DIR', './sessions')
		os.makedirs(self.storage_dir, exist_ok=True)
		self.lock = RLock()
	
	def _get_file_path(self, session_id):
		return os.path.join(self.storage_dir, f'{session_id}.json')
	
	def save_session(self, session_id, session_data):
		with self.lock:
			file_path = self._get_file_path(session_id)
			serializable_data = self._make_serializable(session_data)
			with open(file_path, 'w') as f:
				json.dump(serializable_data, f)
	
	def load_session(self, session_id):
		with self.lock:
			file_path = self._get_file_path(session_id)
			if os.path.exists(file_path):
				with open(file_path, 'r') as f:
					data = json.load(f)
					return self._restore_datetime(data)
			return None
	
	def delete_session(self, session_id):
		with self.lock:
			file_path = self._get_file_path(session_id)
			if os.path.exists(file_path):
				os.remove(file_path)
	
	def get_all_session_ids(self):
		with self.lock:
			session_ids = []
			if os.path.exists(self.storage_dir):
				for filename in os.listdir(self.storage_dir):
					if filename.endswith('.json'):
						session_ids.append(filename[:-5])
			return session_ids
	
	def session_exists(self, session_id):
		with self.lock:
			return os.path.exists(self._get_file_path(session_id))
	
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
		self._init_db()
	
	def _init_db(self):
		with self.lock:
			if self.db_type == 'sqlite':
				conn = sqlite3.connect(self.db_path)
				cursor = conn.cursor()
				cursor.execute('''
					CREATE TABLE IF NOT EXISTS sessions (
						session_id TEXT PRIMARY KEY,
						session_data BLOB,
						created_at TEXT,
						last_accessed TEXT,
						user_id TEXT,
						INDEX idx_last_accessed (last_accessed),
						INDEX idx_user_id (user_id)
					)
				''')
				conn.commit()
				conn.close()
	
	def save_session(self, session_id, session_data):
		with self.lock:
			if self.db_type == 'sqlite':
				conn = sqlite3.connect(self.db_path)
				cursor = conn.cursor()
				serialized = pickle.dumps(session_data)
				cursor.execute('''
					INSERT OR REPLACE INTO sessions 
					(session_id, session_data, created_at, last_accessed, user_id)
					VALUES (?, ?, ?, ?, ?)
				''', (
					session_id,
					serialized,
					session_data.get('created_at', datetime.now()).isoformat(),
					session_data.get('last_accessed', datetime.now()).isoformat(),
					session_data.get('user_id')
				))
				conn.commit()
				conn.close()
	
	def load_session(self, session_id):
		with self.lock:
			if self.db_type == 'sqlite':
				conn = sqlite3.connect(self.db_path)
				cursor = conn.cursor()
				cursor.execute('SELECT session_data FROM sessions WHERE session_id = ?', (session_id,))
				row = cursor.fetchone()
				conn.close()
				if row:
					return pickle.loads(row[0])
			return None
	
	def delete_session(self, session_id):
		with self.lock:
			if self.db_type == 'sqlite':
				conn = sqlite3.connect(self.db_path)
				cursor = conn.cursor()
				cursor.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
				conn.commit()
				conn.close()
	
	def get_all_session_ids(self):
		with self.lock:
			if self.db_type == 'sqlite':
				conn = sqlite3.connect(self.db_path)
				cursor = conn.cursor()
				cursor.execute('SELECT session_id FROM sessions')
				rows = cursor.fetchall()
				conn.close()
				return [row[0] for row in rows]
			return []
	
	def session_exists(self, session_id):
		with self.lock:
			if self.db_type == 'sqlite':
				conn = sqlite3.connect(self.db_path)
				cursor = conn.cursor()
				cursor.execute('SELECT 1 FROM sessions WHERE session_id = ?', (session_id,))
				exists = cursor.fetchone() is not None
				conn.close()
				return exists
			return False
	
	def cleanup_expired_sessions(self, expiry_time):
		with self.lock:
			deleted_count = 0
			if self.db_type == 'sqlite':
				conn = sqlite3.connect(self.db_path)
				cursor = conn.cursor()
				cursor.execute(
					'DELETE FROM sessions WHERE last_accessed < ?',
					(expiry_time.isoformat(),)
				)
				deleted_count = cursor.rowcount
				conn.commit()
				conn.close()
			return deleted_count

class ConcurrentSessionHandler:
	def __init__(self, max_concurrent_per_user=None, max_concurrent_per_session=None):
		self.max_concurrent_per_user = max_concurrent_per_user or int(os.getenv('MAX_CONCURRENT_PER_USER', '5'))
		self.max_concurrent_per_session = max_concurrent_per_session or int(os.getenv('MAX_CONCURRENT_PER_SESSION', '10'))
		self.user_concurrent_requests = defaultdict(int)
		self.session_concurrent_requests = defaultdict(int)
		self.lock = RLock()
		self.request_queue = queue.Queue()
		self.active_requests = {}
	
	def acquire_request_slot(self, session_id, user_id=None):
		with self.lock:
			if self.session_concurrent_requests[session_id] >= self.max_concurrent_per_session:
				return False
			if user_id and self.user_concurrent_requests[user_id] >= self.max_concurrent_per_user:
				return False
			
			self.session_concurrent_requests[session_id] += 1
			if user_id:
				self.user_concurrent_requests[user_id] += 1
			
			request_id = str(uuid.uuid4())
			self.active_requests[request_id] = {
				'session_id': session_id,
				'user_id': user_id,
				'start_time': datetime.now()
			}
			return request_id
	
	def release_request_slot(self, request_id, session_id, user_id=None):
		with self.lock:
			if request_id in self.active_requests:
				del self.active_requests[request_id]
			
			self.session_concurrent_requests[session_id] = max(0, self.session_concurrent_requests[session_id] - 1)
			if user_id:
				self.user_concurrent_requests[user_id] = max(0, self.user_concurrent_requests[user_id] - 1)
	
	def get_concurrent_stats(self):
		with self.lock:
			return {
				'active_requests': len(self.active_requests),
				'user_concurrent': dict(self.user_concurrent_requests),
				'session_concurrent': dict(self.session_concurrent_requests)
			}

class SessionManager:
	def __init__(self, max_workers=None, cleanup_interval=None, session_timeout=None, secret_key=None, storage_backend=None):
		self.sessions = {}
		self.lock = RLock()
		self.condition = Condition(self.lock)
		
		self.max_workers = max_workers or int(os.getenv('SESSION_MAX_WORKERS', '10'))
		self.cleanup_interval = cleanup_interval or int(os.getenv('SESSION_CLEANUP_INTERVAL', '60'))
		self.session_timeout = session_timeout or int(os.getenv('SESSION_TIMEOUT', '180'))
		self.secret_key = secret_key or os.getenv('SESSION_SECRET_KEY', 'benchmark-secret-key-change-in-production')
		
		if storage_backend:
			self.storage_backend = storage_backend
		else:
			storage_type = os.getenv('SESSION_STORAGE_TYPE', 'file').lower()
			if storage_type == 'database':
				db_path = os.getenv('SESSION_DB_PATH', './sessions.db')
				db_type = os.getenv('SESSION_DB_TYPE', 'sqlite')
				self.storage_backend = DatabaseStorageBackend(db_path=db_path, db_type=db_type)
			else:
				storage_dir = os.getenv('SESSION_STORAGE_DIR', './sessions')
				self.storage_backend = FileStorageBackend(storage_dir=storage_dir)
		
		self.concurrent_handler = ConcurrentSessionHandler()
		self.user_sessions = defaultdict(list)
		self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
		self.session_activity = {}
		self.cleanup_thread = None
		self.running = True
		self._load_sessions_from_storage()
		self._start_cleanup_thread()

	def _load_sessions_from_storage(self):
		session_ids = self.storage_backend.get_all_session_ids()
		for session_id in session_ids:
			session_data = self.storage_backend.load_session(session_id)
			if session_data:
				self.sessions[session_id] = session_data
				user_id = session_data.get('user_id')
				if user_id:
					self.user_sessions[user_id].append(session_id)
				self.session_activity[session_id] = {
					'requests': 0,
					'last_request_time': datetime.now(),
					'concurrent_count': 0,
					'peak_concurrent': 0,
					'active_request_ids': []
				}

	def _start_cleanup_thread(self):
		self.cleanup_thread = Thread(target=self._cleanup_loop, daemon=True)
		self.cleanup_thread.start()

	def _cleanup_loop(self):
		while self.running:
			time.sleep(self.cleanup_interval)
			self.cleanup_expired_async()

	def create_session(self, user_id=None):
		session_id = str(uuid.uuid4())
		with self.lock:
			session_data = {
				'data': {},
				'created_at': datetime.now(),
				'last_accessed': datetime.now(),
				'user_id': user_id,
				'activity_log': [],
				'concurrent_requests': 0,
				'active_request_ids': []
			}
			self.sessions[session_id] = session_data
			self.storage_backend.save_session(session_id, session_data)
			if user_id:
				self.user_sessions[user_id].append(session_id)
			self.session_activity[session_id] = {
				'requests': 0,
				'last_request_time': datetime.now(),
				'concurrent_count': 0,
				'peak_concurrent': 0,
				'active_request_ids': []
			}
			self.condition.notify_all()
		return