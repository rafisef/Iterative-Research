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

class StorageBackend:
	def save_session(self, session_id, session_data):
		raise NotImplementedError
	
	def load_session(self, session_id):
		raise NotImplementedError
	
	def delete_session(self, session_id):
		raise NotImplementedError
	
	def get_all_session_ids(self):
		raise NotImplementedError
	
	def session_exists(self, session_id):
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
	def __init__(self, db_path=None):
		self.db_path = db_path or os.getenv('SESSION_DB_PATH', './sessions.db')
		self.lock = RLock()
		self._init_db()
	
	def _init_db(self):
		with self.lock:
			conn = sqlite3.connect(self.db_path)
			cursor = conn.cursor()
			cursor.execute('''
				CREATE TABLE IF NOT EXISTS sessions (
					session_id TEXT PRIMARY KEY,
					session_data BLOB,
					created_at TEXT,
					last_accessed TEXT,
					user_id TEXT
				)
			''')
			conn.commit()
			conn.close()
	
	def save_session(self, session_id, session_data):
		with self.lock:
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
			conn = sqlite3.connect(self.db_path)
			cursor = conn.cursor()
			cursor.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
			conn.commit()
			conn.close()
	
	def get_all_session_ids(self):
		with self.lock:
			conn = sqlite3.connect(self.db_path)
			cursor = conn.cursor()
			cursor.execute('SELECT session_id FROM sessions')
			rows = cursor.fetchall()
			conn.close()
			return [row[0] for row in rows]
	
	def session_exists(self, session_id):
		with self.lock:
			conn = sqlite3.connect(self.db_path)
			cursor = conn.cursor()
			cursor.execute('SELECT 1 FROM sessions WHERE session_id = ?', (session_id,))
			exists = cursor.fetchone() is not None
			conn.close()
			return exists

class SessionManager:
	def __init__(self, max_workers=None, cleanup_interval=None, session_timeout=None, secret_key=None, storage_backend=None):
		self.sessions = {}
		self.lock = RLock()
		self.condition = Condition(self.lock)
		
		self.max_workers = max_workers or int(os.getenv('SESSION_MAX_WORKERS', '10'))
		self.cleanup_interval = cleanup_interval or int(os.getenv('SESSION_CLEANUP_INTERVAL', '60'))
		self.session_timeout = session_timeout or int(os.getenv('SESSION_TIMEOUT', '180'))
		self.secret_key = secret_key or os.getenv('SESSION_SECRET_KEY', 'benchmark-secret-key-change-in-production')
		
		storage_type = os.getenv('SESSION_STORAGE_TYPE', 'file').lower()
		if storage_backend:
			self.storage_backend = storage_backend
		elif storage_type == 'database':
			self.storage_backend = DatabaseStorageBackend()
		else:
			self.storage_backend = FileStorageBackend()
		
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
					'peak_concurrent': 0
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
				'concurrent_requests': 0
			}
			self.sessions[session_id] = session_data
			self.storage_backend.save_session(session_id, session_data)
			if user_id:
				self.user_sessions[user_id].append(session_id)
			self.session_activity[session_id] = {
				'requests': 0,
				'last_request_time': datetime.now(),
				'concurrent_count': 0,
				'peak_concurrent': 0
			}
			self.condition.notify_all()
		return session_id

	def get_session(self, session_id):
		with self.lock:
			if session_id in self.sessions:
				session_data = self.sessions[session_id]
				session_data['last_accessed'] = datetime.now()
				session_data['concurrent_requests'] += 1
				self.storage_backend.save_session(session_id, session_data)
				if session_id in self.session_activity:
					self.session_activity[session_id]['requests'] += 1
					self.session_activity[session_id]['last_request_time'] = datetime.now()
					self.session_activity[session_id]['concurrent_count'] += 1
					current_concurrent = self.session_activity[session_id]['concurrent_count']
					if current_concurrent > self.session_activity[session_id]['peak_concurrent']:
						self.session_activity[session_id]['peak_concurrent'] = current_concurrent
				self._cleanup_expired()
				return session_data['data']
		return None

	def release_session(self, session_id):
		with self.lock:
			if session_id in self.sessions:
				self.sessions[session_id]['concurrent_requests'] = max(0, self.sessions[session_id]['concurrent_requests'] - 1)
				self.storage_backend.save_session(session_id, self.sessions[session_id])
				if session_id in self.session_activity:
					self.session_activity[session_id]['concurrent_count'] = max(0, self.session_activity[session_id]['concurrent_count'] - 1)

	def set_session_value(self, session_id, key, value):
		with self.lock:
			if session_id in self.sessions:
				self.sessions[session_id]['data'][key] = value
				self.sessions[session_id]['last_accessed'] = datetime.now()
				self.sessions[session_id]['activity_log'].append({
					'action': 'set',
					'key': key,
					'timestamp': datetime.now()
				})
				self.storage_backend.save_session(session_id, self.sessions[session_id])
				self.condition.notify_all()

	def get_user_sessions(self, user_id):
		with self.lock:
			return self.user_sessions.get(user_id, []).copy()

	def invalidate_session(self, session_id):
		with self.lock:
			if session_id in self.sessions:
				user_id = self.sessions[session_id].get('user_id')
				self.storage_backend.delete_session(session_id)
				del self.sessions[session_id]
				if session_id in self.session_activity:
					del self.session_activity[session_id]
				if user_id and session_id in self.user_sessions[user_id]:
					self.user_sessions[user_id].remove(session_id)
				self.condition.notify_all()

	def invalidate_user_sessions(self, user_id):
		with self.lock:
			sessions_to_remove = self.user_sessions.get(user_id, []).copy()
			for session_id in sessions_to_remove:
				if session_id in self.sessions:
					self.storage_backend.delete_session(session_id)
					del self.sessions[session_id]
					if session_id in self.session_activity:
						del self.session_activity[session_id]
			if user_id in self.user_sessions:
				self.user_sessions[user_id].clear()
			self.condition.notify_all()

	def get_session_activity(self, session_id):
		with self.lock:
			activity = self.session_activity.get(session_id, {}).copy()
			return activity

	def _cleanup_expired(self):
		current_time = datetime.now()
		expired_sessions = []
		for sid, session_data in list(self.sessions.items()):
			if (current_time - session_data['last_accessed']).seconds > self.session_timeout:
				expired_sessions.append(sid)
		for sid in expired_sessions:
			user_id = self.sessions[sid].get('user_id')
			self.storage_backend.delete_session(sid)
			del self.sessions[sid]
			if sid in self.session_activity:
				del self.session_activity[sid]
			if user_id and sid in self.user_sessions[user_id]:
				self.user_sessions[user_id].remove(sid)

	def cleanup_expired_async(self):
		def cleanup():
			with self.lock:
				self._cleanup_expired()
		self.executor.submit(cleanup)

	def get_all_sessions_count(self):
		with self.lock:
			return len(self.sessions)

	def get_user_session_count(self, user_id):
		with self.lock:
			return len(self.user_sessions.get(user_id, []))

	def get_concurrent_sessions_info(self):
		with self.lock:
			info = {
				'total_sessions': len(self.sessions),
				'total_concurrent_requests': sum(s.get('concurrent_requests', 0) for s in self.sessions.values()),
				'sessions_by_user': {uid: len(sids) for uid, sids in self.user_sessions.items() if sids}
			}
			return info

	def shutdown(self):
		self.running = False
		if self.cleanup_thread:
			self.cleanup_thread.join(timeout=5