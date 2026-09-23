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
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Union, Coroutine
import uuid
import threading
import asyncio
import time
from datetime import datetime, timedelta
import inspect
import json
import os
import sqlite3
import pickle
import psycopg2
from psycopg2.extras import RealDictCursor


class StorageBackend(ABC):
	@abstractmethod
	def create_session(self, session_id: str, session_data: Dict[str, Any]) -> bool:
		pass

	@abstractmethod
	async def create_session_async(self, session_id: str, session_data: Dict[str, Any]) -> bool:
		pass

	@abstractmethod
	def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
		pass

	@abstractmethod
	async def get_session_async(self, session_id: str) -> Optional[Dict[str, Any]]:
		pass

	@abstractmethod
	def update_session(self, session_id: str, session_data: Dict[str, Any]) -> bool:
		pass

	@abstractmethod
	async def update_session_async(self, session_id: str, session_data: Dict[str, Any]) -> bool:
		pass

	@abstractmethod
	def delete_session(self, session_id: str) -> bool:
		pass

	@abstractmethod
	async def delete_session_async(self, session_id: str) -> bool:
		pass

	@abstractmethod
	def cleanup_expired_sessions(self, timeout: int) -> int:
		pass

	@abstractmethod
	async def cleanup_expired_sessions_async(self, timeout: int) -> int:
		pass

	@abstractmethod
	def get_all_sessions(self) -> Dict[str, Dict[str, Any]]:
		pass

	@abstractmethod
	async def get_all_sessions_async(self) -> Dict[str, Dict[str, Any]]:
		pass


class FileStorageBackend(StorageBackend):
	def __init__(self, storage_dir: str = './sessions'):
		self.storage_dir = storage_dir
		os.makedirs(storage_dir, exist_ok=True)
		self.lock = threading.RLock()
		self.async_lock = asyncio.Lock()

	def _get_session_path(self, session_id: str) -> str:
		return os.path.join(self.storage_dir, f'{session_id}.json')

	def create_session(self, session_id: str, session_data: Dict[str, Any]) -> bool:
		with self.lock:
			try:
				path = self._get_session_path(session_id)
				with open(path, 'w') as f:
					json.dump(session_data, f)
				return True
			except Exception:
				return False

	async def create_session_async(self, session_id: str, session_data: Dict[str, Any]) -> bool:
		async with self.async_lock:
			try:
				path = self._get_session_path(session_id)
				with open(path, 'w') as f:
					json.dump(session_data, f)
				return True
			except Exception:
				return False

	def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
		with self.lock:
			try:
				path = self._get_session_path(session_id)
				if not os.path.exists(path):
					return None
				with open(path, 'r') as f:
					return json.load(f)
			except Exception:
				return None

	async def get_session_async(self, session_id: str) -> Optional[Dict[str, Any]]:
		async with self.async_lock:
			try:
				path = self._get_session_path(session_id)
				if not os.path.exists(path):
					return None
				with open(path, 'r') as f:
					return json.load(f)
			except Exception:
				return None

	def update_session(self, session_id: str, session_data: Dict[str, Any]) -> bool:
		with self.lock:
			try:
				path = self._get_session_path(session_id)
				with open(path, 'w') as f:
					json.dump(session_data, f)
				return True
			except Exception:
				return False

	async def update_session_async(self, session_id: str, session_data: Dict[str, Any]) -> bool:
		async with self.async_lock:
			try:
				path = self._get_session_path(session_id)
				with open(path, 'w') as f:
					json.dump(session_data, f)
				return True
			except Exception:
				return False

	def delete_session(self, session_id: str) -> bool:
		with self.lock:
			try:
				path = self._get_session_path(session_id)
				if os.path.exists(path):
					os.remove(path)
					return True
				return False
			except Exception:
				return False

	async def delete_session_async(self, session_id: str) -> bool:
		async with self.async_lock:
			try:
				path = self._get_session_path(session_id)
				if os.path.exists(path):
					os.remove(path)
					return True
				return False
			except Exception:
				return False

	def cleanup_expired_sessions(self, timeout: int) -> int:
		with self.lock:
			try:
				deleted_count = 0
				current_time = datetime.now()
				for filename in os.listdir(self.storage_dir):
					if not filename.endswith('.json'):
						continue
					path = os.path.join(self.storage_dir, filename)
					try:
						with open(path, 'r') as f:
							session_data = json.load(f)
						last_accessed = datetime.fromisoformat(session_data.get('last_accessed', datetime.now().isoformat()))
						if (current_time - last_accessed).total_seconds() > timeout:
							os.remove(path)
							deleted_count += 1
					except Exception:
						pass
				return deleted_count
			except Exception:
				return 0

	async def cleanup_expired_sessions_async(self, timeout: int) -> int:
		async with self.async_lock:
			try:
				deleted_count = 0
				current_time = datetime.now()
				for filename in os.listdir(self.storage_dir):
					if not filename.endswith('.json'):
						continue
					path = os.path.join(self.storage_dir, filename)
					try:
						with open(path, 'r') as f:
							session_data = json.load(f)
						last_accessed = datetime.fromisoformat(session_data.get('last_accessed', datetime.now().isoformat()))
						if (current_time - last_accessed).total_seconds() > timeout:
							os.remove(path)
							deleted_count += 1
					except Exception:
						pass
				return deleted_count
			except Exception:
				return 0

	def get_all_sessions(self) -> Dict[str, Dict[str, Any]]:
		with self.lock:
			try:
				sessions = {}
				for filename in os.listdir(self.storage_dir):
					if not filename.endswith('.json'):
						continue
					session_id = filename[:-5]
					path = os.path.join(self.storage_dir, filename)
					try:
						with open(path, 'r') as f:
							sessions[session_id] = json.load(f)
					except Exception:
						pass
				return sessions
			except Exception:
				return {}

	async def get_all_sessions_async(self) -> Dict[str, Dict[str, Any]]:
		async with self.async_lock:
			try:
				sessions = {}
				for filename in os.listdir(self.storage_dir):
					if not filename.endswith('.json'):
						continue
					session_id = filename[:-5]
					path = os.path.join(self.storage_dir, filename)
					try:
						with open(path, 'r') as f:
							sessions[session_id] = json.load(f)
					except Exception:
						pass
				return sessions
			except Exception:
				return {}


class SQLiteStorageBackend(StorageBackend):
	def __init__(self, db_path: str = './sessions.db'):
		self.db_path = db_path
		self.lock = threading.RLock()
		self.async_lock = asyncio.Lock()
		self._init_db()

	def _init_db(self):
		with self.lock:
			try:
				conn = sqlite3.connect(self.db_path)
				cursor = conn.cursor()
				cursor.execute('''
					CREATE TABLE IF NOT EXISTS sessions (
						session_id TEXT PRIMARY KEY,
						user_info TEXT NOT NULL,
						created_at TEXT NOT NULL,
						last_accessed TEXT NOT NULL,
						data TEXT NOT NULL
					)
				''')
				conn.commit()
				conn.close()
			except Exception:
				pass

	def _get_connection(self) -> sqlite3.Connection:
		conn = sqlite3.connect(self.db_path)
		conn.row_factory = sqlite3.Row
		return conn

	def create_session(self, session_id: str, session_data: Dict[str, Any]) -> bool:
		with self.lock:
			try:
				conn = self._get_connection()
				cursor = conn.cursor()
				cursor.execute('''
					INSERT INTO sessions (session_id, user_info, created_at, last_accessed, data)
					VALUES (?, ?, ?, ?, ?)
				''', (
					session_id,
					json.dumps(session_data.get('user_info', {})),
					session_data.get('created_at', datetime.now().isoformat()),
					session_data.get('last_accessed', datetime.now().isoformat()),
					json.dumps(session_data.get('data', {}))
				))
				conn.commit()
				conn.close()
				return True
			except Exception:
				return False

	async def create_session_async(self, session_id: str, session_data: Dict[str, Any]) -> bool:
		async with self.async_lock:
			try:
				conn = self._get_connection()
				cursor = conn.cursor()
				cursor.execute('''
					INSERT INTO sessions (session_id, user_info, created_at, last_accessed, data)
					VALUES (?, ?, ?, ?, ?)
				''', (
					session_id,
					json.dumps(session_data.get('user_info', {})),
					session_data.get('created_at', datetime.now().isoformat()),
					session_data.get('last_accessed', datetime.now().isoformat()),
					json.dumps(session_data.get('data', {}))
				))
				conn.commit()
				conn.close()
				return True
			except Exception:
				return False

	def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
		with self.lock:
			try:
				conn = self._get_connection()
				cursor = conn.cursor()
				cursor.execute('SELECT * FROM sessions WHERE session_id = ?', (session_id,))
				row = cursor.fetchone()
				conn.close()
				
				if not row:
					return None
				
				return {
					'user_info': json.loads(row['user_info']),
					'created_at': row['created_at'],
					'last_accessed': row['last_accessed'],
					'data': json.loads(row['data'])
				}
			except Exception:
				return None

	async def get_session_async(self, session_id: str) -> Optional[Dict[str, Any]]:
		async with self.async_lock:
			try:
				conn = self._get_connection()
				cursor = conn.cursor()
				cursor.execute('SELECT * FROM sessions WHERE session_id = ?', (session_id,))
				row = cursor.fetchone()
				conn.close()
				
				if not row:
					return None
				
				return {
					'user_info': json.loads(row['user_info']),
					'created_at': row['created_at'],
					'last_accessed': row['last_accessed'],
					'data': json.loads(row['data'])
				}
			except Exception:
				return None

	def update_session(self, session_id: str, session_data: Dict[str, Any]) -> bool:
		with self.lock:
			try:
				conn = self._get_connection()
				cursor = conn.cursor()
				cursor.execute('''
					UPDATE sessions
					SET user_info = ?, created_at = ?, last_accessed = ?, data = ?
					WHERE session_id = ?
				''', (
					json.dumps(session_data.get('user_info', {})),
					session_data.get('created_at', datetime.now().isoformat()),
					session_data.get('last_accessed', datetime.now().isoformat()),
					json.dumps(session_data.get('data', {})),
					session_id
				))
				conn.commit()
				conn.close()
				return True
			except Exception:
				return False

	async def update_session_async(self, session_id: str, session_data: Dict[str, Any]) -> bool:
		async with self.async_lock:
			try:
				conn = self._get_connection()
				cursor = conn.cursor()
				cursor.execute('''
					UPDATE sessions
					SET user_info = ?, created_at = ?, last_accessed = ?, data = ?
					WHERE session_id = ?
				''', (
					json.dumps(session_data.get('user_info', {})),
					session_data.get('created_at', datetime.now().isoformat()),
					session_data.get('last_accessed', datetime.now().isoformat()),
					json.dumps(session_data.get('data', {})),
					session_id
				))
				conn.commit()
				conn.close()
				return True
			except Exception:
				return False

	def delete_session(self, session_id: str) -> bool:
		with self.lock:
			try:
				conn = self._get_connection()
				cursor = conn.cursor()
				cursor.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
				conn.commit()
				conn.close()
				return True
			except Exception:
				return False

	async def delete_session_async(self, session_id: str) -> bool:
		async with self.async_lock:
			try:
				conn = self._get_connection()
				cursor = conn.cursor()
				cursor.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
				conn.commit()
				conn.close()
				return True
			except Exception:
				return False

	def cleanup_expired_sessions(self, timeout: int) -> int:
		with self.lock:
			try:
				conn = self._get_connection()
				cursor = conn.cursor()
				current_time = datetime.now().isoformat()
				cursor.execute('''
					DELETE FROM sessions
					WHERE datetime(last_accessed) < datetime(?, '-' || ? || ' seconds')
				''',