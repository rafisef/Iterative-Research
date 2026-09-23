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
from typing import Dict, List, Optional, Any, Callable
from abc import ABC, abstractmethod
import hashlib
import hmac

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

class AuthenticationProvider(ABC):
	@abstractmethod
	def authenticate(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
		raise NotImplementedError
	
	@abstractmethod
	def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
		raise NotImplementedError
	
	@abstractmethod
	def refresh_token(self, token: str) -> Optional[str]:
		raise NotImplementedError
	
	@abstractmethod
	def logout(self, token: str) -> bool:
		raise NotImplementedError

class BasicAuthProvider(AuthenticationProvider):
	def __init__(self, user_store: Dict[str, str]):
		self.user_store = user_store
		self.lock = RLock()
		self.active_tokens = {}
	
	def authenticate(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
		username = credentials.get('username')
		password = credentials.get('password')
		
		if not username or not password:
			return None
		
		if username in self.user_store and self.user_store[username] == password:
			token = str(uuid.uuid4())
			with self.lock:
				self.active_tokens[token] = {
					'username': username,
					'created_at': datetime.now(),
					'last_accessed': datetime.now()
				}
			return {
				'user_id': username,
				'token': token,
				'auth_type': 'basic',
				'authenticated_at': datetime.now()
			}
		return None
	
	def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
		with self.lock:
			if token in self.active_tokens:
				token_data = self.active_tokens[token]
				token_data['last_accessed'] = datetime.now()
				return {
					'user_id': token_data['username'],
					'token': token,
					'auth_type': 'basic'
				}
		return None
	
	def refresh_token(self, token: str) -> Optional[str]:
		with self.lock:
			if token in self.active_tokens:
				new_token = str(uuid.uuid4())
				token_data = self.active_tokens.pop(token)
				self.active_tokens[new_token] = token_data
				self.active_tokens[new_token]['last_accessed'] = datetime.now()
				return new_token
		return None
	
	def logout(self, token: str) -> bool:
		with self.lock:
			if token in self.active_tokens:
				del self.active_tokens[token]
				return True
		return False

class TokenAuthProvider(AuthenticationProvider):
	def __init__(self, secret_key: str, token_lifetime: int = 3600):
		self.secret_key = secret_key
		self.token_lifetime = token_lifetime
		self.lock = RLock()
		self.issued_tokens = {}
		self.revoked_tokens = set()
	
	def authenticate(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
		user_id = credentials.get('user_id')
		if not user_id:
			return None
		
		token = self._generate_token(user_id)
		with self.lock:
			self.issued_tokens[token] = {
				'user_id': user_id,
				'created_at': datetime.now(),
				'expires_at': datetime.now() + timedelta(seconds=self.token_lifetime)
			}
		
		return {
			'user_id': user_id,
			'token': token,
			'auth_type': 'token',
			'expires_in': self.token_lifetime,
			'authenticated_at': datetime.now()
		}
	
	def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
		with self.lock:
			if token in self.revoked_tokens:
				return None
			
			if token in self.issued_tokens:
				token_data = self.issued_tokens[token]
				if token_data['expires_at'] > datetime.now():
					return {
						'user_id': token_data['user_id'],
						'token': token,
						'auth_type': 'token'
					}
		return None
	
	def refresh_token(self, token: str) -> Optional[str]:
		with self.lock:
			if token in self.issued_tokens:
				token_data = self.issued_tokens.pop(token)
				new_token = self._generate_token(token_data['user_id'])
				self.issued_tokens[new_token] = {
					'user_id': token_data['user_id'],
					'created_at': datetime.now(),
					'expires_at': datetime.now() + timedelta(seconds=self.token_lifetime)
				}
				return new_token
		return None
	
	def logout(self, token: str) -> bool:
		with self.lock:
			if token in self.issued_tokens:
				del self.issued_tokens[token]
			self.revoked_tokens.add(token)
		return True
	
	def _generate_token(self, user_id: str) -> str:
		timestamp = str(int(time.time()))
		data = f"{user_id}:{timestamp}:{uuid.uuid4()}"
		token = hashlib.sha256(data.encode()).hexdigest()
		return token

class OAuthProvider(AuthenticationProvider):
	def __init__(self, client_id: str, client_secret: str, callback_url: str):
		self.client_id = client_id
		self.client_secret = client_secret
		self.callback_url = callback_url
		self.lock = RLock()
		self.authorization_codes = {}
		self.access_tokens = {}
	
	def authenticate(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
		auth_code = credentials.get('code')
		if not auth_code:
			return None
		
		with self.lock:
			if auth_code in self.authorization_codes:
				code_data = self.authorization_codes.pop(auth_code)
				access_token = str(uuid.uuid4())
				self.access_tokens[