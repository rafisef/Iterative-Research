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

import os
import json
import sqlite3
import random
import string
import urllib.parse
import threading
import time
import asyncio
import hashlib
import hmac
from abc import ABC, abstractmethod
from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
from collections import defaultdict

class StorageBackend(ABC):
	@abstractmethod
	def get(self, key):
		pass

	@abstractmethod
	def set(self, key, value):
		pass

	@abstractmethod
	def exists(self, key):
		pass

	@abstractmethod
	def delete(self, key):
		pass

	@abstractmethod
	def list_keys(self, pattern=None):
		pass

	@abstractmethod
	async def get_async(self, key):
		pass

	@abstractmethod
	async def set_async(self, key, value):
		pass

	@abstractmethod
	async def exists_async(self, key):
		pass

	@abstractmethod
	async def delete_async(self, key):
		pass

	@abstractmethod
	async def list_keys_async(self, pattern=None):
		pass

class FileStorage(StorageBackend):
	def __init__(self, storage_dir):
		self.storage_dir = storage_dir
		self.lock = threading.RLock()
		os.makedirs(storage_dir, exist_ok=True)

	def _get_path(self, key):
		safe_key = key.replace('/', '_').replace('\\', '_')
		return os.path.join(self.storage_dir, f'{safe_key}.json')

	def get(self, key):
		with self.lock:
			path = self._get_path(key)
			if os.path.exists(path):
				try:
					with open(path, 'r') as f:
						data = json.load(f)
						return data.get('value')
				except (json.JSONDecodeError, IOError):
					return None
			return None

	def set(self, key, value):
		with self.lock:
			path = self._get_path(key)
			try:
				with open(path, 'w') as f:
					json.dump({'value': value, 'timestamp': time.time()}, f)
			except IOError:
				pass

	def exists(self, key):
		with self.lock:
			return os.path.exists(self._get_path(key))

	def delete(self, key):
		with self.lock:
			path = self._get_path(key)
			try:
				if os.path.exists(path):
					os.remove(path)
					return True
			except IOError:
				pass
			return False

	def list_keys(self, pattern=None):
		with self.lock:
			keys = []
			try:
				for filename in os.listdir(self.storage_dir):
					if filename.endswith('.json'):
						key = filename[:-5].replace('_', '/')
						if pattern is None or pattern in key:
							keys.append(key)
			except OSError:
				pass
			return keys

	async def get_async(self, key):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.get, key)

	async def set_async(self, key, value):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.set, key, value)

	async def exists_async(self, key):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.exists, key)

	async def delete_async(self, key):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.delete, key)

	async def list_keys_async(self, pattern=None):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.list_keys, pattern)

class DatabaseStorage(StorageBackend):
	def __init__(self, db_path):
		self.db_path = db_path
		self.lock = threading.RLock()
		self._init_db()

	def _init_db(self):
		try:
			with self.lock:
				conn = sqlite3.connect(self.db_path, check_same_thread=False)
				cursor = conn.cursor()
				cursor.execute('''
					CREATE TABLE IF NOT EXISTS storage (
						key TEXT PRIMARY KEY,
						value TEXT NOT NULL,
						timestamp REAL DEFAULT 0
					)
				''')
				cursor.execute('CREATE INDEX IF NOT EXISTS idx_key ON storage(key)')
				conn.commit()
				conn.close()
		except sqlite3.Error:
			pass

	def get(self, key):
		try:
			with self.lock:
				conn = sqlite3.connect(self.db_path, check_same_thread=False)
				cursor = conn.cursor()
				cursor.execute('SELECT value FROM storage WHERE key = ?', (key,))
				result = cursor.fetchone()
				conn.close()
				return result[0] if result else None
		except sqlite3.Error:
			return None

	def set(self, key, value):
		try:
			with self.lock:
				conn = sqlite3.connect(self.db_path, check_same_thread=False)
				cursor = conn.cursor()
				cursor.execute(
					'INSERT OR REPLACE INTO storage (key, value, timestamp) VALUES (?, ?, ?)',
					(key, value, time.time())
				)
				conn.commit()
				conn.close()
		except sqlite3.Error:
			pass

	def exists(self, key):
		try:
			with self.lock:
				conn = sqlite3.connect(self.db_path, check_same_thread=False)
				cursor = conn.cursor()
				cursor.execute('SELECT 1 FROM storage WHERE key = ?', (key,))
				result = cursor.fetchone()
				conn.close()
				return result is not None
		except sqlite3.Error:
			return False

	def delete(self, key):
		try:
			with self.lock:
				conn = sqlite3.connect(self.db_path, check_same_thread=False)
				cursor = conn.cursor()
				cursor.execute('DELETE FROM storage WHERE key = ?', (key,))
				deleted = cursor.rowcount > 0
				conn.commit()
				conn.close()
				return deleted
		except sqlite3.Error:
			return False

	def list_keys(self, pattern=None):
		try:
			with self.lock:
				conn = sqlite3.connect(self.db_path, check_same_thread=False)
				cursor = conn.cursor()
				if pattern:
					cursor.execute('SELECT key FROM storage WHERE key LIKE ?', (f'%{pattern}%',))
				else:
					cursor.execute('SELECT key FROM storage')
				results = cursor.fetchall()
				conn.close()
				return [row[0] for row in results]
		except sqlite3.Error:
			return []

	async def get_async(self, key):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.get, key)

	async def set_async(self, key, value):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.set, key, value)

	async def exists_async(self, key):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.exists, key)

	async def delete_async(self, key):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.delete, key)

	async def list_keys_async(self, pattern=None):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.list_keys, pattern)

class HybridStorage(StorageBackend):
	def __init__(self, primary_storage, fallback_storage=None):
		self.primary = primary_storage
		self.fallback = fallback_storage
		self.lock = threading.RLock()

	def get(self, key):
		with self.lock:
			try:
				value = self.primary.get(key)
				if value is not None:
					return value
			except Exception:
				pass
			
			if self.fallback:
				try:
					return self.fallback.get(key)
				except Exception:
					pass
			return None

	def set(self, key, value):
		with self.lock:
			try:
				self.primary.set(key, value)
			except Exception:
				pass
			
			if self.fallback:
				try:
					self.fallback.set(key, value)
				except Exception:
					pass

	def exists(self, key):
		with self.lock:
			try:
				if self.primary.exists(key):
					return True
			except Exception:
				pass
			
			if self.fallback:
				try:
					return self.fallback.exists(key)
				except Exception:
					pass
			return False

	def delete(self, key):
		with self.lock:
			deleted = False
			try:
				if self.primary.delete(key):
					deleted = True
			except Exception:
				pass
			
			if self.fallback:
				try:
					if self.fallback.delete(key):
						deleted = True
				except Exception:
					pass
			return deleted

	def list_keys(self, pattern=None):
		with self.lock:
			keys = set()
			try:
				keys.update(self.primary.list_keys(pattern))
			except Exception:
				pass
			
			if self.fallback:
				try:
					keys.update(self.fallback.list_keys(pattern))
				except Exception:
					pass
			return list(keys)

	async def get_async(self, key):
		try:
			value = await self.primary.get_async(key)
			if value is not None:
				return value
		except Exception:
			pass
		
		if self.fallback:
			try:
				return await self.fallback.get_async(key)
			except Exception:
				pass
		return None

	async def set_async(self, key, value):
		try:
			await self.primary.set_async(key, value)
		except Exception:
			pass
		
		if self.fallback:
			try:
				await self.fallback.set_async(key, value)
			except Exception:
				pass

	async def exists_async(self, key):
		try:
			if await self.primary.exists_async(key):
				return True
		except Exception:
			pass
		
		if self.fallback:
			try:
				return await self.fallback.exists_async(key)
			except Exception:
				pass
		return False

	async def delete_async(self, key):
		deleted = False
		try:
			if await self.primary.delete_async(key):
				deleted = True
		except Exception:
			pass
		
		if self.fallback:
			try:
				if await self.fallback.delete_async(key):
					deleted = True
			except Exception:
				pass
		return deleted

	async def list_keys_async(self, pattern=None):
		keys = set()
		try:
			keys.update(await self.primary.list_keys_async(pattern))
		except Exception:
			pass
		
		if self.fallback:
			try:
				keys.update(await self.fallback.list_keys_async(pattern))
			except Exception:
				pass
		return list(keys)

class StorageFactory:
	@staticmethod
	def create_file_storage(storage_dir):
		return FileStorage(storage_dir)

	@staticmethod
	def create_database_storage(db_path):
		return DatabaseStorage(db_path)

	@staticmethod
	def create_hybrid_storage(primary_type, primary_config, fallback_type=None, fallback_config=None):
		primary = None
		fallback = None

		if primary_type == 'file':
			primary = FileStorage(primary_config)
		elif primary_type == 'database':
			primary = DatabaseStorage(primary_config)

		if fallback_type and fallback_config:
			if fallback_type == 'file':
				fallback = FileStorage(fallback_config)
			elif fallback_type == 'database':
				fallback = DatabaseStorage(fallback_config)

		return HybridStorage(primary, fallback)

class AuthenticationProvider(ABC):
	@abstractmethod
	def authenticate(self, credentials):
		pass

	@abstractmethod
	def validate_token(self, token):
		pass

	@abstractmethod
	def get_user_info(self, user_id):
		pass

	@abstractmethod
	async def authenticate_async(self, credentials):
		pass

	@abstractmethod
	async def validate_token_async(self, token):
		pass

class BasicAuthProvider(AuthenticationProvider):
	def __init__(self, storage):
		self.storage = storage

	def authenticate(self, credentials):
		if not isinstance(credentials, dict) or 'username' not in credentials or 'password' not in credentials:
			return None
		
		username = credentials.get('username')
		password = credentials.get('password')
		
		stored_hash = self.storage.get(f'user:{username}:password_hash')
		if not stored_hash:
			return None
		
		password_hash = hashlib.sha256(password.encode()).hexdigest()
		if password_hash == stored_hash:
			user_id = self.storage.get(f'user:{username}:id')
			return {'user_id': user_id, 'username': username, 'provider': 'basic'}
		
		return None

	def validate_token(self, token):
		user_data = self.storage.get(f'token:{token}')
		if user_data:
			try:
				data = json.loads(user_data)
				if time.time() - data.get('created_at', 0) < 3600:
					return data
			except json.JSONDecodeError:
				pass
		return None

	def get_user_info(self, user_id):
		user_info = self.storage.get(f'user_info:{user_id}')
		if user_info:
			try:
				return json.loads(user_info)
			except json.JSONDecodeError:
				pass
		return None

	async def authenticate_async(self, credentials):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.authenticate, credentials)

	async def validate_token_async(self, token):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.validate_token, token)

class TokenAuthProvider(AuthenticationProvider):
	def __init__(self, storage, secret_key):
		self.storage = storage
		self.secret_key = secret_key

	def authenticate(self, credentials):
		if not isinstance(credentials, dict) or 'api_key' not in credentials:
			return None
		
		api_key = credentials.get('api_key')
		api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
		
		user_id = self