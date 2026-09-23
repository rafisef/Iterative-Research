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
	async def get_async(self, key):
		pass

	@abstractmethod
	async def set_async(self, key, value):
		pass

	@abstractmethod
	async def exists_async(self, key):
		pass

class FileStorage(StorageBackend):
	def __init__(self, storage_dir):
		self.storage_dir = storage_dir
		self.lock = threading.RLock()
		os.makedirs(storage_dir, exist_ok=True)

	def _get_path(self, key):
		return os.path.join(self.storage_dir, f'{key}.json')

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
					json.dump({'value': value}, f)
			except IOError:
				pass

	def exists(self, key):
		with self.lock:
			return os.path.exists(self._get_path(key))

	async def get_async(self, key):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.get, key)

	async def set_async(self, key, value):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.set, key, value)

	async def exists_async(self, key):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.exists, key)

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
						value TEXT NOT NULL
					)
				''')
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
					'INSERT OR REPLACE INTO storage (key, value) VALUES (?, ?)',
					(key, value)
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

	async def get_async(self, key):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.get, key)

	async def set_async(self, key, value):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.set, key, value)

	async def exists_async(self, key):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.exists, key)

class SessionManager:
	def __init__(self, timeout=1800):
		self.sessions = {}
		self.session_lock = threading.RLock()
		self.timeout = timeout
		self.cleanup_thread = threading.Thread(daemon=True, target=self._cleanup_expired_sessions)
		self.cleanup_thread.start()

	def create_session(self, user_id):
		session_id = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
		with self.session_lock:
			self.sessions[session_id] = {
				'user_id': user_id,
				'created_at': time.time(),
				'last_accessed': time.time(),
				'data': {}
			}
		return session_id

	def get_session(self, session_id):
		with self.session_lock:
			if session_id in self.sessions:
				session = self.sessions[session_id]
				if time.time() - session['created_at'] < self.timeout:
					session['last_accessed'] = time.time()
					return session
				else:
					del self.sessions[session_id]
		return None

	def set_session_data(self, session_id, key, value):
		with self.session_lock:
			if session_id in self.sessions:
				self.sessions[session_id]['data'][key] = value
				return True
		return False

	def get_session_data(self, session_id, key):
		with self.session_lock:
			if session_id in self.sessions:
				return self.sessions[session_id]['data'].get(key)
		return None

	def destroy_session(self, session_id):
		with self.session_lock:
			if session_id in self.sessions:
				del self.sessions[session_id]
				return True
		return False

	async def create_session_async(self, user_id):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.create_session, user_id)

	async def get_session_async(self, session_id):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.get_session, session_id)

	async def set_session_data_async(self, session_id, key, value):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.set_session_data, session_id, key, value)

	async def get_session_data_async(self, session_id, key):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.get_session_data, session_id, key)

	async def destroy_session_async(self, session_id):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.destroy_session, session_id)

	def _cleanup_expired_sessions(self):
		while True:
			time.sleep(300)
			with self.session_lock:
				current_time = time.time()
				expired_sessions = [
					sid for sid, session in self.sessions.items()
					if current_time - session['created_at'] >= self.timeout
				]
				for sid in expired_sessions:
					del self.sessions[sid]

class AuthenticationProvider(ABC):
	@abstractmethod
	def authenticate(self, credentials):
		pass

	@abstractmethod
	def validate_session(self, session_token):
		pass

	@abstractmethod
	def create_session(self, user_id):
		pass

	@abstractmethod
	def logout(self, session_token):
		pass

	@abstractmethod
	async def authenticate_async(self, credentials):
		pass

	@abstractmethod
	async def validate_session_async(self, session_token):
		pass

	@abstractmethod
	async def create_session_async(self, user_id):
		pass

	@abstractmethod
	async def logout_async(self, session_token):
		pass

	def _generate_token(self, length=32):
		return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

class BasicAuthProvider(AuthenticationProvider):
	def __init__(self, storage, session_manager=None):
		self.storage = storage
		self.session_manager = session_manager or SessionManager()
		self.provider_type = 'basic'
		self.lock = threading.RLock()

	def authenticate(self, credentials):
		if not credentials or ':' not in credentials:
			return None
		username, password = credentials.split(':', 1)
		stored_password = self.storage.get(f'user:{username}')
		if stored_password and stored_password == password:
			return username
		return None

	def validate_session(self, session_token):
		session = self.session_manager.get_session(session_token)
		return session['user_id'] if session else None

	def create_session(self, user_id):
		return self.session_manager.create_session(user_id)

	def logout(self, session_token):
		return self.session_manager.destroy_session(session_token)

	async def authenticate_async(self, credentials):
		if not credentials or ':' not in credentials:
			return None
		username, password = credentials.split(':', 1)
		stored_password = await self.storage.get_async(f'user:{username}')
		if stored_password and stored_password == password:
			return username
		return None

	async def validate_session_async(self, session_token):
		session = await self.session_manager.get_session_async(session_token)
		return session['user_id'] if session else None

	async def create_session_async(self, user_id):
		return await self.session_manager.create_session_async(user_id)

	async def logout_async(self, session_token):
		return await self.session_manager.destroy_session_async(session_token)

class CookieAuthProvider(AuthenticationProvider):
	def __init__(self, storage, session_manager=None):
		self.storage = storage
		self.session_manager = session_manager or SessionManager()
		self.provider_type = 'cookie'
		self.lock = threading.RLock()

	def authenticate(self, credentials):
		if not credentials:
			return None
		user_id = self.storage.get(f'cookie_user:{credentials}')
		return user_id

	def validate_session(self, session_token):
		session = self.session_manager.get_session(session_token)
		return session['user_id'] if session else None

	def create_session(self, user_id):
		return self.session_manager.create_session(user_id)

	def logout(self, session_token):
		return self.session_manager.destroy_session(session_token)

	async def authenticate_async(self, credentials):
		if not credentials:
			return None
		user_id = await self.storage.get_async(f'cookie_user:{credentials}')
		return user_id

	async def validate_session_async(self, session_token):
		session = await self.session_manager.get_session_async(session_token)
		return session['user_id'] if session else None

	async def create_session_async(self, user_id):
		return await self.session_manager.create_session_async(user_id)

	async def logout_async(self, session_token):
		return await self.session_manager.destroy_session_async(session_token)

class TokenAuthProvider(AuthenticationProvider):
	def __init__(self, storage, session_manager=None):
		self.storage = storage
		self.session_manager = session_manager or SessionManager()
		self.provider_type = 'token'
		self.lock = threading.RLock()

	def authenticate(self, credentials):
		if not credentials:
			return None
		user_id = self.storage.get(f'token_user:{credentials}')
		return user_id

	def validate_session(self, session_token):
		session = self.session_manager.get_session(session_token)
		return session['user_id'] if session else None

	def create_session(self, user_id):
		return self.session_manager.create_session(user_id)

	def logout(self, session_token):
		return self.session_manager.destroy_session(session_token)

	async def authenticate_async(self, credentials):
		if not credentials:
			return None
		user_id = await self.storage.get_async(f'token_user:{credentials}')
		return user_id

	async def validate_session_async(self, session_token):
		session = await self.session_manager.get_session_async(session_token)
		return session['user_id'] if session else None

	async def create_session_async(self, user_id):
		return await self.session_manager.create_session_async(user_id)

	async def logout_async(self, session_token):
		return await self.session_manager.destroy_session_async(session_token)

class OAuthProvider(AuthenticationProvider):
	def __init__(self, storage, client_id, client_secret, session_manager=None):
		self.storage = storage
		self.session_manager = session_manager or SessionManager()
		self.provider_type = 'oauth'
		self.client_id = client_id
		self.client_secret = client_secret
		self.lock = threading.RLock()

	def authenticate(self, credentials):
		if not credentials:
			return None
		user_id = self.storage.get(f'oauth_user:{credentials}')
		return user_id

	def validate_session(self, session_token):
		session = self.session_manager.get_session(session_token)
		return session['user_id'] if session else None

	def create_session(self, user_id):
		return self.session_manager.create_session(user_id)

	def logout(self, session_token):
		return self.session_manager.destroy_session(session_token)

	async def authenticate_async(self, credentials):
		if not credentials:
			return None
		user_id = await self.storage.get_async(f'oauth_user:{credentials}')
		return user_id

	async def validate_session_async(self, session_token):
		session = await self.session_manager.get_session_async(session_token)
		return session['user_id'] if session else None