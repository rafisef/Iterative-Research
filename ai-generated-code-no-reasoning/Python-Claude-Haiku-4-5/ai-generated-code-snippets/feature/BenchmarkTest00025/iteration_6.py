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

class LDAPAuthProvider(AuthenticationProvider):
	def __init__(self, storage, ldap_server=None, session_manager=None):
		self.storage = storage
		self.session_manager = session_manager or SessionManager()
		self.provider_type = 'ldap'
		self.ldap_server = ldap_server
		self.lock = threading.RLock()

	def authenticate(self, credentials):
		if not credentials or ':' not in credentials:
			return None
		username, password = credentials.split(':', 1)
		stored_password = self.storage.get(f'ldap_user:{username}')
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

class Config:
	def __init__(self, config_file=None):
		self.config_data = {}
		
		if config_file and os.path.exists(config_file):
			try:
				with open(config_file, 'r') as f:
					self.config_data = json.load(f)
			except (json.JSONDecodeError, IOError):
				pass
		
		self.cookie_max_age = self._get_config('BENCHMARK_COOKIE_MAX_AGE', 'cookie_max_age', 180, int)
		self.cookie_secure = self._get_config('BENCHMARK_COOKIE_SECURE', 'cookie_secure', 'True', lambda x: str(x).lower() == 'true')
		self.cookie_domain = self._get_config('BENCHMARK_COOKIE_DOMAIN', 'cookie_domain', 'localhost', str)
		self.cookie_path = self._get_config('BENCHMARK_COOKIE_PATH', 'cookie_path', '/benchmark/weakrand-00/BenchmarkTest00025', str)
		self.route_prefix = self._get_config('BENCHMARK_ROUTE_PREFIX', 'route_prefix', '/benchmark/weakrand-00', str)
		self.template_path = self._get_config('BENCHMARK_TEMPLATE_PATH', 'template_path', 'web/weakrand-00/BenchmarkTest00025.html', str)
		self.storage_type = self._get_config('BENCHMARK_STORAGE_TYPE', 'storage_type', 'file', lambda x: str(x).lower())
		self.storage_path = self._get_config('BENCHMARK_STORAGE_PATH', 'storage_path', './benchmark_storage', str)
		self.auth_providers = self._get_config('BENCHMARK_AUTH_PROVIDERS', 'auth_providers', 'basic,cookie,token', lambda x: str(x).lower().split(','))
		self.db_path = self._get_config('BENCHMARK_DB_PATH', 'db_path', '', str)
		self.oauth_client_id = self._get_config('BENCHMARK_OAUTH_CLIENT_ID', 'oauth_client_id', '', str)
		self.oauth_client_secret = self._get_config('BENCHMARK_OAUTH_CLIENT_SECRET', 'oauth_client_secret', '', str)
		self.ldap_server = self._get_config('BENCHMARK_LDAP_SERVER', 'ldap_server', '', str)
		self.session_timeout = self._get_config('BENCHMARK_SESSION_TIMEOUT', 'session_timeout', 1800, int)

	def _get_config(self, env_var, config_key, default, type_converter):
		env_value = os.getenv(env_var)
		if env_value is not None:
			try:
				return type_converter(env_value)
			except (ValueError, TypeError):
				pass
		
		if config_key in self.config_data:
			try:
				return type_converter(self.config_data[config_key])
			except (ValueError, TypeError):
				pass
		
		if callable(type_converter):
			try:
				return type_converter(default)
			except (ValueError, TypeError):
				return default
		return default

	def get_storage(self):
		if self.storage_type == 'database':
			db_path = self.db_path if self.db_path else os.path.join(self.storage_path, 'benchmark.db')
			return DatabaseStorage(db_path)
		else:
			return FileStorage(self.storage_path)

	def get_auth_providers(self, storage, session_manager):
		providers = {}
		provider_map = {
			'basic': lambda s, sm: BasicAuthProvider(s, sm),
			'cookie': lambda s, sm: CookieAuthProvider(s, sm),
			'token': lambda s, sm: TokenAuthProvider(s, sm),
			'oauth': lambda s, sm: OAuthProvider(s, self.oauth_client_id, self.oauth_client_secret, sm),
			'ldap': lambda s, sm: LDAPAuthProvider(s, self.ldap_server, sm),
		}
		for provider_name in self.auth_providers:
			provider_name = provider_name.strip()
			if provider_name in provider_map:
				try:
					providers[provider_name