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

import asyncio
import uuid
import inspect
import os
import json
import sqlite3
import threading
from threading import Lock, RLock, Condition
from flask import redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html
from functools import wraps
from abc import ABC, abstractmethod
from collections import defaultdict
from time import time
from pathlib import Path
from queue import Queue
import weakref

def get_config_value(key, default=None, env_var=None):
	if env_var is None:
		env_var = f"BENCHMARK_{key.upper()}"
	
	env_value = os.getenv(env_var)
	if env_value is not None:
		if env_value.lower() in ('true', '1', 'yes'):
			return True
		elif env_value.lower() in ('false', '0', 'no'):
			return False
		try:
			return int(env_value)
		except ValueError:
			return env_value
	
	return default

class StorageProvider(ABC):
	@abstractmethod
	def save(self, key, value):
		pass
	
	@abstractmethod
	def load(self, key):
		pass
	
	@abstractmethod
	def delete(self, key):
		pass
	
	@abstractmethod
	def exists(self, key):
		pass
	
	@abstractmethod
	def get_all(self):
		pass

class FileStorageProvider(StorageProvider):
	def __init__(self, base_path=None):
		if base_path is None:
			base_path = os.path.join(os.getcwd(), '.benchmark_storage')
		self.base_path = Path(base_path)
		self.base_path.mkdir(parents=True, exist_ok=True)
		self.lock = RLock()
	
	def _get_file_path(self, key):
		safe_key = key.replace('/', '_').replace('\\', '_')
		return self.base_path / f"{safe_key}.json"
	
	def save(self, key, value):
		with self.lock:
			file_path = self._get_file_path(key)
			with open(file_path, 'w') as f:
				json.dump(value, f)
	
	def load(self, key):
		with self.lock:
			file_path = self._get_file_path(key)
			if file_path.exists():
				with open(file_path, 'r') as f:
					return json.load(f)
		return None
	
	def delete(self, key):
		with self.lock:
			file_path = self._get_file_path(key)
			if file_path.exists():
				file_path.unlink()
				return True
		return False
	
	def exists(self, key):
		with self.lock:
			file_path = self._get_file_path(key)
			return file_path.exists()
	
	def get_all(self):
		with self.lock:
			result = {}
			for file_path in self.base_path.glob("*.json"):
				key = file_path.stem
				with open(file_path, 'r') as f:
					result[key] = json.load(f)
			return result

class DatabaseStorageProvider(StorageProvider):
	def __init__(self, db_path=None, db_type='sqlite'):
		if db_path is None:
			db_path = os.path.join(os.getcwd(), '.benchmark_storage.db')
		self.db_path = db_path
		self.db_type = db_type
		self.lock = RLock()
		self._init_database()
	
	def _init_database(self):
		with self.lock:
			if self.db_type == 'sqlite':
				conn = sqlite3.connect(self.db_path)
				cursor = conn.cursor()
				cursor.execute('''
					CREATE TABLE IF NOT EXISTS storage (
						key TEXT PRIMARY KEY,
						value TEXT NOT NULL,
						created_at REAL,
						updated_at REAL
					)
				''')
				conn.commit()
				conn.close()
	
	def save(self, key, value):
		with self.lock:
			if self.db_type == 'sqlite':
				conn = sqlite3.connect(self.db_path)
				cursor = conn.cursor()
				current_time = time()
				value_json = json.dumps(value)
				
				cursor.execute('SELECT key FROM storage WHERE key = ?', (key,))
				exists = cursor.fetchone() is not None
				
				if exists:
					cursor.execute('''
						UPDATE storage SET value = ?, updated_at = ? WHERE key = ?
					''', (value_json, current_time, key))
				else:
					cursor.execute('''
						INSERT INTO storage (key, value, created_at, updated_at)
						VALUES (?, ?, ?, ?)
					''', (key, value_json, current_time, current_time))
				
				conn.commit()
				conn.close()
	
	def load(self, key):
		with self.lock:
			if self.db_type == 'sqlite':
				conn = sqlite3.connect(self.db_path)
				cursor = conn.cursor()
				cursor.execute('SELECT value FROM storage WHERE key = ?', (key,))
				result = cursor.fetchone()
				conn.close()
				
				if result:
					return json.loads(result[0])
		return None
	
	def delete(self, key):
		with self.lock:
			if self.db_type == 'sqlite':
				conn = sqlite3.connect(self.db_path)
				cursor = conn.cursor()
				cursor.execute('DELETE FROM storage WHERE key = ?', (key,))
				rows_affected = cursor.rowcount
				conn.commit()
				conn.close()
				return rows_affected > 0
		return False
	
	def exists(self, key):
		with self.lock:
			if self.db_type == 'sqlite':
				conn = sqlite3.connect(self.db_path)
				cursor = conn.cursor()
				cursor.execute('SELECT 1 FROM storage WHERE key = ?', (key,))
				result = cursor.fetchone()
				conn.close()
				return result is not None
		return False
	
	def get_all(self):
		with self.lock:
			result = {}
			if self.db_type == 'sqlite':
				conn = sqlite3.connect(self.db_path)
				cursor = conn.cursor()
				cursor.execute('SELECT key, value FROM storage')
				rows = cursor.fetchall()
				conn.close()
				
				for key, value in rows:
					result[key] = json.loads(value)
			return result

class AuthenticationProvider(ABC):
	def __init__(self, name, storage_provider=None):
		self.name = name
		self.storage_provider = storage_provider
	
	@abstractmethod
	def authenticate(self, credentials):
		pass
	
	@abstractmethod
	def validate_token(self, token):
		pass
	
	@abstractmethod
	def get_user_info(self, token):
		pass

class BasicAuthProvider(AuthenticationProvider):
	def __init__(self, storage_provider=None):
		super().__init__('basic', storage_provider)
		self.users = {}
		self.users_lock = RLock()
		if storage_provider:
			self.users = storage_provider.load('basic_auth_users') or {}
	
	def add_user(self, username, password):
		with self.users_lock:
			self.users[username] = password
			if self.storage_provider:
				self.storage_provider.save('basic_auth_users', self.users)
	
	def authenticate(self, credentials):
		if isinstance(credentials, dict) and 'username' in credentials and 'password' in credentials:
			username = credentials['username']
			password = credentials['password']
			with self.users_lock:
				if username in self.users and self.users[username] == password:
					return str(uuid.uuid4())
		return None
	
	def validate_token(self, token):
		return token is not None and isinstance(token, str) and len(token) > 0
	
	def get_user_info(self, token):
		return {'provider': 'basic', 'token': token}

class TokenAuthProvider(AuthenticationProvider):
	def __init__(self, storage_provider=None):
		super().__init__('token', storage_provider)
		self.valid_tokens = set()
		self.tokens_lock = RLock()
		if storage_provider:
			tokens_list = storage_provider.load('token_auth_tokens') or []
			self.valid_tokens = set(tokens_list)
	
	def add_token(self, token):
		with self.tokens_lock:
			self.valid_tokens.add(token)
			if self.storage_provider:
				self.storage_provider.save('token_auth_tokens', list(self.valid_tokens))
	
	def authenticate(self, credentials):
		if isinstance(credentials, dict) and 'token' in credentials:
			token = credentials['token']
			with self.tokens_lock:
				if token in self.valid_tokens:
					return token
		return None
	
	def validate_token(self, token):
		with self.tokens_lock:
			return token in self.valid_tokens
	
	def get_user_info(self, token):
		return {'provider': 'token', 'token': token}

class APIKeyAuthProvider(AuthenticationProvider):
	def __init__(self, storage_provider=None):
		super().__init__('apikey', storage_provider)
		self.api_keys = {}
		self.keys_lock = RLock()
		if storage_provider:
			self.api_keys = storage_provider.load('apikey_auth_keys') or {}
	
	def add_api_key(self, key, user_id):
		with self.keys_lock:
			self.api_keys[key] = user_id
			if self.storage_provider:
				self.storage_provider.save('apikey_auth_keys', self.api_keys)
	
	def authenticate(self, credentials):
		if isinstance(credentials, dict) and 'api_key' in credentials:
			api_key = credentials['api_key']
			with self.keys_lock:
				if api_key in self.api_keys:
					return api_key
		return None
	
	def validate_token(self, token):
		with self.keys_lock:
			return token in self.api_keys
	
	def get_user_info(self, token):
		with self.keys_lock:
			return {'provider': 'apikey', 'user_id': self.api_keys.get(token), 'token': token}

class OAuth2Provider(AuthenticationProvider):
	def __init__(self, client_id, client_secret, storage_provider=None):
		super().__init__('oauth2', storage_provider)
		self.client_id = client_id
		self.client_secret = client_secret
		self.authorization_codes = {}
		self.access_tokens = {}
		self.oauth_lock = RLock()
		
		if storage_provider:
			self.authorization_codes = storage_provider.load('oauth2_auth_codes') or {}
			self.access_tokens = storage_provider.load('oauth2_access_tokens') or {}
	
	def generate_authorization_code(self, user_id):
		code = str(uuid.uuid4())
		with self.oauth_lock:
			self.authorization_codes[code] = {'user_id': user_id, 'created_at': time()}
			if self.storage_provider:
				self.storage_provider.save('oauth2_auth_codes', self.authorization_codes)
		return code
	
	def authenticate(self, credentials):
		if isinstance(credentials, dict):
			if 'code' in credentials:
				code = credentials['code']
				with self.oauth_lock:
					if code in self.authorization_codes:
						auth_data = self.authorization_codes[code]
						if time() - auth_data['created_at'] < 600:
							access_token = str(uuid.uuid4())
							self.access_tokens[access_token] = {
								'user_id': auth_data['user_id'],
								'created_at': time()
							}
							del self.authorization_codes[code]
							if self.storage_provider:
								self.storage_provider.save('oauth2_auth_codes', self.authorization_codes)
								self.storage_provider.save('oauth2_access_tokens', self.access_tokens)
							return access_token
		return None
	
	def validate_token(self, token):
		with self.oauth_lock:
			if token in self.access_tokens:
				token_data = self.access_tokens[token]
				if time() - token_data['created_at'] < 3600:
					return True
				else:
					del self.access_tokens[token]
					if self.storage_provider:
						self.storage_provider.save('oauth2_access_tokens', self.access_tokens)
		return False
	
	def get_user_info(self, token):
		with self.oauth_lock:
			if token in self.access_tokens:
				return {
					'provider': 'oauth2',
					'user_id': self.access_tokens[token]['user_id'],
					'token': token
				}
		return None

class LDAPAuthProvider(AuthenticationProvider):
	def __init__(self, storage_provider=None):
		super().__init__('ldap', storage_provider)
		self.users = {}
		self.users_lock = RLock()
		if storage_provider:
			self.users = storage_provider.load('ldap_auth_users') or {}
	
	def add_user(self, username, password):
		with self.users_lock:
			self.users[username] = password
			if self.storage_provider:
				self.storage_provider.save('ldap_auth_users', self.users)
	
	def authenticate(self, credentials):
		if isinstance(credentials, dict) and 'username' in credentials and 'password' in credentials:
			username = credentials['username']
			password = credentials['password']
			with self.users_lock:
				if username in self.users and self.users[username] == password:
					return str(uuid.uuid4())
		return None
	
	def validate_token(self, token):
		return token is not None and isinstance(token, str) and len(token) > 0
	
	def get_user_info(self, token):
		return {'provider': 'ldap', 'token': token}

class SessionData:
	def __init__(self, session_id, user_info=None):
		self.session_id = session_id
		self.data = {}
		self.lock = RLock()
		self.condition = Condition(self.lock)
		self.created_at = time()
		self.last_accessed = time()
		self.user_info = user_info
		self.access_count = 0
		self.is_valid = True
	
	def get(self, key, default=None):
		with self.lock:
			self.last_accessed = time()
			self.access_count += 1
			return self.data.get(key, default)
	
	def set(self, key, value):
		with self