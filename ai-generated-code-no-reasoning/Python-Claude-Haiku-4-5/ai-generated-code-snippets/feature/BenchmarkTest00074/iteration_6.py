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
import asyncio
import hashlib
import hmac
from abc import ABC, abstractmethod
from pathlib import Path
from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html

def get_config(key, default=None):
	env_key = f"BENCHMARK_{key.upper()}"
	return os.getenv(env_key, default)

class StorageProvider(ABC):
	@abstractmethod
	def save(self, key, data):
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
	def list_keys(self):
		pass

class FileStorageProvider(StorageProvider):
	def __init__(self, base_path=None):
		self.base_path = Path(base_path or get_config('file_storage_path', './data'))
		self.base_path.mkdir(parents=True, exist_ok=True)

	def _get_file_path(self, key):
		safe_key = key.replace('/', '_').replace('\\', '_')
		return self.base_path / f"{safe_key}.json"

	def save(self, key, data):
		try:
			file_path = self._get_file_path(key)
			with open(file_path, 'w') as f:
				json.dump(data, f)
			return True
		except Exception as e:
			print(f"Error saving to file: {e}")
			return False

	def load(self, key):
		try:
			file_path = self._get_file_path(key)
			if not file_path.exists():
				return None
			with open(file_path, 'r') as f:
				return json.load(f)
		except Exception as e:
			print(f"Error loading from file: {e}")
			return None

	def delete(self, key):
		try:
			file_path = self._get_file_path(key)
			if file_path.exists():
				file_path.unlink()
			return True
		except Exception as e:
			print(f"Error deleting file: {e}")
			return False

	def exists(self, key):
		file_path = self._get_file_path(key)
		return file_path.exists()

	def list_keys(self):
		try:
			keys = []
			for file_path in self.base_path.glob("*.json"):
				key = file_path.stem
				keys.append(key)
			return keys
		except Exception as e:
			print(f"Error listing keys: {e}")
			return []

class DatabaseStorageProvider(StorageProvider):
	def __init__(self, db_path=None, db_type='sqlite'):
		self.db_path = db_path or get_config('db_storage_path', './benchmark.db')
		self.db_type = db_type
		self._init_database()

	def _init_database(self):
		try:
			if self.db_type == 'sqlite':
				conn = sqlite3.connect(self.db_path)
				cursor = conn.cursor()
				cursor.execute('''
					CREATE TABLE IF NOT EXISTS storage (
						key TEXT PRIMARY KEY,
						data TEXT NOT NULL,
						created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
						updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
					)
				''')
				conn.commit()
				conn.close()
		except Exception as e:
			print(f"Error initializing database: {e}")

	def _get_connection(self):
		if self.db_type == 'sqlite':
			return sqlite3.connect(self.db_path)
		raise ValueError(f"Unsupported database type: {self.db_type}")

	def save(self, key, data):
		try:
			conn = self._get_connection()
			cursor = conn.cursor()
			data_str = json.dumps(data)
			cursor.execute('''
				INSERT OR REPLACE INTO storage (key, data, updated_at)
				VALUES (?, ?, CURRENT_TIMESTAMP)
			''', (key, data_str))
			conn.commit()
			conn.close()
			return True
		except Exception as e:
			print(f"Error saving to database: {e}")
			return False

	def load(self, key):
		try:
			conn = self._get_connection()
			cursor = conn.cursor()
			cursor.execute('SELECT data FROM storage WHERE key = ?', (key,))
			row = cursor.fetchone()
			conn.close()
			if row:
				return json.loads(row[0])
			return None
		except Exception as e:
			print(f"Error loading from database: {e}")
			return None

	def delete(self, key):
		try:
			conn = self._get_connection()
			cursor = conn.cursor()
			cursor.execute('DELETE FROM storage WHERE key = ?', (key,))
			conn.commit()
			conn.close()
			return True
		except Exception as e:
			print(f"Error deleting from database: {e}")
			return False

	def exists(self, key):
		try:
			conn = self._get_connection()
			cursor = conn.cursor()
			cursor.execute('SELECT 1 FROM storage WHERE key = ?', (key,))
			exists = cursor.fetchone() is not None
			conn.close()
			return exists
		except Exception as e:
			print(f"Error checking existence in database: {e}")
			return False

	def list_keys(self):
		try:
			conn = self._get_connection()
			cursor = conn.cursor()
			cursor.execute('SELECT key FROM storage')
			rows = cursor.fetchall()
			conn.close()
			return [row[0] for row in rows]
		except Exception as e:
			print(f"Error listing keys from database: {e}")
			return []

class AuthProvider(ABC):
	@abstractmethod
	def authenticate(self, credentials):
		pass

	@abstractmethod
	async def authenticate_async(self, credentials):
		pass

	@abstractmethod
	def validate_credentials(self, credentials):
		pass

class BasicAuthProvider(AuthProvider):
	def authenticate(self, credentials):
		if not self.validate_credentials(credentials):
			return False
		username, password = credentials.get('username'), credentials.get('password')
		expected_user = get_config('basic_auth_user', 'admin')
		expected_pass = get_config('basic_auth_pass', 'password')
		return username == expected_user and password == expected_pass

	async def authenticate_async(self, credentials):
		return await asyncio.to_thread(self.authenticate, credentials)

	def validate_credentials(self, credentials):
		return credentials and 'username' in credentials and 'password' in credentials

class TokenAuthProvider(AuthProvider):
	def authenticate(self, credentials):
		if not self.validate_credentials(credentials):
			return False
		token = credentials.get('token')
		valid_tokens = get_config('token_auth_tokens', 'token123,token456').split(',')
		return token in valid_tokens

	async def authenticate_async(self, credentials):
		return await asyncio.to_thread(self.authenticate, credentials)

	def validate_credentials(self, credentials):
		return credentials and 'token' in credentials

class OAuthProvider(AuthProvider):
	def authenticate(self, credentials):
		if not self.validate_credentials(credentials):
			return False
		oauth_token = credentials.get('oauth_token')
		oauth_secret = get_config('oauth_secret', 'secret123')
		return oauth_token and oauth_token == oauth_secret

	async def authenticate_async(self, credentials):
		return await asyncio.to_thread(self.authenticate, credentials)

	def validate_credentials(self, credentials):
		return credentials and 'oauth_token' in credentials

class LDAPAuthProvider(AuthProvider):
	def authenticate(self, credentials):
		if not self.validate_credentials(credentials):
			return False
		username = credentials.get('username')
		password = credentials.get('password')
		ldap_user = get_config('ldap_auth_user', 'admin')
		ldap_pass = get_config('ldap_auth_pass', 'password')
		return username == ldap_user and password == ldap_pass

	async def authenticate_async(self, credentials):
		return await asyncio.to_thread(self.authenticate, credentials)

	def validate_credentials(self, credentials):
		return credentials and 'username' in credentials and 'password' in credentials

class APIKeyAuthProvider(AuthProvider):
	def authenticate(self, credentials):
		if not self.validate_credentials(credentials):
			return False
		api_key = credentials.get('api_key')
		valid_keys = get_config('api_key_auth_keys', 'key123,key456').split(',')
		return api_key in valid_keys

	async def authenticate_async(self, credentials):
		return await asyncio.to_thread(self.authenticate, credentials)

	def validate_credentials(self, credentials):
		return credentials and 'api_key' in credentials

class HMACAuthProvider(AuthProvider):
	def authenticate(self, credentials):
		if not self.validate_credentials(credentials):
			return False
		message = credentials.get('message')
		signature = credentials.get('signature')
		secret = get_config('hmac_auth_secret', 'secret123')
		expected_signature = hmac.new(
			secret.encode(),
			message.encode(),
			hashlib.sha256
		).hexdigest()
		return hmac.compare_digest(signature, expected_signature)

	async def authenticate_async(self, credentials):
		return await asyncio.to_thread(self.authenticate, credentials)

	def validate_credentials(self, credentials):
		return credentials and 'message' in credentials and 'signature' in credentials

class CustomAuthProvider(AuthProvider):
	def __init__(self, auth_func, validate_func=None):
		self.auth_func = auth_func
		self.validate_func = validate_func or (lambda c: bool(c))

	def authenticate(self, credentials):
		if not self.validate_credentials(credentials):
			return False
		return self.auth_func(credentials)

	async def authenticate_async(self, credentials):
		return await asyncio.to_thread(self.authenticate, credentials)

	def validate_credentials(self, credentials):
		return self.validate_func(credentials)

class ChainAuthProvider(AuthProvider):
	def __init__(self, providers, require_all=True):
		self.providers = providers
		self.require_all = require_all

	def authenticate(self, credentials):
		results = [p.authenticate(credentials) for p in self.providers]
		return all(results) if self.require_all else any(results)

	async def authenticate_async(self, credentials):
		results = await asyncio.gather(*[p.authenticate_async(credentials) for p in self.providers])
		return all(results) if self.require_all else any(results)

	def validate_credentials(self, credentials):
		return all(p.validate_credentials(credentials) for p in self.providers) or any(p.validate_credentials(credentials) for p in self.providers)

class FallbackAuthProvider(AuthProvider):
	def __init__(self, providers):
		self.providers = providers

	def authenticate(self, credentials):
		for provider in self.providers:
			if provider.validate_credentials(credentials) and provider.authenticate(credentials):
				return True
		return False

	async def authenticate_async(self, credentials):
		for provider in self.providers:
			if provider.validate_credentials(credentials) and await provider.authenticate_async(credentials):
				return True
		return False

	def validate_credentials(self, credentials):
		return any(p.validate_credentials(credentials) for p in self.providers)

class AuthenticationManager:
	def __init__(self, storage_provider=None):
		self.providers = {}
		self.provider_configs = {}
		self.provider_strategies = {}
		self.storage_provider = storage_provider or FileStorageProvider()
		self.register_provider('basic', BasicAuthProvider())
		self.register_provider('token', TokenAuthProvider())
		self.register_provider('oauth', OAuthProvider())
		self.register_provider('ldap', LDAPAuthProvider())
		self.register_provider('apikey', APIKeyAuthProvider())
		self.register_provider('hmac', HMACAuthProvider())
		self._load_providers_from_storage()

	def set_storage_provider(self, storage_provider):
		if not isinstance(storage_provider, StorageProvider):
			raise TypeError("Storage provider must be an instance of StorageProvider")
		self.storage_provider = storage_provider
		self._load_providers_from_storage()

	def _save_provider_config(self, name):
		config_data = {
			'name': name,
			'provider_class': self.providers[name].__class__.__name__,
			'config': self.provider_configs.get(name, {}),
			'strategy': self.provider_strategies.get(name, 'single')
		}
		self.storage_provider.save(f"provider_{name}", config_data)

	def _load_providers_from_storage(self):
		keys = self.storage_provider.list_keys()
		for key in keys:
			if key.startswith('provider_'):
				try:
					data = self.storage_provider.load(key)
					if data:
						name = data.get('name')
						config = data.get('config', {})
						strategy = data.get('strategy', 'single')
						self.provider_configs[name] = config
						self.provider_strategies[name] = strategy
				except Exception as e:
					print(f"Error loading provider from storage: {e}")

	def register_provider(self, name, provider, config=None, strategy=None):
		if not isinstance(provider, AuthProvider):
			raise TypeError(f"Provider must be an instance of AuthProvider")
		self.providers[name] = provider
		self.provider_configs[name] = config or {}
		self.provider_strategies[name] = strategy or 'single'
		self._save_provider_config(name)

	def get_provider(self, name):
		return self.providers.get(name)

	def get_provider_config(self, name):
		return self.provider_configs.get(name, {})

	def get_provider_strategy(self, name):
		return self.provider_strategies.get(name, 'single')

	def authenticate(self, provider_name, credentials):
		provider = self.get_provider(provider_name)
		if not provider:
			return False
		return provider.authenticate(credentials)

	async def authenticate_async(self, provider_name, credentials):
		provider = self.get_provider(provider_name)
		if not provider:
			return False
		return await provider.authenticate_async(credentials)

	def authenticate_with_chain(self, provider_names, credentials_map, require_all=True):
		providers = [self.get_provider(name) for name in provider_names if self.has_provider(name)]
		if not providers:
			return False
		
		results = []
		for name, provider in zip(provider_names, providers):
			if self.has_provider(name):
				creds = credentials_map.get(name, {})
				results.append(provider.authenticate(creds))
		
		return all(results) if require_all else any(results)

	async def authenticate_with_chain_async(self, provider_names, credentials