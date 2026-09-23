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
from abc import ABC, abstractmethod
from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html

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
		os.makedirs(storage_dir, exist_ok=True)

	def _get_path(self, key):
		return os.path.join(self.storage_dir, f'{key}.json')

	def get(self, key):
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
		path = self._get_path(key)
		try:
			with open(path, 'w') as f:
				json.dump({'value': value}, f)
		except IOError:
			pass

	def exists(self, key):
		return os.path.exists(self._get_path(key))

class DatabaseStorage(StorageBackend):
	def __init__(self, db_path):
		self.db_path = db_path
		self._init_db()

	def _init_db(self):
		try:
			conn = sqlite3.connect(self.db_path)
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
			conn = sqlite3.connect(self.db_path)
			cursor = conn.cursor()
			cursor.execute('SELECT value FROM storage WHERE key = ?', (key,))
			result = cursor.fetchone()
			conn.close()
			return result[0] if result else None
		except sqlite3.Error:
			return None

	def set(self, key, value):
		try:
			conn = sqlite3.connect(self.db_path)
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
			conn = sqlite3.connect(self.db_path)
			cursor = conn.cursor()
			cursor.execute('SELECT 1 FROM storage WHERE key = ?', (key,))
			result = cursor.fetchone()
			conn.close()
			return result is not None
		except sqlite3.Error:
			return False

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
	def __init__(self, storage):
		self.storage = storage
		self.provider_type = 'basic'

	def authenticate(self, credentials):
		if not credentials or ':' not in credentials:
			return None
		username, password = credentials.split(':', 1)
		stored_password = self.storage.get(f'user:{username}')
		if stored_password and stored_password == password:
			return username
		return None

	def validate_session(self, session_token):
		return self.storage.get(f'session:{session_token}')

	def create_session(self, user_id):
		token = self._generate_token()
		self.storage.set(f'session:{token}', user_id)
		return token

	def logout(self, session_token):
		key = f'session:{session_token}'
		if self.storage.exists(key):
			self.storage.set(key, '')
			return True
		return False

class CookieAuthProvider(AuthenticationProvider):
	def __init__(self, storage):
		self.storage = storage
		self.provider_type = 'cookie'

	def authenticate(self, credentials):
		if not credentials:
			return None
		user_id = self.storage.get(f'cookie_user:{credentials}')
		return user_id

	def validate_session(self, session_token):
		return self.storage.get(f'cookie_session:{session_token}')

	def create_session(self, user_id):
		token = self._generate_token()
		self.storage.set(f'cookie_session:{token}', user_id)
		return token

	def logout(self, session_token):
		key = f'cookie_session:{session_token}'
		if self.storage.exists(key):
			self.storage.set(key, '')
			return True
		return False

class TokenAuthProvider(AuthenticationProvider):
	def __init__(self, storage):
		self.storage = storage
		self.provider_type = 'token'

	def authenticate(self, credentials):
		if not credentials:
			return None
		user_id = self.storage.get(f'token_user:{credentials}')
		return user_id

	def validate_session(self, session_token):
		return self.storage.get(f'token_session:{session_token}')

	def create_session(self, user_id):
		token = self._generate_token()
		self.storage.set(f'token_session:{token}', user_id)
		return token

	def logout(self, session_token):
		key = f'token_session:{session_token}'
		if self.storage.exists(key):
			self.storage.set(key, '')
			return True
		return False

class OAuthProvider(AuthenticationProvider):
	def __init__(self, storage, client_id, client_secret):
		self.storage = storage
		self.provider_type = 'oauth'
		self.client_id = client_id
		self.client_secret = client_secret

	def authenticate(self, credentials):
		if not credentials:
			return None
		user_id = self.storage.get(f'oauth_user:{credentials}')
		return user_id

	def validate_session(self, session_token):
		return self.storage.get(f'oauth_session:{session_token}')

	def create_session(self, user_id):
		token = self._generate_token()
		self.storage.set(f'oauth_session:{token}', user_id)
		return token

	def logout(self, session_token):
		key = f'oauth_session:{session_token}'
		if self.storage.exists(key):
			self.storage.set(key, '')
			return True
		return False

class LDAPAuthProvider(AuthenticationProvider):
	def __init__(self, storage, ldap_server=None):
		self.storage = storage
		self.provider_type = 'ldap'
		self.ldap_server = ldap_server

	def authenticate(self, credentials):
		if not credentials or ':' not in credentials:
			return None
		username, password = credentials.split(':', 1)
		stored_password = self.storage.get(f'ldap_user:{username}')
		if stored_password and stored_password == password:
			return username
		return None

	def validate_session(self, session_token):
		return self.storage.get(f'ldap_session:{session_token}')

	def create_session(self, user_id):
		token = self._generate_token()
		self.storage.set(f'ldap_session:{token}', user_id)
		return token

	def logout(self, session_token):
		key = f'ldap_session:{session_token}'
		if self.storage.exists(key):
			self.storage.set(key, '')
			return True
		return False

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

	def get_auth_providers(self, storage):
		providers = {}
		provider_map = {
			'basic': lambda s: BasicAuthProvider(s),
			'cookie': lambda s: CookieAuthProvider(s),
			'token': lambda s: TokenAuthProvider(s),
			'oauth': lambda s: OAuthProvider(s, self.oauth_client_id, self.oauth_client_secret),
			'ldap': lambda s: LDAPAuthProvider(s, self.ldap_server),
		}
		for provider_name in self.auth_providers:
			provider_name = provider_name.strip()
			if provider_name in provider_map:
				try:
					providers[provider_name] = provider_map[provider_name](storage)
				except Exception:
					pass
		return providers

class AuthenticationManager:
	def __init__(self, providers):
		self.providers = providers

	def authenticate(self, provider_name, credentials):
		if provider_name not in self.providers:
			return None
		return self.providers[provider_name].authenticate(credentials)

	def validate_session(self, provider_name, session_token):
		if provider_name not in self.providers:
			return None
		return self.providers[provider_name].validate_session(session_token)

	def create_session(self, provider_name, user_id):
		if provider_name not in self.providers:
			return None
		return self.providers[provider_name].create_session(user_id)

	def logout(self, provider_name, session_token):
		if provider_name not in self.providers:
			return False
		return self.providers[provider_name].logout(session_token)

	def get_available_providers(self):
		return list(self.providers.keys())

	def register_custom_provider(self, provider_name, provider_instance):
		if isinstance(provider_instance, AuthenticationProvider):
			self.providers[provider_name] = provider_instance
			return True
		return False

def init(app, config_file=None):
	config = Config(config_file)
	storage = config.get_storage()
	auth_providers = config.get_auth_providers(storage)
	auth_manager = AuthenticationManager(auth_providers)

	@app.route(f'{config.route_prefix}/BenchmarkTest00025', methods=['GET'])
	def BenchmarkTest00025_get():
		response = make_response(render_template(config.template_path))
		response.set_cookie('BenchmarkTest00025', 'whatever',
			max_age=config.cookie_max_age,
			secure=config.cookie_secure,
			path=config.cookie_path,
			domain=config.cookie_domain)
		return response

	@app.route(f'{config.route_prefix}/BenchmarkTest00025', methods=['POST'])
	def BenchmarkTest00025_post():
		RESPONSE = ""

		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00025", "noCookieValueSupplied"))

		superstring = f'90583{param}abcd'
		bar = superstring[len('90583'):len(superstring)-5]

		num = 'BenchmarkTest00025'[13:]
		user = f'Nancy{num}'
		cookie = f'rememberMe{num}'
		value = str(random.normalvariate())[2:]

		if storage.exists(cookie) and request.cookies.get(cookie) == storage.get(cookie):
			RESPONSE += (
				f'Welcome back: {user}<br/>'
			)
		else:
			storage.set(cookie, value)
			RESPONSE += (