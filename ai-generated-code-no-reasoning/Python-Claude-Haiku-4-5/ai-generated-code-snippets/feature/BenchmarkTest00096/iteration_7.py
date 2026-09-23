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
from threading import Lock, RLock
from flask import redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html
from functools import wraps
from abc import ABC, abstractmethod
from collections import defaultdict
from time import time

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

class AuthenticationProvider(ABC):
	def __init__(self, name):
		self.name = name
	
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
	def __init__(self):
		super().__init__('basic')
		self.users = {}
	
	def add_user(self, username, password):
		self.users[username] = password
	
	def authenticate(self, credentials):
		if isinstance(credentials, dict) and 'username' in credentials and 'password' in credentials:
			username = credentials['username']
			password = credentials['password']
			if username in self.users and self.users[username] == password:
				return str(uuid.uuid4())
		return None
	
	def validate_token(self, token):
		return token is not None and isinstance(token, str) and len(token) > 0
	
	def get_user_info(self, token):
		return {'provider': 'basic', 'token': token}

class TokenAuthProvider(AuthenticationProvider):
	def __init__(self):
		super().__init__('token')
		self.valid_tokens = set()
	
	def add_token(self, token):
		self.valid_tokens.add(token)
	
	def authenticate(self, credentials):
		if isinstance(credentials, dict) and 'token' in credentials:
			token = credentials['token']
			if token in self.valid_tokens:
				return token
		return None
	
	def validate_token(self, token):
		return token in self.valid_tokens
	
	def get_user_info(self, token):
		return {'provider': 'token', 'token': token}

class APIKeyAuthProvider(AuthenticationProvider):
	def __init__(self):
		super().__init__('apikey')
		self.api_keys = {}
	
	def add_api_key(self, key, user_id):
		self.api_keys[key] = user_id
	
	def authenticate(self, credentials):
		if isinstance(credentials, dict) and 'api_key' in credentials:
			api_key = credentials['api_key']
			if api_key in self.api_keys:
				return api_key
		return None
	
	def validate_token(self, token):
		return token in self.api_keys
	
	def get_user_info(self, token):
		return {'provider': 'apikey', 'user_id': self.api_keys.get(token), 'token': token}

class OAuth2Provider(AuthenticationProvider):
	def __init__(self, client_id, client_secret):
		super().__init__('oauth2')
		self.client_id = client_id
		self.client_secret = client_secret
		self.authorization_codes = {}
		self.access_tokens = {}
	
	def generate_authorization_code(self, user_id):
		code = str(uuid.uuid4())
		self.authorization_codes[code] = {'user_id': user_id, 'created_at': time()}
		return code
	
	def authenticate(self, credentials):
		if isinstance(credentials, dict):
			if 'code' in credentials:
				code = credentials['code']
				if code in self.authorization_codes:
					auth_data = self.authorization_codes[code]
					if time() - auth_data['created_at'] < 600:
						access_token = str(uuid.uuid4())
						self.access_tokens[access_token] = {
							'user_id': auth_data['user_id'],
							'created_at': time()
						}
						del self.authorization_codes[code]
						return access_token
		return None
	
	def validate_token(self, token):
		if token in self.access_tokens:
			token_data = self.access_tokens[token]
			if time() - token_data['created_at'] < 3600:
				return True
			else:
				del self.access_tokens[token]
		return False
	
	def get_user_info(self, token):
		if token in self.access_tokens:
			return {
				'provider': 'oauth2',
				'user_id': self.access_tokens[token]['user_id'],
				'token': token
			}
		return None

class LDAPAuthProvider(AuthenticationProvider):
	def __init__(self):
		super().__init__('ldap')
		self.users = {}
	
	def add_user(self, username, password):
		self.users[username] = password
	
	def authenticate(self, credentials):
		if isinstance(credentials, dict) and 'username' in credentials and 'password' in credentials:
			username = credentials['username']
			password = credentials['password']
			if username in self.users and self.users[username] == password:
				return str(uuid.uuid4())
		return None
	
	def validate_token(self, token):
		return token is not None and isinstance(token, str) and len(token) > 0
	
	def get_user_info(self, token):
		return {'provider': 'ldap', 'token': token}

class ConcurrentSessionManager:
	def __init__(self, session_timeout=3600):
		self.sessions = {}
		self.session_lock = RLock()
		self.session_timeout = session_timeout
		self.user_sessions = defaultdict(set)
	
	def create_session(self, session_id, user_info=None):
		with self.session_lock:
			self.sessions[session_id] = {
				'data': {},
				'lock': RLock(),
				'created_at': time(),
				'last_accessed': time(),
				'user_info': user_info
			}
			if user_info:
				self.user_sessions[user_info.get('token')].add(session_id)
	
	def get_session(self, session_id):
		with self.session_lock:
			if session_id in self.sessions:
				session_data = self.sessions[session_id]
				if time() - session_data['last_accessed'] > self.session_timeout:
					del self.sessions[session_id]
					return None
				session_data['last_accessed'] = time()
				return session_data
		return None
	
	def update_session_data(self, session_id, key, value):
		session_data = self.get_session(session_id)
		if session_data:
			with session_data['lock']:
				session_data['data'][key] = value
				return True
		return False
	
	def get_session_data(self, session_id, key=None):
		session_data = self.get_session(session_id)
		if session_data:
			with session_data['lock']:
				if key:
					return session_data['data'].get(key)
				return session_data['data'].copy()
		return None
	
	def clear_session(self, session_id):
		with self.session_lock:
			if session_id in self.sessions:
				del self.sessions[session_id]
				return True
		return False
	
	def clear_user_sessions(self, token):
		with self.session_lock:
			sessions = self.user_sessions.get(token, set()).copy()
			for session_id in sessions:
				if session_id in self.sessions:
					del self.sessions[session_id]
			if token in self.user_sessions:
				del self.user_sessions[token]

class AuthenticationManager:
	def __init__(self, session_manager):
		self.providers = {}
		self.active_tokens = {}
		self.token_lock = RLock()
		self.session_manager = session_manager
		self.provider_strategies = {}
	
	def register_provider(self, provider):
		self.providers[provider.name] = provider
	
	def register_provider_strategy(self, provider_name, strategy_func):
		self.provider_strategies[provider_name] = strategy_func
	
	def authenticate(self, provider_name, credentials):
		if provider_name not in self.providers:
			return None
		
		provider = self.providers[provider_name]
		
		if provider_name in self.provider_strategies:
			strategy = self.provider_strategies[provider_name]
			token = strategy(provider, credentials)
		else:
			token = provider.authenticate(credentials)
		
		if token:
			with self.token_lock:
				user_info = provider.get_user_info(token)
				self.active_tokens[token] = {
					'provider': provider_name,
					'user_info': user_info,
					'created_at': time()
				}
				self.session_manager.create_session(str(uuid.uuid4()), user_info)
		
		return token
	
	def validate_token(self, token, provider_name=None):
		with self.token_lock:
			if token not in self.active_tokens:
				return False
		
		if provider_name:
			if provider_name not in self.providers:
				return False
			provider = self.providers[provider_name]
		else:
			with self.token_lock:
				provider_name = self.active_tokens[token]['provider']
			provider = self.providers[provider_name]
		
		return provider.validate_token(token)
	
	def get_user_info(self, token):
		with self.token_lock:
			if token in self.active_tokens:
				return self.active_tokens[token]['user_info']
		return None
	
	def revoke_token(self, token):
		with self.token_lock:
			if token in self.active_tokens:
				del self.active_tokens[token]
				self.session_manager.clear_user_sessions(token)
				return True
		return False
	
	def get_available_providers(self):
		return list(self.providers.keys())
	
	def switch_provider(self, token, new_provider_name):
		if new_provider_name not in self.providers:
			return False
		
		with self.token_lock:
			if token in self.active_tokens:
				self.active_tokens[token]['provider'] = new_provider_name
				return True
		return False

def require_auth(auth_manager, provider_name=None, allow_multiple=False):
	def decorator(f):
		@wraps(f)
		def decorated_function(*args, **kwargs):
			auth_header = request.headers.get('Authorization')
			token = None
			
			if auth_header:
				parts = auth_header.split()
				if len(parts) == 2 and parts[0] == 'Bearer':
					token = parts[1]
			
			if not token or not auth_manager.validate_token(token, provider_name):
				return {'error': 'Unauthorized'}, 401
			
			if provider_name and not allow_multiple:
				with auth_manager.token_lock:
					if token in auth_manager.active_tokens:
						current_provider = auth_manager.active_tokens[token]['provider']
						if current_provider != provider_name:
							return {'error': 'Invalid provider'}, 403
			
			request.auth_token = token
			request.auth_user = auth_manager.get_user_info(token)
			
			return f(*args, **kwargs)
		return decorated_function
	return decorator

def require_auth_async(auth_manager, provider_name=None, allow_multiple=False):
	def decorator(f):
		@wraps(f)
		async def decorated_function(*args, **kwargs):
			auth_header = request.headers.get('Authorization')
			token = None
			
			if auth_header:
				parts = auth_header.split()
				if len(parts) == 2 and parts[0] == 'Bearer':
					token = parts[1]
			
			if not token or not auth_manager.validate_token(token, provider_name):
				return {'error': 'Unauthorized'}, 401
			
			if provider_name and not allow_multiple:
				with auth_manager.token_lock:
					if token in auth_manager.active_tokens:
						current_provider = auth_manager.active_tokens[token]['provider']
						if current_provider != provider_name:
							return {'error': 'Invalid provider'}, 403
			
			request.auth_token = token
			request.auth_user = auth_manager.get_user_info(token)
			
			return await f(*args, **kwargs)
		return decorated_function
	return decorator

def init(app):
	secret_key = get_config_value('secret_key', env_var='BENCHMARK_SECRET_KEY')
	if secret_key is None:
		secret_key = str(uuid.uuid4())
	app.config['SECRET_KEY'] = secret_key
	
	session_manager = ConcurrentSessionManager(session_timeout=3600)
	
	auth_manager = AuthenticationManager(session_manager)
	basic_auth = BasicAuthProvider()
	token_auth = TokenAuthProvider()
	api_key_auth = APIKeyAuthProvider()
	oauth2_auth = OAuth2Provider('client_id', 'client_secret')
	ldap_auth = LDAPAuthProvider()
	
	auth_manager.register_provider(basic_auth)
	auth_manager.register_provider(token_auth)
	auth_manager.register_provider(api_key_auth)
	auth_manager.register_provider(oauth2_auth)
	auth_manager.register_provider(ldap_auth)

	def get_or_create_session():
		if 'session_id' not in session:
			session['session_id'] = str(uuid.uuid4())
		
		session_id = session['session_id']
		session_data = session_manager.get_session(session_id)
		
		if session_data is None:
			user_info = None
			if hasattr(request, 'auth_user'):
				user_info = request.auth_user
			session_manager.create_session(session_id, user_info)
			session_data = session_manager.get_session(session_id)
		
		return session_id, session_data

	def process_benchmark_test(param):
		RESPONSE = ""

		if not param:
			param = ""

		possible = "ABC"
		guess = possible[0]
		
		match guess:
			case 'A':
				bar = param
			case 'B':