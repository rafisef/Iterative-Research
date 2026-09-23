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
from threading import Lock
from flask import redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html
from functools import wraps
from abc import ABC, abstractmethod

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

class AuthenticationManager:
	def __init__(self):
		self.providers = {}
		self.active_tokens = {}
		self.token_lock = Lock()
	
	def register_provider(self, provider):
		self.providers[provider.name] = provider
	
	def authenticate(self, provider_name, credentials):
		if provider_name not in self.providers:
			return None
		
		provider = self.providers[provider_name]
		token = provider.authenticate(credentials)
		
		if token:
			with self.token_lock:
				self.active_tokens[token] = {
					'provider': provider_name,
					'user_info': provider.get_user_info(token)
				}
		
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
				return True
		return False

def require_auth(auth_manager, provider_name=None):
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
			
			request.auth_token = token
			request.auth_user = auth_manager.get_user_info(token)
			
			return f(*args, **kwargs)
		return decorated_function
	return decorator

def require_auth_async(auth_manager, provider_name=None):
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
	
	session_store = {}
	session_lock = Lock()
	
	auth_manager = AuthenticationManager()
	basic_auth = BasicAuthProvider()
	token_auth = TokenAuthProvider()
	api_key_auth = APIKeyAuthProvider()
	
	auth_manager.register_provider(basic_auth)
	auth_manager.register_provider(token_auth)
	auth_manager.register_provider(api_key_auth)

	def get_or_create_session():
		if 'session_id' not in session:
			session['session_id'] = str(uuid.uuid4())
		
		session_id = session['session_id']
		
		with session_lock:
			if session_id not in session_store:
				session_store[session_id] = {
					'data': {},
					'lock': Lock()
				}
		
		return session_id, session_store[session_id]

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
				bar = 'bob'
			case 'C' | 'D':
				bar = param
			case _:
				bar = 'bob\'s your uncle'

		otherarg = "static text"
		RESPONSE += (
			f'bar is \'{bar}\' and otherarg is \'{otherarg}\''
		)

		return RESPONSE

	async def process_benchmark_test_async(param):
		RESPONSE = ""

		if not param:
			param = ""

		possible = "ABC"
		guess = possible[0]
		
		match guess:
			case 'A':
				bar = param
			case 'B':
				bar = 'bob'
			case 'C' | 'D':
				bar = param
			case _:
				bar = 'bob\'s your uncle'

		otherarg = "static text"
		RESPONSE += (
			f'bar is \'{bar}\' and otherarg is \'{otherarg}\''
		)

		await asyncio.sleep(0)
		return RESPONSE

	def execute_operation(operation_func, *args, **kwargs):
		if inspect.iscoroutinefunction(operation_func):
			return asyncio.run(operation_func(*args, **kwargs))
		else:
			return operation_func(*args, **kwargs)

	async def execute_operation_async(operation_func, *args, **kwargs):
		if inspect.iscoroutinefunction(operation_func):
			return await operation_func(*args, **kwargs)
		else:
			return operation_func(*args, **kwargs)

	@app.route('/benchmark/auth/login', methods=['POST'])
	def login():
		data = request.get_json()
		provider_name = data.get('provider', 'basic')
		
		token = auth_manager.authenticate(provider_name, data)
		
		if token:
			return {'token': token, 'provider': provider_name}
		return {'error': 'Authentication failed'}, 401

	@app.route('/benchmark/auth/logout', methods=['POST'])
	def logout():
		auth_header = request.headers.get('Authorization')
		if auth_header:
			parts = auth_header.split()
			if len(parts) == 2 and parts[0] == 'Bearer':
				token = parts[1]
				auth_manager.revoke_token(token)
				return {'status': 'logged out'}
		return {'error': 'No token provided'}, 400

	@app.route('/benchmark/auth/validate', methods=['GET'])
	def validate_auth():
		auth_header = request.headers.get('Authorization')
		if auth_header:
			parts = auth_header.split()
			if len(parts) == 2 and parts[0] == 'Bearer':
				token = parts[1]
				if auth_manager.validate_token(token):
					user_info = auth_manager.get_user_info(token)
					return {'valid': True, 'user_info': user_info}
		return {'valid': False}, 401

	@app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['GET'])
	def BenchmarkTest00096_get():
		return BenchmarkTest00096_post()

	@app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['POST'])
	def BenchmarkTest00096_post():
		session_id, session_data = get_or_create_session()
		
		with session_data['lock']:
			param = request.form.get("BenchmarkTest00096")
			result = execute_operation(process_benchmark_test, param)
			session_data['data']['last_result'] = result
		
		return result

	@app.route('/benchmark/xss-00/BenchmarkTest00096/async', methods=['GET'])
	async def BenchmarkTest00096_async_get():
		return await BenchmarkTest00096_async_post()

	@app.route('/benchmark/xss-00/BenchmarkTest00096/async', methods=['POST'])
	async def BenchmarkTest00096_async_post():
		session_id, session_data = get_or_create_session()
		
		param = request.form.get("BenchmarkTest00096")
		result = await execute_operation_async(process_benchmark_test_async, param)
		
		with session_data['lock']:
			session_data['data']['last_result'] = result
		
		return result

	@app.route('/benchmark/xss-00/BenchmarkTest00096/hybrid', methods=['GET'])
	def BenchmarkTest00096_hybrid_get():
		return BenchmarkTest00096_hybrid_post()

	@app.route('/benchmark/xss-00/BenchmarkTest00096/hybrid', methods=['POST'])
	def BenchmarkTest00096_hybrid_post():
		session_id, session_data = get_or_create_session()
		
		with session_data['lock']:
			param = request.form.get("BenchmarkTest00096")
			result = execute_operation(process_benchmark_test_async, param)
			session_data['data']['last_result'] = result
		
		return result

	@app.route('/benchmark/xss-00/BenchmarkTest00096/hybrid-async', methods=['GET'])
	async def BenchmarkTest00096_hybrid_async_get():
		return await BenchmarkTest00096_hybrid_async_post()

	@app.route('/benchmark/xss-00/BenchmarkTest00096/hybrid-async', methods=['POST'])
	async def BenchmarkTest00096_hybrid_async_post():
		session_id, session_data = get_or_create_session()
		
		param = request.form.get("BenchmarkTest00096")
		result = await execute_operation_async(process_benchmark_test, param)
		
		with session_data['lock']:
			session_data['data']['last_result'] = result
		
		return result

	@app.route('/benchmark/session/status', methods=['GET'])
	def get_session_status():
		session_id, session_data = get_or_create_session()
		
		with session_data['lock']:
			return {
				'session_id': session_id,
				'data': session_data['data']
			}

	@app.route('/benchmark/session/status-async', methods=['GET'])
	async def get_session_status_async():
		session_id, session_data = get_or_create_session()
		
		with session_data['lock']:
			await asyncio.sleep(0)
			return {
				'session_id': session_id,
				'data': session_data['data']
			}

	@app.route('/benchmark/session/clear', methods=['POST'])
	def clear_session():
		session_id, session_data = get_or_create_session()
		
		with session_data['lock']:
			session_data['data'].clear()
		
		return {'status': 'cleared'}

	@app.route('/benchmark/session/clear-async', methods=['POST'])
	async def clear_session_async():
		session_id, session_data = get_or_create_session()
		
		with session_data['lock']:
			session_data['data'].clear()
			await asyncio.sleep(0)
		
		return {'status': 'cleared'}