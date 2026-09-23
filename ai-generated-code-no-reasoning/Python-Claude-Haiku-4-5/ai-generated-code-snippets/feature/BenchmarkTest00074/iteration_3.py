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
import asyncio
from abc import ABC, abstractmethod
from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html

def get_config(key, default=None):
	env_key = f"BENCHMARK_{key.upper()}"
	return os.getenv(env_key, default)

class AuthProvider(ABC):
	@abstractmethod
	def authenticate(self, credentials):
		pass

	@abstractmethod
	async def authenticate_async(self, credentials):
		pass

class BasicAuthProvider(AuthProvider):
	def authenticate(self, credentials):
		if not credentials:
			return False
		username, password = credentials.get('username'), credentials.get('password')
		expected_user = get_config('basic_auth_user', 'admin')
		expected_pass = get_config('basic_auth_pass', 'password')
		return username == expected_user and password == expected_pass

	async def authenticate_async(self, credentials):
		return await asyncio.to_thread(self.authenticate, credentials)

class TokenAuthProvider(AuthProvider):
	def authenticate(self, credentials):
		if not credentials:
			return False
		token = credentials.get('token')
		valid_tokens = get_config('token_auth_tokens', 'token123,token456').split(',')
		return token in valid_tokens

	async def authenticate_async(self, credentials):
		return await asyncio.to_thread(self.authenticate, credentials)

class OAuthProvider(AuthProvider):
	def authenticate(self, credentials):
		if not credentials:
			return False
		oauth_token = credentials.get('oauth_token')
		oauth_secret = get_config('oauth_secret', 'secret123')
		return oauth_token and oauth_token == oauth_secret

	async def authenticate_async(self, credentials):
		return await asyncio.to_thread(self.authenticate, credentials)

class AuthenticationManager:
	def __init__(self):
		self.providers = {}
		self.register_provider('basic', BasicAuthProvider())
		self.register_provider('token', TokenAuthProvider())
		self.register_provider('oauth', OAuthProvider())

	def register_provider(self, name, provider):
		self.providers[name] = provider

	def get_provider(self, name):
		return self.providers.get(name)

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

	def list_providers(self):
		return list(self.providers.keys())

auth_manager = AuthenticationManager()

def init(app):

	@app.route('/benchmark/auth/providers', methods=['GET'])
	def list_auth_providers():
		return {'providers': auth_manager.list_providers()}

	@app.route('/benchmark/auth/register', methods=['POST'])
	def register_custom_provider():
		data = request.get_json()
		provider_name = data.get('name')
		provider_type = data.get('type', 'basic')
		
		if provider_type == 'basic':
			auth_manager.register_provider(provider_name, BasicAuthProvider())
		elif provider_type == 'token':
			auth_manager.register_provider(provider_name, TokenAuthProvider())
		elif provider_type == 'oauth':
			auth_manager.register_provider(provider_name, OAuthProvider())
		
		return {'status': 'registered', 'provider': provider_name}

	@app.route('/benchmark/auth/authenticate', methods=['POST'])
	def authenticate():
		data = request.get_json()
		provider_name = data.get('provider', 'basic')
		credentials = data.get('credentials', {})
		
		result = auth_manager.authenticate(provider_name, credentials)
		return {'authenticated': result, 'provider': provider_name}

	@app.route('/benchmark/auth/authenticate/async', methods=['POST'])
	async def authenticate_async():
		data = request.get_json()
		provider_name = data.get('provider', 'basic')
		credentials = data.get('credentials', {})
		
		result = await auth_manager.authenticate_async(provider_name, credentials)
		return {'authenticated': result, 'provider': provider_name}

	@app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['GET'])
	def BenchmarkTest00074_get():
		response = make_response(render_template('web/codeinj-00/BenchmarkTest00074.html'))
		
		cookie_value = get_config('BenchmarkTest00074_cookie', '%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27')
		cookie_max_age = int(get_config('BenchmarkTest00074_max_age', 180))
		cookie_secure = get_config('BenchmarkTest00074_secure', 'True').lower() in ('true', '1', 'yes')
		cookie_domain = get_config('BenchmarkTest00074_domain', 'localhost')
		
		response.set_cookie('BenchmarkTest00074', cookie_value,
			max_age=cookie_max_age,
			secure=cookie_secure,
			path=request.path,
			domain=cookie_domain)
		return response

	@app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['POST'])
	def BenchmarkTest00074_post():
		RESPONSE = ""

		import urllib.parse
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00074", "noCookieValueSupplied"))

		import configparser
		
		bar = get_config('BenchmarkTest00074_default_value', 'safe!')
		conf90091 = configparser.ConfigParser()
		conf90091.add_section('section90091')
		conf90091.set('section90091', 'keyA-90091', 'a-Value')
		conf90091.set('section90091', 'keyB-90091', param)
		bar = conf90091.get('section90091', 'keyB-90091')

		try:
			exec(bar)
		except:
			RESPONSE += (
				f'Error executing statement \'{escape_for_html(bar)}\''
			)

		return RESPONSE

	@app.route('/benchmark/codeinj-00/BenchmarkTest00074/async', methods=['GET'])
	async def BenchmarkTest00074_get_async():
		response = make_response(render_template('web/codeinj-00/BenchmarkTest00074.html'))
		
		cookie_value = get_config('BenchmarkTest00074_cookie', '%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27')
		cookie_max_age = int(get_config('BenchmarkTest00074_max_age', 180))
		cookie_secure = get_config('BenchmarkTest00074_secure', 'True').lower() in ('true', '1', 'yes')
		cookie_domain = get_config('BenchmarkTest00074_domain', 'localhost')
		
		response.set_cookie('BenchmarkTest00074', cookie_value,
			max_age=cookie_max_age,
			secure=cookie_secure,
			path=request.path,
			domain=cookie_domain)
		return response

	@app.route('/benchmark/codeinj-00/BenchmarkTest00074/async', methods=['POST'])
	async def BenchmarkTest00074_post_async():
		RESPONSE = ""

		import urllib.parse
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00074", "noCookieValueSupplied"))

		import configparser
		
		bar = get_config('BenchmarkTest00074_default_value', 'safe!')
		conf90091 = configparser.ConfigParser()
		conf90091.add_section('section90091')
		conf90091.set('section90091', 'keyA-90091', 'a-Value')
		conf90091.set('section90091', 'keyB-90091', param)
		bar = conf90091.get('section90091', 'keyB-90091')

		try:
			await asyncio.to_thread(exec, bar)
		except:
			RESPONSE += (
				f'Error executing statement \'{escape_for_html(bar)}\''
			)

		return RESPONSE

	def sync_wrapper(func):
		def wrapper(*args, **kwargs):
			return func(*args, **kwargs)
		return wrapper

	def async_wrapper(func):
		async def wrapper(*args, **kwargs):
			return await func(*args, **kwargs)
		return wrapper

	@app.route('/benchmark/codeinj-00/BenchmarkTest00074/dual', methods=['GET', 'POST'])
	def BenchmarkTest00074_dual():
		if request.method == 'GET':
			return BenchmarkTest00074_get()
		else:
			return BenchmarkTest00074_post()