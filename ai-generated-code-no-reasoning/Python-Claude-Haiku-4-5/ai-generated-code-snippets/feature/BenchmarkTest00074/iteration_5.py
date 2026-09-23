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
import hashlib
import hmac
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
	def __init__(self):
		self.providers = {}
		self.provider_configs = {}
		self.provider_strategies = {}
		self.register_provider('basic', BasicAuthProvider())
		self.register_provider('token', TokenAuthProvider())
		self.register_provider('oauth', OAuthProvider())
		self.register_provider('ldap', LDAPAuthProvider())
		self.register_provider('apikey', APIKeyAuthProvider())
		self.register_provider('hmac', HMACAuthProvider())

	def register_provider(self, name, provider, config=None, strategy=None):
		if not isinstance(provider, AuthProvider):
			raise TypeError(f"Provider must be an instance of AuthProvider")
		self.providers[name] = provider
		self.provider_configs[name] = config or {}
		self.provider_strategies[name] = strategy or 'single'

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

	async def authenticate_with_chain_async(self, provider_names, credentials_map, require_all=True):
		tasks = []
		for name in provider_names:
			if self.has_provider(name):
				provider = self.get_provider(name)
				creds = credentials_map.get(name, {})
				tasks.append(provider.authenticate_async(creds))
		
		results = await asyncio.gather(*tasks)
		return all(results) if require_all else any(results)

	def authenticate_with_fallback(self, provider_names, credentials):
		for name in provider_names:
			if self.has_provider(name):
				provider = self.get_provider(name)
				if provider.validate_credentials(credentials) and provider.authenticate(credentials):
					return True
		return False

	async def authenticate_with_fallback_async(self, provider_names, credentials):
		for name in provider_names:
			if self.has_provider(name):
				provider = self.get_provider(name)
				if provider.validate_credentials(credentials) and await provider.authenticate_async(credentials):
					return True
		return False

	def list_providers(self):
		return list(self.providers.keys())

	def unregister_provider(self, name):
		if name in self.providers:
			del self.providers[name]
			if name in self.provider_configs:
				del self.provider_configs[name]
			if name in self.provider_strategies:
				del self.provider_strategies[name]
			return True
		return False

	def has_provider(self, name):
		return name in self.providers

auth_manager = AuthenticationManager()

def init(app):

	@app.route('/benchmark/auth/providers', methods=['GET'])
	def list_auth_providers():
		return {'providers': auth_manager.list_providers()}

	@app.route('/benchmark/auth/providers/<provider_name>', methods=['GET'])
	def get_auth_provider_info(provider_name):
		if not auth_manager.has_provider(provider_name):
			return {'error': 'Provider not found'}, 404
		provider = auth_manager.get_provider(provider_name)
		config = auth_manager.get_provider_config(provider_name)
		strategy = auth_manager.get_provider_strategy(provider_name)
		return {
			'provider': provider_name,
			'type': provider.__class__.__name__,
			'strategy': strategy,
			'config': config
		}

	@app.route('/benchmark/auth/register', methods=['POST'])
	def register_custom_provider():
		data = request.get_json()
		provider_name = data.get('name')
		provider_type = data.get('type', 'basic')
		config = data.get('config', {})
		strategy = data.get('strategy', 'single')
		
		if not provider_name:
			return {'error': 'Provider name is required'}, 400
		
		provider_map = {
			'basic': BasicAuthProvider,
			'token': TokenAuthProvider,
			'oauth': OAuthProvider,
			'ldap': LDAPAuthProvider,
			'apikey': APIKeyAuthProvider,
			'hmac': HMACAuthProvider,
		}
		
		if provider_type not in provider_map:
			return {'error': f'Unknown provider type: {provider_type}'}, 400
		
		provider_instance = provider_map[provider_type]()
		auth_manager.register_provider(provider_name, provider_instance, config, strategy)
		
		return {'status': 'registered', 'provider': provider_name}, 201

	@app.route('/benchmark/auth/register/chain', methods=['POST'])
	def register_chain_provider():
		data = request.get_json()
		provider_name = data.get('name')
		provider_names = data.get('providers', [])
		require_all = data.get('require_all', True)
		config = data.get('config', {})
		
		if not provider_name:
			return {'error': 'Provider name is required'}, 400
		
		if not provider_names:
			return {'error': 'At least one provider must be specified'}, 400
		
		providers = [auth_manager.get_provider(name) for name in provider_names if auth_manager.has_provider(name)]
		
		if not providers:
			return {'error': 'No valid providers found'}, 400
		
		chain_provider = ChainAuthProvider(providers, require_all)
		auth_manager.register_provider(provider_name, chain_provider, config, 'chain')
		
		return {'status': 'registered', 'provider': provider_name, 'type': 'chain'}, 201

	@app.route('/benchmark/auth/register/fallback', methods=['POST'])
	def register_fallback_provider():
		data = request.get_json()
		provider_name = data.get('name')
		provider_names = data.get('providers', [])
		config = data.get('config', {})
		
		if not provider_name:
			return {'error': 'Provider name is required'}, 400
		
		if not provider_names:
			return {'error': 'At least one provider must be specified'}, 400
		
		providers = [auth_manager.get_provider(name) for name in provider_names if auth_manager.has_provider(name)]
		
		if not providers:
			return {'error': 'No valid providers found'}, 400
		
		fallback_provider = FallbackAuthProvider(providers)
		auth_manager.register_provider(provider_name, fallback_provider, config, 'fallback')
		
		return {'status': 'registered', 'provider': provider_name, 'type': 'fallback'}, 201

	@app.route('/benchmark/auth/unregister', methods=['POST'])
	def unregister_custom_provider():
		data = request.get_json()
		provider_name = data.get('name')
		
		if not provider_name:
			return {'error': 'Provider name is required'}, 400
		
		if auth_manager.unregister_provider(provider_name):
			return {'status': 'unregistered', 'provider': provider_name}
		else:
			return {'error': 'Provider not found'}, 404

	@app.route('/benchmark/auth/authenticate', methods=['POST'])
	def authenticate():
		data = request.get_json()
		provider_name = data.get('provider', 'basic')
		credentials = data.get('credentials', {})
		
		if not auth_manager.has_provider(provider_name):
			return {'authenticated': False, 'error': 'Provider not found'}, 404
		
		result = auth_manager.authenticate(provider_name, credentials)
		return {'authenticated': result, 'provider': provider_name}

	@app.route('/benchmark/auth/authenticate/async', methods=['POST'])
	async def authenticate_async():
		data = request.get_json()
		provider_name = data.get('provider', 'basic')
		credentials = data.get('credentials', {})
		
		if not auth_manager.has_provider(provider_name):