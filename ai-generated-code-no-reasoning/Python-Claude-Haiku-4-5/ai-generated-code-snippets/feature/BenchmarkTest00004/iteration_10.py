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

from flask import redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html
from functools import wraps
from uuid import uuid4
import threading
import sqlite3
import json
import os
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
import queue
import asyncio
from typing import Optional, Dict, Any, Callable, Awaitable, Union, List, Tuple
import pickle
import hashlib
import hmac

class SessionStore(ABC):
	@abstractmethod
	def get_or_create_session(self):
		pass
	
	@abstractmethod
	def get_session_data(self, session_id):
		pass
	
	@abstractmethod
	def update_session_data(self, session_id, key, value):
		pass
	
	@abstractmethod
	def get_session_value(self, session_id, key, default=None):
		pass
	
	@abstractmethod
	def cleanup_session(self, session_id):
		pass
	
	@abstractmethod
	def cleanup_expired_sessions(self, max_age_seconds=3600):
		pass
	
	@abstractmethod
	async def async_get_or_create_session(self):
		pass
	
	@abstractmethod
	async def async_get_session_data(self, session_id):
		pass
	
	@abstractmethod
	async def async_update_session_data(self, session_id, key, value):
		pass
	
	@abstractmethod
	async def async_get_session_value(self, session_id, key, default=None):
		pass
	
	@abstractmethod
	async def async_cleanup_session(self, session_id):
		pass
	
	@abstractmethod
	async def async_cleanup_expired_sessions(self, max_age_seconds=3600):
		pass

class AuthenticationProvider(ABC):
	@abstractmethod
	def authenticate(self, credentials: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
		pass
	
	@abstractmethod
	def validate_token(self, token: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
		pass
	
	@abstractmethod
	def generate_token(self, user_data: Dict[str, Any]) -> str:
		pass
	
	@abstractmethod
	def get_provider_name(self) -> str:
		pass
	
	@abstractmethod
	async def async_authenticate(self, credentials: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
		pass
	
	@abstractmethod
	async def async_validate_token(self, token: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
		pass

class LocalAuthenticationProvider(AuthenticationProvider):
	def __init__(self, user_store: Dict[str, Dict[str, Any]]):
		self.user_store = user_store
		self.token_secret = os.urandom(32)
		self.token_ttl = 3600
	
	def _hash_password(self, password: str, salt: Optional[str] = None) -> Tuple[str, str]:
		if salt is None:
			salt = os.urandom(16).hex()
		hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
		return hashed.hex(), salt
	
	def _verify_password(self, password: str, hashed: str, salt: str) -> bool:
		new_hash, _ = self._hash_password(password, salt)
		return hmac.compare_digest(new_hash, hashed)
	
	def authenticate(self, credentials: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
		username = credentials.get('username')
		password = credentials.get('password')
		
		if not username or not password:
			return False, None
		
		user = self.user_store.get(username)
		if not user:
			return False, None
		
		if not self._verify_password(password, user.get('password_hash', ''), user.get('password_salt', '')):
			return False, None
		
		user_data = {k: v for k, v in user.items() if k not in ['password_hash', 'password_salt']}
		return True, user_data
	
	def validate_token(self, token: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
		try:
			parts = token.split('.')
			if len(parts) != 3:
				return False, None
			
			payload_str = parts[1]
			signature = parts[2]
			
			expected_sig = hmac.new(self.token_secret, payload_str.encode(), hashlib.sha256).hexdigest()
			if not hmac.compare_digest(signature, expected_sig):
				return False, None
			
			payload_json = json.loads(payload_str)
			if payload_json.get('exp', 0) < datetime.now().timestamp():
				return False, None
			
			return True, payload_json.get('user')
		except Exception:
			return False, None
	
	def generate_token(self, user_data: Dict[str, Any]) -> str:
		payload = {
			'user': user_data,
			'exp': (datetime.now() + timedelta(seconds=self.token_ttl)).timestamp(),
			'iat': datetime.now().timestamp()
		}
		payload_str = json.dumps(payload)
		signature = hmac.new(self.token_secret, payload_str.encode(), hashlib.sha256).hexdigest()
		return f"local.{payload_str}.{signature}"
	
	def get_provider_name(self) -> str:
		return "local"
	
	async def async_authenticate(self, credentials: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
		return self.authenticate(credentials)
	
	async def async_validate_token(self, token: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
		return self.validate_token(token)

class OAuthProvider(AuthenticationProvider):
	def __init__(self, provider_name: str, client_id: str, client_secret: str, token_endpoint: str, userinfo_endpoint: str):
		self.provider_name = provider_name
		self.client_id = client_id
		self.client_secret = client_secret
		self.token_endpoint = token_endpoint
		self.userinfo_endpoint = userinfo_endpoint
		self.token_cache = {}
		self.cache_ttl = 3600
	
	def authenticate(self, credentials: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
		auth_code = credentials.get('code')
		if not auth_code:
			return False, None
		
		try:
			import requests
			token_response = requests.post(
				self.token_endpoint,
				data={
					'grant_type': 'authorization_code',
					'code': auth_code,
					'client_id': self.client_id,
					'client_secret': self.client_secret
				}
			)
			
			if token_response.status_code != 200:
				return False, None
			
			token_data = token_response.json()
			access_token = token_data.get('access_token')
			
			userinfo_response = requests.get(
				self.userinfo_endpoint,
				headers={'Authorization': f'Bearer {access_token}'}
			)
			
			if userinfo_response.status_code != 200:
				return False, None
			
			user_data = userinfo_response.json()
			return True, user_data
		except Exception:
			return False, None
	
	def validate_token(self, token: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
		if token in self.token_cache:
			cached = self.token_cache[token]
			if cached['exp'] > datetime.now().timestamp():
				return True, cached['user']
		
		try:
			import requests
			userinfo_response = requests.get(
				self.userinfo_endpoint,
				headers={'Authorization': f'Bearer {token}'}
			)
			
			if userinfo_response.status_code != 200:
				return False, None
			
			user_data = userinfo_response.json()
			self.token_cache[token] = {
				'user': user_data,
				'exp': (datetime.now() + timedelta(seconds=self.cache_ttl)).timestamp()
			}
			return True, user_data
		except Exception:
			return False, None
	
	def generate_token(self, user_data: Dict[str, Any]) -> str:
		return str(uuid4())
	
	def get_provider_name(self) -> str:
		return self.provider_name
	
	async def async_authenticate(self, credentials: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
		return self.authenticate(credentials)
	
	async def async_validate_token(self, token: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
		return self.validate_token(token)

class APIKeyProvider(AuthenticationProvider):
	def __init__(self, api_keys: Dict[str, Dict[str, Any]]):
		self.api_keys = api_keys
	
	def authenticate(self, credentials: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
		api_key = credentials.get('api_key')
		if not api_key or api_key not in self.api_keys:
			return False, None
		
		key_data = self.api_keys[api_key]
		if key_data.get('enabled', True) is False:
			return False, None
		
		return True, key_data.get('user')
	
	def validate_token(self, token: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
		return self.authenticate({'api_key': token})
	
	def generate_token(self, user_data: Dict[str, Any]) -> str:
		api_key = hashlib.sha256(os.urandom(32)).hexdigest()
		self.api_keys[api_key] = {'user': user_data, 'enabled': True}
		return api_key
	
	def get_provider_name(self) -> str:
		return "api_key"
	
	async def async_authenticate(self, credentials: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
		return self.authenticate(credentials)
	
	async def async_validate_token(self, token: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
		return self.validate_token(token)

class AuthenticationManager:
	def __init__(self):
		self.providers: Dict[str, AuthenticationProvider] = {}
		self._lock = threading.RLock()
	
	def register_provider(self, provider: AuthenticationProvider) -> None:
		with self._lock:
			self.providers[provider.get_provider_name()] = provider
	
	def unregister_provider(self, provider_name: str) -> None:
		with self._lock:
			if provider_name in self.providers:
				del self.providers[provider_name]
	
	def get_provider(self, provider_name: str) -> Optional[AuthenticationProvider]:
		with self._lock:
			return self.providers.get(provider_name)
	
	def authenticate(self, provider_name: str, credentials: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
		provider = self.get_provider(provider_name)
		if not provider:
			return False, None
		return provider.authenticate(credentials)
	
	def validate_token(self, provider_name: str, token: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
		provider = self.get_provider(provider_name)
		if not provider:
			return False, None
		return provider.validate_token(token)
	
	def generate_token(self, provider_name: str, user_data: Dict[str, Any]) -> Optional[str]:
		provider = self.get_provider(provider_name)
		if not provider:
			return None
		return provider.generate_token(user_data)
	
	def list_providers(self) -> List[str]:
		with self._lock:
			return list(self.providers.keys())
	
	async def async_authenticate(self, provider_name: str, credentials: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]]]:
		provider = self.get_provider(provider_name)
		if not provider:
			return False, None
		return await provider.async_authenticate(credentials)
	
	async def async_validate_token(self, provider_name: str, token: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
		provider = self.get_provider(provider_name)
		if not provider:
			return False, None
		return await provider.async_validate_token(token)

class ConcurrentSessionManager:
	def __init__(self, store: SessionStore, max_workers: int = 10):
		self.store = store
		self.executor = ThreadPoolExecutor(max_workers=max_workers)
		self._active_sessions = {}
		self._active_sessions_lock = threading.RLock()
		self._session_semaphores = {}
		self._semaphores_lock = threading.RLock()
		self._cleanup_thread = None
		self._cleanup_interval = 300
		self._running = False
	
	def _get_session_semaphore(self, session_id, max_concurrent=5):
		with self._semaphores_lock:
			if session_id not in self._session_semaphores:
				self._session_semaphores[session_id] = threading.Semaphore(max_concurrent)
			return self._session_semaphores[session_id]
	
	def _track_session_access(self, session_id):
		with self._active_sessions_lock:
			if session_id not in self._active_sessions:
				self._active_sessions[session_id] = {
					'count': 0,
					'first_access': datetime.now(),
					'last_access': datetime.now()
				}
			self._active_sessions[session_id]['count'] += 1
			self._active_sessions[session_id]['last_access'] = datetime.now()
	
	def _untrack_session_access(self, session_id):
		with self._active_sessions_lock:
			if session_id in self._active_sessions:
				self._active_sessions[session_id]['count'] -= 1
	
	def get_active_sessions_count(self):
		with self._active_sessions_lock:
			return len(self._active_sessions)
	
	def get_session_access_info(self, session_id):
		with self._active_sessions_lock:
			return self._active_sessions.get(session_id, None)
	
	def start_cleanup_thread(self):
		if not self._running:
			self._running = True
			self._cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True)
			self._cleanup_thread.start()
	
	def stop_cleanup_thread(self):
		self._running = False
		if