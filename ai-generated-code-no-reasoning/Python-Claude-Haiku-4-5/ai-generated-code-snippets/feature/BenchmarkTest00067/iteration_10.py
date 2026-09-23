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
import urllib.parse
import base64
import os
import json
import sqlite3
import uuid
import threading
import time
import hmac
import hashlib
from abc import ABC, abstractmethod
from flask import redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html
from threading import RLock, Thread, Semaphore
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from contextlib import contextmanager


class Config:
	def __init__(self, env_override=None):
		if env_override is None:
			env_override = {}
		
		self.storage_type = env_override.get('storage_type') or os.getenv('BENCHMARK_STORAGE_TYPE', 'file')
		self.storage_dir = env_override.get('storage_dir') or os.getenv('BENCHMARK_STORAGE_DIR', './benchmark_storage')
		self.db_path = env_override.get('db_path') or os.getenv('BENCHMARK_DB_PATH', './benchmark_storage/benchmark.db')
		self.session_cleanup_interval = env_override.get('session_cleanup_interval') or int(os.getenv('BENCHMARK_SESSION_CLEANUP_INTERVAL', '3600'))
		self.cookie_max_age = env_override.get('cookie_max_age') or int(os.getenv('BENCHMARK_COOKIE_MAX_AGE', '180'))
		self.cookie_secure = env_override.get('cookie_secure') if env_override.get('cookie_secure') is not None else os.getenv('BENCHMARK_COOKIE_SECURE', 'True').lower() == 'true'
		self.cookie_domain = env_override.get('cookie_domain') or os.getenv('BENCHMARK_COOKIE_DOMAIN', 'localhost')
		self.log_level = env_override.get('log_level') or os.getenv('BENCHMARK_LOG_LEVEL', 'INFO')
		self.debug_mode = env_override.get('debug_mode') if env_override.get('debug_mode') is not None else os.getenv('BENCHMARK_DEBUG_MODE', 'False').lower() == 'true'
		self.max_concurrent_sessions = env_override.get('max_concurrent_sessions') or int(os.getenv('BENCHMARK_MAX_CONCURRENT_SESSIONS', '1000'))
		self.session_timeout = env_override.get('session_timeout') or int(os.getenv('BENCHMARK_SESSION_TIMEOUT', '1800'))
		self.auth_providers = env_override.get('auth_providers') or os.getenv('BENCHMARK_AUTH_PROVIDERS', 'session').split(',')
		self.default_auth_provider = env_override.get('default_auth_provider') or os.getenv('BENCHMARK_DEFAULT_AUTH_PROVIDER', 'session')
		self.max_user_sessions = env_override.get('max_user_sessions') or int(os.getenv('BENCHMARK_MAX_USER_SESSIONS', '5'))
		self.thread_pool_size = env_override.get('thread_pool_size') or int(os.getenv('BENCHMARK_THREAD_POOL_SIZE', '10'))
		self.oauth_providers = env_override.get('oauth_providers') or json.loads(os.getenv('BENCHMARK_OAUTH_PROVIDERS', '{}'))
		self.jwt_secret = env_override.get('jwt_secret') or os.getenv('BENCHMARK_JWT_SECRET', 'default-secret-key')
		self.api_key_header = env_override.get('api_key_header') or os.getenv('BENCHMARK_API_KEY_HEADER', 'X-API-Key')

	def to_dict(self):
		return {
			'storage_type': self.storage_type,
			'storage_dir': self.storage_dir,
			'db_path': self.db_path,
			'session_cleanup_interval': self.session_cleanup_interval,
			'cookie_max_age': self.cookie_max_age,
			'cookie_secure': self.cookie_secure,
			'cookie_domain': self.cookie_domain,
			'log_level': self.log_level,
			'debug_mode': self.debug_mode,
			'max_concurrent_sessions': self.max_concurrent_sessions,
			'session_timeout': self.session_timeout,
			'auth_providers': self.auth_providers,
			'default_auth_provider': self.default_auth_provider,
			'max_user_sessions': self.max_user_sessions,
			'thread_pool_size': self.thread_pool_size,
			'oauth_providers': self.oauth_providers,
			'jwt_secret': self.jwt_secret,
			'api_key_header': self.api_key_header
		}


class ConcurrentSessionManager:
	def __init__(self, cleanup_interval=3600, session_timeout=1800, max_sessions=1000, max_user_sessions=5):
		self.sessions = {}
		self.user_sessions = defaultdict(list)
		self.lock = RLock()
		self.cleanup_interval = cleanup_interval
		self.session_timeout = session_timeout
		self.max_sessions = max_sessions
		self.max_user_sessions = max_user_sessions
		self.cleanup_thread = None
		self.running = False
		self.executor = ThreadPoolExecutor(max_workers=10)
		self.session_semaphore = Semaphore(max_sessions)
		self._start_cleanup_thread()

	def _start_cleanup_thread(self):
		self.running = True
		self.cleanup_thread = Thread(target=self._cleanup_expired_sessions, daemon=True)
		self.cleanup_thread.start()

	def _cleanup_expired_sessions(self):
		while self.running:
			time.sleep(self.cleanup_interval)
			current_time = time.time()
			with self.lock:
				expired_sessions = [
					sid for sid, data in self.sessions.items()
					if current_time - data['last_activity'] > self.session_timeout
				]
				for sid in expired_sessions:
					session_data = self.sessions[sid]
					username = session_data.get('username', 'anonymous')
					if username in self.user_sessions:
						self.user_sessions[username] = [
							s for s in self.user_sessions[username] if s != sid
						]
					del self.sessions[sid]
					self.session_semaphore.release()

	@contextmanager
	def _session_context(self):
		self.session_semaphore.acquire()
		try:
			yield
		finally:
			pass

	def create_session(self, username='anonymous'):
		session_id = str(uuid.uuid4())
		current_time = time.time()
		
		self.session_semaphore.acquire(blocking=True)
		
		with self.lock:
			if len(self.sessions) >= self.max_sessions:
				oldest_session = min(self.sessions.items(), key=lambda x: x[1]['last_activity'])
				old_sid = oldest_session[0]
				old_username = oldest_session[1].get('username', 'anonymous')
				if old_username in self.user_sessions:
					self.user_sessions[old_username] = [
						s for s in self.user_sessions[old_username] if s != old_sid
					]
				del self.sessions[old_sid]
				self.session_semaphore.release()
				self.session_semaphore.acquire(blocking=True)
			
			if len(self.user_sessions.get(username, [])) >= self.max_user_sessions:
				oldest_user_session = min(
					[self.sessions[sid] for sid in self.user_sessions[username] if sid in self.sessions],
					key=lambda x: x['last_activity'],
					default=None
				)
				if oldest_user_session:
					old_sid = oldest_user_session['id']
					self.user_sessions[username] = [
						s for s in self.user_sessions[username] if s != old_sid
					]
					del self.sessions[old_sid]
					self.session_semaphore.release()
					self.session_semaphore.acquire(blocking=True)
			
			self.sessions[session_id] = {
				'id': session_id,
				'data': {},
				'created_at': current_time,
				'last_activity': current_time,
				'thread_id': threading.get_ident(),
				'username': username
			}
			self.user_sessions[username].append(session_id)
		
		return session_id

	def get_session(self, session_id):
		with self.lock:
			if session_id in self.sessions:
				self.sessions[session_id]['last_activity'] = time.time()
				return self.sessions[session_id].copy()
		return None

	def set_session_data(self, session_id, key, value):
		with self.lock:
			if session_id in self.sessions:
				self.sessions[session_id]['data'][key] = value
				self.sessions[session_id]['last_activity'] = time.time()

	def get_session_data(self, session_id, key):
		with self.lock:
			if session_id in self.sessions:
				self.sessions[session_id]['last_activity'] = time.time()
				return self.sessions[session_id]['data'].get(key)
		return None

	def delete_session(self, session_id):
		with self.lock:
			if session_id in self.sessions:
				username = self.sessions[session_id].get('username', 'anonymous')
				if username in self.user_sessions:
					self.user_sessions[username] = [
						s for s in self.user_sessions[username] if s != session_id
					]
				del self.sessions[session_id]
				self.session_semaphore.release()

	def get_active_sessions_count(self):
		with self.lock:
			return len(self.sessions)

	def get_user_sessions_count(self, username):
		with self.lock:
			return len(self.user_sessions.get(username, []))

	def get_user_sessions(self, username):
		with self.lock:
			return self.user_sessions.get(username, []).copy()

	def invalidate_user_sessions(self, username):
		with self.lock:
			sessions_to_delete = self.user_sessions.get(username, []).copy()
			for session_id in sessions_to_delete:
				if session_id in self.sessions:
					del self.sessions[session_id]
					self.session_semaphore.release()
			self.user_sessions[username] = []

	def stop_cleanup(self):
		self.running = False
		if self.cleanup_thread:
			self.cleanup_thread.join(timeout=5)
		self.executor.shutdown(wait=True)


class SessionManager(ConcurrentSessionManager):
	pass


class AuthenticationProvider(ABC):
	@abstractmethod
	def authenticate(self, credentials):
		pass

	@abstractmethod
	async def authenticate_async(self, credentials):
		pass

	@abstractmethod
	def validate_session(self, session_id):
		pass

	@abstractmethod
	async def validate_session_async(self, session_id):
		pass

	@abstractmethod
	def get_user_info(self, session_id):
		pass

	@abstractmethod
	async def get_user_info_async(self, session_id):
		pass

	@abstractmethod
	def logout(self, session_id):
		pass

	@abstractmethod
	async def logout_async(self, session_id):
		pass


class SessionAuthProvider(AuthenticationProvider):
	def __init__(self, session_manager):
		self.session_manager = session_manager

	def authenticate(self, credentials):
		username = credentials.get('username', 'anonymous')
		session_id = self.session_manager.create_session(username=username)
		self.session_manager.set_session_data(session_id, 'authenticated', True)
		self.session_manager.set_session_data(session_id, 'username', username)
		return session_id

	async def authenticate_async(self, credentials):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.authenticate, credentials)

	def validate_session(self, session_id):
		session = self.session_manager.get_session(session_id)
		if session:
			return session['data'].get('authenticated', False)
		return False

	async def validate_session_async(self, session_id):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.validate_session, session_id)

	def get_user_info(self, session_id):
		if self.validate_session(session_id):
			return {
				'username': self.session_manager.get_session_data(session_id, 'username'),
				'authenticated': True,
				'session_id': session_id,
				'provider': 'session'
			}
		return None

	async def get_user_info_async(self, session_id):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.get_user_info, session_id)

	def logout(self, session_id):
		self.session_manager.delete_session(session_id)

	async def logout_async(self, session_id):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.logout, session_id)


class TokenAuthProvider(AuthenticationProvider):
	def __init__(self, session_manager):
		self.session_manager = session_manager
		self.tokens = {}
		self.lock = RLock()

	def authenticate(self, credentials):
		token = str(uuid.uuid4())
		username = credentials.get('username', 'anonymous')
		session_id = self.session_manager.create_session(username=username)
		with self.lock:
			self.tokens[token] = {
				'session_id': session_id,
				'username': username,
				'created_at': time.time()
			}
		self.session_manager.set_session_data(session_id, 'token', token)
		return token

	async def authenticate_async(self, credentials):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.authenticate, credentials)

	def validate_session(self, token):
		with self.lock:
			if token in self.tokens:
				session_id = self.tokens[token]['session_id']
				return self.session_manager.get_session(session_id) is not None
		return False

	async def validate_session_async(self, token):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.validate_session, token)

	def get_user_info(self, token):
		with self.lock:
			if token in self.tokens:
				return {
					'username': self.tokens[token]['username'],
					'authenticated': True,
					'token': token,
					'provider': 'token'
				}
		return None

	async def get_user_info_async(self, token):
		loop = asyncio.get_event_loop()
		return