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
from typing import Optional, Dict, Any, Callable, Awaitable, Union
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
		if self._cleanup_thread:
			self._cleanup_thread.join(timeout=5)
	
	def _cleanup_worker(self):
		while self._running:
			try:
				self.store.cleanup_expired_sessions()
				threading.Event().wait(self._cleanup_interval)
			except Exception:
				pass
	
	def get_or_create_session(self):
		semaphore = self._get_session_semaphore(None)
		with semaphore:
			session_id, session_data = self.store.get_or_create_session()
			self._track_session_access(session_id)
			return session_id, session_data
	
	def get_session_data(self, session_id):
		semaphore = self._get_session_semaphore(session_id)
		with semaphore:
			self._track_session_access(session_id)
			try:
				return self.store.get_session_data(session_id)
			finally:
				self._untrack_session_access(session_id)
	
	def update_session_data(self, session_id, key, value):
		semaphore = self._get_session_semaphore(session_id)
		with semaphore:
			self._track_session_access(session_id)
			try:
				self.store.update_session_data(session_id, key, value)
			finally:
				self._untrack_session_access(session_id)
	
	def get_session_value(self, session_id, key, default=None):
		semaphore = self._get_session_semaphore(session_id)
		with semaphore:
			self._track_session_access(session_id)
			try:
				return self.store.get_session_value(session_id, key, default)
			finally:
				self._untrack_session_access(session_id)
	
	def cleanup_session(self, session_id):
		semaphore = self._get_session_semaphore(session_id)
		with semaphore:
			self.store.cleanup_session(session_id)
			with self._active_sessions_lock:
				if session_id in self._active_sessions:
					del self._active_sessions[session_id]
	
	def cleanup_expired_sessions(self, max_age_seconds=3600):
		self.store.cleanup_expired_sessions(max_age_seconds)
	
	def submit_async_task(self, coro):
		return self.executor.submit(lambda: asyncio.run(coro))
	
	async def async_get_or_create_session(self):
		semaphore = self._get_session_semaphore(None)
		async with asyncio.Semaphore(5):
			session_id, session_data = await self.store.async_get_or_create_session()
			self._track_session_access(session_id)
			return session_id, session_data
	
	async def async_get_session_data(self, session_id):
		semaphore = self._get_session_semaphore(session_id)
		async with asyncio.Semaphore(5):
			self._track_session_access(session_id)
			try:
				return await self.store.async_get_session_data(session_id)
			finally:
				self._untrack_session_access(session_id)
	
	async def async_update_session_data(self, session_id, key, value):
		semaphore = self._get_session_semaphore(session_id)
		async with asyncio.Semaphore(5):
			self._track_session_access(session_id)
			try:
				await self.store.async_update_session_data(session_id, key, value)
			finally:
				self._untrack_session_access(session_id)
	
	async def async_get_session_value(self, session_id, key, default=None):
		semaphore = self._get_session_semaphore(session_id)
		async with asyncio.Semaphore(5):
			self._track_session_access(session_id)
			try:
				return await self.store.async_get_session_value(session_id, key, default)
			finally:
				self._untrack_session_access(session_id)
	
	async def async_cleanup_session(self, session_id):
		semaphore = self._get_session_semaphore(session_id)
		async with asyncio.Semaphore(5):
			await self.store.async_cleanup_session(session_id)
			with self._active_sessions_lock:
				if session_id in self._active_sessions:
					del self._active_sessions[session_id]
	
	async def async_cleanup_expired_sessions(self, max_age_seconds=3600):
		await self.store.async_cleanup_expired_sessions(max_age_seconds)

class FileSessionStore(SessionStore):
	def __init__(self, storage_path='sessions', max_age_seconds=3600):
		self._session_store = {}
		self._session_lock = threading.RLock()
		self._session_locks = {}
		self._locks_lock = threading.RLock()
		self._async_lock = asyncio.Lock()
		self.max_age_seconds = max_age_seconds
		self.storage_path = storage_path
		if not os.path.exists(self.storage_path):
			os.makedirs(self.storage_path)
	
	def _get_session_lock(self, session_id):
		with self._locks_lock:
			if session_id not in self._session_locks:
				self._session_locks[session_id] = threading.RLock()
			return self._session_locks[session_id]
	
	def _get_file_path(self, session_id):
		return os.path.join(self.storage_path, f'{session_id}.json')
	
	def _load_session_from_file(self, session_id):
		file_path = self._get_file_path(session_id)
		if os.path.exists(file_path):
			try:
				with open(file_path, 'r') as f:
					return json.load(f)
			except (json.JSONDecodeError, IOError):
				return None
		return None
	
	def _save_session_to_file(self, session_id, data):
		file_path = self._get_file_path(session_id)
		try:
			with open(file_path, 'w') as f:
				json.dump(data, f)
		except IOError:
			pass
	
	def get_or_create_session(self):
		session_id = session.get('session_id')
		
		if not session_id:
			session_id = str(uuid4())
			session['session_id'] = session_id
		
		session_lock = self._get_session_lock(session_id)
		
		with self._session_lock:
			if session_id not in self._session_store:
				file_data = self._load_session_from_file(session_id)
				if file_data:
					self._session_store[session_id] = {
						'data': file_data.get('data', {}),
						'created_at': datetime.fromisoformat(file_data.get('created_at', datetime.now().isoformat())),
						'updated_at': datetime.fromisoformat(file_data.get('updated_at', datetime.now().isoformat()))
					}
				else:
					self._session_store[session_id] = {
						'data': {},
						'created_at': datetime.now(),
						'updated_at': datetime.now()
					}
					self._save_session_to_file(session_id, {
						'data': {},
						'created_at': datetime.now().isoformat(),
						'updated_at': datetime.now().isoformat()
					})
		
		return session_id, self._session_store[session_id]
	
	def get_session_data(self, session_id):
		session_lock = self._get_session_lock(session_id)
		with session_lock:
			with self._session_lock:
				if session_id in self._session_store:
					return self._session_store[session_id].copy()
			file_data = self._load_session_from_file(session_id)
			if file_data:
				return file_data.get('data', {})
			return {}
	
	def update_session_data(self, session_id, key, value):
		session_lock = self._get_session_lock(session_id)
		with session_lock:
			with self._session_lock:
				if session_id in self._session_store:
					self._session_store[session_id]['data'][key] = value
					self._session_store[session_id]['updated_at'] = datetime.now()
					self._save_session_to_file(session_id, {
						'data': self._session_store[session_id]['data'],
						'created_at': self._session_store[session_id]['created_at'].isoformat(),
						'updated_at': self._session_store[session_id]['updated_at'].isoformat()
					})
	
	def get_session_value(self, session_id, key, default=None):
		session_lock = self._get_session_lock(session_id)
		with session_lock:
			with self._session_lock:
				if session_id in self._session_store:
					return self._session_store[session_id]['data'].get(key, default)
			file_data = self._load_session_from_file(session_id)
			if file_data:
				return file_data.get('data', {}).get(key, default)
		return default
	
	def cleanup_session(self, session_id):
		session_lock = self._get_session_lock(session_id)
		with session_lock:
			with self._session_lock:
				if session_id in self._session_store:
					del self._session_store[session_id]
			file_path = self._get_file_path(session_id)
			if os.path.exists(file_path):
				try:
					os.remove(file_path)
				except OSError:
					pass
	
	def cleanup_expired_sessions(self, max_age_seconds=3600):
		now = datetime.now()
		expired_sessions = []
		
		with self._session_lock:
			for session_id, session_data in list(self._session_store.items()):
				age = (now - session_data['updated_at']).total_seconds()
				if age > max_age_seconds:
					expired_sessions.append(session_id)
		
		for session_id in expired_sessions:
			self.cleanup_session(session_id)
		
		for filename in os.listdir(self.storage_path):
			if filename.endswith('.json'):
				file_path = os.path.join(self.storage_path, filename)
				try:
					file_time = os.path.getmtime(file_path)
					file_age = (datetime.now() - datetime.fromtimestamp(file_time)).total_seconds()
					if file_age > max_age_seconds: