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

from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Union, Coroutine, Set
import uuid
import threading
import asyncio
import time
from datetime import datetime, timedelta
import inspect
import json
import os
import sqlite3
import pickle
import psycopg2
from psycopg2.extras import RealDictCursor
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import queue


class SessionManager:
	def __init__(self, backend: 'StorageBackend', session_timeout: int = 3600, max_workers: int = 4):
		self.backend = backend
		self.session_timeout = session_timeout
		self.active_sessions: Dict[str, Set[str]] = defaultdict(set)
		self.session_lock = threading.RLock()
		self.cleanup_thread = None
		self.running = False
		self.executor = ThreadPoolExecutor(max_workers=max_workers)
		self.session_semaphore = threading.Semaphore(100)
		self.async_semaphore = asyncio.Semaphore(100)
		self.event_queue = queue.Queue()

	def create_session(self, user_id: str) -> str:
		self.session_semaphore.acquire()
		try:
			session_id = str(uuid.uuid4())
			session_data = {
				'session_id': session_id,
				'user_id': user_id,
				'created_at': datetime.now().isoformat(),
				'last_accessed': datetime.now().isoformat(),
				'user_info': {'user_id': user_id},
				'data': {}
			}
			
			if self.backend.create_session(session_id, session_data):
				with self.session_lock:
					self.active_sessions[user_id].add(session_id)
				self.event_queue.put(('session_created', session_id, user_id))
				return session_id
			return None
		finally:
			self.session_semaphore.release()

	async def create_session_async(self, user_id: str) -> str:
		await self.async_semaphore.acquire()
		try:
			session_id = str(uuid.uuid4())
			session_data = {
				'session_id': session_id,
				'user_id': user_id,
				'created_at': datetime.now().isoformat(),
				'last_accessed': datetime.now().isoformat(),
				'user_info': {'user_id': user_id},
				'data': {}
			}
			
			if await self.backend.create_session_async(session_id, session_data):
				with self.session_lock:
					self.active_sessions[user_id].add(session_id)
				self.event_queue.put(('session_created', session_id, user_id))
				return session_id
			return None
		finally:
			self.async_semaphore.release()

	def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
		session_data = self.backend.get_session(session_id)
		if session_data:
			session_data['last_accessed'] = datetime.now().isoformat()
			self.backend.update_session(session_id, session_data)
		return session_data

	async def get_session_async(self, session_id: str) -> Optional[Dict[str, Any]]:
		session_data = await self.backend.get_session_async(session_id)
		if session_data:
			session_data['last_accessed'] = datetime.now().isoformat()
			await self.backend.update_session_async(session_id, session_data)
		return session_data

	def update_session(self, session_id: str, data: Dict[str, Any]) -> bool:
		session_data = self.backend.get_session(session_id)
		if session_data:
			session_data['last_accessed'] = datetime.now().isoformat()
			session_data['data'].update(data)
			return self.backend.update_session(session_id, session_data)
		return False

	async def update_session_async(self, session_id: str, data: Dict[str, Any]) -> bool:
		session_data = await self.backend.get_session_async(session_id)
		if session_data:
			session_data['last_accessed'] = datetime.now().isoformat()
			session_data['data'].update(data)
			return await self.backend.update_session_async(session_id, session_data)
		return False

	def delete_session(self, session_id: str) -> bool:
		session_data = self.backend.get_session(session_id)
		if session_data and self.backend.delete_session(session_id):
			user_id = session_data.get('user_id')
			if user_id:
				with self.session_lock:
					self.active_sessions[user_id].discard(session_id)
			self.event_queue.put(('session_deleted', session_id, user_id))
			return True
		return False

	async def delete_session_async(self, session_id: str) -> bool:
		session_data = await self.backend.get_session_async(session_id)
		if session_data and await self.backend.delete_session_async(session_id):
			user_id = session_data.get('user_id')
			if user_id:
				with self.session_lock:
					self.active_sessions[user_id].discard(session_id)
			self.event_queue.put(('session_deleted', session_id, user_id))
			return True
		return False

	def get_user_sessions(self, user_id: str) -> Dict[str, Dict[str, Any]]:
		with self.session_lock:
			session_ids = list(self.active_sessions.get(user_id, set()))
		
		user_sessions = {}
		for session_id in session_ids:
			session_data = self.backend.get_session(session_id)
			if session_data:
				user_sessions[session_id] = session_data
		return user_sessions

	async def get_user_sessions_async(self, user_id: str) -> Dict[str, Dict[str, Any]]:
		with self.session_lock:
			session_ids = list(self.active_sessions.get(user_id, set()))
		
		user_sessions = {}
		tasks = [self.backend.get_session_async(session_id) for session_id in session_ids]
		results = await asyncio.gather(*tasks, return_exceptions=True)
		
		for session_id, result in zip(session_ids, results):
			if isinstance(result, dict):
				user_sessions[session_id] = result
		
		return user_sessions

	def invalidate_user_sessions(self, user_id: str) -> int:
		with self.session_lock:
			session_ids = list(self.active_sessions.get(user_id, set()))
		
		deleted_count = 0
		for session_id in session_ids:
			if self.backend.delete_session(session_id):
				deleted_count += 1
		
		with self.session_lock:
			self.active_sessions[user_id].clear()
		
		self.event_queue.put(('sessions_invalidated', user_id, deleted_count))
		return deleted_count

	async def invalidate_user_sessions_async(self, user_id: str) -> int:
		with self.session_lock:
			session_ids = list(self.active_sessions.get(user_id, set()))
		
		deleted_count = 0
		tasks = [self.backend.delete_session_async(session_id) for session_id in session_ids]
		results = await asyncio.gather(*tasks, return_exceptions=True)
		
		for result in results:
			if result is True:
				deleted_count += 1
		
		with self.session_lock:
			self.active_sessions[user_id].clear()
		
		self.event_queue.put(('sessions_invalidated', user_id, deleted_count))
		return deleted_count

	def start_cleanup_thread(self):
		if not self.running:
			self.running = True
			self.cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True)
			self.cleanup_thread.start()

	def stop_cleanup_thread(self):
		self.running = False
		if self.cleanup_thread:
			self.cleanup_thread.join(timeout=5)

	def _cleanup_worker(self):
		while self.running:
			time.sleep(60)
			deleted = self.backend.cleanup_expired_sessions(self.session_timeout)
			if deleted > 0:
				self._sync_active_sessions()

	def _sync_active_sessions(self):
		all_sessions = self.backend.get_all_sessions()
		with self.session_lock:
			self.active_sessions.clear()
			for session_id, session_data in all_sessions.items():
				user_id = session_data.get('user_id')
				if user_id:
					self.active_sessions[user_id].add(session_id)

	def get_session_count(self) -> int:
		with self.session_lock:
			return sum(len(sessions) for sessions in self.active_sessions.values())

	def get_user_session_count(self, user_id: str) -> int:
		with self.session_lock:
			return len(self.active_sessions.get(user_id, set()))

	def shutdown(self):
		self.stop_cleanup_thread()
		self.executor.shutdown(wait=True)


class StorageBackend(ABC):
	@abstractmethod
	def create_session(self, session_id: str, session_data: Dict[str, Any]) -> bool:
		pass

	@abstractmethod
	async def create_session_async(self, session_id: str, session_data: Dict[str, Any]) -> bool:
		pass

	@abstractmethod
	def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
		pass

	@abstractmethod
	async def get_session_async(self, session_id: str) -> Optional[Dict[str, Any]]:
		pass

	@abstractmethod
	def update_session(self, session_id: str, session_data: Dict[str, Any]) -> bool:
		pass

	@abstractmethod
	async def update_session_async(self, session_id: str, session_data: Dict[str, Any]) -> bool:
		pass

	@abstractmethod
	def delete_session(self, session_id: str) -> bool:
		pass

	@abstractmethod
	async def delete_session_async(self, session_id: str) -> bool:
		pass

	@abstractmethod
	def cleanup_expired_sessions(self, timeout: int) -> int:
		pass

	@abstractmethod
	async def cleanup_expired_sessions_async(self, timeout: int) -> int:
		pass

	@abstractmethod
	def get_all_sessions(self) -> Dict[str, Dict[str, Any]]:
		pass

	@abstractmethod
	async def get_all_sessions_async(self) -> Dict[str, Dict[str, Any]]:
		pass


class FileStorageBackend(StorageBackend):
	def __init__(self, storage_dir: str = './sessions'):
		self.storage_dir = storage_dir
		os.makedirs(storage_dir, exist_ok=True)
		self.lock = threading.RLock()
		self.async_lock = asyncio.Lock()
		self.session_locks = defaultdict(threading.RLock)

	def _get_session_path(self, session_id: str) -> str:
		return os.path.join(self.storage_dir, f'{session_id}.json')

	def create_session(self, session_id: str, session_data: Dict[str, Any]) -> bool:
		session_lock = self.session_locks[session_id]
		with session_lock:
			try:
				path = self._get_session_path(session_id)
				with open(path, 'w') as f:
					json.dump(session_data, f)
				return True
			except Exception:
				return False

	async def create_session_async(self, session_id: str, session_data: Dict[str, Any]) -> bool:
		async with self.async_lock:
			try:
				path = self._get_session_path(session_id)
				with open(path, 'w') as f:
					json.dump(session_data, f)
				return True
			except Exception:
				return False

	def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
		session_lock = self.session_locks[session_id]
		with session_lock:
			try:
				path = self._get_session_path(session_id)
				if not os.path.exists(path):
					return None
				with open(path, 'r') as f:
					return json.load(f)
			except Exception:
				return None

	async def get_session_async(self, session_id: str) -> Optional[Dict[str, Any]]:
		async with self.async_lock:
			try:
				path = self._get_session_path(session_id)
				if not os.path.exists(path):
					return None
				with open(path, 'r') as f:
					return json.load(f)
			except Exception:
				return None

	def update_session(self, session_id: str, session_data: Dict[str, Any]) -> bool:
		session_lock = self.session_locks[session_id]
		with session_lock:
			try:
				path = self._get_session_path(session_id)
				with open(path, 'w') as f:
					json.dump(session_data, f)
				return True
			except Exception:
				return False

	async def update_session_async(self, session_id: str, session_data: Dict[str, Any]) -> bool:
		async with self.async_lock:
			try:
				path = self._get_session_path(session_id)
				with open(path, 'w') as f:
					json.dump(session_data, f)
				return True
			except Exception:
				return False

	def delete_session(self, session_id: str) -> bool:
		session_lock = self.session_locks[session_id]
		with session_lock:
			try:
				path = self._get_session_path(session_id)
				if os.path.exists(path):
					os.remove(path)
					del self.session_locks[session_id]
					return True
				return False
			except Exception:
				return False

	async def delete_session_async(self, session_id: str) -> bool:
		async with self.async_lock:
			try:
				path = self._get_session_path(session_id)
				if os.path.exists(path):
					os.remove(path)
					if session_id in self.session_locks:
						del self.session_locks[session_id]
					return True
				return False
			except Exception:
				return False

	def cleanup_expired_sessions(self