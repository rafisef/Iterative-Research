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
from threading import Lock
from datetime import datetime, timedelta
import uuid
import json
import os
import sqlite3
import asyncio
import aiofiles
import aiosqlite
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any

class Config:
	def __init__(self):
		self.storage_type = os.getenv('SESSION_STORAGE_TYPE', 'file')
		self.storage_dir = os.getenv('SESSION_STORAGE_DIR', 'sessions')
		self.db_path = os.getenv('SESSION_DB_PATH', 'sessions.db')
		self.session_timeout_hours = int(os.getenv('SESSION_TIMEOUT_HOURS', '1'))
		self.cleanup_interval = int(os.getenv('SESSION_CLEANUP_INTERVAL', '300'))
	
	def get_storage(self):
		storage_type = self.storage_type.lower()
		if storage_type == 'database':
			return DatabaseSessionStorage(self.db_path)
		elif storage_type == 'memory':
			return MemorySessionStorage()
		else:
			return FileSessionStorage(self.storage_dir)

class SessionStorage(ABC):
	@abstractmethod
	def get(self, session_id):
		pass
	
	@abstractmethod
	def set(self, session_id, session_data):
		pass
	
	@abstractmethod
	def delete(self, session_id):
		pass
	
	@abstractmethod
	def exists(self, session_id):
		pass
	
	@abstractmethod
	def cleanup_expired(self):
		pass
	
	@abstractmethod
	async def async_get(self, session_id):
		pass
	
	@abstractmethod
	async def async_set(self, session_id, session_data):
		pass
	
	@abstractmethod
	async def async_delete(self, session_id):
		pass
	
	@abstractmethod
	async def async_exists(self, session_id):
		pass
	
	@abstractmethod
	async def async_cleanup_expired(self):
		pass

class FileSessionStorage(SessionStorage):
	def __init__(self, storage_dir='sessions'):
		self.storage_dir = storage_dir
		self.lock = Lock()
		if not os.path.exists(storage_dir):
			os.makedirs(storage_dir)
	
	def _get_file_path(self, session_id):
		return os.path.join(self.storage_dir, f'{session_id}.json')
	
	def get(self, session_id):
		with self.lock:
			file_path = self._get_file_path(session_id)
			if os.path.exists(file_path):
				try:
					with open(file_path, 'r') as f:
						return json.load(f)
				except (json.JSONDecodeError, IOError):
					return None
		return None
	
	def set(self, session_id, session_data):
		with self.lock:
			file_path = self._get_file_path(session_id)
			try:
				with open(file_path, 'w') as f:
					json.dump(session_data, f, default=str)
			except IOError:
				pass
	
	def delete(self, session_id):
		with self.lock:
			file_path = self._get_file_path(session_id)
			if os.path.exists(file_path):
				try:
					os.remove(file_path)
				except OSError:
					pass
	
	def exists(self, session_id):
		with self.lock:
			file_path = self._get_file_path(session_id)
			return os.path.exists(file_path)
	
	def cleanup_expired(self):
		with self.lock:
			current_time = datetime.now()
			for filename in os.listdir(self.storage_dir):
				if filename.endswith('.json'):
					file_path = os.path.join(self.storage_dir, filename)
					try:
						with open(file_path, 'r') as f:
							data = json.load(f)
							expires = datetime.fromisoformat(data.get('expires', ''))
							if expires < current_time:
								os.remove(file_path)
					except (json.JSONDecodeError, IOError, ValueError):
						pass
	
	async def async_get(self, session_id):
		file_path = self._get_file_path(session_id)
		if os.path.exists(file_path):
			try:
				async with aiofiles.open(file_path, 'r') as f:
					content = await f.read()
					return json.loads(content)
			except (json.JSONDecodeError, IOError):
				return None
		return None
	
	async def async_set(self, session_id, session_data):
		file_path = self._get_file_path(session_id)
		try:
			async with aiofiles.open(file_path, 'w') as f:
				await f.write(json.dumps(session_data, default=str))
		except IOError:
			pass
	
	async def async_delete(self, session_id):
		file_path = self._get_file_path(session_id)
		if os.path.exists(file_path):
			try:
				os.remove(file_path)
			except OSError:
				pass
	
	async def async_exists(self, session_id):
		file_path = self._get_file_path(session_id)
		return os.path.exists(file_path)
	
	async def async_cleanup_expired(self):
		current_time = datetime.now()
		try:
			for filename in os.listdir(self.storage_dir):
				if filename.endswith('.json'):
					file_path = os.path.join(self.storage_dir, filename)
					try:
						async with aiofiles.open(file_path, 'r') as f:
							content = await f.read()
							data = json.loads(content)
							expires = datetime.fromisoformat(data.get('expires', ''))
							if expires < current_time:
								os.remove(file_path)
					except (json.JSONDecodeError, IOError, ValueError):
						pass
		except OSError:
			pass

class DatabaseSessionStorage(SessionStorage):
	def __init__(self, db_path='sessions.db'):
		self.db_path = db_path
		self.lock = Lock()
		self._init_db()
	
	def _init_db(self):
		with self.lock:
			conn = sqlite3.connect(self.db_path)
			cursor = conn.cursor()
			cursor.execute('''
				CREATE TABLE IF NOT EXISTS sessions (
					session_id TEXT PRIMARY KEY,
					created TEXT NOT NULL,
					last_accessed TEXT NOT NULL,
					expires TEXT NOT NULL,
					data TEXT NOT NULL
				)
			''')
			conn.commit()
			conn.close()
	
	async def _async_init_db(self):
		async with aiosqlite.connect(self.db_path) as db:
			await db.execute('''
				CREATE TABLE IF NOT EXISTS sessions (
					session_id TEXT PRIMARY KEY,
					created TEXT NOT NULL,
					last_accessed TEXT NOT NULL,
					expires TEXT NOT NULL,
					data TEXT NOT NULL
				)
			''')
			await db.commit()
	
	def get(self, session_id):
		with self.lock:
			try:
				conn = sqlite3.connect(self.db_path)
				cursor = conn.cursor()
				cursor.execute('SELECT created, last_accessed, expires, data FROM sessions WHERE session_id = ?', (session_id,))
				row = cursor.fetchone()
				conn.close()
				if row:
					return {
						'created': row[0],
						'last_accessed': row[1],
						'expires': row[2],
						'data': json.loads(row[3])
					}
			except (sqlite3.Error, json.JSONDecodeError):
				pass
		return None
	
	def set(self, session_id, session_data):
		with self.lock:
			try:
				conn = sqlite3.connect(self.db_path)
				cursor = conn.cursor()
				data_json = json.dumps(session_data['data'], default=str)
				cursor.execute('''
					INSERT OR REPLACE INTO sessions (session_id, created, last_accessed, expires, data)
					VALUES (?, ?, ?, ?, ?)
				''', (session_id, session_data['created'], session_data['last_accessed'], session_data['expires'], data_json))
				conn.commit()
				conn.close()
			except sqlite3.Error:
				pass
	
	def delete(self, session_id):
		with self.lock:
			try:
				conn = sqlite3.connect(self.db_path)
				cursor = conn.cursor()
				cursor.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
				conn.commit()
				conn.close()
			except sqlite3.Error:
				pass
	
	def exists(self, session_id):
		with self.lock:
			try:
				conn = sqlite3.connect(self.db_path)
				cursor = conn.cursor()
				cursor.execute('SELECT 1 FROM sessions WHERE session_id = ?', (session_id,))
				result = cursor.fetchone() is not None
				conn.close()
				return result
			except sqlite3.Error:
				pass
		return False
	
	def cleanup_expired(self):
		with self.lock:
			try:
				conn = sqlite3.connect(self.db_path)
				cursor = conn.cursor()
				current_time = datetime.now().isoformat()
				cursor.execute('DELETE FROM sessions WHERE expires < ?', (current_time,))
				conn.commit()
				conn.close()
			except sqlite3.Error:
				pass
	
	async def async_get(self, session_id):
		try:
			async with aiosqlite.connect(self.db_path) as db:
				async with db.execute('SELECT created, last_accessed, expires, data FROM sessions WHERE session_id = ?', (session_id,)) as cursor:
					row = await cursor.fetchone()
					if row:
						return {
							'created': row[0],
							'last_accessed': row[1],
							'expires': row[2],
							'data': json.loads(row[3])
						}
		except (aiosqlite.Error, json.JSONDecodeError):
			pass
		return None
	
	async def async_set(self, session_id, session_data):
		try:
			async with aiosqlite.connect(self.db_path) as db:
				data_json = json.dumps(session_data['data'], default=str)
				await db.execute('''
					INSERT OR REPLACE INTO sessions (session_id, created, last_accessed, expires, data)
					VALUES (?, ?, ?, ?, ?)
				''', (session_id, session_data['created'], session_data['last_accessed'], session_data['expires'], data_json))
				await db.commit()
		except aiosqlite.Error:
			pass
	
	async def async_delete(self, session_id):
		try:
			async with aiosqlite.connect(self.db_path) as db:
				await db.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
				await db.commit()
		except aiosqlite.Error:
			pass
	
	async def async_exists(self, session_id):
		try:
			async with aiosqlite.connect(self.db_path) as db:
				async with db.execute('SELECT 1 FROM sessions WHERE session_id = ?', (session_id,)) as cursor:
					result = await cursor.fetchone() is not None
					return result
		except aiosqlite.Error:
			pass
		return False
	
	async def async_cleanup_expired(self):
		try:
			async with aiosqlite.connect(self.db_path) as db:
				current_time = datetime.now().isoformat()
				await db.execute('DELETE FROM sessions WHERE expires < ?', (current_time,))
				await db.commit()
		except aiosqlite.Error:
			pass

class MemorySessionStorage(SessionStorage):
	def __init__(self):
		self.sessions = {}
		self.lock = Lock()
	
	def get(self, session_id):
		with self.lock:
			return self.sessions.get(session_id)
	
	def set(self, session_id, session_data):
		with self.lock:
			self.sessions[session_id] = session_data
	
	def delete(self, session_id):
		with self.lock:
			if session_id in self.sessions:
				del self.sessions[session_id]
	
	def exists(self, session_id):
		with self.lock:
			return session_id in self.sessions
	
	def cleanup_expired(self):
		with self.lock:
			current_time = datetime.now()
			expired_ids = []
			for session_id, session_data in self.sessions.items():
				try:
					expires = datetime.fromisoformat(session_data.get('expires', ''))
					if expires < current_time:
						expired_ids.append(session_id)
				except ValueError:
					pass
			for session_id in expired_ids:
				del self.sessions[session_id]
	
	async def async_get(self, session_id):
		return self.get(session_id)
	
	async def async_set(self, session_id, session_data):
		self.set(session_id, session_data)
	
	async def async_delete(self, session_id):
		self.delete(session_id)
	
	async def async_exists(self, session_id):
		return self.exists(session_id)
	
	async def async_cleanup_expired(self):
		self.cleanup_expired()

session_storage = None
session_lock = Lock()
config = Config()

def initialize_storage(custom_config=None):
	global session_storage, config
	if custom_config:
		config = custom_config
	session_storage = config.get_storage()

def set_storage(storage):
	global session_storage
	session_storage = storage

def cleanup_expired_sessions():
	if session_storage:
		session_storage.cleanup_expired()

async def async_cleanup_expired_sessions():
	if session_storage:
		await session_storage.async_cleanup_expired()

def get_or_create_session():
	cleanup_expired_sessions()
	
	session_id = request.cookies.get('session_id')
	
	if session_id and session_storage.exists(session_id):
		with session_lock:
			session_data = session_storage.get(session_id)
			if session_data:
				session_data['last_accessed'] = datetime.now().isoformat()
				session_data['expires'] = (datetime.now() + timedelta(hours=config.session_timeout_hours)).isoformat()
				session_storage.set(session_id, session_data)
				return session_id, session_data
	
	new_session_id = str(uuid.uuid4())