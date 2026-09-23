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
import asyncio
import hashlib
import hmac
from abc import ABC, abstractmethod
from pathlib import Path
from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html

def get_config(key, default=None):
	env_key = f"BENCHMARK_{key.upper()}"
	return os.getenv(env_key, default)

class StorageProvider(ABC):
	@abstractmethod
	def save(self, key, data):
		pass

	@abstractmethod
	async def save_async(self, key, data):
		pass

	@abstractmethod
	def load(self, key):
		pass

	@abstractmethod
	async def load_async(self, key):
		pass

	@abstractmethod
	def delete(self, key):
		pass

	@abstractmethod
	async def delete_async(self, key):
		pass

	@abstractmethod
	def exists(self, key):
		pass

	@abstractmethod
	async def exists_async(self, key):
		pass

	@abstractmethod
	def list_keys(self):
		pass

	@abstractmethod
	async def list_keys_async(self):
		pass

class FileStorageProvider(StorageProvider):
	def __init__(self, base_path=None):
		self.base_path = Path(base_path or get_config('file_storage_path', './data'))
		self.base_path.mkdir(parents=True, exist_ok=True)

	def _get_file_path(self, key):
		safe_key = key.replace('/', '_').replace('\\', '_')
		return self.base_path / f"{safe_key}.json"

	def save(self, key, data):
		try:
			file_path = self._get_file_path(key)
			with open(file_path, 'w') as f:
				json.dump(data, f)
			return True
		except Exception as e:
			print(f"Error saving to file: {e}")
			return False

	async def save_async(self, key, data):
		return await asyncio.to_thread(self.save, key, data)

	def load(self, key):
		try:
			file_path = self._get_file_path(key)
			if not file_path.exists():
				return None
			with open(file_path, 'r') as f:
				return json.load(f)
		except Exception as e:
			print(f"Error loading from file: {e}")
			return None

	async def load_async(self, key):
		return await asyncio.to_thread(self.load, key)

	def delete(self, key):
		try:
			file_path = self._get_file_path(key)
			if file_path.exists():
				file_path.unlink()
			return True
		except Exception as e:
			print(f"Error deleting file: {e}")
			return False

	async def delete_async(self, key):
		return await asyncio.to_thread(self.delete, key)

	def exists(self, key):
		file_path = self._get_file_path(key)
		return file_path.exists()

	async def exists_async(self, key):
		return await asyncio.to_thread(self.exists, key)

	def list_keys(self):
		try:
			keys = []
			for file_path in self.base_path.glob("*.json"):
				key = file_path.stem
				keys.append(key)
			return keys
		except Exception as e:
			print(f"Error listing keys: {e}")
			return []

	async def list_keys_async(self):
		return await asyncio.to_thread(self.list_keys)

class DatabaseStorageProvider(StorageProvider):
	def __init__(self, db_path=None, db_type='sqlite', db_host=None, db_user=None, db_password=None, db_name=None):
		self.db_path = db_path or get_config('db_storage_path', './benchmark.db')
		self.db_type = db_type or get_config('db_type', 'sqlite')
		self.db_host = db_host or get_config('db_host')
		self.db_user = db_user or get_config('db_user')
		self.db_password = db_password or get_config('db_password')
		self.db_name = db_name or get_config('db_name')
		self._init_database()

	def _init_database(self):
		try:
			if self.db_type == 'sqlite':
				conn = sqlite3.connect(self.db_path)
				cursor = conn.cursor()
				cursor.execute('''
					CREATE TABLE IF NOT EXISTS storage (
						key TEXT PRIMARY KEY,
						data TEXT NOT NULL,
						created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
						updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
					)
				''')
				conn.commit()
				conn.close()
			elif self.db_type == 'postgresql':
				try:
					import psycopg2
					conn = psycopg2.connect(
						host=self.db_host,
						user=self.db_user,
						password=self.db_password,
						database=self.db_name
					)
					cursor = conn.cursor()
					cursor.execute('''
						CREATE TABLE IF NOT EXISTS storage (
							key TEXT PRIMARY KEY,
							data TEXT NOT NULL,
							created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
							updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
						)
					''')
					conn.commit()
					conn.close()
				except ImportError:
					print("psycopg2 not installed. Please install it for PostgreSQL support.")
			elif self.db_type == 'mysql':
				try:
					import mysql.connector
					conn = mysql.connector.connect(
						host=self.db_host,
						user=self.db_user,
						password=self.db_password,
						database=self.db_name
					)
					cursor = conn.cursor()
					cursor.execute('''
						CREATE TABLE IF NOT EXISTS storage (
							key VARCHAR(255) PRIMARY KEY,
							data LONGTEXT NOT NULL,
							created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
							updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
						)
					''')
					conn.commit()
					conn.close()
				except ImportError:
					print("mysql.connector not installed. Please install it for MySQL support.")
		except Exception as e:
			print(f"Error initializing database: {e}")

	def _get_connection(self):
		if self.db_type == 'sqlite':
			return sqlite3.connect(self.db_path)
		elif self.db_type == 'postgresql':
			import psycopg2
			return psycopg2.connect(
				host=self.db_host,
				user=self.db_user,
				password=self.db_password,
				database=self.db_name
			)
		elif self.db_type == 'mysql':
			import mysql.connector
			return mysql.connector.connect(
				host=self.db_host,
				user=self.db_user,
				password=self.db_password,
				database=self.db_name
			)
		raise ValueError(f"Unsupported database type: {self.db_type}")

	def save(self, key, data):
		try:
			conn = self._get_connection()
			cursor = conn.cursor()
			data_str = json.dumps(data)
			
			if self.db_type == 'sqlite':
				cursor.execute('''
					INSERT OR REPLACE INTO storage (key, data, updated_at)
					VALUES (?, ?, CURRENT_TIMESTAMP)
				''', (key, data_str))
			elif self.db_type == 'postgresql':
				cursor.execute('''
					INSERT INTO storage (key, data, updated_at)
					VALUES (%s, %s, CURRENT_TIMESTAMP)
					ON CONFLICT (key) DO UPDATE SET data = %s, updated_at = CURRENT_TIMESTAMP
				''', (key, data_str, data_str))
			elif self.db_type == 'mysql':
				cursor.execute('''
					INSERT INTO storage (key, data, updated_at)
					VALUES (%s, %s, CURRENT_TIMESTAMP)
					ON DUPLICATE KEY UPDATE data = %s, updated_at = CURRENT_TIMESTAMP
				''', (key, data_str, data_str))
			
			conn.commit()
			conn.close()
			return True
		except Exception as e:
			print(f"Error saving to database: {e}")
			return False

	async def save_async(self, key, data):
		return await asyncio.to_thread(self.save, key, data)

	def load(self, key):
		try:
			conn = self._get_connection()
			cursor = conn.cursor()
			
			if self.db_type == 'sqlite':
				cursor.execute('SELECT data FROM storage WHERE key = ?', (key,))
			else:
				cursor.execute('SELECT data FROM storage WHERE key = %s', (key,))
			
			row = cursor.fetchone()
			conn.close()
			if row:
				return json.loads(row[0])
			return None
		except Exception as e:
			print(f"Error loading from database: {e}")
			return None

	async def load_async(self, key):
		return await asyncio.to_thread(self.load, key)

	def delete(self, key):
		try:
			conn = self._get_connection()
			cursor = conn.cursor()
			
			if self.db_type == 'sqlite':
				cursor.execute('DELETE FROM storage WHERE key = ?', (key,))
			else:
				cursor.execute('DELETE FROM storage WHERE key = %s', (key,))
			
			conn.commit()
			conn.close()
			return True
		except Exception as e:
			print(f"Error deleting from database: {e}")
			return False

	async def delete_async(self, key):
		return await asyncio.to_thread(self.delete, key)

	def exists(self, key):
		try:
			conn = self._get_connection()
			cursor = conn.cursor()
			
			if self.db_type == 'sqlite':
				cursor.execute('SELECT 1 FROM storage WHERE key = ?', (key,))
			else:
				cursor.execute('SELECT 1 FROM storage WHERE key = %s', (key,))
			
			exists = cursor.fetchone() is not None
			conn.close()
			return exists
		except Exception as e:
			print(f"Error checking existence in database: {e}")
			return False

	async def exists_async(self, key):
		return await asyncio.to_thread(self.exists, key)

	def list_keys(self):
		try:
			conn = self._get_connection()
			cursor = conn.cursor()
			cursor.execute('SELECT key FROM storage')
			rows = cursor.fetchall()
			conn.close()
			return [row[0] for row in rows]
		except Exception as e:
			print(f"Error listing keys from database: {e}")
			return []

	async def list_keys_async(self):
		return await asyncio.to_thread(self.list_keys)

class HybridStorageProvider(StorageProvider):
	def __init__(self, primary_provider, fallback_provider):
		self.primary = primary_provider
		self.fallback = fallback_provider

	def save(self, key, data):
		primary_result = self.primary.save(key, data)
		if not primary_result:
			return self.fallback.save(key, data)
		return primary_result

	async def save_async(self, key, data):
		primary_result = await self.primary.save_async(key, data)
		if not primary_result:
			return await self.fallback.save_async(key, data)
		return primary_result

	def load(self, key):
		result = self.primary.load(key)
		if result is None:
			return self.fallback.load(key)
		return result

	async def load_async(self, key):
		result = await self.primary.load_async(key)
		if result is None:
			return await self.fallback.load_async(key)
		return result

	def delete(self, key):
		primary_result = self.primary.delete(key)
		fallback_result = self.fallback.delete(key)
		return primary_result or fallback_result

	async def delete_async(self, key):
		primary_result = await self.primary.delete_async(key)
		fallback_result = await self.fallback.delete_async(key)
		return primary_result or fallback_result

	def exists(self, key):
		return self.primary.exists(key) or self.fallback.exists(key)

	async def exists_async(self, key):
		primary_exists = await self.primary.exists_async(key)
		if primary_exists:
			return True
		return await self.fallback.exists_async(key)

	def list_keys(self):
		primary_keys = set(self.primary.list_keys())
		fallback_keys = set(self.fallback.list_keys())
		return list(primary_keys.union(fallback_keys))

	async def list_keys_async(self):
		primary_keys = set(await self.primary.list_keys_async())
		fallback_keys = set(await self.fallback.list_keys_async())
		return list(primary_keys.union(fallback_keys))

class StorageProviderFactory:
	@staticmethod
	def create_provider(provider_type='file', **kwargs):
		if provider_type == 'file':
			return FileStorageProvider(base_path=kwargs.get('base_path'))
		elif provider_type == 'database':
			return DatabaseStorageProvider(
				db_path=kwargs.get('db_path'),
				db_type=kwargs.get('db_type', 'sqlite'),
				db_host=kwargs.get('db_host'),
				db_user=kwargs.get('db_user'),
				db_password=kwargs.get('db_password'),
				db_name=kwargs.get('db_name')
			)
		elif provider_type == 'hybrid':
			primary = StorageProviderFactory.create_provider(
				kwargs.get('primary_type', 'file'),
				**kwargs.get('primary_config', {})
			)
			fallback = StorageProviderFactory.create_provider(
				kwargs.get('fallback_type', 'database'),
				**kwargs.get('fallback_config', {})
			)
			return HybridStorageProvider(primary, fallback)
		else:
			raise ValueError(f"Unknown provider type: {provider_type}")

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
		return username == expected