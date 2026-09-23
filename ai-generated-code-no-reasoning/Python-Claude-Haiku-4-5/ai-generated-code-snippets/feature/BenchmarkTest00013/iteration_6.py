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
import asyncio
import inspect
import os
from abc import ABC, abstractmethod
import json
from datetime import datetime
import sqlite3
import pickle
from functools import wraps
from typing import Optional, Dict, Any, Callable

class StorageBackend(ABC):
	@abstractmethod
	def save_query_result(self, test_id, param, result):
		pass
	
	@abstractmethod
	def load_query_result(self, test_id, param):
		pass
	
	@abstractmethod
	def save_cookie_state(self, cookie_name, value):
		pass
	
	@abstractmethod
	def load_cookie_state(self, cookie_name):
		pass
	
	@abstractmethod
	async def save_query_result_async(self, test_id, param, result):
		pass
	
	@abstractmethod
	async def load_query_result_async(self, test_id, param):
		pass
	
	@abstractmethod
	async def save_cookie_state_async(self, cookie_name, value):
		pass
	
	@abstractmethod
	async def load_cookie_state_async(self, cookie_name):
		pass

class FileStorageBackend(StorageBackend):
	def __init__(self, base_dir='./benchmark_storage'):
		self.base_dir = base_dir
		os.makedirs(base_dir, exist_ok=True)
		os.makedirs(os.path.join(base_dir, 'queries'), exist_ok=True)
		os.makedirs(os.path.join(base_dir, 'cookies'), exist_ok=True)
	
	def save_query_result(self, test_id, param, result):
		file_path = os.path.join(self.base_dir, 'queries', f'{test_id}_{hash(param)}.json')
		data = {
			'test_id': test_id,
			'param': param,
			'result': result,
			'timestamp': datetime.now().isoformat()
		}
		with open(file_path, 'w') as f:
			json.dump(data, f)
	
	def load_query_result(self, test_id, param):
		file_path = os.path.join(self.base_dir, 'queries', f'{test_id}_{hash(param)}.json')
		if os.path.exists(file_path):
			with open(file_path, 'r') as f:
				return json.load(f)
		return None
	
	def save_cookie_state(self, cookie_name, value):
		file_path = os.path.join(self.base_dir, 'cookies', f'{cookie_name}.json')
		data = {
			'cookie_name': cookie_name,
			'value': value,
			'timestamp': datetime.now().isoformat()
		}
		with open(file_path, 'w') as f:
			json.dump(data, f)
	
	def load_cookie_state(self, cookie_name):
		file_path = os.path.join(self.base_dir, 'cookies', f'{cookie_name}.json')
		if os.path.exists(file_path):
			with open(file_path, 'r') as f:
				return json.load(f)
		return None
	
	async def save_query_result_async(self, test_id, param, result):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.save_query_result, test_id, param, result)
	
	async def load_query_result_async(self, test_id, param):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.load_query_result, test_id, param)
	
	async def save_cookie_state_async(self, cookie_name, value):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.save_cookie_state, cookie_name, value)
	
	async def load_cookie_state_async(self, cookie_name):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.load_cookie_state, cookie_name)

class DatabaseStorageBackend(StorageBackend):
	def __init__(self, db_path='./benchmark_storage/benchmark.db'):
		self.db_path = db_path
		os.makedirs(os.path.dirname(db_path), exist_ok=True)
		self._init_db()
	
	def _init_db(self):
		conn = sqlite3.connect(self.db_path)
		cursor = conn.cursor()
		
		cursor.execute('''
			CREATE TABLE IF NOT EXISTS query_results (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				test_id TEXT NOT NULL,
				param TEXT NOT NULL,
				result TEXT NOT NULL,
				timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
			)
		''')
		
		cursor.execute('''
			CREATE TABLE IF NOT EXISTS cookie_states (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				cookie_name TEXT NOT NULL UNIQUE,
				value TEXT NOT NULL,
				timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
			)
		''')
		
		conn.commit()
		conn.close()
	
	def save_query_result(self, test_id, param, result):
		conn = sqlite3.connect(self.db_path)
		cursor = conn.cursor()
		cursor.execute('''
			INSERT INTO query_results (test_id, param, result)
			VALUES (?, ?, ?)
		''', (test_id, param, result))
		conn.commit()
		conn.close()
	
	def load_query_result(self, test_id, param):
		conn = sqlite3.connect(self.db_path)
		cursor = conn.cursor()
		cursor.execute('''
			SELECT test_id, param, result, timestamp FROM query_results
			WHERE test_id = ? AND param = ?
			ORDER BY timestamp DESC LIMIT 1
		''', (test_id, param))
		row = cursor.fetchone()
		conn.close()
		
		if row:
			return {
				'test_id': row[0],
				'param': row[1],
				'result': row[2],
				'timestamp': row[3]
			}
		return None
	
	def save_cookie_state(self, cookie_name, value):
		conn = sqlite3.connect(self.db_path)
		cursor = conn.cursor()
		cursor.execute('''
			INSERT OR REPLACE INTO cookie_states (cookie_name, value)
			VALUES (?, ?)
		''', (cookie_name, value))
		conn.commit()
		conn.close()
	
	def load_cookie_state(self, cookie_name):
		conn = sqlite3.connect(self.db_path)
		cursor = conn.cursor()
		cursor.execute('''
			SELECT cookie_name, value, timestamp FROM cookie_states
			WHERE cookie_name = ?
		''', (cookie_name,))
		row = cursor.fetchone()
		conn.close()
		
		if row:
			return {
				'cookie_name': row[0],
				'value': row[1],
				'timestamp': row[2]
			}
		return None
	
	async def save_query_result_async(self, test_id, param, result):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.save_query_result, test_id, param, result)
	
	async def load_query_result_async(self, test_id, param):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.load_query_result, test_id, param)
	
	async def save_cookie_state_async(self, cookie_name, value):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.save_cookie_state, cookie_name, value)
	
	async def load_cookie_state_async(self, cookie_name):
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.load_cookie_state, cookie_name)

class AuthenticationProvider(ABC):
	@abstractmethod
	def authenticate(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
		pass
	
	@abstractmethod
	async def authenticate_async(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
		pass
	
	@abstractmethod
	def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
		pass
	
	@abstractmethod
	async def validate_token_async(self, token: str) -> Optional[Dict[str, Any]]:
		pass

class BasicAuthProvider(AuthenticationProvider):
	def __init__(self, users: Dict[str, str]):
		self.users = users
	
	def authenticate(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
		username = credentials.get('username')
		password = credentials.get('password')
		
		if username in self.users and self.users[username] == password:
			return {'username': username, 'authenticated': True}
		return None
	
	async def authenticate_async(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.authenticate, credentials)
	
	def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
		import base64
		try:
			decoded = base64.b64decode(token).decode('utf-8')
			username, password = decoded.split(':', 1)
			return self.authenticate({'username': username, 'password': password})
		except:
			return None
	
	async def validate_token_async(self, token: str) -> Optional[Dict[str, Any]]:
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.validate_token, token)

class TokenAuthProvider(AuthenticationProvider):
	def __init__(self, valid_tokens: Dict[str, Dict[str, Any]]):
		self.valid_tokens = valid_tokens
	
	def authenticate(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
		token = credentials.get('token')
		if token in self.valid_tokens:
			return self.valid_tokens[token]
		return None
	
	async def authenticate_async(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.authenticate, credentials)
	
	def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
		if token in self.valid_tokens:
			return self.valid_tokens[token]
		return None
	
	async def validate_token_async(self, token: str) -> Optional[Dict[str, Any]]:
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.validate_token, token)

class SessionAuthProvider(AuthenticationProvider):
	def __init__(self):
		self.sessions = {}
	
	def authenticate(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
		session_id = credentials.get('session_id')
		if session_id in self.sessions:
			return self.sessions[session_id]
		return None
	
	async def authenticate_async(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.authenticate, credentials)
	
	def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
		if token in self.sessions:
			return self.sessions[token]
		return None
	
	async def validate_token_async(self, token: str) -> Optional[Dict[str, Any]]:
		loop = asyncio.get_event_loop()
		return await loop.run_in_executor(None, self.validate_token, token)
	
	def create_session(self, session_id: str, user_data: Dict[str, Any]):
		self.sessions[session_id] = user_data
	
	def destroy_session(self, session_id: str):
		if session_id in self.sessions:
			del self.sessions[session_id]

class AuthenticationManager:
	def __init__(self):
		self.providers: Dict[str, AuthenticationProvider] = {}
		self.active_provider: Optional[str] = None
	
	def register_provider(self, name: str, provider: AuthenticationProvider):
		self.providers[name] = provider
		if self.active_provider is None:
			self.active_provider = name
	
	def set_active_provider(self, name: str):
		if name in self.providers:
			self.active_provider = name
			return True
		return False
	
	def get_provider(self, name: Optional[str] = None) -> Optional[AuthenticationProvider]:
		if name:
			return self.providers.get(name)
		if self.active_provider:
			return self.providers.get(self.active_provider)
		return None
	
	def authenticate(self, credentials: Dict[str, Any], provider: Optional[str] = None) -> Optional[Dict[str, Any]]:
		auth_provider = self.get_provider(provider)
		if auth_provider:
			return auth_provider.authenticate(credentials)
		return None
	
	async def authenticate_async(self, credentials: Dict[str, Any], provider: Optional[str] = None) -> Optional[Dict[str, Any]]:
		auth_provider = self.get_provider(provider)
		if auth_provider:
			return await auth_provider.authenticate_async(credentials)
		return None
	
	def validate_token(self, token: str, provider: Optional[str] = None) -> Optional[Dict[str, Any]]:
		auth_provider = self.get_provider(provider)
		if auth_provider:
			return auth_provider.validate_token(token)
		return None
	
	async def validate_token_async(self, token: str, provider: Optional[str] = None) -> Optional[Dict[str, Any]]:
		auth_provider = self.get_provider(provider)
		if auth_provider:
			return await auth_provider.validate_token_async(token)
		return None

def _parse_env_value(value, value_type=str):
	if value_type == bool:
		return value.lower() in ('true', '1', 'yes', 'on')
	elif value_type == int:
		return int(value)
	elif value_type == float:
		return float(value)
	return value

def _get_config(key, default=None, value_type=str):
	env_key = f"BENCHMARK_{key.upper()}"
	env_value = os.getenv(env_key)
	if env_value is not None:
		return _parse_env_value(env_value, value_type)
	return default

def