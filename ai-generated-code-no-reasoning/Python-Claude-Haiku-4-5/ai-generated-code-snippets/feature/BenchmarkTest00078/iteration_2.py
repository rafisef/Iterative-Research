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
from typing import Dict, Any, Optional
import uuid
import threading
import time
from datetime import datetime, timedelta


class SessionManager:
	def __init__(self, session_timeout: int = 3600):
		self.sessions: Dict[str, Dict[str, Any]] = {}
		self.session_lock = threading.RLock()
		self.session_timeout = session_timeout
		self.cleanup_thread = threading.Thread(target=self._cleanup_expired_sessions, daemon=True)
		self.cleanup_thread.start()

	def create_session(self, user_info: Dict[str, Any]) -> str:
		session_id = str(uuid.uuid4())
		with self.session_lock:
			self.sessions[session_id] = {
				'user_info': user_info,
				'created_at': datetime.now(),
				'last_accessed': datetime.now(),
				'data': {}
			}
		return session_id

	def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
		with self.session_lock:
			if session_id not in self.sessions:
				return None
			
			session = self.sessions[session_id]
			if datetime.now() - session['last_accessed'] > timedelta(seconds=self.session_timeout):
				del self.sessions[session_id]
				return None
			
			session['last_accessed'] = datetime.now()
			return session

	def set_session_data(self, session_id: str, key: str, value: Any) -> bool:
		with self.session_lock:
			if session_id not in self.sessions:
				return False
			
			session = self.sessions[session_id]
			if datetime.now() - session['last_accessed'] > timedelta(seconds=self.session_timeout):
				del self.sessions[session_id]
				return False
			
			session['data'][key] = value
			session['last_accessed'] = datetime.now()
			return True

	def get_session_data(self, session_id: str, key: str) -> Optional[Any]:
		with self.session_lock:
			if session_id not in self.sessions:
				return None
			
			session = self.sessions[session_id]
			if datetime.now() - session['last_accessed'] > timedelta(seconds=self.session_timeout):
				del self.sessions[session_id]
				return None
			
			session['last_accessed'] = datetime.now()
			return session['data'].get(key)

	def destroy_session(self, session_id: str) -> bool:
		with self.session_lock:
			if session_id in self.sessions:
				del self.sessions[session_id]
				return True
			return False

	def _cleanup_expired_sessions(self):
		while True:
			time.sleep(300)
			with self.session_lock:
				expired_sessions = [
					sid for sid, session in self.sessions.items()
					if datetime.now() - session['last_accessed'] > timedelta(seconds=self.session_timeout)
				]
				for sid in expired_sessions:
					del self.sessions[sid]


class AuthenticationProvider(ABC):
	@abstractmethod
	def authenticate(self, credentials: Dict[str, Any]) -> bool:
		pass

	@abstractmethod
	def get_user_info(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
		pass


class BasicAuthProvider(AuthenticationProvider):
	def __init__(self, users: Dict[str, str]):
		self.users = users

	def authenticate(self, credentials: Dict[str, Any]) -> bool:
		username = credentials.get('username')
		password = credentials.get('password')
		return username in self.users and self.users[username] == password

	def get_user_info(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
		if self.authenticate(credentials):
			return {'username': credentials.get('username'), 'provider': 'basic'}
		return None


class TokenAuthProvider(AuthenticationProvider):
	def __init__(self, valid_tokens: Dict[str, Dict[str, Any]]):
		self.valid_tokens = valid_tokens

	def authenticate(self, credentials: Dict[str, Any]) -> bool:
		token = credentials.get('token')
		return token in self.valid_tokens

	def get_user_info(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
		token = credentials.get('token')
		if token in self.valid_tokens:
			user_info = self.valid_tokens[token].copy()
			user_info['provider'] = 'token'
			return user_info
		return None


class APIKeyAuthProvider(AuthenticationProvider):
	def __init__(self, api_keys: Dict[str, Dict[str, Any]]):
		self.api_keys = api_keys

	def authenticate(self, credentials: Dict[str, Any]) -> bool:
		api_key = credentials.get('api_key')
		return api_key in self.api_keys

	def get_user_info(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
		api_key = credentials.get('api_key')
		if api_key in self.api_keys:
			user_info = self.api_keys[api_key].copy()
			user_info['provider'] = 'api_key'
			return user_info
		return None


class AuthenticationManager:
	def __init__(self):
		self.providers: Dict[str, AuthenticationProvider] = {}
		self.default_provider: Optional[str] = None
		self.session_manager = SessionManager()

	def register_provider(self, name: str, provider: AuthenticationProvider, default: bool = False):
		self.providers[name] = provider
		if default:
			self.default_provider = name

	def authenticate(self, provider_name: Optional[str] = None, credentials: Dict[str, Any] = None) -> bool:
		if credentials is None:
			credentials = {}
		
		name = provider_name or self.default_provider
		if name not in self.providers:
			return False
		
		return self.providers[name].authenticate(credentials)

	def get_user_info(self, provider_name: Optional[str] = None, credentials: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
		if credentials is None:
			credentials = {}
		
		name = provider_name or self.default_provider
		if name not in self.providers:
			return None
		
		return self.providers[name].get_user_info(credentials)

	def authenticate_any(self, credentials_by_provider: Dict[str, Dict[str, Any]]) -> tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
		for provider_name, credentials in credentials_by_provider.items():
			if provider_name in self.providers:
				if self.providers[provider_name].authenticate(credentials):
					user_info = self.providers[provider_name].get_user_info(credentials)
					return True, provider_name, user_info
		return False, None, None

	def create_session(self, user_info: Dict[str, Any]) -> str:
		return self.session_manager.create_session(user_info)

	def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
		return self.session_manager.get_session(session_id)

	def set_session_data(self, session_id: str, key: str, value: Any) -> bool:
		return self.session_manager.set_session_data(session_id, key, value)

	def get_session_data(self, session_id: str, key: str) -> Optional[Any]:
		return self.session_manager.get_session_data(session_id, key)

	def destroy_session(self, session_id: str) -> bool:
		return self.session_manager.destroy_session(session_id)


auth_manager = AuthenticationManager()


def init(app):
	basic_users = {
		'user1': 'password1',
		'user2': 'password2'
	}
	auth_manager.register_provider('basic', BasicAuthProvider(basic_users), default=True)

	valid_tokens = {
		'token123': {'username': 'tokenuser1', 'role': 'admin'},
		'token456': {'username': 'tokenuser2', 'role': 'user'}
	}
	auth_manager.register_provider('token', TokenAuthProvider(valid_tokens))

	api_keys = {
		'key_abc123': {'app_name': 'app1', 'role': 'service'},
		'key_xyz789': {'app_name': 'app2', 'role': 'service'}
	}
	auth_manager.register_provider('api_key', APIKeyAuthProvider(api_keys))

	@app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['GET'])
	def BenchmarkTest00078_get():
		response = make_response(render_template('web/deserialization-00/BenchmarkTest00078.html'))
		response.set_cookie('BenchmarkTest00078', 'gASVNwAAAAAAAACMCF9fbWFpbl9flIwOc2FmZV90b19waWNrbGWUk5QpgZR9lCiMAWGUjANmb2-UjAFilEtjdWIu',
			max_age=60*3,
			secure=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['POST'])
	def BenchmarkTest00078_post():
		RESPONSE = ""

		import urllib.parse
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00078", "noCookieValueSupplied"))

		string9895 = 'help'
		string9895 += param
		string9895 += 'snapes on a plane'
		bar = string9895[4:-17]

		import pickle
		import base64
		import helpers.utils

		helpers.utils.sharedstr = "no pickles to be seen here"

		try:
			unpickled = pickle.loads(base64.urlsafe_b64decode(bar))
		except:
			RESPONSE += (
				'Unpickling failed!'
			)
			return RESPONSE

		RESPONSE += (
			f'shared string is {helpers.utils.sharedstr}'
		)

		return RESPONSE

	@app.route('/benchmark/auth/login', methods=['POST'])
	def auth_login():
		provider = request.form.get('provider', 'basic')
		credentials = {
			'username': request.form.get('username'),
			'password': request.form.get('password'),
			'token': request.form.get('token'),
			'api_key': request.form.get('api_key')
		}
		
		if auth_manager.authenticate(provider, credentials):
			user_info = auth_manager.get_user_info(provider, credentials)
			session_id = auth_manager.create_session(user_info)
			response = make_response({'status': 'success', 'user': user_info, 'session_id': session_id})
			response.set_cookie('session_id', session_id, secure=True, httponly=True)
			response.set_cookie('auth_provider', provider, secure=True, httponly=True)
			return response
		
		return {'status': 'failed'}, 401

	@app.route('/benchmark/auth/validate', methods=['POST'])
	def auth_validate():
		session_id = request.cookies.get('session_id')
		
		if session_id:
			session = auth_manager.get_session(session_id)
			if session:
				return {'status': 'success', 'user': session['user_info'], 'session_valid': True}
		
		credentials_by_provider = {
			'basic': {
				'username': request.form.get('username'),
				'password': request.form.get('password')
			},
			'token': {
				'token': request.form.get('token')
			},
			'api_key': {
				'api_key': request.form.get('api_key')
			}
		}
		
		authenticated, provider_name, user_info = auth_manager.authenticate_any(credentials_by_provider)
		
		if authenticated:
			session_id = auth_manager.create_session(user_info)
			response = make_response({'status': 'success', 'provider': provider_name, 'user': user_info, 'session_id': session_id})
			response.set_cookie('session_id', session_id, secure=True, httponly=True)
			return response
		
		return {'status': 'failed'}, 401

	@app.route('/benchmark/auth/logout', methods=['POST'])
	def auth_logout():
		session_id = request.cookies.get('session_id')
		
		if session_id:
			auth_manager.destroy_session(session_id)
		
		response = make_response({'status': 'success'})
		response.delete_cookie('session_id')
		response.delete_cookie('auth_provider')
		return response