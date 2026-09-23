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
import hashlib
import hmac
import os
import time
import json
import base64
import threading
import asyncio
import concurrent.futures

AUTH_PROVIDERS = {}
_thread_pool = concurrent.futures.ThreadPoolExecutor()

def register_auth_provider(name, provider):
    AUTH_PROVIDERS[name] = provider

def _run_sync(func, *args, **kwargs):
    return func(*args, **kwargs)

async def _run_async(func, *args, **kwargs):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(_thread_pool, lambda: func(*args, **kwargs))

class BasicAuthProvider:
    def __init__(self):
        self.users = {}
        self._lock = threading.RLock()
        self._async_lock = None

    def _get_async_lock(self):
        if self._async_lock is None:
            self._async_lock = asyncio.Lock()
        return self._async_lock

    def authenticate(self, username, password):
        with self._lock:
            if username in self.users:
                stored_hash = self.users[username]
                password_hash = hashlib.sha256(password.encode()).hexdigest()
                return hmac.compare_digest(stored_hash, password_hash)
            return False

    async def authenticate_async(self, username, password):
        return await _run_async(self.authenticate, username, password)

    def register_user(self, username, password):
        with self._lock:
            self.users[username] = hashlib.sha256(password.encode()).hexdigest()

    async def register_user_async(self, username, password):
        return await _run_async(self.register_user, username, password)

    def generate_token(self, username):
        timestamp = str(int(time.time()))
        random_bytes = base64.b64encode(os.urandom(32)).decode()
        token_data = json.dumps({
            'username': username,
            'timestamp': timestamp,
            'random': random_bytes
        })
        return base64.b64encode(token_data.encode()).decode()

    async def generate_token_async(self, username):
        return await _run_async(self.generate_token, username)

    def validate_token(self, token):
        try:
            token_data = json.loads(base64.b64decode(token).decode())
            current_time = int(time.time())
            token_time = int(token_data.get('timestamp', 0))
            if current_time - token_time > 3600:
                return False, None
            return True, token_data.get('username')
        except Exception:
            return False, None

    async def validate_token_async(self, token):
        return await _run_async(self.validate_token, token)

class ApiKeyAuthProvider:
    def __init__(self):
        self.api_keys = {}
        self._lock = threading.RLock()

    def generate_api_key(self, client_id):
        with self._lock:
            key = base64.b64encode(os.urandom(32)).decode()
            self.api_keys[key] = {
                'client_id': client_id,
                'created_at': int(time.time())
            }
            return key

    async def generate_api_key_async(self, client_id):
        return await _run_async(self.generate_api_key, client_id)

    def authenticate(self, api_key):
        with self._lock:
            if api_key in self.api_keys:
                key_data = self.api_keys[api_key]
                current_time = int(time.time())
                if current_time - key_data['created_at'] > 86400:
                    del self.api_keys[api_key]
                    return False, None
                return True, key_data['client_id']
            return False, None

    async def authenticate_async(self, api_key):
        return await _run_async(self.authenticate, api_key)

    def revoke_api_key(self, api_key):
        with self._lock:
            if api_key in self.api_keys:
                del self.api_keys[api_key]
                return True
            return False

    async def revoke_api_key_async(self, api_key):
        return await _run_async(self.revoke_api_key, api_key)

class SessionAuthProvider:
    def __init__(self):
        self.sessions = {}
        self._lock = threading.RLock()
        self._user_sessions = {}

    def create_session(self, user_id):
        with self._lock:
            session_id = base64.b64encode(os.urandom(32)).decode()
            current_time = int(time.time())
            self.sessions[session_id] = {
                'user_id': user_id,
                'created_at': current_time,
                'last_accessed': current_time
            }
            if user_id not in self._user_sessions:
                self._user_sessions[user_id] = set()
            self._user_sessions[user_id].add(session_id)
            return session_id

    async def create_session_async(self, user_id):
        return await _run_async(self.create_session, user_id)

    def validate_session(self, session_id):
        with self._lock:
            if session_id in self.sessions:
                session_data = self.sessions[session_id]
                current_time = int(time.time())
                if current_time - session_data['last_accessed'] > 1800:
                    user_id = session_data['user_id']
                    del self.sessions[session_id]
                    if user_id in self._user_sessions:
                        self._user_sessions[user_id].discard(session_id)
                    return False, None
                self.sessions[session_id]['last_accessed'] = current_time
                return True, session_data['user_id']
            return False, None

    async def validate_session_async(self, session_id):
        return await _run_async(self.validate_session, session_id)

    def invalidate_session(self, session_id):
        with self._lock:
            if session_id in self.sessions:
                user_id = self.sessions[session_id]['user_id']
                del self.sessions[session_id]
                if user_id in self._user_sessions:
                    self._user_sessions[user_id].discard(session_id)
                return True
            return False

    async def invalidate_session_async(self, session_id):
        return await _run_async(self.invalidate_session, session_id)

    def invalidate_all_user_sessions(self, user_id):
        with self._lock:
            if user_id in self._user_sessions:
                session_ids = list(self._user_sessions[user_id])
                for session_id in session_ids:
                    if session_id in self.sessions:
                        del self.sessions[session_id]
                del self._user_sessions[user_id]
                return True
            return False

    async def invalidate_all_user_sessions_async(self, user_id):
        return await _run_async(self.invalidate_all_user_sessions, user_id)

    def get_user_sessions(self, user_id):
        with self._lock:
            if user_id not in self._user_sessions:
                return []
            active_sessions = []
            current_time = int(time.time())
            stale = []
            for session_id in self._user_sessions[user_id]:
                if session_id in self.sessions:
                    session_data = self.sessions[session_id]
                    if current_time - session_data['last_accessed'] <= 1800:
                        active_sessions.append({
                            'session_id': session_id,
                            'created_at': session_data['created_at'],
                            'last_accessed': session_data['last_accessed']
                        })
                    else:
                        stale.append(session_id)
            for session_id in stale:
                del self.sessions[session_id]
                self._user_sessions[user_id].discard(session_id)
            return active_sessions

    async def get_user_sessions_async(self, user_id):
        return await _run_async(self.get_user_sessions, user_id)

    def cleanup_expired_sessions(self):
        with self._lock:
            current_time = int(time.time())
            expired = [
                sid for sid, data in self.sessions.items()
                if current_time - data['last_accessed'] > 1800
            ]
            for session_id in expired:
                user_id = self.sessions[session_id]['user_id']
                del self.sessions[session_id]
                if user_id in self._user_sessions:
                    self._user_sessions[user_id].discard(session_id)

    async def cleanup_expired_sessions_async(self):
        return await _run_async(self.cleanup_expired_sessions)

basic_auth_provider = BasicAuthProvider()
api_key_provider = ApiKeyAuthProvider()
session_auth_provider = SessionAuthProvider()

register_auth_provider('basic', basic_auth_provider)
register_auth_provider('api_key', api_key_provider)
register_auth_provider('session', session_auth_provider)

def authenticate_request(req):
    auth_header = req.headers.get('Authorization', '')

    if auth_header.startswith('Bearer '):
        token = auth_header[7:]
        valid, username = basic_auth_provider.validate_token(token)
        if valid:
            return True, username, 'basic'

    api_key = req.headers.get('X-API-Key', '')
    if api_key:
        valid, client_id = api_key_provider.authenticate(api_key)
        if valid:
            return True, client_id, 'api_key'

    session_id = req.cookies.get('session_id', '')
    if session_id:
        valid, user_id = session_auth_provider.validate_session(session_id)
        if valid:
            return True, user_id, 'session'

    return False, None, None

async def authenticate_request_async(req):
    auth_header = req.headers.get('Authorization', '')

    if auth_header.startswith('Bearer '):
        token = auth_header[7:]
        valid, username = await basic_auth_provider.validate_token_async(token)
        if valid:
            return True, username, 'basic'

    api_key = req.headers.get('X-API-Key', '')
    if api_key:
        valid, client_id = await api_key_provider.authenticate_async(api_key)
        if valid:
            return True, client_id, 'api_key'

    session_id = req.cookies.get('session_id', '')
    if session_id:
        valid, user_id = await session_auth_provider.validate_session_async(session_id)
        if valid:
            return True, user_id, 'session'

    return False, None, None

def _run_coroutine_sync(coro):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            future = asyncio.run_coroutine_threadsafe(coro, loop)
            return future.result()
        else:
            return loop.run_until_complete(coro)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

def init(app):

    @app.route('/auth/register', methods=['POST'])
    def register():
        data = request.get_json() or {}
        username = data.get('username', '')
        password = data.get('password', '')

        if not username or not password:
            return json.dumps({'error': 'Username and password required'}), 400

        use_async = data.get('async', False)
        if use_async:
            _run_coroutine_sync(basic_auth_provider.register_user_async(username, password))
        else:
            basic_auth_provider.register_user(username, password)

        return json.dumps({'message': 'User registered successfully'}), 201

    @app.route('/auth/login', methods=['POST'])
    def login():
        data = request.get_json() or {}
        username = data.get('username', '')
        password = data.get('password', '')
        provider_name = data.get('provider', 'basic')
        use_async = data.get('async', False)

        if provider_name == 'basic':
            if use_async:
                authenticated = _run_coroutine_sync(
                    basic_auth_provider.authenticate_async(username, password)
                )
            else:
                authenticated = basic_auth_provider.authenticate(username, password)

            if authenticated:
                if use_async:
                    token = _run_coroutine_sync(
                        basic_auth_provider.generate_token_async(username)
                    )
                    session_id = _run_coroutine_sync(
                        session_auth_provider.create_session_async(username)
                    )
                else:
                    token = basic_auth_provider.generate_token(username)
                    session_id = session_auth_provider.create_session(username)

                response = make_response(json.dumps({
                    'token': token,
                    'provider': 'basic'
                }))
                response.set_cookie('session_id', session_id,
                    max_age=1800,
                    secure=True,
                    httponly=True,
                    path='/')
                return response, 200

        return json.dumps({'error': 'Authentication failed'}), 401

    @app.route('/auth/logout', methods=['POST'])
    def logout():
        session_id = request.cookies.get('session_id', '')
        data = request.get_json() or {}
        use_async = data.get('async', False)

        if session_id:
            if use_async:
                _run_coroutine_sync(session_auth_provider.invalidate_session_async(session_id))
            else:
                session_auth_provider.invalidate_session(session_id)

        response = make_response(json.dumps({'message': 'Logged out successfully'}))
        response.delete_cookie('session_id')
        return response, 200

    @app.route('/auth/logout/all', methods=['POST'])
    def logout_all():
        data = request.get_json() or {}
        use_async = data.get('async', False)

        if use_async:
            authenticated, user_id, provider = _run_coroutine_sync(
                authenticate_request_async(request)
            )
        else:
            authenticated, user_id, provider = authenticate_request(request)

        if not authenticated:
            return json.dumps({'error': 'Authentication required'}), 401

        if use_async:
            _run_coroutine_sync(
                session_auth_provider.invalidate_all_user_sessions_async(user_id)
            )