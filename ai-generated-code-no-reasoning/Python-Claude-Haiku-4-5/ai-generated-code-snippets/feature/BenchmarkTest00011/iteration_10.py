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
from abc import ABC, abstractmethod
import json
import os
from datetime import datetime, timedelta
import threading
import uuid
from functools import wraps
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
import time
import hashlib
import hmac
import base64
from collections import defaultdict
import asyncio
from contextlib import asynccontextmanager
import inspect
import jwt

class SessionManager:
    def __init__(self, max_sessions=10000, session_timeout=3600, max_concurrent_sessions_per_user=5):
        self._sessions = {}
        self._lock = threading.RLock()
        self._async_lock = asyncio.Lock()
        self._max_sessions = max_sessions
        self._session_timeout = session_timeout
        self._max_concurrent_sessions_per_user = max_concurrent_sessions_per_user
        self._user_sessions = defaultdict(list)
        self._user_sessions_lock = threading.RLock()
        self._session_activity_queue = Queue()
        self._cleanup_thread = threading.Thread(daemon=True, target=self._cleanup_expired_sessions)
        self._cleanup_thread.start()
        self._activity_logger_thread = threading.Thread(daemon=True, target=self._log_session_activity)
        self._activity_logger_thread.start()
    
    def create_session(self, user_id=None, provider=None):
        session_id = str(uuid.uuid4())
        with self._lock:
            if len(self._sessions) >= self._max_sessions:
                self._cleanup_expired_sessions()
            
            self._sessions[session_id] = {
                'created_at': datetime.now(),
                'last_accessed': datetime.now(),
                'data': {},
                'lock': threading.RLock(),
                'async_lock': asyncio.Lock(),
                'active': True,
                'user_id': user_id,
                'provider': provider,
                'request_count': 0,
                'concurrent_requests': 0
            }
        
        if user_id:
            with self._user_sessions_lock:
                self._user_sessions[user_id].append(session_id)
                if len(self._user_sessions[user_id]) > self._max_concurrent_sessions_per_user:
                    old_session = self._user_sessions[user_id].pop(0)
                    self.delete_session(old_session)
        
        return session_id
    
    def get_session(self, session_id):
        with self._lock:
            session_obj = self._sessions.get(session_id)
            if session_obj and session_obj['active']:
                session_obj['last_accessed'] = datetime.now()
                session_obj['request_count'] += 1
                return session_obj
        return None
    
    async def get_session_async(self, session_id):
        async with self._async_lock:
            session_obj = self._sessions.get(session_id)
            if session_obj and session_obj['active']:
                session_obj['last_accessed'] = datetime.now()
                session_obj['request_count'] += 1
                return session_obj
        return None
    
    def set_session_data(self, session_id, key, value):
        session_obj = self.get_session(session_id)
        if session_obj:
            with session_obj['lock']:
                session_obj['data'][key] = value
    
    async def set_session_data_async(self, session_id, key, value):
        session_obj = await self.get_session_async(session_id)
        if session_obj:
            async with session_obj['async_lock']:
                session_obj['data'][key] = value
    
    def get_session_data(self, session_id, key, default=None):
        session_obj = self.get_session(session_id)
        if session_obj:
            with session_obj['lock']:
                return session_obj['data'].get(key, default)
        return default
    
    async def get_session_data_async(self, session_id, key, default=None):
        session_obj = await self.get_session_async(session_id)
        if session_obj:
            async with session_obj['async_lock']:
                return session_obj['data'].get(key, default)
        return default
    
    def delete_session(self, session_id):
        with self._lock:
            if session_id in self._sessions:
                session_obj = self._sessions[session_id]
                user_id = session_obj.get('user_id')
                del self._sessions[session_id]
        
        if user_id:
            with self._user_sessions_lock:
                if user_id in self._user_sessions:
                    self._user_sessions[user_id] = [
                        s for s in self._user_sessions[user_id] if s != session_id
                    ]
    
    async def delete_session_async(self, session_id):
        async with self._async_lock:
            if session_id in self._sessions:
                session_obj = self._sessions[session_id]
                user_id = session_obj.get('user_id')
                del self._sessions[session_id]
        
        if user_id:
            with self._user_sessions_lock:
                if user_id in self._user_sessions:
                    self._user_sessions[user_id] = [
                        s for s in self._user_sessions[user_id] if s != session_id
                    ]
    
    def get_user_sessions(self, user_id):
        with self._user_sessions_lock:
            return list(self._user_sessions.get(user_id, []))
    
    def increment_concurrent_requests(self, session_id):
        session_obj = self.get_session(session_id)
        if session_obj:
            with session_obj['lock']:
                session_obj['concurrent_requests'] += 1
    
    async def increment_concurrent_requests_async(self, session_id):
        session_obj = await self.get_session_async(session_id)
        if session_obj:
            async with session_obj['async_lock']:
                session_obj['concurrent_requests'] += 1
    
    def decrement_concurrent_requests(self, session_id):
        session_obj = self.get_session(session_id)
        if session_obj:
            with session_obj['lock']:
                session_obj['concurrent_requests'] = max(0, session_obj['concurrent_requests'] - 1)
    
    async def decrement_concurrent_requests_async(self, session_id):
        session_obj = await self.get_session_async(session_id)
        if session_obj:
            async with session_obj['async_lock']:
                session_obj['concurrent_requests'] = max(0, session_obj['concurrent_requests'] - 1)
    
    def get_session_stats(self, session_id):
        session_obj = self.get_session(session_id)
        if session_obj:
            with session_obj['lock']:
                return {
                    'session_id': session_id,
                    'user_id': session_obj.get('user_id'),
                    'provider': session_obj.get('provider'),
                    'request_count': session_obj['request_count'],
                    'concurrent_requests': session_obj['concurrent_requests'],
                    'created_at': session_obj['created_at'].isoformat(),
                    'last_accessed': session_obj['last_accessed'].isoformat()
                }
        return None
    
    async def get_session_stats_async(self, session_id):
        session_obj = await self.get_session_async(session_id)
        if session_obj:
            async with session_obj['async_lock']:
                return {
                    'session_id': session_id,
                    'user_id': session_obj.get('user_id'),
                    'provider': session_obj.get('provider'),
                    'request_count': session_obj['request_count'],
                    'concurrent_requests': session_obj['concurrent_requests'],
                    'created_at': session_obj['created_at'].isoformat(),
                    'last_accessed': session_obj['last_accessed'].isoformat()
                }
        return None
    
    def _cleanup_expired_sessions(self):
        while True:
            time.sleep(300)
            with self._lock:
                now = datetime.now()
                expired_sessions = [
                    sid for sid, sobj in self._sessions.items()
                    if (now - sobj['last_accessed']).total_seconds() > self._session_timeout
                ]
                for sid in expired_sessions:
                    session_obj = self._sessions[sid]
                    user_id = session_obj.get('user_id')
                    del self._sessions[sid]
                    
                    if user_id:
                        with self._user_sessions_lock:
                            if user_id in self._user_sessions:
                                self._user_sessions[user_id] = [
                                    s for s in self._user_sessions[user_id] if s != sid
                                ]
    
    def _log_session_activity(self):
        while True:
            try:
                activity = self._session_activity_queue.get(timeout=5)
                pass
            except:
                pass
    
    def get_active_sessions_count(self):
        with self._lock:
            return len(self._sessions)
    
    def get_user_active_sessions_count(self, user_id):
        with self._user_sessions_lock:
            return len(self._user_sessions.get(user_id, []))

class ConcurrentRequestHandler:
    def __init__(self, session_manager, max_queue_size=1000):
        self._session_manager = session_manager
        self._request_queues = {}
        self._queue_lock = threading.RLock()
        self._max_queue_size = max_queue_size
        self._executor = ThreadPoolExecutor(max_workers=20)
    
    def _get_session_queue(self, session_id):
        with self._queue_lock:
            if session_id not in self._request_queues:
                self._request_queues[session_id] = Queue(maxsize=self._max_queue_size)
            return self._request_queues[session_id]
    
    def handle_request(self, session_id, request_func, *args, **kwargs):
        session_obj = self._session_manager.get_session(session_id)
        if not session_obj:
            return None
        
        self._session_manager.increment_concurrent_requests(session_id)
        try:
            if inspect.iscoroutinefunction(request_func):
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    result = loop.run_until_complete(request_func(*args, **kwargs))
                    return result
                finally:
                    loop.close()
            else:
                queue = self._get_session_queue(session_id)
                future = self._executor.submit(request_func, *args, **kwargs)
                result = future.result(timeout=30)
                return result
        finally:
            self._session_manager.decrement_concurrent_requests(session_id)
    
    async def handle_request_async(self, session_id, request_func, *args, **kwargs):
        session_obj = await self._session_manager.get_session_async(session_id)
        if not session_obj:
            return None
        
        await self._session_manager.increment_concurrent_requests_async(session_id)
        try:
            if inspect.iscoroutinefunction(request_func):
                result = await request_func(*args, **kwargs)
                return result
            else:
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(None, request_func, *args, **kwargs)
                return result
        finally:
            await self._session_manager.decrement_concurrent_requests_async(session_id)

class AuthenticationProvider(ABC):
    @abstractmethod
    def authenticate(self, credentials):
        pass
    
    @abstractmethod
    async def authenticate_async(self, credentials):
        pass
    
    @abstractmethod
    def validate_session(self, session_id, session_data):
        pass
    
    @abstractmethod
    async def validate_session_async(self, session_id, session_data):
        pass
    
    @abstractmethod
    def get_user_info(self, session_data):
        pass
    
    @abstractmethod
    async def get_user_info_async(self, session_data):
        pass
    
    @abstractmethod
    def get_provider_name(self):
        pass

class BasicAuthProvider(AuthenticationProvider):
    def __init__(self, username='admin', password='admin'):
        self.username = username
        self.password = password
    
    def authenticate(self, credentials):
        if isinstance(credentials, dict) and 'username' in credentials and 'password' in credentials:
            if credentials['username'] == self.username and credentials['password'] == self.password:
                return {'authenticated': True, 'username': credentials['username'], 'provider': 'basic'}
        return {'authenticated': False}
    
    async def authenticate_async(self, credentials):
        return self.authenticate(credentials)
    
    def validate_session(self, session_id, session_data):
        return session_data.get('authenticated', False)
    
    async def validate_session_async(self, session_id, session_data):
        return self.validate_session(session_id, session_data)
    
    def get_user_info(self, session_data):
        return {'username': session_data.get('username', 'unknown'), 'provider': 'basic'}
    
    async def get_user_info_async(self, session_data):
        return self.get_user_info(session_data)
    
    def get_provider_name(self):
        return 'basic'

class TokenAuthProvider(AuthenticationProvider):
    def __init__(self, secret_key='benchmark_secret'):
        self.secret_key = secret_key
        self.valid_tokens = {}
        self._lock = threading.RLock()
        self._async_lock = asyncio.Lock()
    
    def generate_token(self, user_id):
        token = str(uuid.uuid4())
        with self._lock:
            self.valid_tokens[token] = {'user_id': user_id, 'created_at': datetime.now()}
        return token
    
    async def generate_token_async(self, user_id):
        token = str(uuid.uuid4())
        async with self._async_lock:
            self.valid_tokens[token] = {'user_id': user_id, 'created_at': datetime.now()}
        return token
    
    def authenticate(self, credentials):
        if isinstance(credentials, dict) and 'token' in credentials:
            with self._lock:
                if credentials['token'] in self.valid_tokens:
                    token_data = self.valid_tokens[credentials['token']]
                    return {'authenticated': True, 'user_id': token_data['user_id'], 'provider': 'token'}
        return {'authenticated': False}
    
    async def authenticate