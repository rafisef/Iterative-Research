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
from datetime import datetime
import threading
import uuid
from functools import wraps
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
import time

class SessionManager:
    def __init__(self, max_sessions=10000, session_timeout=3600):
        self._sessions = {}
        self._lock = threading.RLock()
        self._max_sessions = max_sessions
        self._session_timeout = session_timeout
        self._cleanup_thread = threading.Thread(daemon=True, target=self._cleanup_expired_sessions)
        self._cleanup_thread.start()
    
    def create_session(self):
        session_id = str(uuid.uuid4())
        with self._lock:
            if len(self._sessions) >= self._max_sessions:
                self._cleanup_expired_sessions()
            
            self._sessions[session_id] = {
                'created_at': datetime.now(),
                'last_accessed': datetime.now(),
                'data': {},
                'lock': threading.RLock(),
                'active': True
            }
        return session_id
    
    def get_session(self, session_id):
        with self._lock:
            session_obj = self._sessions.get(session_id)
            if session_obj and session_obj['active']:
                session_obj['last_accessed'] = datetime.now()
                return session_obj
        return None
    
    def set_session_data(self, session_id, key, value):
        session_obj = self.get_session(session_id)
        if session_obj:
            with session_obj['lock']:
                session_obj['data'][key] = value
    
    def get_session_data(self, session_id, key, default=None):
        session_obj = self.get_session(session_id)
        if session_obj:
            with session_obj['lock']:
                return session_obj['data'].get(key, default)
        return default
    
    def delete_session(self, session_id):
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
    
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
                    del self._sessions[sid]
    
    def get_active_sessions_count(self):
        with self._lock:
            return len(self._sessions)

class AuthenticationProvider(ABC):
    @abstractmethod
    def authenticate(self, credentials):
        pass
    
    @abstractmethod
    def validate_session(self, session_id, session_data):
        pass
    
    @abstractmethod
    def get_user_info(self, session_data):
        pass

class BasicAuthProvider(AuthenticationProvider):
    def __init__(self, username='admin', password='admin'):
        self.username = username
        self.password = password
    
    def authenticate(self, credentials):
        if isinstance(credentials, dict) and 'username' in credentials and 'password' in credentials:
            if credentials['username'] == self.username and credentials['password'] == self.password:
                return {'authenticated': True, 'username': credentials['username']}
        return {'authenticated': False}
    
    def validate_session(self, session_id, session_data):
        return session_data.get('authenticated', False)
    
    def get_user_info(self, session_data):
        return {'username': session_data.get('username', 'unknown')}

class TokenAuthProvider(AuthenticationProvider):
    def __init__(self, secret_key='benchmark_secret'):
        self.secret_key = secret_key
        self.valid_tokens = {}
        self._lock = threading.RLock()
    
    def generate_token(self, user_id):
        token = str(uuid.uuid4())
        with self._lock:
            self.valid_tokens[token] = {'user_id': user_id, 'created_at': datetime.now()}
        return token
    
    def authenticate(self, credentials):
        if isinstance(credentials, dict) and 'token' in credentials:
            with self._lock:
                if credentials['token'] in self.valid_tokens:
                    token_data = self.valid_tokens[credentials['token']]
                    return {'authenticated': True, 'user_id': token_data['user_id']}
        return {'authenticated': False}
    
    def validate_session(self, session_id, session_data):
        return session_data.get('authenticated', False)
    
    def get_user_info(self, session_data):
        return {'user_id': session_data.get('user_id', 'unknown')}

class OAuthProvider(AuthenticationProvider):
    def __init__(self, provider_name='oauth', client_id='', client_secret=''):
        self.provider_name = provider_name
        self.client_id = client_id
        self.client_secret = client_secret
        self.authorized_clients = {}
        self._lock = threading.RLock()
    
    def authenticate(self, credentials):
        if isinstance(credentials, dict) and 'oauth_token' in credentials:
            with self._lock:
                if credentials['oauth_token'] in self.authorized_clients:
                    client_data = self.authorized_clients[credentials['oauth_token']]
                    return {'authenticated': True, 'oauth_id': client_data['oauth_id']}
        return {'authenticated': False}
    
    def validate_session(self, session_id, session_data):
        return session_data.get('authenticated', False)
    
    def get_user_info(self, session_data):
        return {'oauth_id': session_data.get('oauth_id', 'unknown'), 'provider': self.provider_name}
    
    def register_oauth_client(self, oauth_token, oauth_id):
        with self._lock:
            self.authorized_clients[oauth_token] = {'oauth_id': oauth_id, 'created_at': datetime.now()}

class StorageBackend(ABC):
    @abstractmethod
    def save_query_result(self, session_id, test_id, param, result):
        pass
    
    @abstractmethod
    def get_query_results(self, session_id, test_id):
        pass

class FileStorageBackend(StorageBackend):
    def __init__(self, base_path='./storage'):
        self.base_path = base_path
        self._lock = threading.RLock()
        self._session_locks = {}
        os.makedirs(base_path, exist_ok=True)
    
    def _get_session_lock(self, session_id):
        with self._lock:
            if session_id not in self._session_locks:
                self._session_locks[session_id] = threading.RLock()
            return self._session_locks[session_id]
    
    def save_query_result(self, session_id, test_id, param, result):
        file_path = os.path.join(self.base_path, f'{session_id}_{test_id}.json')
        session_lock = self._get_session_lock(session_id)
        
        with session_lock:
            data = []
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    data = json.load(f)
            
            data.append({
                'timestamp': datetime.now().isoformat(),
                'param': param,
                'result': result
            })
            
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
    
    def get_query_results(self, session_id, test_id):
        file_path = os.path.join(self.base_path, f'{session_id}_{test_id}.json')
        session_lock = self._get_session_lock(session_id)
        
        with session_lock:
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    return json.load(f)
        return []

class DatabaseStorageBackend(StorageBackend):
    def __init__(self, db_module, db_type='sqlite', max_workers=10):
        self.db_module = db_module
        self.db_type = db_type
        self._lock = threading.RLock()
        self._session_locks = {}
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._init_table()
    
    def _get_session_lock(self, session_id):
        with self._lock:
            if session_id not in self._session_locks:
                self._session_locks[session_id] = threading.RLock()
            return self._session_locks[session_id]
    
    def _init_table(self):
        con = self.db_module.get_connection()
        cur = con.cursor()
        if self.db_type == 'sqlite':
            cur.execute('''
                CREATE TABLE IF NOT EXISTS benchmark_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    test_id TEXT NOT NULL,
                    param TEXT,
                    result TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            cur.execute('''
                CREATE INDEX IF NOT EXISTS idx_session_test
                ON benchmark_results(session_id, test_id)
            ''')
        elif self.db_type == 'mysql':
            cur.execute('''
                CREATE TABLE IF NOT EXISTS benchmark_results (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    session_id VARCHAR(255) NOT NULL,
                    test_id VARCHAR(255) NOT NULL,
                    param LONGTEXT,
                    result LONGTEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_session_test (session_id, test_id)
                )
            ''')
        elif self.db_type == 'postgresql':
            cur.execute('''
                CREATE TABLE IF NOT EXISTS benchmark_results (
                    id SERIAL PRIMARY KEY,
                    session_id VARCHAR(255) NOT NULL,
                    test_id VARCHAR(255) NOT NULL,
                    param TEXT,
                    result TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            cur.execute('''
                CREATE INDEX IF NOT EXISTS idx_session_test
                ON benchmark_results(session_id, test_id)
            ''')
        con.commit()
        con.close()
    
    def save_query_result(self, session_id, test_id, param, result):
        session_lock = self._get_session_lock(session_id)
        
        def _save():
            with session_lock:
                con = self.db_module.get_connection()
                cur = con.cursor()
                try:
                    if self.db_type == 'sqlite':
                        cur.execute('''
                            INSERT INTO benchmark_results (session_id, test_id, param, result)
                            VALUES (?, ?, ?, ?)
                        ''', (session_id, test_id, param, result))
                    elif self.db_type in ['mysql', 'postgresql']:
                        cur.execute('''
                            INSERT INTO benchmark_results (session_id, test_id, param, result)
                            VALUES (%s, %s, %s, %s)
                        ''', (session_id, test_id, param, result))
                    con.commit()
                finally:
                    con.close()
        
        self._executor.submit(_save)
    
    def get_query_results(self, session_id, test_id):
        session_lock = self._get_session_lock(session_id)
        
        with session_lock:
            con = self.db_module.get_connection()
            cur = con.cursor()
            try:
                if self.db_type == 'sqlite':
                    cur.execute('''
                        SELECT session_id, test_id, param, result, timestamp
                        FROM benchmark_results
                        WHERE session_id = ? AND test_id = ?
                        ORDER BY timestamp DESC
                    ''', (session_id, test_id))
                else:
                    cur.execute('''
                        SELECT session_id, test_id, param, result, timestamp
                        FROM benchmark_results
                        WHERE session_id = %s AND test_id = %s
                        ORDER BY timestamp DESC
                    ''', (session_id, test_id))
                results = cur.fetchall()
            finally:
                con.close()
            
            return [
                {
                    'session_id': r[0],
                    'test_id': r[1],
                    'param': r[2],
                    'result': r[3],
                    'timestamp': r[4]
                } for r in results
            ]

class StorageFactory:
    _storage_backend = None
    _lock = threading.RLock()
    
    @classmethod
    def set_backend(cls, backend):
        with cls._lock:
            cls._storage_backend = backend
    
    @classmethod
    def get_backend(cls):
        with cls._lock:
            if cls._storage_backend is None:
                cls._storage_backend = FileStorageBackend()
            return cls._storage_backend

class AuthenticationManager:
    def __init__(self):
        self._providers = {}
        self._default_provider = None
        self._lock = threading.RLock()
    
    def register_provider(self, name, provider, is_default=False):
        with self._lock:
            self._providers[name] = provider
            if is_default or self._default_provider is None:
                self._default_provider = name
    
    def get_provider(self, name=None):
        with self._lock:
            if name is None:
                name = self._default_provider
            return self._providers.get(name)
    
    def authenticate(self, credentials, provider_name=None):
        provider = self.get_provider(provider_name)
        if provider:
            return provider.authenticate(credentials)
        return {'authenticated': False}
    
    def validate_session(self, session_id, session_data, provider_name=None):
        provider = self.get_provider(provider_name)
        if provider:
            return provider.validate_session(session_id, session_data)
        return False
    
    def get_user_info(self, session_data, provider_name=None):
        provider = self.get_provider(provider_name)
        if provider:
            return provider.get_user_info(session_data)
        return {}

def _get_config_from_env(storage_type):
    if storage_type == 'file':
        return {
            'base_path': os.getenv('BENCHMARK_STORAGE_PATH', './storage')
        }
    elif storage_type == 'database':
        return {
            'db_type': os.getenv('BENCHMARK_DB_TYPE', 'sqlite'),
            'db_host': os.getenv('BENCHMARK_DB_HOST', 'localhost'),
            'db_port': os.getenv('BENCHMARK