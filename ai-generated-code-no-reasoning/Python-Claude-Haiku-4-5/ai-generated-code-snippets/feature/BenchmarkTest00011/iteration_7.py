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
import hashlib
import hmac
import base64

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
                return {'authenticated': True, 'username': credentials['username'], 'provider': 'basic'}
        return {'authenticated': False}
    
    def validate_session(self, session_id, session_data):
        return session_data.get('authenticated', False)
    
    def get_user_info(self, session_data):
        return {'username': session_data.get('username', 'unknown'), 'provider': 'basic'}

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
                    return {'authenticated': True, 'user_id': token_data['user_id'], 'provider': 'token'}
        return {'authenticated': False}
    
    def validate_session(self, session_id, session_data):
        return session_data.get('authenticated', False)
    
    def get_user_info(self, session_data):
        return {'user_id': session_data.get('user_id', 'unknown'), 'provider': 'token'}

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
                    return {'authenticated': True, 'oauth_id': client_data['oauth_id'], 'provider': 'oauth'}
        return {'authenticated': False}
    
    def validate_session(self, session_id, session_data):
        return session_data.get('authenticated', False)
    
    def get_user_info(self, session_data):
        return {'oauth_id': session_data.get('oauth_id', 'unknown'), 'provider': self.provider_name}
    
    def register_oauth_client(self, oauth_token, oauth_id):
        with self._lock:
            self.authorized_clients[oauth_token] = {'oauth_id': oauth_id, 'created_at': datetime.now()}

class LDAPAuthProvider(AuthenticationProvider):
    def __init__(self, server_uri='ldap://localhost', base_dn='dc=example,dc=com'):
        self.server_uri = server_uri
        self.base_dn = base_dn
        self.ldap_module = None
        try:
            import ldap
            self.ldap_module = ldap
        except ImportError:
            pass
    
    def authenticate(self, credentials):
        if not self.ldap_module or not isinstance(credentials, dict):
            return {'authenticated': False}
        
        if 'username' not in credentials or 'password' not in credentials:
            return {'authenticated': False}
        
        try:
            conn = self.ldap_module.initialize(self.server_uri)
            user_dn = f'uid={credentials["username"]},{self.base_dn}'
            conn.simple_bind_s(user_dn, credentials['password'])
            conn.unbind_s()
            return {'authenticated': True, 'username': credentials['username'], 'provider': 'ldap'}
        except Exception:
            return {'authenticated': False}
    
    def validate_session(self, session_id, session_data):
        return session_data.get('authenticated', False)
    
    def get_user_info(self, session_data):
        return {'username': session_data.get('username', 'unknown'), 'provider': 'ldap'}

class JWTAuthProvider(AuthenticationProvider):
    def __init__(self, secret_key='benchmark_jwt_secret', algorithm='HS256'):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.jwt_module = None
        self.valid_tokens = {}
        self._lock = threading.RLock()
        try:
            import jwt
            self.jwt_module = jwt
        except ImportError:
            pass
    
    def generate_token(self, user_id, user_data=None):
        if not self.jwt_module:
            return None
        
        payload = {
            'user_id': user_id,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow().timestamp() + 3600
        }
        if user_data:
            payload.update(user_data)
        
        token = self.jwt_module.encode(payload, self.secret_key, algorithm=self.algorithm)
        with self._lock:
            self.valid_tokens[token] = {'user_id': user_id, 'created_at': datetime.now()}
        return token
    
    def authenticate(self, credentials):
        if not self.jwt_module or not isinstance(credentials, dict):
            return {'authenticated': False}
        
        if 'jwt_token' not in credentials:
            return {'authenticated': False}
        
        try:
            with self._lock:
                if credentials['jwt_token'] not in self.valid_tokens:
                    return {'authenticated': False}
            
            payload = self.jwt_module.decode(
                credentials['jwt_token'],
                self.secret_key,
                algorithms=[self.algorithm]
            )
            return {'authenticated': True, 'user_id': payload.get('user_id'), 'provider': 'jwt'}
        except Exception:
            return {'authenticated': False}
    
    def validate_session(self, session_id, session_data):
        return session_data.get('authenticated', False)
    
    def get_user_info(self, session_data):
        return {'user_id': session_data.get('user_id', 'unknown'), 'provider': 'jwt'}

class APIKeyAuthProvider(AuthenticationProvider):
    def __init__(self):
        self.valid_api_keys = {}
        self._lock = threading.RLock()
    
    def register_api_key(self, api_key, user_id, user_data=None):
        with self._lock:
            self.valid_api_keys[api_key] = {
                'user_id': user_id,
                'user_data': user_data or {},
                'created_at': datetime.now()
            }
    
    def revoke_api_key(self, api_key):
        with self._lock:
            if api_key in self.valid_api_keys:
                del self.valid_api_keys[api_key]
    
    def authenticate(self, credentials):
        if not isinstance(credentials, dict) or 'api_key' not in credentials:
            return {'authenticated': False}
        
        with self._lock:
            if credentials['api_key'] in self.valid_api_keys:
                key_data = self.valid_api_keys[credentials['api_key']]
                return {
                    'authenticated': True,
                    'user_id': key_data['user_id'],
                    'provider': 'api_key'
                }
        return {'authenticated': False}
    
    def validate_session(self, session_id, session_data):
        return session_data.get('authenticated', False)
    
    def get_user_info(self, session_data):
        return {'user_id': session_data.get('user_id', 'unknown'), 'provider': 'api_key'}

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
                    result