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

AUTH_PROVIDERS = {}

def register_auth_provider(name, provider):
    AUTH_PROVIDERS[name] = provider

class BasicAuthProvider:
    def __init__(self):
        self.users = {}

    def authenticate(self, username, password):
        if username in self.users:
            stored_hash = self.users[username]
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            return hmac.compare_digest(stored_hash, password_hash)
        return False

    def register_user(self, username, password):
        self.users[username] = hashlib.sha256(password.encode()).hexdigest()

    def generate_token(self, username):
        timestamp = str(int(time.time()))
        random_bytes = base64.b64encode(os.urandom(32)).decode()
        token_data = json.dumps({
            'username': username,
            'timestamp': timestamp,
            'random': random_bytes
        })
        return base64.b64encode(token_data.encode()).decode()

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

class ApiKeyAuthProvider:
    def __init__(self):
        self.api_keys = {}

    def generate_api_key(self, client_id):
        key = base64.b64encode(os.urandom(32)).decode()
        self.api_keys[key] = {
            'client_id': client_id,
            'created_at': int(time.time())
        }
        return key

    def authenticate(self, api_key):
        if api_key in self.api_keys:
            key_data = self.api_keys[api_key]
            current_time = int(time.time())
            if current_time - key_data['created_at'] > 86400:
                del self.api_keys[api_key]
                return False, None
            return True, key_data['client_id']
        return False, None

    def revoke_api_key(self, api_key):
        if api_key in self.api_keys:
            del self.api_keys[api_key]
            return True
        return False

class SessionAuthProvider:
    def __init__(self):
        self.sessions = {}

    def create_session(self, user_id):
        session_id = base64.b64encode(os.urandom(32)).decode()
        self.sessions[session_id] = {
            'user_id': user_id,
            'created_at': int(time.time()),
            'last_accessed': int(time.time())
        }
        return session_id

    def validate_session(self, session_id):
        if session_id in self.sessions:
            session_data = self.sessions[session_id]
            current_time = int(time.time())
            if current_time - session_data['last_accessed'] > 1800:
                del self.sessions[session_id]
                return False, None
            self.sessions[session_id]['last_accessed'] = current_time
            return True, session_data['user_id']
        return False, None

    def invalidate_session(self, session_id):
        if session_id in self.sessions:
            del self.sessions[session_id]
            return True
        return False

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

def init(app):

    @app.route('/auth/register', methods=['POST'])
    def register():
        data = request.get_json() or {}
        username = data.get('username', '')
        password = data.get('password', '')
        
        if not username or not password:
            return json.dumps({'error': 'Username and password required'}), 400
        
        basic_auth_provider.register_user(username, password)
        return json.dumps({'message': 'User registered successfully'}), 201

    @app.route('/auth/login', methods=['POST'])
    def login():
        data = request.get_json() or {}
        username = data.get('username', '')
        password = data.get('password', '')
        provider_name = data.get('provider', 'basic')
        
        if provider_name == 'basic':
            if basic_auth_provider.authenticate(username, password):
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
        if session_id:
            session_auth_provider.invalidate_session(session_id)
        
        response = make_response(json.dumps({'message': 'Logged out successfully'}))
        response.delete_cookie('session_id')
        return response, 200

    @app.route('/auth/api-key', methods=['POST'])
    def generate_api_key():
        authenticated, user_id, provider = authenticate_request(request)
        
        if not authenticated:
            return json.dumps({'error': 'Authentication required'}), 401
        
        api_key = api_key_provider.generate_api_key(user_id)
        return json.dumps({'api_key': api_key}), 201

    @app.route('/auth/api-key/revoke', methods=['POST'])
    def revoke_api_key():
        data = request.get_json() or {}
        api_key = data.get('api_key', '')
        
        if api_key_provider.revoke_api_key(api_key):
            return json.dumps({'message': 'API key revoked'}), 200
        
        return json.dumps({'error': 'API key not found'}), 404

    @app.route('/auth/providers', methods=['GET'])
    def list_providers():
        return json.dumps({'providers': list(AUTH_PROVIDERS.keys())}), 200

    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['GET'])
    def BenchmarkTest00078_get():
        response = make_response(render_template('web/deserialization-00/BenchmarkTest00078.html'))
        response.set_cookie('BenchmarkTest00078', 'gASVNwAAAAAAAACMCF9fbWFpbl9flIwOc2FmZV90b19waWNrbGWUk5QpgZR9lCiMAWGUjANmb2-UjAFilEtjdWIu',
            max_age=60*3,
            secure=True,
            path=request.path,
            domain='localhost')
        return response
        return BenchmarkTest00078_post()

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