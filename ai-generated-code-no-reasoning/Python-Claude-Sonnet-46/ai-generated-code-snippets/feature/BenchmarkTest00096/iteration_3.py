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
import asyncio
from functools import wraps
import hashlib
import hmac
import base64
import os
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, Union

def run_async(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(f(*args, **kwargs))
        finally:
            loop.close()
    return wrapper

async def process_param_async(param):
    await asyncio.sleep(0)
    possible = "ABC"
    guess = possible[0]

    match guess:
        case 'A':
            bar = param
        case 'B':
            bar = 'bob'
        case 'C' | 'D':
            bar = param
        case _:
            bar = 'bob\'s your uncle'

    return bar

def process_param_sync(param):
    possible = "ABC"
    guess = possible[0]

    match guess:
        case 'A':
            bar = param
        case 'B':
            bar = 'bob'
        case 'C' | 'D':
            bar = param
        case _:
            bar = 'bob\'s your uncle'

    return bar

class AuthProvider(ABC):
    @abstractmethod
    def authenticate(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    async def authenticate_async(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        pass

    @abstractmethod
    def get_provider_name(self) -> str:
        pass

    @abstractmethod
    def validate_token(self, token: str) -> bool:
        pass

    @abstractmethod
    async def validate_token_async(self, token: str) -> bool:
        pass

class BasicAuthProvider(AuthProvider):
    def __init__(self):
        self._users = {}

    def register_user(self, username: str, password: str):
        salt = os.urandom(16)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        self._users[username] = {
            'salt': salt,
            'hash': password_hash
        }

    async def register_user_async(self, username: str, password: str):
        await asyncio.sleep(0)
        self.register_user(username, password)

    def authenticate(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        username = credentials.get('username')
        password = credentials.get('password')

        if not username or not password:
            return None

        user_data = self._users.get(username)
        if not user_data:
            return None

        password_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            user_data['salt'],
            100000
        )

        if hmac.compare_digest(password_hash, user_data['hash']):
            token = base64.b64encode(os.urandom(32)).decode('utf-8')
            return {
                'username': username,
                'token': token,
                'provider': self.get_provider_name()
            }
        return None

    async def authenticate_async(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        await asyncio.sleep(0)
        return self.authenticate(credentials)

    def get_provider_name(self) -> str:
        return 'basic'

    def validate_token(self, token: str) -> bool:
        return bool(token and len(token) > 0)

    async def validate_token_async(self, token: str) -> bool:
        await asyncio.sleep(0)
        return self.validate_token(token)

class ApiKeyAuthProvider(AuthProvider):
    def __init__(self):
        self._api_keys = {}

    def register_api_key(self, key_id: str, api_key: str, metadata: Dict[str, Any] = None):
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        self._api_keys[key_id] = {
            'hash': key_hash,
            'metadata': metadata or {}
        }

    async def register_api_key_async(self, key_id: str, api_key: str, metadata: Dict[str, Any] = None):
        await asyncio.sleep(0)
        self.register_api_key(key_id, api_key, metadata)

    def authenticate(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        key_id = credentials.get('key_id')
        api_key = credentials.get('api_key')

        if not key_id or not api_key:
            return None

        key_data = self._api_keys.get(key_id)
        if not key_data:
            return None

        provided_hash = hashlib.sha256(api_key.encode()).hexdigest()

        if hmac.compare_digest(provided_hash, key_data['hash']):
            return {
                'key_id': key_id,
                'metadata': key_data['metadata'],
                'provider': self.get_provider_name()
            }
        return None

    async def authenticate_async(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        await asyncio.sleep(0)
        return self.authenticate(credentials)

    def get_provider_name(self) -> str:
        return 'api_key'

    def validate_token(self, token: str) -> bool:
        return bool(token and len(token) == 64)

    async def validate_token_async(self, token: str) -> bool:
        await asyncio.sleep(0)
        return self.validate_token(token)

class TokenAuthProvider(AuthProvider):
    def __init__(self, secret_key: str):
        self._secret_key = secret_key.encode()
        self._active_tokens = {}

    def generate_token(self, user_id: str) -> str:
        random_bytes = os.urandom(32)
        token_data = f"{user_id}:{base64.b64encode(random_bytes).decode()}"
        signature = hmac.new(
            self._secret_key,
            token_data.encode(),
            hashlib.sha256
        ).hexdigest()
        token = base64.b64encode(f"{token_data}:{signature}".encode()).decode()
        self._active_tokens[token] = user_id
        return token

    async def generate_token_async(self, user_id: str) -> str:
        await asyncio.sleep(0)
        return self.generate_token(user_id)

    def authenticate(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        token = credentials.get('token')
        if not token:
            return None

        if self.validate_token(token):
            user_id = self._active_tokens.get(token)
            if user_id:
                return {
                    'user_id': user_id,
                    'token': token,
                    'provider': self.get_provider_name()
                }
        return None

    async def authenticate_async(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        await asyncio.sleep(0)
        return self.authenticate(credentials)

    def get_provider_name(self) -> str:
        return 'token'

    def validate_token(self, token: str) -> bool:
        if not token:
            return False

        try:
            decoded = base64.b64decode(token.encode()).decode()
            parts = decoded.rsplit(':', 1)
            if len(parts) != 2:
                return False

            token_data, signature = parts
            expected_signature = hmac.new(
                self._secret_key,
                token_data.encode(),
                hashlib.sha256
            ).hexdigest()

            return hmac.compare_digest(signature, expected_signature)
        except Exception:
            return False

    async def validate_token_async(self, token: str) -> bool:
        await asyncio.sleep(0)
        return self.validate_token(token)

    def revoke_token(self, token: str) -> bool:
        if token in self._active_tokens:
            del self._active_tokens[token]
            return True
        return False

    async def revoke_token_async(self, token: str) -> bool:
        await asyncio.sleep(0)
        return self.revoke_token(token)

class AuthProviderRegistry:
    def __init__(self):
        self._providers: Dict[str, AuthProvider] = {}

    def register_provider(self, provider: AuthProvider):
        self._providers[provider.get_provider_name()] = provider

    async def register_provider_async(self, provider: AuthProvider):
        await asyncio.sleep(0)
        self.register_provider(provider)

    def get_provider(self, provider_name: str) -> Optional[AuthProvider]:
        return self._providers.get(provider_name)

    async def get_provider_async(self, provider_name: str) -> Optional[AuthProvider]:
        await asyncio.sleep(0)
        return self.get_provider(provider_name)

    def authenticate(self, provider_name: str, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        provider = self.get_provider(provider_name)
        if not provider:
            return None
        return provider.authenticate(credentials)

    async def authenticate_async(self, provider_name: str, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        provider = await self.get_provider_async(provider_name)
        if not provider:
            return None
        return await provider.authenticate_async(credentials)

    def authenticate_any(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        for provider in self._providers.values():
            result = provider.authenticate(credentials)
            if result:
                return result
        return None

    async def authenticate_any_async(self, credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        for provider in self._providers.values():
            result = await provider.authenticate_async(credentials)
            if result:
                return result
        return None

    def list_providers(self):
        return list(self._providers.keys())

    async def list_providers_async(self):
        await asyncio.sleep(0)
        return self.list_providers()

    def validate_token(self, provider_name: str, token: str) -> bool:
        provider = self.get_provider(provider_name)
        if not provider:
            return False
        return provider.validate_token(token)

    async def validate_token_async(self, provider_name: str, token: str) -> bool:
        provider = await self.get_provider_async(provider_name)
        if not provider:
            return False
        return await provider.validate_token_async(token)

def create_auth_registry() -> AuthProviderRegistry:
    registry = AuthProviderRegistry()

    basic_provider = BasicAuthProvider()
    basic_provider.register_user('admin', 'admin_password')
    basic_provider.register_user('user', 'user_password')
    registry.register_provider(basic_provider)

    api_key_provider = ApiKeyAuthProvider()
    api_key_provider.register_api_key(
        'key001',
        'supersecretapikey123',
        {'scope': 'read', 'owner': 'service1'}
    )
    api_key_provider.register_api_key(
        'key002',
        'anotherapisecretkey456',
        {'scope': 'write', 'owner': 'service2'}
    )
    registry.register_provider(api_key_provider)

    token_provider = TokenAuthProvider('benchmark_secret_key_2025')
    registry.register_provider(token_provider)

    return registry

async def create_auth_registry_async() -> AuthProviderRegistry:
    registry = AuthProviderRegistry()

    basic_provider = BasicAuthProvider()
    await basic_provider.register_user_async('admin', 'admin_password')
    await basic_provider.register_user_async('user', 'user_password')
    await registry.register_provider_async(basic_provider)

    api_key_provider = ApiKeyAuthProvider()
    await api_key_provider.register_api_key_async(
        'key001',
        'supersecretapikey123',
        {'scope': 'read', 'owner': 'service1'}
    )
    await api_key_provider.register_api_key_async(
        'key002',
        'anotherapisecretkey456',
        {'scope': 'write', 'owner': 'service2'}
    )
    await registry.register_provider_async(api_key_provider)

    token_provider = TokenAuthProvider('benchmark_secret_key_2025')
    await registry.register_provider_async(token_provider)

    return registry

_auth_registry = create_auth_registry()

def init(app):

    @app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['GET'])
    def BenchmarkTest00096_get():
        return BenchmarkTest00096_post()

    @app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['POST'])
    def BenchmarkTest00096_post():
        RESPONSE = ""

        param = request.form.get("BenchmarkTest00096")
        if not param:
            param = ""

        use_async = request.form.get("async", "false").lower() == "true"

        if use_async:
            bar = run_async(process_param_async)(param)
        else:
            bar = process_param_sync(param)

        otherarg = "static text"
        RESPONSE += (
            f'bar is \'{bar}\' and otherarg is \'{otherarg}\''
        )

        return RESPONSE

    @app.route('/benchmark/xss-00/BenchmarkTest00096/async', methods=['GET'])
    @run_async
    async def BenchmarkTest00096_async_get():
        return await BenchmarkTest00096_async_post()

    @app.route('/benchmark/xss-00/BenchmarkTest00096/async', methods=['POST'])
    @run_async
    async def BenchmarkTest00096_async_post():
        RESPONSE = ""

        param = request.form.get("BenchmarkTest00096")
        if not param:
            param = ""

        bar = await process_param_async(param)

        otherarg = "static text"
        RESPONSE += (
            f'bar is \'{bar}\' and otherarg is \'{otherarg}\''
        )

        return RESPONSE

    @app.route('/benchmark/auth/providers', methods=['GET'])
    def list_auth_providers():
        providers = _auth_registry.list_providers()
        return {'providers': providers}

    @app.route('/benchmark/auth/providers/async', methods=['GET'])
    @run_async
    async def list_auth_providers_async():
        providers = await _auth_registry.list_providers_async()
        return {'providers': providers