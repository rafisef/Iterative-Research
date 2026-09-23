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
from typing import Optional, Dict, Any, Union, List

ENV_ADMIN_USERNAME = os.environ.get("BENCHMARK_ADMIN_USERNAME", "admin")
ENV_ADMIN_PASSWORD = os.environ.get("BENCHMARK_ADMIN_PASSWORD", "admin_password")
ENV_USER_USERNAME = os.environ.get("BENCHMARK_USER_USERNAME", "user")
ENV_USER_PASSWORD = os.environ.get("BENCHMARK_USER_PASSWORD", "user_password")
ENV_API_KEY_001_ID = os.environ.get("BENCHMARK_API_KEY_001_ID", "key001")
ENV_API_KEY_001_VALUE = os.environ.get("BENCHMARK_API_KEY_001_VALUE", "supersecretapikey123")
ENV_API_KEY_001_SCOPE = os.environ.get("BENCHMARK_API_KEY_001_SCOPE", "read")
ENV_API_KEY_001_OWNER = os.environ.get("BENCHMARK_API_KEY_001_OWNER", "service1")
ENV_API_KEY_002_ID = os.environ.get("BENCHMARK_API_KEY_002_ID", "key002")
ENV_API_KEY_002_VALUE = os.environ.get("BENCHMARK_API_KEY_002_VALUE", "anotherapisecretkey456")
ENV_API_KEY_002_SCOPE = os.environ.get("BENCHMARK_API_KEY_002_SCOPE", "write")
ENV_API_KEY_002_OWNER = os.environ.get("BENCHMARK_API_KEY_002_OWNER", "service2")
ENV_TOKEN_SECRET_KEY = os.environ.get("BENCHMARK_TOKEN_SECRET_KEY", "benchmark_secret_key_2025")
ENV_ASYNC_DEFAULT = os.environ.get("BENCHMARK_ASYNC_DEFAULT", "false").lower() == "true"
ENV_PBKDF2_ITERATIONS = int(os.environ.get("BENCHMARK_PBKDF2_ITERATIONS", "100000"))
ENV_TOKEN_MIN_LENGTH = int(os.environ.get("BENCHMARK_TOKEN_MIN_LENGTH", "1"))
ENV_API_KEY_HASH_LENGTH = int(os.environ.get("BENCHMARK_API_KEY_HASH_LENGTH", "64"))
ENV_OAUTH_CLIENT_ID = os.environ.get("BENCHMARK_OAUTH_CLIENT_ID", "benchmark_client")
ENV_OAUTH_CLIENT_SECRET = os.environ.get("BENCHMARK_OAUTH_CLIENT_SECRET", "benchmark_client_secret")
ENV_OAUTH_TOKEN_EXPIRY = int(os.environ.get("BENCHMARK_OAUTH_TOKEN_EXPIRY", "3600"))
ENV_CERT_AUTH_ENABLED = os.environ.get("BENCHMARK_CERT_AUTH_ENABLED", "false").lower() == "true"
ENV_LDAP_AUTH_ENABLED = os.environ.get("BENCHMARK_LDAP_AUTH_ENABLED", "false").lower() == "true"
ENV_LDAP_SERVER = os.environ.get("BENCHMARK_LDAP_SERVER", "ldap://localhost:389")
ENV_LDAP_BASE_DN = os.environ.get("BENCHMARK_LDAP_BASE_DN", "dc=example,dc=com")
ENV_MFA_SECRET_KEY = os.environ.get("BENCHMARK_MFA_SECRET_KEY", "mfa_secret_key_2025")
ENV_MFA_CODE_LENGTH = int(os.environ.get("BENCHMARK_MFA_CODE_LENGTH", "6"))
ENV_MFA_TIME_STEP = int(os.environ.get("BENCHMARK_MFA_TIME_STEP", "30"))

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

    def get_provider_metadata(self) -> Dict[str, Any]:
        return {
            'name': self.get_provider_name(),
            'type': self.__class__.__name__
        }

    async def get_provider_metadata_async(self) -> Dict[str, Any]:
        await asyncio.sleep(0)
        return self.get_provider_metadata()

class BasicAuthProvider(AuthProvider):
    def __init__(self, iterations: int = None):
        self._users = {}
        self._iterations = iterations if iterations is not None else ENV_PBKDF2_ITERATIONS

    def register_user(self, username: str, password: str):
        salt = os.urandom(16)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, self._iterations)
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
            self._iterations
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
        return bool(token and len(token) >= ENV_TOKEN_MIN_LENGTH)

    async def validate_token_async(self, token: str) -> bool:
        await asyncio.sleep(0)
        return self.validate_token(token)

    def list_users(self) -> List[str]:
        return list(self._users.keys())

    async def list_users_async(self) -> List[str]:
        await asyncio.sleep(0)
        return self.list_users()

    def remove_user(self, username: str) -> bool:
        if username in self._users:
            del self._users[username]
            return True
        return False

    async def remove_user_async(self, username: str) -> bool:
        await asyncio.sleep(0)
        return self.remove_user(username)

    def update_password(self, username: str, new_password: str) -> bool:
        if username not in self._users:
            return False
        self.register_user(username, new_password)
        return True

    async def update_password_async(self, username: str, new_password: str) -> bool:
        await asyncio.sleep(0)
        return self.update_password(username, new_password)

class ApiKeyAuthProvider(AuthProvider):
    def __init__(self, expected_hash_length: int = None):
        self._api_keys = {}
        self._expected_hash_length = expected_hash_length if expected_hash_length is not None else ENV_API_KEY_HASH_LENGTH

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
        return bool(token and len(token) == self._expected_hash_length)

    async def validate_token_async(self, token: str) -> bool:
        await asyncio.sleep(0)
        return self.validate_token(token)

    def revoke_api_key(self, key_id: str) -> bool:
        if key_id in self._api_keys:
            del self._api_keys[key_id]
            return True
        return False

    async def revoke_api_key_async(self, key_id: str) -> bool:
        await asyncio.sleep(0)
        return self.revoke_api_key(key_id)

    def list_api_keys(self) -> List[str]:
        return list(self._api_keys.keys())

    async def list_api_keys_async(self) -> List[str]:
        await asyncio.sleep(0)
        return self.list_api_keys()

    def update_api_key_metadata(self, key_id: str, metadata: Dict[str, Any]) -> bool:
        if key_id not in self._api_keys:
            return False
        self._api_keys[key_id]['metadata'] = metadata
        return True

    async def update_api_key_metadata_async(self, key_id: str, metadata: Dict[str, Any]) -> bool:
        await asyncio.sleep(0)
        return self.update_api_key_metadata(key_id, metadata)

class TokenAuthProvider(AuthProvider):
    def __init__(self, secret_key: str = None):
        resolved_key = secret_key if secret_key is not None else ENV_TOKEN_SECRET_KEY
        self._secret_key = resolved_key.encode()
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

    def list_active_tokens(self) -> List[str]:
        return list(self._active_tokens.keys())

    async def list_active_tokens_async(self) -> List[str]:
        await asyncio.sleep(