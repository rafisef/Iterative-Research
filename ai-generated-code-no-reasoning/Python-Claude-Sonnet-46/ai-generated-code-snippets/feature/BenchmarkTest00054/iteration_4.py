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
import aiofiles
import hashlib
import base64
import io
import urllib.parse
import helpers.utils
import concurrent.futures
import os
import threading
import time
import logging
import hmac
import secrets
import json
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from enum import Enum

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

_executor = concurrent.futures.ThreadPoolExecutor(
    max_workers=int(os.environ.get('BENCHMARK_THREAD_POOL_SIZE', 10))
)

_HASH_ALGORITHM = os.environ.get('BENCHMARK_HASH_ALGORITHM', 'md5')
_PASSWORD_FILE = os.environ.get(
    'BENCHMARK_PASSWORD_FILE',
    f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt'
)
_COOKIE_NAME = os.environ.get('BENCHMARK_COOKIE_NAME', 'BenchmarkTest00054')
_COOKIE_SECRET = os.environ.get('BENCHMARK_COOKIE_SECRET', 'someSecret')
_COOKIE_MAX_AGE = int(os.environ.get('BENCHMARK_COOKIE_MAX_AGE', 60 * 3))
_COOKIE_SECURE = os.environ.get('BENCHMARK_COOKIE_SECURE', 'true').lower() == 'true'
_COOKIE_DOMAIN = os.environ.get('BENCHMARK_COOKIE_DOMAIN', 'localhost')
_DEFAULT_ASYNC = os.environ.get('BENCHMARK_DEFAULT_ASYNC', 'false').lower() == 'true'
_INPUT_READ_LIMIT = int(os.environ.get('BENCHMARK_INPUT_READ_LIMIT', 1000))
_ROUTE_PREFIX = os.environ.get('BENCHMARK_ROUTE_PREFIX', '/benchmark/hash-00/BenchmarkTest00054')
_HASH_ITERATIONS = int(os.environ.get('BENCHMARK_HASH_ITERATIONS', 1))
_WRITE_TIMEOUT = float(os.environ.get('BENCHMARK_WRITE_TIMEOUT', 5.0))
_RETRY_ATTEMPTS = int(os.environ.get('BENCHMARK_RETRY_ATTEMPTS', 3))
_RETRY_DELAY = float(os.environ.get('BENCHMARK_RETRY_DELAY', 0.1))
_AUTH_PROVIDER = os.environ.get('BENCHMARK_AUTH_PROVIDER', 'cookie')
_AUTH_TOKEN_HEADER = os.environ.get('BENCHMARK_AUTH_TOKEN_HEADER', 'X-Auth-Token')
_AUTH_BASIC_REALM = os.environ.get('BENCHMARK_AUTH_BASIC_REALM', 'BenchmarkTest')
_AUTH_JWT_SECRET = os.environ.get('BENCHMARK_AUTH_JWT_SECRET', 'jwt-secret-key')
_AUTH_API_KEYS_FILE = os.environ.get('BENCHMARK_AUTH_API_KEYS_FILE', '')
_AUTH_SESSION_TIMEOUT = int(os.environ.get('BENCHMARK_AUTH_SESSION_TIMEOUT', 3600))
_AUTH_MULTI_PROVIDERS = os.environ.get('BENCHMARK_AUTH_MULTI_PROVIDERS', '').split(',')

_file_lock = threading.Lock()
_async_file_lock = asyncio.Lock() if False else None
_sessions_lock = threading.Lock()
_active_sessions: Dict[str, Dict[str, Any]] = {}
_api_keys_cache: Optional[Dict[str, str]] = None
_api_keys_cache_lock = threading.Lock()


class AuthProviderType(Enum):
    COOKIE = 'cookie'
    TOKEN = 'token'
    BASIC = 'basic'
    JWT = 'jwt'
    API_KEY = 'api_key'
    SESSION = 'session'
    MULTI = 'multi'


@dataclass
class AuthResult:
    authenticated: bool
    identity: Optional[str] = None
    provider: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class AuthProviderConfig:
    provider_type: AuthProviderType
    enabled: bool = True
    priority: int = 0
    config: Dict[str, Any] = field(default_factory=dict)


class BaseAuthProvider(ABC):
    def __init__(self, config: AuthProviderConfig):
        self.config = config
        self.provider_type = config.provider_type

    @abstractmethod
    def authenticate(self, request_context: Dict[str, Any]) -> AuthResult:
        pass

    @abstractmethod
    def extract_credentials(self, request_context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        pass

    def get_provider_name(self) -> str:
        return self.provider_type.value


class CookieAuthProvider(BaseAuthProvider):
    def __init__(self, config: AuthProviderConfig):
        super().__init__(config)
        self.cookie_name = config.config.get('cookie_name', _COOKIE_NAME)
        self.cookie_secret = config.config.get('cookie_secret', _COOKIE_SECRET)

    def extract_credentials(self, request_context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        cookies = request_context.get('cookies', {})
        cookie_value = cookies.get(self.cookie_name)
        if cookie_value:
            return {'cookie_value': cookie_value, 'cookie_name': self.cookie_name}
        return None

    def authenticate(self, request_context: Dict[str, Any]) -> AuthResult:
        credentials = self.extract_credentials(request_context)
        if not credentials:
            return AuthResult(
                authenticated=False,
                provider=self.get_provider_name(),
                error='No cookie found'
            )
        cookie_value = credentials.get('cookie_value', '')
        decoded_value = urllib.parse.unquote_plus(cookie_value)
        return AuthResult(
            authenticated=True,
            identity=decoded_value,
            provider=self.get_provider_name(),
            metadata={'cookie_name': self.cookie_name, 'raw_value': cookie_value}
        )


class TokenAuthProvider(BaseAuthProvider):
    def __init__(self, config: AuthProviderConfig):
        super().__init__(config)
        self.header_name = config.config.get('header_name', _AUTH_TOKEN_HEADER)
        self.valid_tokens = config.config.get('valid_tokens', {})

    def extract_credentials(self, request_context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        headers = request_context.get('headers', {})
        token = headers.get(self.header_name) or headers.get(self.header_name.lower())
        if token:
            if token.startswith('Bearer '):
                token = token[7:]
            return {'token': token}
        return None

    def authenticate(self, request_context: Dict[str, Any]) -> AuthResult:
        credentials = self.extract_credentials(request_context)
        if not credentials:
            return AuthResult(
                authenticated=False,
                provider=self.get_provider_name(),
                error='No token found in headers'
            )
        token = credentials.get('token', '')
        identity = self.valid_tokens.get(token)
        if identity:
            return AuthResult(
                authenticated=True,
                identity=identity,
                provider=self.get_provider_name(),
                metadata={'token_prefix': token[:8] + '...' if len(token) > 8 else token}
            )
        if self.valid_tokens:
            return AuthResult(
                authenticated=False,
                provider=self.get_provider_name(),
                error='Invalid token'
            )
        return AuthResult(
            authenticated=True,
            identity=token,
            provider=self.get_provider_name(),
            metadata={'token_prefix': token[:8] + '...' if len(token) > 8 else token}
        )


class BasicAuthProvider(BaseAuthProvider):
    def __init__(self, config: AuthProviderConfig):
        super().__init__(config)
        self.realm = config.config.get('realm', _AUTH_BASIC_REALM)
        self.users = config.config.get('users', {})

    def extract_credentials(self, request_context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        headers = request_context.get('headers', {})
        auth_header = headers.get('Authorization') or headers.get('authorization')
        if not auth_header or not auth_header.startswith('Basic '):
            return None
        try:
            encoded = auth_header[6:]
            decoded = base64.b64decode(encoded).decode('utf-8')
            if ':' in decoded:
                username, password = decoded.split(':', 1)
                return {'username': username, 'password': password}
        except Exception:
            pass
        return None

    def authenticate(self, request_context: Dict[str, Any]) -> AuthResult:
        credentials = self.extract_credentials(request_context)
        if not credentials:
            return AuthResult(
                authenticated=False,
                provider=self.get_provider_name(),
                error='No Basic auth credentials found'
            )
        username = credentials.get('username', '')
        password = credentials.get('password', '')
        if self.users:
            stored_password = self.users.get(username)
            if stored_password and hmac.compare_digest(stored_password, password):
                return AuthResult(
                    authenticated=True,
                    identity=username,
                    provider=self.get_provider_name(),
                    metadata={'realm': self.realm}
                )
            return AuthResult(
                authenticated=False,
                provider=self.get_provider_name(),
                error='Invalid credentials'
            )
        return AuthResult(
            authenticated=True,
            identity=username,
            provider=self.get_provider_name(),
            metadata={'realm': self.realm}
        )


class JWTAuthProvider(BaseAuthProvider):
    def __init__(self, config: AuthProviderConfig):
        super().__init__(config)
        self.secret = config.config.get('secret', _AUTH_JWT_SECRET)
        self.algorithm = config.config.get('algorithm', 'HS256')

    def extract_credentials(self, request_context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        headers = request_context.get('headers', {})
        auth_header = headers.get('Authorization') or headers.get('authorization')
        if auth_header and auth_header.startswith('Bearer '):
            return {'token': auth_header[7:]}
        cookies = request_context.get('cookies', {})
        jwt_cookie = cookies.get('jwt_token')
        if jwt_cookie:
            return {'token': jwt_cookie}
        return None

    def _decode_jwt_payload(self, token: str) -> Optional[Dict[str, Any]]:
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            header_b64, payload_b64, signature_b64 = parts
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += '=' * padding
            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            return json.loads(payload_bytes.decode('utf-8'))
        except Exception:
            return None

    def _verify_jwt_signature(self, token: str) -> bool:
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return False
            header_payload = f'{parts[0]}.{parts[1]}'
            expected_sig = hmac.new(
                self.secret.encode('utf-8'),
                header_payload.encode('utf-8'),
                hashlib.sha256
            ).digest()
            padding = 4 - len(parts[2]) % 4
            if padding != 4:
                sig_b64 = parts[2] + '=' * padding
            else:
                sig_b64 = parts[2]
            actual_sig = base64.urlsafe_b64decode(sig_b64)
            return hmac.compare_digest(expected_sig, actual_sig)
        except Exception:
            return False

    def authenticate(self, request_context: Dict[str, Any]) -> AuthResult:
        credentials = self.extract_credentials(request_context)
        if not credentials:
            return AuthResult(
                authenticated=False,
                provider=self.get_provider_name(),
                error='No JWT token found'
            )
        token = credentials.get('token', '')
        payload = self._decode_jwt_payload(token)
        if not payload:
            return AuthResult(
                authenticated=False,
                provider=self.get_provider_name(),
                error='Invalid JWT format'
            )
        exp = payload.get('exp')
        if exp and time.time() > exp:
            return AuthResult(
                authenticated=False,
                provider=self.get_provider_name(),
                error='JWT token expired'
            )
        identity = payload.get('sub') or payload.get('identity') or payload.get('user')
        if not identity:
            return AuthResult(
                authenticated=False,
                provider=self.get_provider_name(),
                error='No identity in JWT payload'
            )
        return AuthResult(
            authenticated=True,
            identity=str(identity),
            provider=self.get_provider_name(),
            metadata={'jwt_payload': {k: v for k, v in payload.items() if k not in ('sub', 'identity')}}
        )

    def generate_token(self, identity: str, expires_in: int = 3600) -> str:
        header = base64.urlsafe_b64encode(
            json.dumps({'alg': 'HS256', 'typ': 'JWT'}).encode()
        ).rstrip(b'=').decode()
        payload_data = {
            'sub': identity,
            'iat': int(time.time()),
            'exp': int(time.time()) + expires_in
        }
        payload = base64.urlsafe_b64encode(
            json.dumps(payload_data).encode()
        ).rstrip(b'=').decode()
        header_payload = f'{header}.{payload}'
        signature = hmac.new(
            self.secret.encode('utf-8'),
            header_payload.encode('utf-8'),
            hashlib.sha256
        ).digest()
        sig = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
        return f'{header_payload}.{sig}'


class ApiKeyAuthProvider(BaseAuthProvider):
    def __init__(self, config: AuthProviderConfig):
        super().__init__(config)
        self.header_name = config.config.get('header_name', 'X-API-Key')
        self.query_param = config.config.get('query_param', 'api_key')
        self.api_keys_file = config.config.get('api_keys_file', _AUTH_API_KEYS_FILE)
        self.api_keys = config.config.get('api_keys', {})

    def _load_api_keys_from_file(self) -> Dict[str, str]:
        global _api_keys_cache
        with