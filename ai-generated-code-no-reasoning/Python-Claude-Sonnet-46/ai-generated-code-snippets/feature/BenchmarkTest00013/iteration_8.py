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
import concurrent.futures
import urllib.parse
import elementpath
import xml.etree.ElementTree as ET
import helpers.utils
import os
import sqlite3
import threading
import time
import logging
import hashlib
import hmac
import base64
import json
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, Tuple, List

logger = logging.getLogger(__name__)


def _get_env_int(key, default):
    try:
        return int(os.environ.get(key, str(default)))
    except (ValueError, TypeError):
        return default


def _get_env_bool(key, default):
    val = os.environ.get(key)
    if val is None:
        return default
    return val.strip().lower() == "true"


def _get_env_str(key, default):
    val = os.environ.get(key)
    if val is None:
        return default
    return val


def _get_env_float(key, default):
    try:
        return float(os.environ.get(key, str(default)))
    except (ValueError, TypeError):
        return default


def _get_env_list(key, default):
    val = os.environ.get(key)
    if val is None:
        return default
    return [item.strip() for item in val.split(",") if item.strip()]


def _get_env_json(key, default):
    val = os.environ.get(key)
    if val is None:
        return default
    try:
        return json.loads(val)
    except (ValueError, TypeError):
        return default


def load_config(overrides: Optional[Dict[str, Any]] = None):
    default_max_workers = concurrent.futures.ThreadPoolExecutor()._max_workers
    cfg = {
        "THREAD_POOL_SIZE": _get_env_int("BENCHMARK_THREAD_POOL_SIZE", default_max_workers),
        "COOKIE_NAME": _get_env_str("BENCHMARK_COOKIE_NAME", "BenchmarkTest00013"),
        "COOKIE_VALUE": _get_env_str("BENCHMARK_COOKIE_VALUE", "2222"),
        "COOKIE_MAX_AGE": _get_env_int("BENCHMARK_COOKIE_MAX_AGE", 60 * 3),
        "COOKIE_SECURE": _get_env_bool("BENCHMARK_COOKIE_SECURE", True),
        "COOKIE_DOMAIN": _get_env_str("BENCHMARK_COOKIE_DOMAIN", "localhost"),
        "COOKIE_DEFAULT_VALUE": _get_env_str("BENCHMARK_COOKIE_DEFAULT_VALUE", "noCookieValueSupplied"),
        "ROUTE_PREFIX": _get_env_str("BENCHMARK_ROUTE_PREFIX", "/benchmark/xpathi-00/BenchmarkTest00013"),
        "USE_ASYNC_DEFAULT": _get_env_bool("BENCHMARK_USE_ASYNC_DEFAULT", False),
        "XML_FILE_PATH": _get_env_str("BENCHMARK_XML_FILE_PATH", f"{helpers.utils.RES_DIR}/employees.xml"),
        "STORAGE_BACKEND": _get_env_str("BENCHMARK_STORAGE_BACKEND", "file").lower(),
        "DB_PATH": _get_env_str("BENCHMARK_DB_PATH", f"{helpers.utils.RES_DIR}/employees.db"),
        "ASYNC_TIMEOUT": _get_env_float("BENCHMARK_ASYNC_TIMEOUT", 30.0),
        "RETRY_COUNT": _get_env_int("BENCHMARK_RETRY_COUNT", 3),
        "RETRY_DELAY": _get_env_float("BENCHMARK_RETRY_DELAY", 0.5),
        "ENABLE_CACHE": _get_env_bool("BENCHMARK_ENABLE_CACHE", False),
        "CACHE_TTL": _get_env_int("BENCHMARK_CACHE_TTL", 60),
        "AUTH_PROVIDER": _get_env_str("BENCHMARK_AUTH_PROVIDER", "basic"),
        "AUTH_SECRET_KEY": _get_env_str("BENCHMARK_AUTH_SECRET_KEY", "default-secret-key-change-in-production"),
        "AUTH_TOKEN_TTL": _get_env_int("BENCHMARK_AUTH_TOKEN_TTL", 3600),
        "AUTH_OAUTH_CLIENT_ID": _get_env_str("BENCHMARK_AUTH_OAUTH_CLIENT_ID", ""),
        "AUTH_OAUTH_CLIENT_SECRET": _get_env_str("BENCHMARK_AUTH_OAUTH_CLIENT_SECRET", ""),
        "AUTH_OAUTH_AUTHORIZE_URL": _get_env_str("BENCHMARK_AUTH_OAUTH_AUTHORIZE_URL", ""),
        "AUTH_OAUTH_TOKEN_URL": _get_env_str("BENCHMARK_AUTH_OAUTH_TOKEN_URL", ""),
        "AUTH_OAUTH_USERINFO_URL": _get_env_str("BENCHMARK_AUTH_OAUTH_USERINFO_URL", ""),
        "AUTH_LDAP_SERVER": _get_env_str("BENCHMARK_AUTH_LDAP_SERVER", ""),
        "AUTH_LDAP_PORT": _get_env_int("BENCHMARK_AUTH_LDAP_PORT", 389),
        "AUTH_LDAP_BASE_DN": _get_env_str("BENCHMARK_AUTH_LDAP_BASE_DN", ""),
        "AUTH_LDAP_USE_TLS": _get_env_bool("BENCHMARK_AUTH_LDAP_USE_TLS", False),
        "AUTH_SAML_ENTITY_ID": _get_env_str("BENCHMARK_AUTH_SAML_ENTITY_ID", ""),
        "AUTH_SAML_SSO_URL": _get_env_str("BENCHMARK_AUTH_SAML_SSO_URL", ""),
        "AUTH_SAML_CERTIFICATE": _get_env_str("BENCHMARK_AUTH_SAML_CERTIFICATE", ""),
        "AUTH_MULTI_PROVIDERS": _get_env_str("BENCHMARK_AUTH_MULTI_PROVIDERS", "basic"),
        "AUTH_ALLOW_MULTIPLE": _get_env_bool("BENCHMARK_AUTH_ALLOW_MULTIPLE", False),
        "LOG_LEVEL": _get_env_str("BENCHMARK_LOG_LEVEL", "INFO").upper(),
        "LOG_FORMAT": _get_env_str("BENCHMARK_LOG_FORMAT", "%(asctime)s %(levelname)s %(name)s %(message)s"),
        "LOG_FILE": _get_env_str("BENCHMARK_LOG_FILE", ""),
        "MAX_REQUEST_SIZE": _get_env_int("BENCHMARK_MAX_REQUEST_SIZE", 1024 * 1024),
        "ALLOWED_HOSTS": _get_env_list("BENCHMARK_ALLOWED_HOSTS", ["localhost", "127.0.0.1"]),
        "CORS_ORIGINS": _get_env_list("BENCHMARK_CORS_ORIGINS", []),
        "CORS_ENABLED": _get_env_bool("BENCHMARK_CORS_ENABLED", False),
        "RATE_LIMIT_ENABLED": _get_env_bool("BENCHMARK_RATE_LIMIT_ENABLED", False),
        "RATE_LIMIT_REQUESTS": _get_env_int("BENCHMARK_RATE_LIMIT_REQUESTS", 100),
        "RATE_LIMIT_WINDOW": _get_env_int("BENCHMARK_RATE_LIMIT_WINDOW", 60),
        "SESSION_TIMEOUT": _get_env_int("BENCHMARK_SESSION_TIMEOUT", 1800),
        "SESSION_COOKIE_SECURE": _get_env_bool("BENCHMARK_SESSION_COOKIE_SECURE", True),
        "SESSION_COOKIE_HTTPONLY": _get_env_bool("BENCHMARK_SESSION_COOKIE_HTTPONLY", True),
        "SESSION_COOKIE_SAMESITE": _get_env_str("BENCHMARK_SESSION_COOKIE_SAMESITE", "Lax"),
        "DB_POOL_SIZE": _get_env_int("BENCHMARK_DB_POOL_SIZE", 5),
        "DB_POOL_TIMEOUT": _get_env_float("BENCHMARK_DB_POOL_TIMEOUT", 30.0),
        "DB_POOL_RECYCLE": _get_env_int("BENCHMARK_DB_POOL_RECYCLE", 3600),
        "DB_ECHO": _get_env_bool("BENCHMARK_DB_ECHO", False),
        "FEATURE_FLAGS": _get_env_json("BENCHMARK_FEATURE_FLAGS", {}),
        "EXTRA_HEADERS": _get_env_json("BENCHMARK_EXTRA_HEADERS", {}),
        "TRUSTED_PROXIES": _get_env_list("BENCHMARK_TRUSTED_PROXIES", []),
        "METRICS_ENABLED": _get_env_bool("BENCHMARK_METRICS_ENABLED", False),
        "METRICS_PATH": _get_env_str("BENCHMARK_METRICS_PATH", "/metrics"),
        "HEALTH_CHECK_PATH": _get_env_str("BENCHMARK_HEALTH_CHECK_PATH", "/health"),
        "TLS_CERT_FILE": _get_env_str("BENCHMARK_TLS_CERT_FILE", ""),
        "TLS_KEY_FILE": _get_env_str("BENCHMARK_TLS_KEY_FILE", ""),
        "TLS_CA_FILE": _get_env_str("BENCHMARK_TLS_CA_FILE", ""),
        "TLS_VERIFY": _get_env_bool("BENCHMARK_TLS_VERIFY", True),
        "WORKER_TIMEOUT": _get_env_int("BENCHMARK_WORKER_TIMEOUT", 30),
        "GRACEFUL_SHUTDOWN_TIMEOUT": _get_env_int("BENCHMARK_GRACEFUL_SHUTDOWN_TIMEOUT", 10),
        "DEBUG": _get_env_bool("BENCHMARK_DEBUG", False),
        "TESTING": _get_env_bool("BENCHMARK_TESTING", False),
        "ENVIRONMENT": _get_env_str("BENCHMARK_ENVIRONMENT", "production").lower(),
    }
    if overrides:
        for key, value in overrides.items():
            cfg[key] = value
    return cfg


def reload_config(overrides: Optional[Dict[str, Any]] = None):
    global config
    global executor
    global COOKIE_NAME, COOKIE_VALUE, COOKIE_MAX_AGE, COOKIE_SECURE, COOKIE_DOMAIN
    global COOKIE_DEFAULT_VALUE, BENCHMARK_ROUTE_PREFIX, BENCHMARK_USE_ASYNC_DEFAULT
    global XML_FILE_PATH, STORAGE_BACKEND, DB_PATH, ASYNC_TIMEOUT, RETRY_COUNT
    global RETRY_DELAY, ENABLE_CACHE, CACHE_TTL, AUTH_PROVIDER, AUTH_SECRET_KEY
    global AUTH_TOKEN_TTL, AUTH_MULTI_PROVIDERS, AUTH_ALLOW_MULTIPLE
    global LOG_LEVEL, LOG_FORMAT, LOG_FILE, MAX_REQUEST_SIZE, ALLOWED_HOSTS
    global CORS_ORIGINS, CORS_ENABLED, RATE_LIMIT_ENABLED, RATE_LIMIT_REQUESTS
    global RATE_LIMIT_WINDOW, SESSION_TIMEOUT, SESSION_COOKIE_SECURE
    global SESSION_COOKIE_HTTPONLY, SESSION_COOKIE_SAMESITE, DB_POOL_SIZE
    global DB_POOL_TIMEOUT, DB_POOL_RECYCLE, DB_ECHO, FEATURE_FLAGS, EXTRA_HEADERS
    global TRUSTED_PROXIES, METRICS_ENABLED, METRICS_PATH, HEALTH_CHECK_PATH
    global TLS_CERT_FILE, TLS_KEY_FILE, TLS_CA_FILE, TLS_VERIFY, WORKER_TIMEOUT
    global GRACEFUL_SHUTDOWN_TIMEOUT, DEBUG, TESTING, ENVIRONMENT
    global storage_backend_instance

    config = load_config(overrides)
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=config["THREAD_POOL_SIZE"])

    COOKIE_NAME = config["COOKIE_NAME"]
    COOKIE_VALUE = config["COOKIE_VALUE"]
    COOKIE_MAX_AGE = config["COOKIE_MAX_AGE"]
    COOKIE_SECURE = config["COOKIE_SECURE"]
    COOKIE_DOMAIN = config["COOKIE_DOMAIN"]
    COOKIE_DEFAULT_VALUE = config["COOKIE_DEFAULT_VALUE"]
    BENCHMARK_ROUTE_PREFIX = config["ROUTE_PREFIX"]
    BENCHMARK_USE_ASYNC_DEFAULT = config["USE_ASYNC_DEFAULT"]
    XML_FILE_PATH = config["XML_FILE_PATH"]
    STORAGE_BACKEND = config["STORAGE_BACKEND"]
    DB_PATH = config["DB_PATH"]
    ASYNC_TIMEOUT = config["ASYNC_TIMEOUT"]
    RETRY_COUNT = config["RETRY_COUNT"]
    RETRY_DELAY = config["RETRY_DELAY"]
    ENABLE_CACHE = config["ENABLE_CACHE"]
    CACHE_TTL = config["CACHE_TTL"]
    AUTH_PROVIDER = config["AUTH_PROVIDER"]
    AUTH_SECRET_KEY = config["AUTH_SECRET_KEY"]
    AUTH_TOKEN_TTL = config["AUTH_TOKEN_TTL"]
    AUTH_MULTI_PROVIDERS = config["AUTH_MULTI_PROVIDERS"]
    AUTH_ALLOW_MULTIPLE = config["AUTH_ALLOW_MULTIPLE"]
    LOG_LEVEL = config["LOG_LEVEL"]
    LOG_FORMAT = config["LOG_FORMAT"]
    LOG_FILE = config["LOG_FILE"]
    MAX_REQUEST_SIZE = config["MAX_REQUEST_SIZE"]
    ALLOWED_HOSTS = config["ALLOWED_HOSTS"]
    CORS_ORIGINS = config["CORS_ORIGINS"]
    CORS_ENABLED = config["CORS_ENABLED"]
    RATE_LIMIT_ENABLED = config["RATE_LIMIT_ENABLED"]
    RATE_LIMIT_REQUESTS = config["RATE_LIMIT_REQUESTS"]
    RATE_LIMIT_WINDOW = config["RATE_LIMIT_WINDOW"]
    SESSION_TIMEOUT = config["SESSION_TIMEOUT"]
    SESSION_COOKIE_SECURE = config["SESSION_COOKIE_SECURE"]
    SESSION_COOKIE_HTTPONLY = config["SESSION_COOKIE_HTTPONLY"]
    SESSION_COOKIE_SAMESITE = config["SESSION_COOKIE_SAMESITE"]
    DB_POOL_SIZE = config["DB_POOL_SIZE"]
    DB_POOL_TIMEOUT = config["DB_POOL_TIMEOUT"]
    DB_POOL_RECYCLE = config["DB_POOL_RECYCLE"]
    DB_ECHO = config["DB_ECHO"]
    FEATURE_FLAGS = config["FEATURE_FLAGS"]
    EXTRA_HEADERS = config["EXTRA_HEADERS"]
    TRUSTED_PROXIES = config["TRUSTED_PROXIES"]
    METRICS_ENABLED = config["METRICS_ENABLED"]
    METRICS_PATH = config["METRICS_PATH"]
    HEALTH_CHECK_PATH = config["HEALTH_CHECK_PATH"]
    TLS_CERT_FILE = config["TLS_CERT_FILE"]
    TLS_KEY_FILE = config["TLS_KEY_FILE"]
    TLS_CA_FILE = config["TLS_CA_FILE"]
    TLS_VERIFY = config["TLS_VERIFY"]
    WORKER_TIMEOUT = config["WORKER_TIMEOUT"]
    GRACEFUL_SHUTDOWN_TIMEOUT = config["GRACEFUL_SHUTDOWN_TIMEOUT"]
    DEBUG = config["DEBUG"]