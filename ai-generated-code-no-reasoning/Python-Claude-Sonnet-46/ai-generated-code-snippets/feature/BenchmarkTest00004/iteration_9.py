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
import threading
import asyncio
import uuid
import json
import os
import sqlite3
import aiosqlite
import time
import hashlib
import hmac
import aiofiles
import aiofiles.os
from contextlib import contextmanager, asynccontextmanager
from typing import Optional, Dict, Any, List, Callable, Set, Tuple
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import weakref
import logging
import queue
import concurrent.futures

logger = logging.getLogger(__name__)

session_store = {}
session_lock = threading.Lock()
async_session_lock = asyncio.Lock()
session_locks = {}
session_locks_lock = threading.Lock()
async_session_locks = {}
async_session_locks_lock = asyncio.Lock()
user_session_index = {}
user_session_index_lock = threading.Lock()
async_user_session_index = {}
async_user_session_index_lock = asyncio.Lock()

STORAGE_BACKEND = os.environ.get('SESSION_STORAGE_BACKEND', 'memory')
SESSION_FILE_DIR = os.environ.get('SESSION_FILE_DIR', '/tmp/sessions')
SESSION_DB_PATH = os.environ.get('SESSION_DB_PATH', '/tmp/sessions.db')
SESSION_MAX_AGE = int(os.environ.get('SESSION_MAX_AGE', 1800))
SESSION_SECRET = os.environ.get('SESSION_SECRET', os.urandom(32).hex())
MAX_SESSIONS_PER_USER = int(os.environ.get('MAX_SESSIONS_PER_USER', 10))
SESSION_ROTATION_INTERVAL = int(os.environ.get('SESSION_ROTATION_INTERVAL', 300))
MAX_CONCURRENT_REQUESTS_PER_SESSION = int(os.environ.get('MAX_CONCURRENT_REQUESTS_PER_SESSION', 10))
MAX_CONCURRENT_SESSIONS_GLOBAL = int(os.environ.get('MAX_CONCURRENT_SESSIONS_GLOBAL', 10000))
SESSION_CLEANUP_INTERVAL = int(os.environ.get('SESSION_CLEANUP_INTERVAL', 60))
SESSION_HEARTBEAT_INTERVAL = int(os.environ.get('SESSION_HEARTBEAT_INTERVAL', 30))
CONCURRENT_SESSION_POLICY = os.environ.get('CONCURRENT_SESSION_POLICY', 'allow')

session_request_counts = {}
session_request_counts_lock = threading.Lock()
async_session_request_counts = {}
async_session_request_counts_lock = asyncio.Lock()

session_active_requests = {}
session_active_requests_lock = threading.Lock()
async_session_active_requests = {}
async_session_active_requests_lock = asyncio.Lock()

session_semaphores = {}
session_semaphores_lock = threading.Lock()
async_session_semaphores = {}
async_session_semaphores_lock = asyncio.Lock()

session_heartbeats = {}
session_heartbeats_lock = threading.Lock()

concurrent_session_events = {}
concurrent_session_events_lock = threading.Lock()
async_concurrent_session_events = {}
async_concurrent_session_events_lock = asyncio.Lock()

global_session_semaphore = threading.Semaphore(MAX_CONCURRENT_SESSIONS_GLOBAL)
async_global_session_semaphore = None

db_pool = []
db_pool_lock = threading.Lock()
DB_POOL_SIZE = int(os.environ.get('DB_POOL_SIZE', 5))

thread_pool = concurrent.futures.ThreadPoolExecutor(
    max_workers=int(os.environ.get('SESSION_THREAD_POOL_SIZE', 20))
)

_cleanup_thread = None
_cleanup_thread_lock = threading.Lock()
_async_cleanup_task = None


def _get_async_global_semaphore():
    global async_global_session_semaphore
    if async_global_session_semaphore is None:
        async_global_session_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SESSIONS_GLOBAL)
    return async_global_session_semaphore


def _get_session_lock(session_id: str) -> threading.Lock:
    with session_locks_lock:
        if session_id not in session_locks:
            session_locks[session_id] = threading.Lock()
        return session_locks[session_id]


async def _get_async_session_lock(session_id: str) -> asyncio.Lock:
    async with async_session_locks_lock:
        if session_id not in async_session_locks:
            async_session_locks[session_id] = asyncio.Lock()
        return async_session_locks[session_id]


def _get_session_semaphore(session_id: str) -> threading.Semaphore:
    with session_semaphores_lock:
        if session_id not in session_semaphores:
            session_semaphores[session_id] = threading.Semaphore(MAX_CONCURRENT_REQUESTS_PER_SESSION)
        return session_semaphores[session_id]


async def _get_async_session_semaphore(session_id: str) -> asyncio.Semaphore:
    async with async_session_semaphores_lock:
        if session_id not in async_session_semaphores:
            async_session_semaphores[session_id] = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS_PER_SESSION)
        return async_session_semaphores[session_id]


@contextmanager
def session_request_context(session_id: str):
    semaphore = _get_session_semaphore(session_id)
    acquired = semaphore.acquire(timeout=5.0)
    if not acquired:
        raise RuntimeError(f"Session {session_id} exceeded concurrent request limit")
    try:
        with session_active_requests_lock:
            session_active_requests[session_id] = session_active_requests.get(session_id, 0) + 1
        with session_request_counts_lock:
            session_request_counts[session_id] = session_request_counts.get(session_id, 0) + 1
        yield session_id
    finally:
        with session_active_requests_lock:
            if session_id in session_active_requests:
                session_active_requests[session_id] = max(0, session_active_requests[session_id] - 1)
        semaphore.release()


@asynccontextmanager
async def async_session_request_context(session_id: str):
    semaphore = await _get_async_session_semaphore(session_id)
    try:
        await asyncio.wait_for(semaphore.acquire(), timeout=5.0)
    except asyncio.TimeoutError:
        raise RuntimeError(f"Session {session_id} exceeded concurrent request limit")
    try:
        async with async_session_active_requests_lock:
            async_session_active_requests[session_id] = async_session_active_requests.get(session_id, 0) + 1
        async with async_session_request_counts_lock:
            async_session_request_counts[session_id] = async_session_request_counts.get(session_id, 0) + 1
        yield session_id
    finally:
        async with async_session_active_requests_lock:
            if session_id in async_session_active_requests:
                async_session_active_requests[session_id] = max(0, async_session_active_requests[session_id] - 1)
        semaphore.release()


def create_session(user_id: str, data: Optional[Dict[str, Any]] = None) -> Optional[str]:
    with user_session_index_lock:
        user_sessions = user_session_index.get(user_id, [])
        active_sessions = []
        for sid in user_sessions:
            with session_lock:
                if sid in session_store:
                    sdata = session_store[sid]
                    if time.time() - sdata.get('last_active', 0) < SESSION_MAX_AGE:
                        active_sessions.append(sid)
        user_session_index[user_id] = active_sessions

        if len(active_sessions) >= MAX_SESSIONS_PER_USER:
            if CONCURRENT_SESSION_POLICY == 'reject':
                return None
            elif CONCURRENT_SESSION_POLICY == 'replace_oldest':
                oldest_sid = _find_oldest_session(active_sessions)
                if oldest_sid:
                    _terminate_session(oldest_sid, user_id)
                    active_sessions = [s for s in active_sessions if s != oldest_sid]
                    user_session_index[user_id] = active_sessions
            elif CONCURRENT_SESSION_POLICY == 'replace_lru':
                lru_sid = _find_lru_session(active_sessions)
                if lru_sid:
                    _terminate_session(lru_sid, user_id)
                    active_sessions = [s for s in active_sessions if s != lru_sid]
                    user_session_index[user_id] = active_sessions

    if not global_session_semaphore.acquire(blocking=False):
        logger.warning("Global session limit reached")
        return None

    session_id = str(uuid.uuid4())
    session_data = {
        'session_id': session_id,
        'user_id': user_id,
        'created_at': time.time(),
        'last_active': time.time(),
        'last_rotated': time.time(),
        'data': data or {},
        'active': True,
        'ip_address': None,
        'user_agent': None,
        'concurrent_request_count': 0,
        'total_request_count': 0,
        'terminated': False,
        'termination_reason': None
    }

    with session_lock:
        session_store[session_id] = session_data

    with user_session_index_lock:
        if user_id not in user_session_index:
            user_session_index[user_id] = []
        user_session_index[user_id].append(session_id)

    with session_heartbeats_lock:
        session_heartbeats[session_id] = time.time()

    _notify_session_event(session_id, 'created', user_id)
    _ensure_cleanup_thread()
    return session_id


async def async_create_session(user_id: str, data: Optional[Dict[str, Any]] = None) -> Optional[str]:
    async with async_user_session_index_lock:
        user_sessions = async_user_session_index.get(user_id, [])
        active_sessions = []
        for sid in user_sessions:
            async with async_session_lock:
                if sid in session_store:
                    sdata = session_store[sid]
                    if time.time() - sdata.get('last_active', 0) < SESSION_MAX_AGE:
                        active_sessions.append(sid)
        async_user_session_index[user_id] = active_sessions

        if len(active_sessions) >= MAX_SESSIONS_PER_USER:
            if CONCURRENT_SESSION_POLICY == 'reject':
                return None
            elif CONCURRENT_SESSION_POLICY == 'replace_oldest':
                oldest_sid = _find_oldest_session(active_sessions)
                if oldest_sid:
                    await _async_terminate_session(oldest_sid, user_id)
                    active_sessions = [s for s in active_sessions if s != oldest_sid]
                    async_user_session_index[user_id] = active_sessions
            elif CONCURRENT_SESSION_POLICY == 'replace_lru':
                lru_sid = _find_lru_session(active_sessions)
                if lru_sid:
                    await _async_terminate_session(lru_sid, user_id)
                    active_sessions = [s for s in active_sessions if s != lru_sid]
                    async_user_session_index[user_id] = active_sessions

    sem = _get_async_global_semaphore()
    acquired = False
    try:
        await asyncio.wait_for(sem.acquire(), timeout=1.0)
        acquired = True
    except asyncio.TimeoutError:
        logger.warning("Global async session limit reached")
        return None

    session_id = str(uuid.uuid4())
    session_data = {
        'session_id': session_id,
        'user_id': user_id,
        'created_at': time.time(),
        'last_active': time.time(),
        'last_rotated': time.time(),
        'data': data or {},
        'active': True,
        'ip_address': None,
        'user_agent': None,
        'concurrent_request_count': 0,
        'total_request_count': 0,
        'terminated': False,
        'termination_reason': None
    }

    async with async_session_lock:
        session_store[session_id] = session_data

    async with async_user_session_index_lock:
        if user_id not in async_user_session_index:
            async_user_session_index[user_id] = []
        async_user_session_index[user_id].append(session_id)

    with session_heartbeats_lock:
        session_heartbeats[session_id] = time.time()

    await _async_notify_session_event(session_id, 'created', user_id)
    return session_id


def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    with _get_session_lock(session_id):
        with session_lock:
            sdata = session_store.get(session_id)
        if sdata is None:
            return None
        if sdata.get('terminated'):
            return None
        if time.time() - sdata.get('last_active', 0) > SESSION_MAX_AGE:
            _terminate_session(session_id, sdata.get('user_id'), reason='expired')
            return None
        sdata['last_active'] = time.time()
        with session_heartbeats_lock:
            session_heartbeats[session_id] = time.time()
        if time.time() - sdata.get('last_rotated', 0) > SESSION_ROTATION_INTERVAL:
            _rotate_session_id(session_id)
        return dict(sdata)


async def async_get_session(session_id: str) -> Optional[Dict[str, Any]]:
    lock = await _get_async_session_lock(session_id)
    async with lock:
        async with async_session_lock:
            sdata = session_store.get(session_id)
        if sdata is None:
            return None
        if sdata.get('terminated'):
            return None
        if time.time() - sdata.get('last_active', 0) > SESSION_MAX_AGE:
            await _async_terminate_session(session_id, sdata.get('user_id'), reason='expired')
            return None
        sdata['last_active'] = time.time()
        with session_heartbeats_lock:
            session_heartbeats[session_id] = time.time()
        return dict(sdata)


def update_session(session_id: str,