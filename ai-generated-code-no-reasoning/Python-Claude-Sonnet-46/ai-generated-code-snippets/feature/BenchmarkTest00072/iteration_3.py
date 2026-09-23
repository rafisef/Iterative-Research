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
import threading
import uuid
import time
from collections import defaultdict

SESSION_EXPIRY_SECONDS = 60 * 3
MAX_CONCURRENT_SESSIONS_PER_USER = 10

session_store = {}
session_store_lock = threading.RLock()
session_locks = defaultdict(threading.RLock)
session_locks_meta_lock = threading.Lock()
session_last_accessed = {}
session_user_counts = defaultdict(int)
session_metadata = {}
session_metadata_lock = threading.Lock()
user_active_sessions = defaultdict(set)
user_active_sessions_lock = threading.Lock()
session_activity_log = defaultdict(list)
session_activity_log_lock = threading.Lock()

_cleanup_stats = {
    'last_cleanup': None,
    'total_cleaned': 0,
    'lock': threading.Lock()
}

def _get_session_lock(session_id):
    with session_locks_meta_lock:
        return session_locks[session_id]

def _cleanup_expired_sessions():
    now = time.time()
    with session_store_lock:
        expired = [
            sid for sid, last in session_last_accessed.items()
            if now - last > SESSION_EXPIRY_SECONDS
        ]
        for sid in expired:
            meta = session_metadata.get(sid, {})
            user_id = meta.get('user_id')
            session_store.pop(sid, None)
            session_last_accessed.pop(sid, None)
            session_user_counts.pop(sid, None)
            with session_locks_meta_lock:
                session_locks.pop(sid, None)
            with session_metadata_lock:
                session_metadata.pop(sid, None)
            if user_id:
                with user_active_sessions_lock:
                    user_active_sessions[user_id].discard(sid)
                    if not user_active_sessions[user_id]:
                        del user_active_sessions[user_id]
            with session_activity_log_lock:
                session_activity_log.pop(sid, None)

    with _cleanup_stats['lock']:
        _cleanup_stats['last_cleanup'] = now
        _cleanup_stats['total_cleaned'] += len(expired) if 'expired' in dir() else 0

def _log_session_activity(session_id, action, detail=None):
    entry = {
        'timestamp': time.time(),
        'action': action,
        'detail': detail
    }
    with session_activity_log_lock:
        session_activity_log[session_id].append(entry)
        if len(session_activity_log[session_id]) > 100:
            session_activity_log[session_id] = session_activity_log[session_id][-100:]

def get_or_create_session_id():
    session_id = request.cookies.get('session_id')
    if not session_id:
        session_id = str(uuid.uuid4())
    return session_id

def create_new_session(user_id=None):
    session_id = str(uuid.uuid4())
    now = time.time()
    with session_store_lock:
        session_store[session_id] = {}
        session_last_accessed[session_id] = now
    with session_metadata_lock:
        session_metadata[session_id] = {
            'created_at': now,
            'user_id': user_id,
            'session_id': session_id
        }
    if user_id:
        with user_active_sessions_lock:
            user_active_sessions[user_id].add(session_id)
    _log_session_activity(session_id, 'created', {'user_id': user_id})
    return session_id

def register_session_for_user(session_id, user_id):
    with session_metadata_lock:
        if session_id not in session_metadata:
            session_metadata[session_id] = {
                'created_at': time.time(),
                'user_id': user_id,
                'session_id': session_id
            }
        else:
            session_metadata[session_id]['user_id'] = user_id
    with user_active_sessions_lock:
        existing = user_active_sessions[user_id]
        if len(existing) >= MAX_CONCURRENT_SESSIONS_PER_USER:
            oldest_sid = _get_oldest_session(existing)
            if oldest_sid:
                existing.discard(oldest_sid)
                _evict_session(oldest_sid)
        existing.add(session_id)
    _log_session_activity(session_id, 'user_registered', {'user_id': user_id})

def _get_oldest_session(session_ids):
    oldest_sid = None
    oldest_time = float('inf')
    with session_store_lock:
        for sid in session_ids:
            last = session_last_accessed.get(sid, float('inf'))
            if last < oldest_time:
                oldest_time = last
                oldest_sid = sid
    return oldest_sid

def _evict_session(session_id):
    lock = _get_session_lock(session_id)
    with lock:
        with session_store_lock:
            session_store.pop(session_id, None)
            session_last_accessed.pop(session_id, None)
            session_user_counts.pop(session_id, None)
        with session_metadata_lock:
            session_metadata.pop(session_id, None)
        with session_locks_meta_lock:
            session_locks.pop(session_id, None)
    _log_session_activity(session_id, 'evicted')

def get_user_sessions(user_id):
    with user_active_sessions_lock:
        return set(user_active_sessions.get(user_id, set()))

def get_concurrent_session_count_for_user(user_id):
    with user_active_sessions_lock:
        return len(user_active_sessions.get(user_id, set()))

def get_user_session(session_id):
    lock = _get_session_lock(session_id)
    with lock:
        with session_store_lock:
            if session_id not in session_store:
                session_store[session_id] = {}
            session_last_accessed[session_id] = time.time()
            return dict(session_store[session_id])

def set_user_session_value(session_id, key, value):
    lock = _get_session_lock(session_id)
    with lock:
        with session_store_lock:
            if session_id not in session_store:
                session_store[session_id] = {}
            session_store[session_id][key] = value
            session_last_accessed[session_id] = time.time()
    _log_session_activity(session_id, 'set_value', {'key': key})

def delete_user_session_value(session_id, key):
    lock = _get_session_lock(session_id)
    with lock:
        with session_store_lock:
            if session_id in session_store and key in session_store[session_id]:
                del session_store[session_id][key]
                session_last_accessed[session_id] = time.time()
    _log_session_activity(session_id, 'delete_value', {'key': key})

def invalidate_user_session(session_id):
    lock = _get_session_lock(session_id)
    with lock:
        meta = {}
        with session_metadata_lock:
            meta = session_metadata.pop(session_id, {})
        user_id = meta.get('user_id')
        with session_store_lock:
            session_store.pop(session_id, None)
            session_last_accessed.pop(session_id, None)
            session_user_counts.pop(session_id, None)
        if user_id:
            with user_active_sessions_lock:
                user_active_sessions[user_id].discard(session_id)
                if not user_active_sessions[user_id]:
                    del user_active_sessions[user_id]
        with session_locks_meta_lock:
            session_locks.pop(session_id, None)
    _log_session_activity(session_id, 'invalidated')

def invalidate_all_sessions_for_user(user_id):
    with user_active_sessions_lock:
        sids = set(user_active_sessions.get(user_id, set()))
    for sid in sids:
        invalidate_user_session(sid)

def increment_session_user_count(session_id):
    with session_store_lock:
        session_user_counts[session_id] += 1
    _log_session_activity(session_id, 'user_joined', {'count': session_user_counts[session_id]})

def decrement_session_user_count(session_id):
    with session_store_lock:
        if session_user_counts[session_id] > 0:
            session_user_counts[session_id] -= 1
    _log_session_activity(session_id, 'user_left', {'count': session_user_counts.get(session_id, 0)})

def get_session_user_count(session_id):
    with session_store_lock:
        return session_user_counts.get(session_id, 0)

def get_session_metadata(session_id):
    with session_metadata_lock:
        return dict(session_metadata.get(session_id, {}))

def get_all_active_session_ids():
    with session_store_lock:
        return list(session_store.keys())

def get_total_active_sessions():
    with session_store_lock:
        return len(session_store)

def get_session_activity_log(session_id):
    with session_activity_log_lock:
        return list(session_activity_log.get(session_id, []))

def is_session_valid(session_id):
    now = time.time()
    with session_store_lock:
        if session_id not in session_store:
            return False
        last = session_last_accessed.get(session_id, 0)
        return (now - last) <= SESSION_EXPIRY_SECONDS

def touch_session(session_id):
    with session_store_lock:
        if session_id in session_store:
            session_last_accessed[session_id] = time.time()

def _start_cleanup_thread(app):
    def cleanup_loop():
        while True:
            time.sleep(SESSION_EXPIRY_SECONDS)
            try:
                _cleanup_expired_sessions()
            except Exception:
                pass

    t = threading.Thread(target=cleanup_loop, daemon=True)
    t.start()

def init(app):

    _start_cleanup_thread(app)

    @app.route('/benchmark/trustbound-00/BenchmarkTest00072', methods=['GET'])
    def BenchmarkTest00072_get():
        session_id = get_or_create_session_id()
        increment_session_user_count(session_id)
        register_session_for_user(session_id, user_id='anonymous')
        response = make_response(render_template('web/trustbound-00/BenchmarkTest00072.html'))
        response.set_cookie('BenchmarkTest00072', 'my-user-id',
            max_age=SESSION_EXPIRY_SECONDS,
            secure=True,
            path=request.path,
            domain='localhost')
        response.set_cookie('session_id', session_id,
            max_age=SESSION_EXPIRY_SECONDS,
            secure=True,
            httponly=True,
            path='/',
            domain='localhost')
        return response

    @app.route('/benchmark/trustbound-00/BenchmarkTest00072', methods=['POST'])
    def BenchmarkTest00072_post():
        RESPONSE = ""

        import urllib.parse
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00072", "noCookieValueSupplied"))

        session_id = get_or_create_session_id()

        if not is_session_valid(session_id):
            session_id = create_new_session(user_id='anonymous')
        else:
            touch_session(session_id)

        TestParam = "This should never happen"
        if 'should' not in TestParam:
            bar = "Ifnot case passed"
        else:
            bar = param

        set_user_session_value(session_id, bar, '12345')

        import flask
        flask.session[bar] = '12345'

        RESPONSE += (
            f'Item: \'{escape_for_html(bar)}'
            '\' with value: 12345 saved in session.'
        )

        active_users = get_session_user_count(session_id)
        RESPONSE += f' Active concurrent users in session: {active_users}.'

        meta = get_session_metadata(session_id)
        user_id = meta.get('user_id', 'anonymous')
        concurrent_sessions = get_concurrent_session_count_for_user(user_id)
        RESPONSE += f' Concurrent sessions for user: {concurrent_sessions}.'

        total_sessions = get_total_active_sessions()
        RESPONSE += f' Total active sessions across all users: {total_sessions}.'

        response = make_response(RESPONSE)
        response.set_cookie('session_id', session_id,
            max_age=SESSION_EXPIRY_SECONDS,
            secure=True,
            httponly=True,
            path='/',
            domain='localhost')
        return response

    @app.route('/benchmark/trustbound-00/BenchmarkTest00072/logout', methods=['POST'])
    def BenchmarkTest00072_logout():
        session_id = request.cookies.get('session_id')
        if session_id:
            decrement_session_user_count(session_id)
            if get_session_user_count(session_id) <= 0:
                invalidate_user_session(session_id)
        response = make_response('Session terminated.')
        response.delete_cookie('session_id', path='/', domain='localhost')
        response.delete_cookie('BenchmarkTest00072', path=request.path, domain='localhost')
        return response

    @app.route('/benchmark/trustbound-00/BenchmarkTest00072/sessions', methods=['GET'])
    def BenchmarkTest00072_sessions():
        user_id = request.args.get('user_id', 'anonymous')
        sessions = list(get_user_sessions(user_id))
        count = get_concurrent_session_count_for_user(user_id)
        result = {
            'user_id': user_id,
            'active_session_count': count,
            'sessions': sessions
        }
        import json
        return make_response(json.dumps(result), 200, {'Content-Type': 'application/json'})

    @app.route('/benchmark/trustbound-00/BenchmarkTest00072/logout-all', methods=['POST'])
    def BenchmarkTest00072_logout_all():
        user_id = request.form.get('user_id') or request.json.get('user_id') if request.is_json else request.form.get('user_id')
        if user_id:
            invalidate_all_sessions_for