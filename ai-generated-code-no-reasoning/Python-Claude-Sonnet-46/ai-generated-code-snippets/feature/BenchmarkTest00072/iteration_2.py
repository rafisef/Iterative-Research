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

session_store = {}
session_store_lock = threading.RLock()
session_locks = defaultdict(threading.RLock)
session_locks_meta_lock = threading.Lock()
session_last_accessed = {}
session_user_counts = defaultdict(int)

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
            session_store.pop(sid, None)
            session_last_accessed.pop(sid, None)
            session_user_counts.pop(sid, None)
            with session_locks_meta_lock:
                session_locks.pop(sid, None)

def get_or_create_session_id():
    session_id = request.cookies.get('session_id')
    if not session_id:
        session_id = str(uuid.uuid4())
    return session_id

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

def delete_user_session_value(session_id, key):
    lock = _get_session_lock(session_id)
    with lock:
        with session_store_lock:
            if session_id in session_store and key in session_store[session_id]:
                del session_store[session_id][key]
                session_last_accessed[session_id] = time.time()

def invalidate_user_session(session_id):
    lock = _get_session_lock(session_id)
    with lock:
        with session_store_lock:
            session_store.pop(session_id, None)
            session_last_accessed.pop(session_id, None)
            session_user_counts.pop(session_id, None)
        with session_locks_meta_lock:
            session_locks.pop(session_id, None)

def increment_session_user_count(session_id):
    with session_store_lock:
        session_user_counts[session_id] += 1

def decrement_session_user_count(session_id):
    with session_store_lock:
        if session_user_counts[session_id] > 0:
            session_user_counts[session_id] -= 1

def get_session_user_count(session_id):
    with session_store_lock:
        return session_user_counts.get(session_id, 0)

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