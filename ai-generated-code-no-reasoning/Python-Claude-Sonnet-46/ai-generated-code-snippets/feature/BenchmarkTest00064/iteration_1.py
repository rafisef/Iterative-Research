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
import uuid
import time

session_store = {}
session_store_lock = threading.Lock()

def create_session(user_id):
    session_id = str(uuid.uuid4())
    with session_store_lock:
        session_store[session_id] = {
            'user_id': user_id,
            'created_at': time.time(),
            'data': {}
        }
    return session_id

def get_session(session_id):
    with session_store_lock:
        return session_store.get(session_id)

def update_session(session_id, key, value):
    with session_store_lock:
        if session_id in session_store:
            session_store[session_id]['data'][key] = value
            return True
        return False

def delete_session(session_id):
    with session_store_lock:
        if session_id in session_store:
            del session_store[session_id]
            return True
        return False

def cleanup_expired_sessions(max_age=180):
    current_time = time.time()
    with session_store_lock:
        expired = [
            sid for sid, sdata in session_store.items()
            if current_time - sdata['created_at'] > max_age
        ]
        for sid in expired:
            del session_store[sid]

def init(app):

    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET'])
    def BenchmarkTest00064_get():
        cleanup_expired_sessions()
        session_id = request.cookies.get('session_id')
        if not session_id or not get_session(session_id):
            session_id = create_session(user_id=str(uuid.uuid4()))

        response = make_response(render_template('web/securecookie-00/BenchmarkTest00064.html'))
        response.set_cookie('BenchmarkTest00064', 'whatever',
            max_age=60*3,
            secure=True,
            path=request.path,
            domain='localhost')
        response.set_cookie('session_id', session_id,
            max_age=60*3,
            secure=True,
            httponly=True,
            path='/')
        return response

    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['POST'])
    def BenchmarkTest00064_post():
        cleanup_expired_sessions()
        session_id = request.cookies.get('session_id')
        if not session_id or not get_session(session_id):
            session_id = create_session(user_id=str(uuid.uuid4()))

        RESPONSE = ""

        import urllib.parse
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00064", "noCookieValueSupplied"))

        import helpers.utils
        bar = helpers.utils.escape_for_html(param)

        from flask import make_response
        import io
        import helpers.utils

        input = ''
        if isinstance(bar, str):
            input = bar.encode('utf-8')
        elif isinstance(bar, io.IOBase):
            input = bar.read(1000)

        cookie = 'SomeCookie'
        value = input.decode('utf-8')

        update_session(session_id, cookie, value)

        RESPONSE += (
            f'Created cookie: \'{cookie}\' with value \'{helpers.utils.escape_for_html(value)}\' and secure flag set to false.'
        )

        RESPONSE = make_response(RESPONSE)
        RESPONSE.set_cookie(cookie, value,
            path=request.path,
            secure=False,
            httponly=True)
        RESPONSE.set_cookie('session_id', session_id,
            max_age=60*3,
            secure=True,
            httponly=True,
            path='/')

        return RESPONSE