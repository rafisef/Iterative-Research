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
import os
import json
import sqlite3

session_store = {}
session_store_lock = threading.Lock()

STORAGE_BACKEND = os.environ.get('SESSION_STORAGE_BACKEND', 'memory')
FILE_STORAGE_PATH = os.environ.get('SESSION_FILE_STORAGE_PATH', '/tmp/sessions')
DB_STORAGE_PATH = os.environ.get('SESSION_DB_STORAGE_PATH', '/tmp/sessions.db')

_db_lock = threading.Lock()


def _init_file_storage():
    os.makedirs(FILE_STORAGE_PATH, exist_ok=True)


def _init_db_storage():
    with _db_lock:
        conn = sqlite3.connect(DB_STORAGE_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at REAL NOT NULL,
                data TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()


def _file_path(session_id):
    return os.path.join(FILE_STORAGE_PATH, f"{session_id}.json")


def create_session(user_id):
    session_id = str(uuid.uuid4())
    session_data = {
        'user_id': user_id,
        'created_at': time.time(),
        'data': {}
    }

    if STORAGE_BACKEND == 'file':
        _init_file_storage()
        with open(_file_path(session_id), 'w') as f:
            json.dump(session_data, f)
    elif STORAGE_BACKEND == 'database':
        _init_db_storage()
        with _db_lock:
            conn = sqlite3.connect(DB_STORAGE_PATH)
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO sessions (session_id, user_id, created_at, data) VALUES (?, ?, ?, ?)',
                (session_id, user_id, session_data['created_at'], json.dumps(session_data['data']))
            )
            conn.commit()
            conn.close()
    else:
        with session_store_lock:
            session_store[session_id] = session_data

    return session_id


def get_session(session_id):
    if STORAGE_BACKEND == 'file':
        _init_file_storage()
        path = _file_path(session_id)
        if os.path.exists(path):
            with open(path, 'r') as f:
                return json.load(f)
        return None
    elif STORAGE_BACKEND == 'database':
        _init_db_storage()
        with _db_lock:
            conn = sqlite3.connect(DB_STORAGE_PATH)
            cursor = conn.cursor()
            cursor.execute(
                'SELECT session_id, user_id, created_at, data FROM sessions WHERE session_id = ?',
                (session_id,)
            )
            row = cursor.fetchone()
            conn.close()
        if row:
            return {
                'user_id': row[1],
                'created_at': row[2],
                'data': json.loads(row[3])
            }
        return None
    else:
        with session_store_lock:
            return session_store.get(session_id)


def update_session(session_id, key, value):
    if STORAGE_BACKEND == 'file':
        _init_file_storage()
        path = _file_path(session_id)
        if os.path.exists(path):
            with open(path, 'r') as f:
                session_data = json.load(f)
            session_data['data'][key] = value
            with open(path, 'w') as f:
                json.dump(session_data, f)
            return True
        return False
    elif STORAGE_BACKEND == 'database':
        _init_db_storage()
        with _db_lock:
            conn = sqlite3.connect(DB_STORAGE_PATH)
            cursor = conn.cursor()
            cursor.execute(
                'SELECT data FROM sessions WHERE session_id = ?',
                (session_id,)
            )
            row = cursor.fetchone()
            if row:
                data = json.loads(row[0])
                data[key] = value
                cursor.execute(
                    'UPDATE sessions SET data = ? WHERE session_id = ?',
                    (json.dumps(data), session_id)
                )
                conn.commit()
                conn.close()
                return True
            conn.close()
        return False
    else:
        with session_store_lock:
            if session_id in session_store:
                session_store[session_id]['data'][key] = value
                return True
            return False


def delete_session(session_id):
    if STORAGE_BACKEND == 'file':
        _init_file_storage()
        path = _file_path(session_id)
        if os.path.exists(path):
            os.remove(path)
            return True
        return False
    elif STORAGE_BACKEND == 'database':
        _init_db_storage()
        with _db_lock:
            conn = sqlite3.connect(DB_STORAGE_PATH)
            cursor = conn.cursor()
            cursor.execute(
                'DELETE FROM sessions WHERE session_id = ?',
                (session_id,)
            )
            deleted = cursor.rowcount > 0
            conn.commit()
            conn.close()
        return deleted
    else:
        with session_store_lock:
            if session_id in session_store:
                del session_store[session_id]
                return True
            return False


def cleanup_expired_sessions(max_age=180):
    current_time = time.time()

    if STORAGE_BACKEND == 'file':
        _init_file_storage()
        for filename in os.listdir(FILE_STORAGE_PATH):
            if filename.endswith('.json'):
                path = os.path.join(FILE_STORAGE_PATH, filename)
                try:
                    with open(path, 'r') as f:
                        session_data = json.load(f)
                    if current_time - session_data.get('created_at', 0) > max_age:
                        os.remove(path)
                except (json.JSONDecodeError, KeyError, OSError):
                    pass
    elif STORAGE_BACKEND == 'database':
        _init_db_storage()
        cutoff = current_time - max_age
        with _db_lock:
            conn = sqlite3.connect(DB_STORAGE_PATH)
            cursor = conn.cursor()
            cursor.execute(
                'DELETE FROM sessions WHERE created_at < ?',
                (cutoff,)
            )
            conn.commit()
            conn.close()
    else:
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