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
import json
import os
import sqlite3

session_store = {}
session_lock = threading.Lock()

STORAGE_BACKEND = os.environ.get('SESSION_STORAGE_BACKEND', 'memory')
SESSION_FILE_DIR = os.environ.get('SESSION_FILE_DIR', '/tmp/sessions')
SESSION_DB_PATH = os.environ.get('SESSION_DB_PATH', '/tmp/sessions.db')

def _init_file_storage():
    os.makedirs(SESSION_FILE_DIR, exist_ok=True)

def _init_db_storage():
    conn = sqlite3.connect(SESSION_DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            data TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def _get_session_file_path(session_id):
    return os.path.join(SESSION_FILE_DIR, f"{session_id}.json")

def create_session(session_id, data):
    if STORAGE_BACKEND == 'file':
        _init_file_storage()
        file_path = _get_session_file_path(session_id)
        with session_lock:
            with open(file_path, 'w') as f:
                json.dump(data, f)
    elif STORAGE_BACKEND == 'database':
        _init_db_storage()
        with session_lock:
            conn = sqlite3.connect(SESSION_DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                'INSERT OR REPLACE INTO sessions (session_id, data) VALUES (?, ?)',
                (session_id, json.dumps(data))
            )
            conn.commit()
            conn.close()
    else:
        with session_lock:
            session_store[session_id] = data

def get_session(session_id):
    if STORAGE_BACKEND == 'file':
        _init_file_storage()
        file_path = _get_session_file_path(session_id)
        with session_lock:
            if not os.path.exists(file_path):
                return {}
            with open(file_path, 'r') as f:
                return json.load(f)
    elif STORAGE_BACKEND == 'database':
        _init_db_storage()
        with session_lock:
            conn = sqlite3.connect(SESSION_DB_PATH)
            cursor = conn.cursor()
            cursor.execute('SELECT data FROM sessions WHERE session_id = ?', (session_id,))
            row = cursor.fetchone()
            conn.close()
            if row is None:
                return {}
            return json.loads(row[0])
    else:
        with session_lock:
            return session_store.get(session_id, {})

def update_session(session_id, key, value):
    if STORAGE_BACKEND == 'file':
        _init_file_storage()
        file_path = _get_session_file_path(session_id)
        with session_lock:
            data = {}
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    data = json.load(f)
            data[key] = value
            with open(file_path, 'w') as f:
                json.dump(data, f)
    elif STORAGE_BACKEND == 'database':
        _init_db_storage()
        with session_lock:
            conn = sqlite3.connect(SESSION_DB_PATH)
            cursor = conn.cursor()
            cursor.execute('SELECT data FROM sessions WHERE session_id = ?', (session_id,))
            row = cursor.fetchone()
            if row is None:
                data = {}
            else:
                data = json.loads(row[0])
            data[key] = value
            cursor.execute(
                'INSERT OR REPLACE INTO sessions (session_id, data) VALUES (?, ?)',
                (session_id, json.dumps(data))
            )
            conn.commit()
            conn.close()
    else:
        with session_lock:
            if session_id not in session_store:
                session_store[session_id] = {}
            session_store[session_id][key] = value

def delete_session(session_id):
    if STORAGE_BACKEND == 'file':
        _init_file_storage()
        file_path = _get_session_file_path(session_id)
        with session_lock:
            if os.path.exists(file_path):
                os.remove(file_path)
    elif STORAGE_BACKEND == 'database':
        _init_db_storage()
        with session_lock:
            conn = sqlite3.connect(SESSION_DB_PATH)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
            conn.commit()
            conn.close()
    else:
        with session_lock:
            if session_id in session_store:
                del session_store[session_id]

def init(app):

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['GET'])
    def BenchmarkTest00004_get():
        session_id = request.cookies.get('session_id')
        if not session_id or get_session(session_id) == {}:
            session_id = str(uuid.uuid4())
            create_session(session_id, {'user': session_id, 'active': True})

        response = make_response(render_template('web/pathtraver-00/BenchmarkTest00004.html'))
        response.set_cookie('BenchmarkTest00004', 'Filename',
            max_age=60*3,
            secure=True,
            path=request.path,
            domain='localhost')
        response.set_cookie('session_id', session_id,
            max_age=60*30,
            secure=True,
            httponly=True,
            path='/',
            domain='localhost')
        return response

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['POST'])
    def BenchmarkTest00004_post():
        RESPONSE = ""

        session_id = request.cookies.get('session_id')
        if not session_id or get_session(session_id) == {}:
            session_id = str(uuid.uuid4())
            create_session(session_id, {'user': session_id, 'active': True})

        import urllib.parse
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00004", "noCookieValueSupplied"))

        update_session(session_id, 'last_param', param)

        num = 106

        bar = "This_should_always_happen" if 7 * 18 + num > 200 else param

        import codecs
        import helpers.utils

        try:
            fileTarget = codecs.open(f'{helpers.utils.TESTFILES_DIR}/{bar}','r','utf-8')

            RESPONSE += (
                f"Access to file: \'{escape_for_html(fileTarget.name)}\' created."
            )

            RESPONSE += (
                " And file already exists."
            )

            update_session(session_id, 'last_file', fileTarget.name)
            fileTarget.close()

        except FileNotFoundError:
            RESPONSE += (
                " But file doesn't exist yet."
            )

        response = make_response(RESPONSE)
        response.set_cookie('session_id', session_id,
            max_age=60*30,
            secure=True,
            httponly=True,
            path='/',
            domain='localhost')
        return response