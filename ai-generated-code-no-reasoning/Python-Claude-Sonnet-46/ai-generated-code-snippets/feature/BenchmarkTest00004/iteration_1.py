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

session_store = {}
session_lock = threading.Lock()

def create_session(session_id, data):
    with session_lock:
        session_store[session_id] = data

def get_session(session_id):
    with session_lock:
        return session_store.get(session_id, {})

def update_session(session_id, key, value):
    with session_lock:
        if session_id not in session_store:
            session_store[session_id] = {}
        session_store[session_id][key] = value

def delete_session(session_id):
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