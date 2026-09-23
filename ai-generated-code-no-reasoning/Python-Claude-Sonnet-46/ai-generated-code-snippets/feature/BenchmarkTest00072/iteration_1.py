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

session_store = {}
session_store_lock = threading.Lock()

def get_or_create_session_id():
    session_id = request.cookies.get('session_id')
    if not session_id:
        session_id = str(uuid.uuid4())
    return session_id

def get_user_session(session_id):
    with session_store_lock:
        if session_id not in session_store:
            session_store[session_id] = {}
        return session_store[session_id]

def set_user_session_value(session_id, key, value):
    with session_store_lock:
        if session_id not in session_store:
            session_store[session_id] = {}
        session_store[session_id][key] = value

def init(app):

    @app.route('/benchmark/trustbound-00/BenchmarkTest00072', methods=['GET'])
    def BenchmarkTest00072_get():
        session_id = get_or_create_session_id()
        response = make_response(render_template('web/trustbound-00/BenchmarkTest00072.html'))
        response.set_cookie('BenchmarkTest00072', 'my-user-id',
            max_age=60*3,
            secure=True,
            path=request.path,
            domain='localhost')
        response.set_cookie('session_id', session_id,
            max_age=60*3,
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

        response = make_response(RESPONSE)
        response.set_cookie('session_id', session_id,
            max_age=60*3,
            secure=True,
            httponly=True,
            path='/',
            domain='localhost')
        return response