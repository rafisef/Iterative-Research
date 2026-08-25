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
import asyncio
from collections import defaultdict
import threading
import json
import sqlite3
import os

AUTH_PROVIDERS = {
    'local': lambda creds: True,
    'oauth': lambda creds: 'access_token' in creds,
    'saml': lambda creds: creds.get('saml_response') is not None
}

class FileStorage:
    def __init__(self, filename='sessions.json'):
        self.filename = filename
        if not os.path.exists(filename):
            with open(filename, 'w') as f:
                json.dump({}, f)
    def load(self):
        with open(self.filename, 'r') as f:
            return json.load(f)
    def save(self, data):
        with open(self.filename, 'w') as f:
            json.dump(data, f)

class DatabaseStorage:
    def __init__(self, db_path='sessions.db'):
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute('CREATE TABLE IF NOT EXISTS sessions (user TEXT, sid TEXT)')
    def load(self):
        cursor = self.conn.execute('SELECT user, sid FROM sessions')
        data = defaultdict(list)
        for user, sid in cursor.fetchall():
            data[user].append(sid)
        return data
    def save(self, data):
        self.conn.execute('DELETE FROM sessions')
        for user, sids in data.items():
            for sid in sids:
                self.conn.execute('INSERT INTO sessions (user, sid) VALUES (?, ?)', (user, sid))
        self.conn.commit()

STORAGE = None
user_sessions = defaultdict(list)
session_lock = threading.Lock()

def set_storage(storage_type, **kwargs):
    global STORAGE, user_sessions
    if storage_type == 'file':
        STORAGE = FileStorage(**kwargs)
        user_sessions = STORAGE.load()
    elif storage_type == 'db':
        STORAGE = DatabaseStorage(**kwargs)
        user_sessions = STORAGE.load()

def authenticate(provider, credentials):
    if provider in AUTH_PROVIDERS:
        func = AUTH_PROVIDERS[provider]
        if asyncio.iscoroutinefunction(func):
            return asyncio.run(func(credentials))
        result = func(credentials)
        if result:
            with session_lock:
                user_sessions[credentials.get('user', 'anonymous')].append(session.get('sid'))
                if STORAGE:
                    STORAGE.save(user_sessions)
        return result
    return False

async def async_authenticate(provider, credentials):
    if provider in AUTH_PROVIDERS:
        func = AUTH_PROVIDERS[provider]
        if asyncio.iscoroutinefunction(func):
            return await func(credentials)
        result = func(credentials)
        if result:
            async with asyncio.Lock():
                user_sessions[credentials.get('user', 'anonymous')].append(session.get('sid'))
                if STORAGE:
                    STORAGE.save(user_sessions)
        return result
    return False

def init(app):

	@app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET'])
	def BenchmarkTest00064_get():
		response = make_response(render_template('web/securecookie-00/BenchmarkTest00064.html'))
		response.set_cookie('BenchmarkTest00064', 'whatever',
			max_age=60*3,
			secure=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['POST'])
	def BenchmarkTest00064_post():
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

		RESPONSE += (
			f'Created cookie: \'{cookie}\' with value \'{helpers.utils.escape_for_html(value)}\' and secure flag set to false.'
		)

		RESPONSE = make_response(RESPONSE)
		RESPONSE.set_cookie(cookie, value,
			path=request.path,
			secure=False,
			httponly=True)

		return RESPONSE

	@app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET'])
	async def async_BenchmarkTest00064_get():
		response = make_response(render_template('web/securecookie-00/BenchmarkTest00064.html'))
		response.set_cookie('BenchmarkTest00064', 'whatever',
			max_age=60*3,
			secure=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['POST'])
	async def async_BenchmarkTest00064_post():
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

		RESPONSE += (
			f'Created cookie: \'{cookie}\' with value \'{helpers.utils.escape_for_html(value)}\' and secure flag set to false.'
		)

		RESPONSE = make_response(RESPONSE)
		RESPONSE.set_cookie(cookie, value,
			path=request.path,
			secure=False,
			httponly=True)

		return RESPONSE