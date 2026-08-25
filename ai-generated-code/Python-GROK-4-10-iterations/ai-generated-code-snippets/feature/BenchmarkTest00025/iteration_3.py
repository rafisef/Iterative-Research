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
import os

STORAGE_TYPE = os.getenv('STORAGE_TYPE', 'file')

if STORAGE_TYPE == 'file':
    import json
    SESSION_FILE = os.getenv('SESSION_FILE', '/tmp/mysession.json')
    try:
        with open(SESSION_FILE, 'r') as f:
            mysession = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        mysession = {}
    def _save_session():
        with open(SESSION_FILE, 'w') as f:
            json.dump(mysession, f)
elif STORAGE_TYPE == 'db':
    import sqlite3
    DB_PATH = os.getenv('DB_PATH', '/tmp/mysession.db')
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute('CREATE TABLE IF NOT EXISTS sessions (key TEXT PRIMARY KEY, value TEXT)')
    conn.commit()
    mysession = {}
    def _load_db():
        cursor = conn.cursor()
        cursor.execute('SELECT key, value FROM sessions')
        for key, value in cursor.fetchall():
            mysession[key] = value
    _load_db()
    def _save_session():
        cursor = conn.cursor()
        for key, value in mysession.items():
            cursor.execute('INSERT OR REPLACE INTO sessions (key, value) VALUES (?, ?)', (key, value))
        conn.commit()
else:
    from helpers.utils import mysession
    def _save_session():
        pass

def init(app):

	@app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET'])
	def BenchmarkTest00025_get():
		response = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
		response.set_cookie('BenchmarkTest00025', 'whatever',
			max_age=60*3,
			secure=True,
			path=request.path,
			domain=os.getenv('BENCHMARK_DOMAIN', 'localhost'))
		return response
		return BenchmarkTest00025_post()

	@app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['POST'])
	def BenchmarkTest00025_post():
		RESPONSE = ""

		import urllib.parse
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00025", "noCookieValueSupplied"))

		superstring = f'90583{param}abcd'
		bar = superstring[len('90583'):len(superstring)-5]

		import random
		from helpers.utils import mysession

		num = 'BenchmarkTest00025'[13:]
		user = f'Nancy{num}'
		cookie = f'rememberMe{num}'
		value = str(random.normalvariate())[2:]

		if cookie in mysession and request.cookies.get(cookie) == mysession[cookie]:
			RESPONSE += (
				f'Welcome back: {user}<br/>'
			)
		else:
			mysession[cookie] = value
			_save_session()
			RESPONSE += (
				f'{user} has been remembered with cookie: '
				f'{cookie} whose value is: {mysession[cookie]}<br/>'
			)

		return RESPONSE