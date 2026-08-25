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
import json
import sqlite3
import os

class FileStorage:
    def __init__(self, filepath='session.json'):
        self.filepath = filepath
        if not os.path.exists(self.filepath):
            with open(self.filepath, 'w') as f:
                json.dump({}, f)
    def __contains__(self, key):
        with open(self.filepath, 'r') as f:
            data = json.load(f)
        return key in data
    def __getitem__(self, key):
        with open(self.filepath, 'r') as f:
            data = json.load(f)
        return data[key]
    def __setitem__(self, key, value):
        with open(self.filepath, 'r') as f:
            data = json.load(f)
        data[key] = value
        with open(self.filepath, 'w') as f:
            json.dump(data, f)

class DBStorage:
    def __init__(self, dbpath='sessions.db'):
        self.dbpath = dbpath
        conn = sqlite3.connect(self.dbpath)
        conn.execute('CREATE TABLE IF NOT EXISTS sessions (key TEXT PRIMARY KEY, value TEXT)')
        conn.commit()
        conn.close()
    def __contains__(self, key):
        conn = sqlite3.connect(self.dbpath)
        cur = conn.execute('SELECT value FROM sessions WHERE key=?', (key,))
        result = cur.fetchone() is not None
        conn.close()
        return result
    def __getitem__(self, key):
        conn = sqlite3.connect(self.dbpath)
        cur = conn.execute('SELECT value FROM sessions WHERE key=?', (key,))
        value = cur.fetchone()[0]
        conn.close()
        return value
    def __setitem__(self, key, value):
        conn = sqlite3.connect(self.dbpath)
        conn.execute('INSERT OR REPLACE INTO sessions (key, value) VALUES (?, ?)', (key, value))
        conn.commit()
        conn.close()

STORAGE_TYPE = 'file'
if STORAGE_TYPE == 'file':
    mysession = FileStorage()
elif STORAGE_TYPE == 'db':
    mysession = DBStorage()
else:
    from helpers.utils import mysession

def init(app):

	@app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET'])
	def BenchmarkTest00025_get():
		response = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
		response.set_cookie('BenchmarkTest00025', 'whatever',
			max_age=60*3,
			secure=True,
			path=request.path,
			domain='localhost')
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
			RESPONSE += (
				f'{user} has been remembered with cookie: '
				f'{cookie} whose value is: {mysession[cookie]}<br/>'
			)

		return RESPONSE