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
import helpers.db_sqlite
import json
import os

class Storage:
    def save(self, data):
        raise NotImplementedError

    def retrieve(self, key):
        raise NotImplementedError

class FileStorage(Storage):
    def __init__(self, file_path):
        self.file_path = file_path

    def save(self, data):
        with open(self.file_path, 'w') as f:
            json.dump(data, f)

    def retrieve(self, key):
        if not os.path.exists(self.file_path):
            return None
        with open(self.file_path, 'r') as f:
            data = json.load(f)
            return data.get(key, None)

class DatabaseStorage(Storage):
    def save(self, data):
        con = helpers.db_sqlite.get_connection()
        cur = con.cursor()
        cur.execute("INSERT INTO storage (key, value) VALUES (?, ?)", (data['key'], data['value']))
        con.commit()
        con.close()

    def retrieve(self, key):
        con = helpers.db_sqlite.get_connection()
        cur = con.cursor()
        cur.execute("SELECT value FROM storage WHERE key = ?", (key,))
        result = cur.fetchone()
        con.close()
        return result[0] if result else None

def init(app, storage_option='file', storage_path='storage.json'):
    if storage_option == 'file':
        storage = FileStorage(storage_path)
    elif storage_option == 'database':
        storage = DatabaseStorage()
    else:
        raise ValueError("Invalid storage option")

    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['GET'])
    def BenchmarkTest00011_get():
        response = make_response(render_template('web/sqli-00/BenchmarkTest00011.html'))
        response.set_cookie('BenchmarkTest00011', 'bar',
            max_age=60*3,
            secure=True,
            path=request.path,
            domain='localhost')
        return response
        return BenchmarkTest00011_post()

    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['POST'])
    def BenchmarkTest00011_post():
        RESPONSE = ""

        import urllib.parse
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00011", "noCookieValueSupplied"))

        bar = "This should never happen"
        if 'should' in bar:
            bar = param

        sql = f'SELECT username from USERS where password = ?'
        con = helpers.db_sqlite.get_connection()
        cur = con.cursor()
        cur.execute(sql, (bar,))
        RESPONSE += (
            helpers.db_sqlite.results(cur, sql)
        )
        con.close()

        return RESPONSE