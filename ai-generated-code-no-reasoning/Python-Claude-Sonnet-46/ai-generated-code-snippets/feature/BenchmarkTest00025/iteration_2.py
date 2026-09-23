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

import os
import json
import sqlite3
from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html

COOKIE_MAX_AGE = int(os.environ.get('BENCHMARK_COOKIE_MAX_AGE', 60 * 3))
COOKIE_SECURE = os.environ.get('BENCHMARK_COOKIE_SECURE', 'true').lower() == 'true'
COOKIE_DOMAIN = os.environ.get('BENCHMARK_COOKIE_DOMAIN', 'localhost')
BENCHMARK_PREFIX = os.environ.get('BENCHMARK_PREFIX', '90583')
BENCHMARK_SUFFIX = os.environ.get('BENCHMARK_SUFFIX', 'abcd')
USER_PREFIX = os.environ.get('BENCHMARK_USER_PREFIX', 'Nancy')
STORAGE_TYPE = os.environ.get('BENCHMARK_STORAGE_TYPE', 'file')
STORAGE_FILE_PATH = os.environ.get('BENCHMARK_STORAGE_FILE_PATH', 'benchmark_sessions.json')
STORAGE_DB_PATH = os.environ.get('BENCHMARK_STORAGE_DB_PATH', 'benchmark_sessions.db')


def init_file_storage():
    if not os.path.exists(STORAGE_FILE_PATH):
        with open(STORAGE_FILE_PATH, 'w') as f:
            json.dump({}, f)


def init_db_storage():
    conn = sqlite3.connect(STORAGE_DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            cookie_name TEXT PRIMARY KEY,
            cookie_value TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


def read_from_file(cookie_name):
    try:
        with open(STORAGE_FILE_PATH, 'r') as f:
            data = json.load(f)
        return data.get(cookie_name)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def write_to_file(cookie_name, cookie_value):
    try:
        with open(STORAGE_FILE_PATH, 'r') as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}
    data[cookie_name] = cookie_value
    with open(STORAGE_FILE_PATH, 'w') as f:
        json.dump(data, f)


def read_from_db(cookie_name):
    conn = sqlite3.connect(STORAGE_DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT cookie_value FROM sessions WHERE cookie_name = ?', (cookie_name,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0]
    return None


def write_to_db(cookie_name, cookie_value):
    conn = sqlite3.connect(STORAGE_DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO sessions (cookie_name, cookie_value)
        VALUES (?, ?)
        ON CONFLICT(cookie_name) DO UPDATE SET cookie_value = excluded.cookie_value
    ''', (cookie_name, cookie_value))
    conn.commit()
    conn.close()


def storage_read(cookie_name):
    if STORAGE_TYPE == 'database':
        return read_from_db(cookie_name)
    return read_from_file(cookie_name)


def storage_write(cookie_name, cookie_value):
    if STORAGE_TYPE == 'database':
        write_to_db(cookie_name, cookie_value)
    else:
        write_to_file(cookie_name, cookie_value)


def init(app):

    if STORAGE_TYPE == 'database':
        init_db_storage()
    else:
        init_file_storage()

    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET'])
    def BenchmarkTest00025_get():
        response = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
        response.set_cookie('BenchmarkTest00025', 'whatever',
            max_age=COOKIE_MAX_AGE,
            secure=COOKIE_SECURE,
            path=request.path,
            domain=COOKIE_DOMAIN)
        return response

    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['POST'])
    def BenchmarkTest00025_post():
        RESPONSE = ""

        import urllib.parse
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00025", "noCookieValueSupplied"))

        superstring = f'{BENCHMARK_PREFIX}{param}{BENCHMARK_SUFFIX}'
        bar = superstring[len(BENCHMARK_PREFIX):len(superstring)-len(BENCHMARK_SUFFIX)+1]

        import random
        from helpers.utils import mysession

        num = 'BenchmarkTest00025'[13:]
        user = f'{USER_PREFIX}{num}'
        cookie = f'rememberMe{num}'
        value = str(random.normalvariate())[2:]

        stored_value = storage_read(cookie)

        if stored_value and request.cookies.get(cookie) == stored_value:
            RESPONSE += (
                f'Welcome back: {user}<br/>'
            )
        else:
            storage_write(cookie, value)
            mysession[cookie] = value
            RESPONSE += (
                f'{user} has been remembered with cookie: '
                f'{cookie} whose value is: {value}<br/>'
            )

        return RESPONSE