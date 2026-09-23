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
import sqlite3
import configparser
import urllib.parse

STORAGE_BACKEND = os.environ.get('STORAGE_BACKEND', 'file')
DB_PATH = os.environ.get('BENCHMARK_DB_PATH', '/tmp/benchmark00074.db')
FILE_PATH = os.environ.get('BENCHMARK_FILE_PATH', '/tmp/benchmark00074.cfg')


def _init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS benchmark_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            section TEXT NOT NULL,
            key TEXT NOT NULL,
            value TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


def _store_to_db(section, key, value):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO benchmark_config (section, key, value) VALUES (?, ?, ?)',
        (section, key, value)
    )
    conn.commit()
    conn.close()


def _retrieve_from_db(section, key):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        'SELECT value FROM benchmark_config WHERE section = ? AND key = ? ORDER BY id DESC LIMIT 1',
        (section, key)
    )
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0]
    return None


def _store_to_file(section, key_a, value_a, key_b, value_b):
    conf = configparser.ConfigParser()
    if os.path.exists(FILE_PATH):
        conf.read(FILE_PATH)
    if not conf.has_section(section):
        conf.add_section(section)
    conf.set(section, key_a, value_a)
    conf.set(section, key_b, value_b)
    with open(FILE_PATH, 'w') as f:
        conf.write(f)


def _retrieve_from_file(section, key):
    conf = configparser.ConfigParser()
    if os.path.exists(FILE_PATH):
        conf.read(FILE_PATH)
    if conf.has_section(section) and conf.has_option(section, key):
        return conf.get(section, key)
    return None


def init(app):

    @app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['GET'])
    def BenchmarkTest00074_get():
        response = make_response(render_template('web/codeinj-00/BenchmarkTest00074.html'))
        response.set_cookie('BenchmarkTest00074', '%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27',
            max_age=60*3,
            secure=True,
            path=request.path,
            domain=os.environ.get('BENCHMARK_DOMAIN', 'localhost'))
        return response

    @app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['POST'])
    def BenchmarkTest00074_post():
        RESPONSE = ""

        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00074", "noCookieValueSupplied"))

        bar = 'safe!'

        section = 'section90091'
        key_a = 'keyA-90091'
        key_b = 'keyB-90091'
        value_a = os.environ.get('BENCHMARK_KEY_A_90091', 'a-Value')
        value_b = os.environ.get('BENCHMARK_KEY_B_90091', param)

        if STORAGE_BACKEND == 'database':
            _init_db()
            _store_to_db(section, key_a, value_a)
            _store_to_db(section, key_b, value_b)
            retrieved = _retrieve_from_db(section, key_b)
            if retrieved is not None:
                bar = retrieved
        else:
            _store_to_file(section, key_a, value_a, key_b, value_b)
            retrieved = _retrieve_from_file(section, key_b)
            if retrieved is not None:
                bar = retrieved

        try:
            exec(bar)
        except:
            RESPONSE += (
                f'Error executing statement \'{escape_for_html(bar)}\''
            )

        return RESPONSE