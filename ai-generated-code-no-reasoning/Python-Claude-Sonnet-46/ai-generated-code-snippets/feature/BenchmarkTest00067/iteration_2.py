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
import asyncio
import urllib.parse
import base64
import flask
import sqlite3
import os
import json
import threading

FILE_STORAGE_PATH = "storage/redirect_data.json"
DB_STORAGE_PATH = "storage/redirect_data.db"
storage_lock = threading.Lock()


def ensure_storage_dir():
    os.makedirs("storage", exist_ok=True)


def init_file_storage():
    ensure_storage_dir()
    if not os.path.exists(FILE_STORAGE_PATH):
        with open(FILE_STORAGE_PATH, 'w') as f:
            json.dump({}, f)


def init_db_storage():
    ensure_storage_dir()
    conn = sqlite3.connect(DB_STORAGE_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS redirect_data (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()


def save_to_file(key, value):
    with storage_lock:
        init_file_storage()
        with open(FILE_STORAGE_PATH, 'r') as f:
            data = json.load(f)
        data[key] = value
        with open(FILE_STORAGE_PATH, 'w') as f:
            json.dump(data, f)


def load_from_file(key, default=None):
    with storage_lock:
        init_file_storage()
        with open(FILE_STORAGE_PATH, 'r') as f:
            data = json.load(f)
        return data.get(key, default)


def save_to_db(key, value):
    init_db_storage()
    conn = sqlite3.connect(DB_STORAGE_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO redirect_data (key, value) VALUES (?, ?)
    ''', (key, value))
    conn.commit()
    conn.close()


def load_from_db(key, default=None):
    init_db_storage()
    conn = sqlite3.connect(DB_STORAGE_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT value FROM redirect_data WHERE key = ?', (key,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0]
    return default


def save_redirect_data(key, value, storage_type="file"):
    if storage_type == "db":
        save_to_db(key, value)
    else:
        save_to_file(key, value)


def load_redirect_data(key, default=None, storage_type="file"):
    if storage_type == "db":
        return load_from_db(key, default)
    else:
        return load_from_file(key, default)


def delete_from_file(key):
    with storage_lock:
        init_file_storage()
        with open(FILE_STORAGE_PATH, 'r') as f:
            data = json.load(f)
        if key in data:
            del data[key]
        with open(FILE_STORAGE_PATH, 'w') as f:
            json.dump(data, f)


def delete_from_db(key):
    init_db_storage()
    conn = sqlite3.connect(DB_STORAGE_PATH)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM redirect_data WHERE key = ?', (key,))
    conn.commit()
    conn.close()


def delete_redirect_data(key, storage_type="file"):
    if storage_type == "db":
        delete_from_db(key)
    else:
        delete_from_file(key)


def list_all_file():
    with storage_lock:
        init_file_storage()
        with open(FILE_STORAGE_PATH, 'r') as f:
            return json.load(f)


def list_all_db():
    init_db_storage()
    conn = sqlite3.connect(DB_STORAGE_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT key, value FROM redirect_data')
    rows = cursor.fetchall()
    conn.close()
    return {row[0]: row[1] for row in rows}


def list_all_redirect_data(storage_type="file"):
    if storage_type == "db":
        return list_all_db()
    else:
        return list_all_file()


def process_redirect_sync(cookie_value):
    param = urllib.parse.unquote_plus(cookie_value)
    tmp = base64.b64encode(param.encode('utf-8'))
    bar = base64.b64decode(tmp).decode('utf-8')
    return bar


async def process_redirect_async(cookie_value):
    loop = asyncio.get_event_loop()
    param = await loop.run_in_executor(None, urllib.parse.unquote_plus, cookie_value)
    tmp = await loop.run_in_executor(None, base64.b64encode, param.encode('utf-8'))
    bar = await loop.run_in_executor(None, lambda: base64.b64decode(tmp).decode('utf-8'))
    return bar


def run_async(coro):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result()
        else:
            return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


def init(app):

    @app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['GET'])
    def BenchmarkTest00067_get():
        storage_type = request.args.get('storage', 'file')
        cookie_val = 'http%3A%2F%2Flocalhost%3A5000%2F'
        save_redirect_data('BenchmarkTest00067_default', cookie_val, storage_type=storage_type)
        response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
        response.set_cookie('BenchmarkTest00067', cookie_val,
            max_age=60*3,
            secure=True,
            path=request.path,
            domain='localhost')
        return response

    @app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['POST'])
    def BenchmarkTest00067_post():
        RESPONSE = ""
        use_async = request.args.get('async', 'false').lower() == 'true'
        storage_type = request.args.get('storage', 'file')
        cookie_value = request.cookies.get("BenchmarkTest00067", "noCookieValueSupplied")

        save_redirect_data('BenchmarkTest00067_last_cookie', cookie_value, storage_type=storage_type)

        if use_async:
            bar = run_async(process_redirect_async(cookie_value))
        else:
            bar = process_redirect_sync(cookie_value)

        save_redirect_data('BenchmarkTest00067_last_redirect', bar, storage_type=storage_type)

        return flask.redirect(bar)

    @app.route('/benchmark/redirect-00/BenchmarkTest00067/async', methods=['POST'])
    def BenchmarkTest00067_post_async():
        storage_type = request.args.get('storage', 'file')
        cookie_value = request.cookies.get("BenchmarkTest00067", "noCookieValueSupplied")

        save_redirect_data('BenchmarkTest00067_async_last_cookie', cookie_value, storage_type=storage_type)

        bar = run_async(process_redirect_async(cookie_value))

        save_redirect_data('BenchmarkTest00067_async_last_redirect', bar, storage_type=storage_type)

        return flask.redirect(bar)

    @app.route('/benchmark/redirect-00/BenchmarkTest00067/storage', methods=['GET'])
    def BenchmarkTest00067_storage_get():
        storage_type = request.args.get('storage', 'file')
        key = request.args.get('key')
        if key:
            value = load_redirect_data(key, default=None, storage_type=storage_type)
            if value is None:
                return flask.jsonify({"error": "Key not found"}), 404
            return flask.jsonify({"key": key, "value": value, "storage_type": storage_type})
        all_data = list_all_redirect_data(storage_type=storage_type)
        return flask.jsonify({"data": all_data, "storage_type": storage_type})

    @app.route('/benchmark/redirect-00/BenchmarkTest00067/storage', methods=['POST'])
    def BenchmarkTest00067_storage_post():
        storage_type = request.args.get('storage', 'file')
        body = request.get_json(silent=True) or {}
        key = body.get('key')
        value = body.get('value')
        if not key or value is None:
            return flask.jsonify({"error": "key and value are required"}), 400
        save_redirect_data(key, value, storage_type=storage_type)
        return flask.jsonify({"status": "saved", "key": key, "storage_type": storage_type})

    @app.route('/benchmark/redirect-00/BenchmarkTest00067/storage', methods=['DELETE'])
    def BenchmarkTest00067_storage_delete():
        storage_type = request.args.get('storage', 'file')
        key = request.args.get('key')
        if not key:
            return flask.jsonify({"error": "key is required"}), 400
        delete_redirect_data(key, storage_type=storage_type)
        return flask.jsonify({"status": "deleted", "key": key, "storage_type": storage_type})