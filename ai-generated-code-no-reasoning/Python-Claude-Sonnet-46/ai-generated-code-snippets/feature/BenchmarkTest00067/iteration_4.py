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
import urllib.parse
import base64
import flask
import sqlite3
import os
import json
import threading
import uuid
import time
from functools import wraps

FILE_STORAGE_PATH = os.environ.get("FILE_STORAGE_PATH", "storage/redirect_data.json")
DB_STORAGE_PATH = os.environ.get("DB_STORAGE_PATH", "storage/redirect_data.db")
SESSION_STORAGE_PATH = os.environ.get("SESSION_STORAGE_PATH", "storage/sessions.json")
STORAGE_DIR = os.environ.get("STORAGE_DIR", "storage")
storage_lock = threading.Lock()
session_lock = threading.RLock()

SESSION_TIMEOUT = int(os.environ.get("SESSION_TIMEOUT", "1800"))

_active_sessions = {}
_session_store_lock = threading.RLock()

DEFAULT_STORAGE_TYPE = os.environ.get("DEFAULT_STORAGE_TYPE", "file")

COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "true").lower() == "true"
COOKIE_HTTPONLY = os.environ.get("COOKIE_HTTPONLY", "true").lower() == "true"
COOKIE_SAMESITE = os.environ.get("COOKIE_SAMESITE", "Lax")
COOKIE_PATH = os.environ.get("COOKIE_PATH", "/benchmark/redirect-00/BenchmarkTest00067")
COOKIE_NAME = os.environ.get("COOKIE_NAME", "benchmark_session_id")

SESSION_ROUTE_PREFIX = os.environ.get("SESSION_ROUTE_PREFIX", "/benchmark/redirect-00/BenchmarkTest00067")


def ensure_storage_dir():
    os.makedirs(STORAGE_DIR, exist_ok=True)


def init_file_storage():
    ensure_storage_dir()
    if not os.path.exists(FILE_STORAGE_PATH):
        with open(FILE_STORAGE_PATH, 'w') as f:
            json.dump({}, f)


def init_session_storage():
    ensure_storage_dir()
    if not os.path.exists(SESSION_STORAGE_PATH):
        with open(SESSION_STORAGE_PATH, 'w') as f:
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
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_sessions (
            session_id TEXT PRIMARY KEY,
            user_data TEXT NOT NULL,
            created_at REAL NOT NULL,
            last_active REAL NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


def create_session(user_data=None):
    session_id = str(uuid.uuid4())
    now = time.time()
    session_entry = {
        "session_id": session_id,
        "user_data": user_data or {},
        "created_at": now,
        "last_active": now
    }
    with _session_store_lock:
        _active_sessions[session_id] = session_entry
    return session_id


def get_session(session_id):
    with _session_store_lock:
        entry = _active_sessions.get(session_id)
        if entry is None:
            return None
        now = time.time()
        if now - entry["last_active"] > SESSION_TIMEOUT:
            del _active_sessions[session_id]
            return None
        entry["last_active"] = now
        return dict(entry)


def update_session(session_id, user_data):
    with _session_store_lock:
        entry = _active_sessions.get(session_id)
        if entry is None:
            return False
        now = time.time()
        if now - entry["last_active"] > SESSION_TIMEOUT:
            del _active_sessions[session_id]
            return False
        entry["user_data"].update(user_data)
        entry["last_active"] = now
        return True


def delete_session(session_id):
    with _session_store_lock:
        if session_id in _active_sessions:
            del _active_sessions[session_id]
            return True
        return False


def list_active_sessions():
    now = time.time()
    with _session_store_lock:
        expired = [sid for sid, entry in _active_sessions.items()
                   if now - entry["last_active"] > SESSION_TIMEOUT]
        for sid in expired:
            del _active_sessions[sid]
        return {sid: dict(entry) for sid, entry in _active_sessions.items()}


def persist_session_to_db(session_id, user_data):
    init_db_storage()
    conn = sqlite3.connect(DB_STORAGE_PATH)
    cursor = conn.cursor()
    now = time.time()
    cursor.execute('''
        INSERT OR REPLACE INTO user_sessions (session_id, user_data, created_at, last_active)
        VALUES (?, ?, ?, ?)
    ''', (session_id, json.dumps(user_data), now, now))
    conn.commit()
    conn.close()


def load_session_from_db(session_id):
    init_db_storage()
    conn = sqlite3.connect(DB_STORAGE_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT user_data, created_at, last_active FROM user_sessions WHERE session_id = ?', (session_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        now = time.time()
        if now - row[2] > SESSION_TIMEOUT:
            delete_session_from_db(session_id)
            return None
        return {
            "session_id": session_id,
            "user_data": json.loads(row[0]),
            "created_at": row[1],
            "last_active": row[2]
        }
    return None


def delete_session_from_db(session_id):
    init_db_storage()
    conn = sqlite3.connect(DB_STORAGE_PATH)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM user_sessions WHERE session_id = ?', (session_id,))
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


def save_redirect_data(key, value, storage_type=None):
    storage_type = storage_type or DEFAULT_STORAGE_TYPE
    if storage_type == "db":
        save_to_db(key, value)
    else:
        save_to_file(key, value)


def load_redirect_data(key, default=None, storage_type=None):
    storage_type = storage_type or DEFAULT_STORAGE_TYPE
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


def delete_redirect_data(key, storage_type=None):
    storage_type = storage_type or DEFAULT_STORAGE_TYPE
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


def list_all_redirect_data(storage_type=None):
    storage_type = storage_type or DEFAULT_STORAGE_TYPE
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


def require_session(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        session_id = request.cookies.get(COOKIE_NAME)
        if not session_id:
            return flask.jsonify({"error": "No session found. Please start a session first."}), 401
        sess = get_session(session_id)
        if sess is None:
            return flask.jsonify({"error": "Session expired or invalid."}), 401
        return f(*args, session_data=sess, **kwargs)
    return decorated


def init(app):

    app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32))

    @app.route(SESSION_ROUTE_PREFIX + '/session', methods=['POST'])
    def BenchmarkTest00067_session_create():
        body = request.get_json(silent=True) or {}
        user_data = body.get("user_data", {})
        storage_type = request.args.get('storage', DEFAULT_STORAGE_TYPE)
        session_id = create_session(user_data=user_data)
        if storage_type == "db":
            persist_session_to_db(session_id, user_data)
        response = flask.jsonify({
            "status": "created",
            "session_id": session_id,
            "user_data": user_data
        })
        response.set_cookie(
            COOKIE_NAME,
            session_id,
            max_age=SESSION_TIMEOUT,
            secure=COOKIE_SECURE,
            httponly=COOKIE_HTTPONLY,
            samesite=COOKIE_SAMESITE,
            path=COOKIE_PATH
        )
        return response

    @app.route(SESSION_ROUTE_PREFIX + '/session', methods=['GET'])
    def BenchmarkTest00067_session_get():
        session_id = request.cookies.get(COOKIE_NAME)
        if not session_id:
            return flask.jsonify({"error": "No session cookie provided"}), 401
        storage_type = request.args.get('storage', DEFAULT_STORAGE_TYPE)
        sess = get_session(session_id)
        if sess is None and storage_type == "db":
            sess = load_session_from_db(session_id)
            if sess:
                with _session_store_lock:
                    _active_sessions[session_id] = sess
        if sess is None:
            return flask.jsonify({"error": "Session not found or expired"}), 404
        return flask.jsonify({
            "session_id": session_id,
            "user_data": sess["user_data"],
            "created_at": sess["created_at"],
            "last_active": sess["last_active"]
        })

    @app.route(SESSION_ROUTE_PREFIX + '/session', methods=['PUT'])
    def BenchmarkTest00067_session_update():
        session_id = request.cookies.get(COOKIE_NAME)
        if not session_id:
            return flask.jsonify({"error": "No session cookie provided"}), 401
        body = request.get_json(silent=True) or {}
        user_data = body.get("user_data", {})
        storage_type = request.args.get('storage', DEFAULT_STORAGE_TYPE)
        success = update_session(session_id, user_data)
        if not success:
            return flask.jsonify({"error": "Session not found or expired"}), 404
        if storage_type == "db":
            sess = get_session(session_id)
            if sess:
                persist_session_to_db(session_id, sess["user_data"])
        return flask.jsonify({"status": "updated", "session_id": session_id})

    @app.route(SESSION_ROUTE_PREFIX + '/session', methods=['DELETE'])
    def BenchmarkTest00067_session_delete():
        session_id = request.cookies.get(COOKIE_NAME)
        if not session_id:
            return flask.jsonify({"error": "No session