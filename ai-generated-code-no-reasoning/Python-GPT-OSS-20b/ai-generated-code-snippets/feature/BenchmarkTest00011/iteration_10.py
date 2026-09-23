import os
import json
import urllib.parse
import uuid
import sqlite3
import threading
import time
import asyncio
from flask import redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html
import helpers.db_sqlite

STORAGE_TYPE = os.getenv('STORAGE_TYPE', 'db')
FILE_PATH = os.getenv('FILE_PATH', 'users.json')
SESSION_DB_PATH = os.getenv('SESSION_DB_PATH', 'sessions.sqlite')
SESSION_FILE_PATH = os.getenv('SESSION_FILE_PATH', 'sessions.json')
SESSION_TIMEOUT = int(os.getenv('SESSION_TIMEOUT', 180))
lock = threading.Lock()
providers = {}

def register_provider(name, func):
    providers[name] = func

def default_provider_func(password):
    if STORAGE_TYPE == 'file':
        if not os.path.exists(FILE_PATH):
            return None
        with open(FILE_PATH, 'r') as f:
            data = json.load(f)
        return data.get('default', {}).get(password)
    else:
        sql = 'SELECT username FROM USERS WHERE password = ? AND provider = ?'
        con = helpers.db_sqlite.get_connection()
        cur = con.cursor()
        cur.execute(sql, (password, 'default'))
        row = cur.fetchone()
        con.close()
        return row[0] if row else None

def env_provider_func(password):
    env_user = os.getenv('ENV_AUTH_USER')
    env_pass = os.getenv('ENV_AUTH_PASS')
    if password == env_pass:
        return env_user
    return None

register_provider('default', default_provider_func)
register_provider('env', env_provider_func)

def get_user_by_password(password, provider='default'):
    return providers.get(provider, lambda p: None)(password)

def format_response(username):
    return f'Username: {escape_for_html(username)}' if username else 'No user found'

def init_session_store():
    if STORAGE_TYPE == 'db':
        con = sqlite3.connect(SESSION_DB_PATH, check_same_thread=False)
        cur = con.cursor()
        cur.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                data TEXT,
                created_at INTEGER,
                username TEXT
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS USERS (
                username TEXT,
                password TEXT,
                provider TEXT,
                PRIMARY KEY (username, provider)
            )
        ''')
        con.commit()
        con.close()
    else:
        if not os.path.exists(SESSION_FILE_PATH):
            with open(SESSION_FILE_PATH, 'w') as f:
                json.dump({}, f)

def _load_session_file():
    with open(SESSION_FILE_PATH, 'r') as f:
        return json.load(f)

def _write_session_file(data):
    with open(SESSION_FILE_PATH, 'w') as f:
        json.dump(data, f)

def get_session_data(session_id):
    if STORAGE_TYPE == 'db':
        with lock:
            con = sqlite3.connect(SESSION_DB_PATH, check_same_thread=False)
            cur = con.cursor()
            cur.execute('SELECT data, created_at, username FROM sessions WHERE session_id = ?', (session_id,))
            row = con.fetchone()
            con.close()
        if row and time.time() - row[1] < SESSION_TIMEOUT:
            return json.loads(row[0]), row[2]
    else:
        with lock:
            data = _load_session_file()
        session = data.get(session_id)
        if session and time.time() - session['created_at'] < SESSION_TIMEOUT:
            return session['data'], session['username']
    return {}, None

def set_session_data(session_id, data):
    username = data.get('username')
    if STORAGE_TYPE == 'db':
        with lock:
            con = sqlite3.connect(SESSION_DB_PATH, check_same_thread=False)
            cur = con.cursor()
            cur.execute('INSERT OR REPLACE INTO sessions (session_id, data, created_at, username) VALUES (?, ?, ?, ?)',
                        (session_id, json.dumps(data), int(time.time()), username))
            con.commit()
            con.close()
    else:
        with lock:
            sessions = _load_session_file()
            sessions[session_id] = {'data': data, 'created_at': int(time.time()), 'username': username}
            _write_session_file(sessions)

def get_user_sessions(username):
    if STORAGE_TYPE == 'db':
        with lock:
            con = sqlite3.connect(SESSION_DB_PATH, check_same_thread=False)
            cur = con.cursor()
            cur.execute('SELECT session_id FROM sessions WHERE username = ?', (username,))
            rows = con.fetchall()
            con.close()
        return [row[0] for row in rows]
    else:
        with lock:
            sessions = _load_session_file()
        return [sid for sid, sess in sessions.items() if sess.get('username') == username]

def delete_session(session_id):
    if STORAGE_TYPE == 'db':
        with lock:
            con = sqlite3.connect(SESSION_DB_PATH, check_same_thread=False)
            cur = con.cursor()
            cur.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
            con.commit()
            con.close()
    else:
        with lock:
            sessions = _load_session_file()
            sessions.pop(session_id, None)
            _write_session_file(sessions)

def cleanup_sessions():
    while True:
        time.sleep(SESSION_TIMEOUT)
        if STORAGE_TYPE == 'db':
            with lock:
                con = sqlite3.connect(SESSION_DB_PATH, check_same_thread=False)
                cur = con.cursor()
                cur.execute('DELETE FROM sessions WHERE ? - created_at > ?', (int(time.time()), SESSION_TIMEOUT))
                con.commit()
                con.close()
        else:
            with lock:
                sessions = _load_session_file()
                now = int(time.time())
                sessions = {sid: sess for sid, sess in sessions.items() if now - sess['created_at'] < SESSION_TIMEOUT}
                _write_session_file(sessions)

async def async_get_session_data(session_id):
    return await asyncio.to_thread(get_session_data, session_id)

async def async_set_session_data(session_id, data):
    await asyncio.to_thread(set_session_data, session_id, data)

async def async_get_user_sessions(username):
    return await asyncio.to_thread(get_user_sessions, username)

def init(app):
    app.secret_key = os.getenv('FLASK_SECRET_KEY', 'default-secret-key')
    init_session_store()
    threading.Thread(target=cleanup_sessions, daemon=True).start()

    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['GET'])
    async def BenchmarkTest00011_get():
        session_id = request.cookies.get('session_id')
        if not session_id:
            session_id = str(uuid.uuid4())
            await async_set_session_data(session_id, {})
        response = make_response(await asyncio.to_thread(render_template, 'web/sqli-00/BenchmarkTest00011.html'))
        response.set_cookie('session_id', session_id,
                            max_age=SESSION_TIMEOUT,
                            secure=True,
                            path=request.path,
                            domain='localhost',
                            httponly=True)
        return response

    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['POST'])
    async def BenchmarkTest00011_post():
        session_id = request.cookies.get('session_id')
        if not session_id:
            return 'Session not found', 400
        provider = request.args.get('provider', 'default')
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00011", "noCookieValueSupplied"))
        bar = "This should never happen"
        if 'should' in bar:
            bar = param
        username = get_user_by_password(bar, provider)
        data, _ = await async_get_session_data(session_id)
        data['username'] = username
        await async_set_session_data(session_id, data)
        return format_response(username)

    @app.route('/sessions', methods=['GET'])
    async def list_sessions():
        session_id = request.cookies.get('session_id')
        if not session_id:
            return 'Session not found', 400
        _, username = await async_get_session_data(session_id)
        if not username:
            return 'No user logged in', 400
        sessions = await async_get_user_sessions(username)
        return json.dumps({'user': username, 'sessions': sessions})

    @app.route('/sessions/<sid>', methods=['DELETE'])
    async def delete_user_session(sid):
        session_id = request.cookies.get('session_id')
        if not session_id:
            return 'Session CTO', 400
        _, username = await async_get_session_data(session_id)
        if not username:
            return 'No user logged in', 400
        if sid not in await async_get_user_sessions(username):
            return 'Session not found', 404
        delete_session(sid)
        return 'Session deleted', 200