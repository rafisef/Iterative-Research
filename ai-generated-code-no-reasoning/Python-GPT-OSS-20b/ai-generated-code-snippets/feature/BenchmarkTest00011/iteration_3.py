import os
import json
import urllib.parse
import uuid
import sqlite3
import threading
from flask import redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html
import helpers.db_sqlite

STORAGE_TYPE = os.getenv('STORAGE_TYPE', 'db')
FILE_PATH = os.getenv('FILE_PATH', 'users.json')
SESSION_DB_PATH = os.getenv('SESSION_DB_PATH', 'sessions.sqlite')
lock = threading.Lock()

def get_user_by_password(password):
    if STORAGE_TYPE == 'file':
        if not os.path.exists(FILE_PATH):
            return None
        with open(FILE_PATH, 'r') as f:
            data = json.load(f)
        return data.get(password)
    else:
        sql = 'SELECT username FROM USERS WHERE password = ?'
        con = helpers.db_sqlite.get_connection()
        cur = con.cursor()
        cur.execute(sql, (password,))
        row = cur.fetchone()
        con.close()
        return row[0] if row else None

def format_response(username):
    if username:
        return f'Username: {escape_for_html(username)}'
    return 'No user found'

def init_session_store():
    con = sqlite3.connect(SESSION_DB_PATH, check_same_thread=False)
    cur = con.cursor()
    cur.execute('CREATE TABLE IF NOT EXISTS sessions (session_id TEXT PRIMARY KEY, data TEXT)')
    con.commit()
    con.close()

def get_session_data(session_id):
    with lock:
        con = sqlite3.connect(SESSION_DB_PATH, check_same_thread=False)
        cur = con.cursor()
        cur.execute('SELECT data FROM sessions WHERE session_id = ?', (session_id,))
        row = cur.fetchone()
        con.close()
    return json.loads(row[0]) if row else {}

def set_session_data(session_id, data):
    with lock:
        con = sqlite3.connect(SESSION_DB_PATH, check_same_thread=False)
        cur = con.cursor()
        cur.execute('INSERT OR REPLACE INTO sessions (session_id, data) VALUES (?, ?)', (session_id, json.dumps(data)))
        con.commit()
        con.close()

def init(app):
    app.secret_key = os.getenv('FLASK_SECRET_KEY', 'default-secret-key')
    init_session_store()

    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['GET'])
    def BenchmarkTest00011_get():
        session_id = request.cookies.get('session_id')
        if not session_id:
            session_id = str(uuid.uuid4())
            set_session_data(session_id, {})
        response = make_response(render_template('web/sqli-00/BenchmarkTest00011.html'))
        response.set_cookie('session_id', session_id,
                            max_age=60*3,
                            secure=True,
                            path=request.path,
                            domain='localhost')
        return response

    @app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['POST'])
    def BenchmarkTest00011_post():
        session_id = request.cookies.get('session_id')
        if not session_id:
            return 'Session not found', 400
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00011", "noCookieValueSupplied"))
        bar = "This should never happen"
        if 'should' in bar:
            bar = param
        username = get_user_by_password(bar)
        data = get_session_data(session_id)
        data['username'] = username
        set_session_data(session_id, data)
        return format_response(username)