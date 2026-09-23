from flask import Flask, redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html
import uuid
import urllib.parse
import os
import json
import sqlite3

class FileSessionInterface:
    def __init__(self, folder='session_data'):
        self.folder = folder
        os.makedirs(self.folder, exist_ok=True)
    def open_session(self, app, request):
        sid = request.cookies.get(app.session_cookie_name)
        if not sid:
            sid = str(uuid.uuid4())
            return FileSession(sid, {})
        path = os.path.join(self.folder, f'{sid}.json')
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        else:
            data = {}
        return FileSession(sid, data)
    def save_session(self, app, session, response):
        path = os.path.join(self.folder, f'{session.sid}.json')
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(session.data, f)
        response.set_cookie(app.session_cookie_name, session.sid,
                            httponly=True, secure=True,
                            path='/', max_age=60*60*24)

class FileSession(dict):
    def __init__(self, sid, initial=None):
        super().__init__(initial or {})
        self.sid = sid
    def get(self, key, default=None):
        return super().get(key, default)

class DBSessionInterface:
    def __init__(self, db_path='sessions.sqlite'):
        self.db_path = db_path
        conn = sqlite3.connect(self.db_path)
        conn.execute('CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, data TEXT)')
        conn.commit()
        conn.close()
    def open_session(self, app, request):
        sid = request.cookies.get(app.session_cookie_name)
        if not sid:
            sid = str(uuid.uuid4())
            return DBSession(sid, {})
        conn = sqlite3.connect(self.db_path)
        cur = conn.execute('SELECT data FROM sessions WHERE id=?', (sid,))
        row = cur.fetchone()
        conn.close()
        if row:
            data = json.loads(row[0])
        else:
            data = {}
        return DBSession(sid, data)
    def save_session(self, app, session, response):
        conn = sqlite3.connect(self.db_path)
        conn.execute('REPLACE INTO sessions(id, data) VALUES(?,?)',
                     (session.sid, json.dumps(session.data)))
        conn.commit()
        conn.close()
        response.set_cookie(app.session_cookie_name, session.sid,
                            httponly=True, secure=True,
                            path='/', max_age=60*60*24)

class DBSession(dict):
    def __init__(self, sid, initial=None):
        super().__init__(initial or {})
        self.sid = sid
    def get(self, key, default=None):
        return super().get(key, default)

def init(app):
    app.secret_key = 'default-secret-key'
    storage_type = app.config.get('STORAGE_TYPE', 'file')
    if storage_type == 'db':
        app.session_interface = DBSessionInterface()
    else:
        app.session_interface = FileSessionInterface()
    @app.before_request
    def attach_user():
        if 'user_id' not in session:
            session['user_id'] = str(uuid.uuid4())
    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET'])
    def BenchmarkTest00064_get():
        response = make_response(render_template('web/securecookie-00/BenchmarkTest00064.html'))
        response.set_cookie('BenchmarkTest00064', session['user_id'],
                             max_age=60*3,
                             secure=True,
                             path=request.path,
                             domain='localhost')
        return response
    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['POST'])
    def BenchmarkTest00064_post():
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00064", "noCookieValueSupplied"))
        bar = escape_for_html(param)
        input_data = bar.encode('utf-8') if isinstance(bar, str) else bar.read_ios(1000)
        cookie = 'SomeCookie'
        value = input_data.decode('utf-8')
        session['some_value'] = value
        RESPONSE = (
            f'Created cookie: \'{cookie}\' with value \'{escape_for_html(value)}\' and secure flag set to false.'
        )
        RESPONSE = make_response(RESPONSE)
        RESPONSE.set_cookie(cookie, value,
                            path=request.path,
                            secure=False,
                            httponly=True)
        return RESPONSE