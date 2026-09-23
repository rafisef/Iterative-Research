import os
import uuid
import json
import sqlite3
import configparser
import xml.sax
import xml.dom.minidom
from flask import Flask, redirect, url_for, request, make_response, render_template, session
from flask_session import Session
from helpers.utils import escape_for_html
from flask.sessions import SessionInterface, SessionMixin
from functools import wraps

class FileSession(dict, SessionMixin):
    def __init__(self, data=None):
        super().__init__(data or {})

class FileSessionInterface(SessionInterface):
    def __init__(self, session_dir):
        self.session_dir = session_dir
        os.makedirs(self.session_dir, exist_ok=True)
    def open_session(self, app, request):
        sid = request.cookies.get(app.session_cookie_name)
        if not sid:
            sid = str(uuid.uuid4())
            return FileSession()
        path = os.path.join(self.session_dir, sid)
        if os.path.exists(path):
            with open(path, 'r') as f:
                data = json.load(f)
            return FileSession(data)
        return FileSession()
    def save_session(self, app, session_obj, response):
        sid = session_obj.get('_id') or str(uuid.uuid4())
        session_obj['_id'] = sid
        path = os.path.join(self.session_dir, sid)
        with open(path, 'w') as f:
            json.dump(dict(session_obj), f)
        response.set_cookie(app.session_cookie_name, sid, httponly=True)

class DBSession(dict, SessionMixin):
    def __init__(self, data=None):
        super().__init__(data or {})

class DBSessionInterface(SessionInterface):
    def __init__(self, db_url):
        self.db_url = db_url
        self.conn = sqlite3.connect(self.db_url, check_same_thread=False)
        self.conn.execute('CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, data TEXT)')
        self.conn.commit()
    def open_session(self, app, request):
        sid = request.cookies.get(app.session_cookie_name)
        if not sid:
            sid = str(uuid.uuid4())
            return DBSession()
        cur = self.conn.execute('SELECT data FROM sessions WHERE id=?', (sid,))
        row = cur.fetchone()
        if row:
            data = json.loads(row[0])
            return DBSession(data)
        return DBSession()
    def save_session(self, app, session_obj, response):
        sid = session_obj.get('_id') or str(uuid.uuid4())
        session_obj['_id'] = sid
        data = json.dumps(dict(session_obj))
        self.conn.execute('REPLACE INTO sessions(id, data) VALUES(?,?)', (sid, data))
        self.conn.commit()
        response.set_cookie(app.session_cookie_name, sid, httponly=True)

class AuthProvider:
    def authenticate(self, credentials):
        raise NotImplementedError

class BasicAuthProvider(AuthProvider):
    def __init__(self):
        self.user = os.getenv('BMRK_USER', 'admin')
        self.passwd = os.getenv('BMRK_PASS', 'password')
    def authenticate(self, credentials):
        return credentials.get('username') == self.user and credentials.get('password') == self.passwd

class TokenAuthProvider(AuthProvider):
    def __init__(self):
        self.token = os.getenv('BMRK_TOKEN', 'secret-token')
    def authenticate(self, credentials):
        return credentials.get('token') == self.token

class AuthManager:
    def __init__(self):
        self.providers = {}
    def register(self, name, provider):
        self.providers[name] = provider
    def authenticate(self, provider_name, credentials):
        provider = self.providers.get(provider_name)
        if provider:
            return provider.authenticate(credentials)
        return False

auth_manager = AuthManager()
auth_manager.register('basic', BasicAuthProvider())
auth_manager.register('token', TokenAuthProvider())

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def init(app: Flask):
    app.secret_key = os.getenv('BMRK_SECRET_KEY', 'super-secret-key')
    storage_type = os.getenv('BMRK_SESSION_STORAGE', 'redis')
    if storage_type == 'file':
        app.config['SESSION_TYPE'] = 'filesystem'
        app.config['SESSION_FILE_DIR'] = os.getenv('BMRK_SESSION_DIR', './flask_session')
        app.session_interface = FileSessionInterface(app.config['SESSION_FILE_DIR'])
    elif storage_type == 'db':
        db_url = os.getenv('BMRK_DB_URL', 'sqlite:///sessions.db')
        app.session_interface = DBSessionInterface(db_url)
    else:
        app.config['SESSION_TYPE'] = 'redis'
        app.config['SESSION_REDIS'] = os.getenv('BMRK_REDIS_URL', 'redis://localhost:6379')
        app.config['SESSION_FILE_DIR'] = os.getenv('BMRK_SESSION_DIR', './flask_session')
        Session(app)
    route_path = os.getenv('BMRK_ROUTE_BenchmarkTest00205', '/benchmark/xxe-00/BenchmarkTest00205')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            provider = request.form.get('provider', 'basic')
            if provider == 'basic':
                credentials = {'username': request.form.get('username', ''), 'password': request.form.get('password', '')}
            else:
                credentials = {'token': request.form.get('token', '')}
            if auth_manager.authenticate(provider, credentials):
                session['user'] = provider
                return redirect(request.args.get('next') or url_for('benchmark_test_00205_get'))
            return 'Authentication failed', 401
        return '''
            <form method="post">
                Provider: <select name="provider"><option value="basic">Basic</option><option value="token">Token</option></select><br>
                Username: <input name="username"><br>
                Password: <input name="password" type="password"><br>
                Token: <input name="token"><br>
                <input type="submit" value="Login">
            </form>
        '''

    @app.route(route_path, methods=['GET'])
    @requires_auth
    def benchmark_test_00205_get():
        return benchmark_test_00205_post()

    @app.route(route_path, methods=['POST'])
    @requires_auth
    def benchmark_test_00205_post():
        response = ""
        values = request.form.getlist("BenchmarkTest00205")
        param = values[0] if values else os.getenv('BMRK_BenchmarkTest00205', '')
        session['BenchmarkTest00205'] = param
        section_name = os.getenv('BMRK_CONFIG_SECTION', 'section60568')
        key_a_val = os.getenv('BMRK_KEYA', 'a-Value')
        key_b_val = os.getenv('BMRK_KEYB', param)
        conf = configparser.ConfigParser()
        conf.add_section(section_name)
        conf.set(section_name, 'keyA-60568', key_a_val)
        conf.set(section_name, 'keyB-60568', key_b_val)
        bar = conf.get(section_name, 'keyB-60568')
        session['BenchmarkTest00205'] = bar
        try:
            parser = xml.sax.make_parser()
            parser.setFeature(xml.sax.handler.feature_external_ges, True)
            doc = xml.dom.minidom.parseString(bar, parser)
            out = ''
            processing = [doc.documentElement]
            while processing:
                e = processing.pop(0)
                if e.nodeType == xml.dom.Node.TEXT_NODE:
                    out += e.data
                else:
                    processing[:0] = e.childNodes
            response += f'Your XML doc results are: <br>{escape_for_html(out)}'
        except Exception:
            response += f'There was an error reading your XML doc:<br>{escape_for_html(bar)}'
        return response