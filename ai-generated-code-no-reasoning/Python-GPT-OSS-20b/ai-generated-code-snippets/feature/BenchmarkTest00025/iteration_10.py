import os, json, threading, sqlite3, uuid
from datetime import datetime
from flask import redirect, url_for, request, make_response, render_template, session
from flask.sessions import SessionInterface, SessionMixin
from itsdangerous import URLSafeTimedSerializer

class FileSession(dict, SessionMixin):
    def __init__(self, initial=None, sid=None, new=False):
        dict.__init__(self, initial or {})
        self.sid = sid
        self.new = new

class FileSessionInterface(SessionInterface):
    def __init__(self, app, filename):
        self.app = app
        self.filename = filename
        self.lock = threading.Lock()
        if not os.path.exists(self.filename):
            with open(self.filename, 'w') as f:
                json.dump({}, f)

    def _load_sessions(self):
        with self.lock:
            with open(self.filename, 'r') as f:
                return json.load(f)

    def _save_sessions(self, sessions):
        with self.lock:
            with open(self.filename, 'w') as f:
                json.dump(sessions, f)

    def open_session(self, app, request):
        sid = request.cookies.get(app.session_cookie_name)
        if not sid:
            sid = uuid.uuid4().hex
            return FileSession(sid=sid, new=True)
        sessions = self._load_sessions()
        data = sessions.get(sid, {})
        return FileSession(data, sid=sid, new=False)

    def save_session(self, app, session_obj, response):
        if session_obj:
            sessions = self._load_sessions()
            sessions[session_obj.sid] = dict(session_obj)
            self._save_sessions(sessions)
            response.set_cookie(app.session_cookie_name, session_obj.sid,
                                max_age=app.permanent_session_lifetime.total_seconds(),
                                secure=app.config.get('SESSION_COOKIE_SECURE', True),
                                httponly=True)
        else:
            sessions = self._load_sessions()
            sessions.pop(session_obj.sid, None)
            self._save_sessions(sessions)
            response.delete_cookie(app.session_cookie_name)

class DBSession(dict, SessionMixin):
    def __init__(self, initial=None, sid=None, new=False):
        dict.__init__(self, initial or {})
        self.sid = sid
        self.new = new

class SQLiteSessionInterface(SessionInterface):
    def __init__(self, app, db_path):
        self.app = app
        self.db_path = db_path
        self.lock = threading.Lock()
        self._ensure_table()

    def _ensure_table(self):
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    sid TEXT PRIMARY KEY,
                    data TEXT,
                    last_modified TIMESTAMP
                )
            ''')
            conn.commit()
            conn.close()

    def _get_session_data(self, sid):
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute('SELECT data FROM sessions WHERE sid = ?', (sid,))
            row = cur.fetchone()
            conn.close()
            return json.loads(row[0]) if row else {}

    def _save_session_data(self, sid, data):
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute('REPLACE INTO sessions (sid, data, last_modified) VALUES (?, ?, ?)',
                        (sid, json.dumps(data), datetime.utcnow()))
            conn.commit()
            conn.close()

    def open_session(self, app, request):
        sid = request.cookies.get(app.session_cookie_name)
        if not sid:
            sid = uuid.uuid4().hex
            return DBSession(sid=sid, new=True)
        data = self._get_session_data(sid)
        return DBSession(data, sid=sid, new=False)

    def save_session(self, app, session_obj, response):
        if session_obj:
            self._save_session_data(session_obj.sid, dict(session_obj))
            response.set_cookie(app.session_cookie_name, session_obj.sid,
                                max_age=app.permanent_session_lifetime.total_seconds(),
                                secure=app.config.get('SESSION_COOKIE_SECURE', True),
                                httponly=True)
        else:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cur = conn.cursor()
                cur.execute('DELETE FROM sessions WHERE sid = ?', (session_obj.sid,))
                conn.commit()
                conn.close()
            response.delete_cookie(app.session_cookie_name)

def init(app, config=None):
    env = {
        'BENCHMARK_COOKIE_DOMAIN': os.getenv('BENCHMARK_COOKIE_DOMAIN'),
        'BENCHMARK_COOKIE_MAX_AGE': os.getenv('BENCHMARK_COOKIE_MAX_AGE'),
        'BENCHMARK_COOKIE_SECURE': os.getenv('BENCHMARK_COOKIE_SECURE'),
        'AUTH_PROVIDERS': os.getenv('AUTH_PROVIDERS'),
        'BENCHMARK_SESSION_STORAGE': os.getenv('BENCHMARK_SESSION_STORAGE'),
    }
    if config:
        env.update({f'BENCHMARK_{k.upper()}': v for k, v in config.items()})
    cookie_domain = env.get('BENCHMARK_COOKIE_DOMAIN', 'localhost')
    cookie_max_age = int(env.get('BENCHMARK_COOKIE_MAX_AGE', 60 * 3))
    secure_flag = str(env.get('BENCHMARK_COOKIE_SECURE', 'True')).lower() in ('true', '1', 'yes')
    providers = [p.strip() for p in env.get('AUTH_PROVIDERS', 'google,github').split(',')]
    storage_type = env.get('BENCHMARK_SESSION_STORAGE', 'file')
    if storage_type == 'db':
        app.session_interface = SQLiteSessionInterface(app, 'session_store.db')
    else:
        app.session_interface = FileSessionInterface(app, 'session_store.json')
    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET'])
    def BenchmarkTest00025_get():
        response = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
        response.set_cookie(
            'BenchmarkTest00025',
            'whatever',
            max_age=cookie_max_age,
            secure=secure_flag,
            path=request.path,
            domain=cookie_domain
        )
        return response
    @app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['POST'])
    def BenchmarkTest00025_post():
        RESPONSE = ''
        import urllib.parse
        param = urllib.parse.unquote_plus(
            request.cookies.get("BenchmarkTest00025", "noCookieValueSupplied")
        )
        superstring = f'90583{param}abcd'
        bar = superstring[len('90583'):len(superstring)-5]
        import random
        num = 'BenchmarkTest00025'[13:]
        user = f'Nancy{num}'
        cookie = f'rememberMe{num}'
        value = str(random.normalvariate())[2:]
        if session.get(cookie) == value:
            RESPONSE += f'Welcome back: {user}<br/>'
        else:
            session[cookie] = value
            RESPONSE += (
                f'{user} has been remembered with cookie: '
                f'{cookie} whose value is: {session[cookie]}<br/>'
            )
        return RESPONSE
    @app.route('/auth/<provider>', methods=['GET'])
    def auth_provider(provider):
        if provider not in providers:
            return redirect(url_for('BenchmarkTest00025_get'))
        session.setdefault('auth_providers', {})[provider] = 'token'
        response = make_response(redirect(url_for('BenchmarkTest00025_get')))
        response.set_cookie(
            f'auth_{provider}',
            'token',
            max_age=cookie_max_age,
            secure=secure_flag,
            domain=cookie_domain
        )
        return response
    @app.route('/logout', methods=['GET'])
    def logout():
        session.pop('auth_provider', None)
        session.pop('auth_providers', None)
        response = make_response(redirect(url_for('BenchmarkTest00025_get')))
        for provider in providers:
            response.delete_cookie(f'auth_{provider}', domain=cookie_domain)
        return response