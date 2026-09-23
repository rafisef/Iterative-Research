import json
import sqlite3
import os
import urllib.parse
import base64
import uuid
import asyncio
import threading
from flask import redirect, url_for, request, make_response, render_template, Flask, session
from functools import wraps

class Storage:
    def set(self, key, value): raise NotImplementedError
    def get(self, key): raise NotImplementedError
    async def set_async(self, key, value): return self.set(key, value)
    async def get_async(self, key): return self.get(key)

class FileStorage(Storage):
    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        if not os.path.exists(self.path):
            with open(self.path, 'w') as f:
                json.dump({}, f)
    def _load(self):
        with self._lock:
            with open(self.path, 'r') as f:
                return json.load(f)
    def _save(self, data):
        with self._lock:
            with open(self.path, 'w') as f:
                json.dump(data, f)
    def set(self, key, value):
        data = self._load()
        data[key] = value
        self._save(data)
    def get(self, key):
        data = self._load()
        return data.get(key)
    async def set_async(self, key, value):
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self.set, key, value)
    async def get_async(self, key):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.get, key)

class DBStorage(Storage):
    def __init__(self, path):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.execute('CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT)')
        self.conn.commit()
        self._lock = threading.Lock()
    def set(self, key, value):
        with self._lock:
            self.conn.execute('REPLACE INTO kv(k,v) VALUES(?,?)', (key, value))
            self.conn.commit()
    def get(self, key):
        with self._lock:
            cur = self.conn.execute('SELECT v FROM kv WHERE k=?', (key,))
            row = cur.fetchone()
            return row[0] if row else None
    async def set_async(self, key, value):
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self.set, key, value)
    async def get_async(self, key):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.get, key)

class AuthProvider:
    def authenticate(self, credentials): raise NotImplementedError

class BasicAuthProvider(AuthProvider):
    def __init__(self, users):
        self.users = users
    def authenticate(self, credentials):
        username = credentials.get('username')
        password = credentials.get('password')
        if username in self.users and self.users[username] == password:
            return username
        return None

class TokenAuthProvider(AuthProvider):
    def __init__(self, tokens):
        self.tokens = tokens
    def authenticate(self, credentials):
        token = credentials.get('token')
        if token in self.tokens:
            return self.tokens[token]
        return None

def init(app: Flask, storage_type=None, storage_path=None, auth_providers=None):
    storage_type = storage_type or os.getenv('STORAGE_TYPE', 'file')
    storage_path = storage_path or os.getenv('STORAGE_PATH', 'storage.json')
    secret = os.getenv('FLASK_SECRET_KEY')
    app.secret_key = secret.encode() if secret else os.urandom(24)
    storage = DBStorage(storage_path) if storage_type == 'db' else FileStorage(storage_path)
    providers = {}
    if auth_providers:
        for name, provider in auth_providers.items():
            providers[name] = provider
    def process_redirect(req):
        sid = session.get('sid', str(uuid.uuid4()))
        session['sid'] = sid
        key = f'{sid}_BenchmarkTest00067'
        param = urllib.parse.unquote_plus(req.cookies.get("BenchmarkTest00067", "noCookieValueSupplied"))
        storage.set(key, param)
        tmp = base64.b64encode(param.encode('utf-8'))
        bar = base64.b64decode(tmp).decode('utf-8')
        return redirect(bar)
    async def async_process_redirect(req):
        sid = session.get('sid', str(uuid.uuid4()))
        session['sid'] = sid
        key = f'{sid}_BenchmarkTest00067'
        param = urllib.parse.unquote_plus(req.cookies.get("BenchmarkTest00067", "noCookieValueSupplied"))
        await storage.set_async(key, param)
        tmp = base64.b64encode(param.encode('utf-8'))
        bar = base64.b64decode(tmp).decode('utf-8')
        return redirect(bar)
    def requires_auth(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if 'auth_provider' not in session:
                return redirect(url_for('login', next=request.path))
            return f(*args, **kwargs)
        return wrapper
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            provider_name = request.form.get('provider')
            credentials = request.form.to_dict()
            credentials.pop('provider', None)
            provider = providers.get(provider_name)
            if provider:
                user = provider.authenticate(credentials)
                if user:
                    session['auth_provider'] = provider_name
                    session['user'] = user
                    next_path = request.args.get('next') or url_for('BenchmarkTest00067_get')
                    return redirect(next_path)
        return render_template('login.html', providers=providers.keys())
    @app.route('/logout')
    def logout():
        session.clear()
        return redirect(url_for('BenchmarkTest00067_get'))
    @app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['GET'])
    def BenchmarkTest00067_get():
        response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
        response.set_cookie('BenchmarkTest00067', 'http%3A%2F%2Flocalhost%3A5000%2F',
                            max_age=60*3, secure=True, path=request.path, domain='localhost')
        return response
    @app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['POST'])
    @requires_auth
    def BenchmarkTest00067_post():
        return process_redirect(request)
    @app.route('/benchmark/redirect-00/BenchmarkTest00067_async', methods=['GET', 'POST'])
    async def BenchmarkTest00067_async():
        if request.method == 'GET':
            response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
            response.set_cookie('BenchmarkTest00067', 'http%3A%2F%2Flocalhost%3A5000%2F',
                                max_age=60*3, secure=True, path=request.path, domain='localhost')
            return response
        return await async_process_redirect(request)