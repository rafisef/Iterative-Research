import os
import sqlite3
import configparser
import urllib.parse
import asyncio
import base64
import threading
from flask import Flask, make_response, render_template, request, escape, abort, session

_storage_locks = {}
_storage_sync_locks = {}

class Storage:
    async def load(self):
        raise NotImplementedError
    async def save(self, data):
        raise NotImplementedError
    def load_sync(self):
        raise NotImplementedError
    def save_sync(self, data):
        raise NotImplementedError

class FileStorage(Storage):
    def __init__(self, file_path='conf90091.ini'):
        self.file_path = file_path
        self.lock = _storage_locks.setdefault(self.file_path, asyncio.Lock())
        self.sync_lock = _storage_sync_locks.setdefault(self.file_path, threading.Lock())
    async def load(self):
        config = {}
        if os.path.exists(self.file_path):
            conf = configparser.ConfigParser()
            conf.read(self.file_path)
            if conf.has_section('section90091'):
                for key in ('keyA-90091', 'keyB-90091'):
                    if conf.has_option('section90091', key):
                        config[key] = conf.get('section90091', key)
        return config
    async def save(self, data):
        async with self.lock:
            conf = configparser.ConfigParser()
            conf.add_section('section90091')
            for key in ('keyA-90091', 'keyB-90091'):
                conf.set('section90091', key, data.get(key, ''))
            with open(self.file_path, 'w') as f:
                conf.write(f)
    def load_sync(self):
        config = {}
        if os.path.exists(self.file_path):
            conf = configparser.ConfigParser()
            conf.read(self.file_path)
            if conf.has_section('section90091'):
                for key in ('keyA-90091', 'keyB-90091'):
                    if conf.has_option('section90091', key):
                        config[key] = conf.get('section90091', key)
        return config
    def save_sync(self, data):
        with self.sync_lock:
            conf = configparser.ConfigParser()
            conf.add_section('section90091')
            for key in ('keyA-90091', 'keyB-90091'):
                conf.set('section90091', key, data.get(key, ''))
            with open(self.file_path, 'w') as f:
                conf.write(f)

class DBStorage(Storage):
    def __init__(self, db_path='conf90091.db'):
        self.db_path = db_path
        self.lock = _storage_locks.setdefault(self.db_path, asyncio.Lock())
        self.sync_lock = _storage_sync_locks.setdefault(self.db_path, threading.Lock())
    async def load(self):
        config = {}
        if os.path.exists(self.db_path):
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute("SELECT key, value FROM config WHERE key IN ('keyA-90091','keyB-90091')")
            rows = cur.fetchall()
            for key, value in rows:
                config[key] = value
            conn.close()
        return config
    async def save(self, data):
        async with self.lock:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute("CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)")
            for key in ('keyA-90091', 'keyB-90091'):
                cur.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", (key, data.get(key, '')))
            conn.commit()
            conn.close()
    def load_sync(self):
        config = {}
        if os.path.exists(self.db_path):
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute("SELECT key, value FROM config WHERE key IN ('keyA-90091','keyB-90091')")
            rows = cur.fetchall()
            for key, value in rows:
                config[key] = value
            conn.close()
        return config
    def save_sync(self, data):
        with self.sync_lock:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()
            cur.execute("CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)")
            for key in ('keyA-90091', 'keyB-90091'):
                cur.execute("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)", (key, data.get(key, '')))
            conn.commit()
            conn.close()

def get_storage(storage_type):
    if storage_type == 'file':
        return FileStorage()
    if storage_type == 'db':
        return DBStorage()
    return None

async def load_config_async(storage_type):
    storage = get_storage(storage_type)
    if storage:
        data = await storage.load()
        return data, storage
    return {}, None

def load_config_sync(storage_type):
    storage = get_storage(storage_type)
    if storage:
        data = storage.load_sync()
        return data, storage
    return {}, None

def basic_auth():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Basic '):
        return False
    encoded = auth_header.split(' ', 1)[1]
    try:
        decoded = base64.b64decode(encoded).decode()
    except Exception:
        return False
    user, _, pwd = decoded.partition(':')
    expected_user = os.getenv('AUTH_USER', 'user')
    expected_pwd = os.getenv('AUTH_PASS', 'pass')
    return user == expected_user and pwd == expected_pwd

def token_auth():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return False
    token = auth_header.split(' ', 1)[1]
    expected_token = os.getenv('AUTH_TOKEN', 'secret')
    return token == expected_token

AUTH_PROVIDERS = {
    'basic': basic_auth,
    'token': token_auth
}

def get_auth_provider():
    names = os.getenv('AUTH_PROVIDER', '').split(',')
    return [AUTH_PROVIDERS[name] for name in names if name in AUTH_PROVIDERS]

def init(app: Flask):
    app.secret_key = os.getenv('SECRET_KEY', 'defaultsecret')
    storage_type = os.getenv('STORAGE_TYPE', 'file')
    auth_providers = get_auth_provider()

    @app.before_request
    def auth_middleware():
        if auth_providers and not any(provider() for provider in auth_providers):
            abort(401)
        session.setdefault('user', None)

    @app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['GET'])
    def BenchmarkTest00074_get():
        response = make_response(render_template('web/codeinj-00/BenchmarkTest00074.html'))
        response.set_cookie('BenchmarkTest00074', '%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27',
            max_age=60*3,
            secure=True,
            path=request.path,
            domain='localhost')
        return response

    @app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['POST'])
    async def BenchmarkTest00074_post():
        RESPONSE = ""
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00074", "noCookieValueSupplied"))
        env_keyA = os.getenv('KEYA_90091', 'a-Value')
        env_keyB = os.getenv('KEYB_90091')
        use_keyB = env_keyB if env_keyB is not None else param
        if 'config' in session:
            conf_data = session['config']
            storage = None
        else:
            conf_data, storage = await load_config_async(storage_type)
        keyA = conf_data.get('keyA-90091', env_keyA)
        keyB = conf_data.get('keyB-90091', use_keyB)
        conf_data['keyA-90091'] = keyA
        conf_data['keyB-90091'] = keyB
        bar = conf_data['keyB-90091']
        try:
            exec(bar)
        except Exception as e:
            RESPONSE += f'Error executing statement \'{escape(bar)}\''
        session['config'] = conf_data
        if storage:
            await storage.save(conf_data)
        return RESPONSE

    @app.route('/benchmark/codeinj-00/BenchmarkTest00074-async', methods=['GET'])
    async def BenchmarkTest00074_get_async():
        response = make_response(await asyncio.to_thread(render_template, 'web/codeinj-00/BenchmarkTest00074.html'))
        response.set_cookie('BenchmarkTest00074', '%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27',
            max_age=60*3,
            secure=True,
            path=request.path,
            domain='localhost')
        return response

    @app.route('/benchmark/codeinj-00/BenchmarkTest00074-sync', methods=['GET'])
    def BenchmarkTest00074_get_sync():
        response = make_response(render_template('web/codeinj-00/BenchmarkTest00074.html'))
        response.set_cookie('BenchmarkTest00074', '%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27',
            max_age=60*3,
            secure=True,
            path=request.path,
            domain='localhost')
        return response

    @app.route('/benchmark/codeinj-00/BenchmarkTest00074-sync', methods=['POST'])
    def BenchmarkTest00074_post_sync():
        RESPONSE = ""
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00074", "noCookieValueSupplied"))
        env_keyA = os.getenv('KEYA_90091', 'a-Value')
        env_keyB = os.getenv('KEYB_90091')
        use_keyB = env_keyB if env_keyB is not None else param
        if 'config' in session:
            conf_data = session['config']
            storage = None
        else:
            conf_data, storage = load_config_sync(storage_type)
        keyA = conf_data.get('keyA-90091', env_keyA)
        keyB = conf_data.get('keyB-90091', use_keyB)
        conf_data['keyA-90091'] = keyA
        conf_data['keyB-90091'] = keyB
        bar = conf_data['keyB-90091']
        try:
            exec(bar)
        except Exception as e:
            RESPONSE += f'Error executing statement \'{escape(bar)}\''
        session['config'] = conf_data
        if storage:
            storage.save_sync(conf_data)
        return RESPONSE