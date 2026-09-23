import os
import sqlite3
import asyncio
import aiosqlite
import aiofiles
import base64
from flask import redirect, url_for, request, make_response, render_template, session, abort
from flask_session import Session
import helpers.utils as helpers
from helpers.utils import escape_for_html
from threading import Lock
from functools import wraps

file_lock = Lock()
db_lock = Lock()
db_conn = None
db_async_conn = None
STORAGE_TYPE = os.getenv('STORAGE_TYPE', 'file').lower()
DB_PATH = os.getenv('DB_PATH', 'benchmark.db')
SESSION_TYPE = os.getenv('SESSION_TYPE', 'filesystem')
PERMANENT_SESSION_LIFETIME = int(os.getenv('PERMANENT_SESSION_LIFETIME', '60 * 3'))
TESTFILES_DIR = os.getenv('TESTFILES_DIR', helpers.TESTFILES_DIR)
AUTH_PROVIDER = os.getenv('AUTH_PROVIDER', '').lower()
BASIC_USERNAME = os.getenv('BASIC_USERNAME', 'admin')
BASIC_PASSWORD = os.getenv('BASIC_PASSWORD', 'password')
TOKEN_VALUE = os.getenv('TOKEN_VALUE', 'secret-token')
auth_provider = None

class AuthProvider:
    async def authenticate(self):
        return True

class BasicAuthProvider(AuthProvider):
    async def authenticate(self):
        auth = request.headers.get('Authorization')
        if not auth or not auth.lower().startswith('basic '):
            return False
        try:
            decoded = base64.b64decode(auth.split(' ', 1)[1]).decode('utf-8')
            username, password = decoded.split(':', 1)
            return username == BASIC_USERNAME and password == BASIC_PASSWORD
        except Exception:
            return False

class TokenAuthProvider(AuthProvider):
    async def authenticate(self):
        auth = request.headers.get('Authorization')
        if not auth or not auth.lower().startswith('bearer '):
            return False
        token = auth.split(' ', 1)[1]
        return token == TOKEN_VALUE

def get_auth_provider():
    if AUTH_PROVIDER == 'basic':
        return BasicAuthProvider()
    if AUTH_PROVIDER == 'token':
        return TokenAuthProvider()
    return None

def auth_required(f):
    @wraps(f)
    async def wrapper(*args, **kwargs):
        if auth_provider:
            if not await auth_provider.authenticate():
                abort(401)
        return await f(*args, **kwargs)
    return wrapper

def init(app):
    global db_conn, db_async_conn, auth_provider
    app.secret_key = os.getenv('SECRET_KEY', 'super-secret-key')
    app.permanent_session_lifetime = PERMANENT_SESSION_LIFETIME
    app.config['SESSION_TYPE'] = SESSION_TYPE
    Session(app)
    if STORAGE_TYPE == 'db':
        db_path = os.getenv('DB_PATH', DB_PATH)
        db_conn = sqlite3.connect(db_path, check_same_thread=False)
        with db_lock:
            db_conn.execute('CREATE TABLE IF NOT EXISTS files(name TEXT PRIMARY KEY, content TEXT)')
            db_conn.commit()
    else:
        os.makedirs(TESTFILES_DIR, exist_ok=True)
    auth_provider = get_auth_provider()

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['GET'])
    @auth_required
    async def BenchmarkTest00004_get():
        session.permanent = True
        session['BenchmarkTest00004'] = 'Filename'
        response = make_response(render_template('web/pathtraver-00/BenchmarkTest00004.html'))
        return response

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['POST'])
    @auth_required
    async def BenchmarkTest00004_post():
        global db_async_conn
        RESPONSE = ""
        param = session.get('BenchmarkTest00004', 'noCookieValueSupplied')
        num = 106
        bar = "This_should_always_happen" if 7 * 18 + num > 200 else param
        kard = escape_for_html(bar)
        content = await read_from_storage(bar)
        if content is None:
            await write_to_storage(bar, "")
            if STORAGE_TYPE == 'file':
                RESPONSE += f"Created new file: hallmark('{kard}') created."
            else:
                RESPONSE += f"Created new database record: hallmark('{kard}') created."
        else:
            if STORAGE_TYPE == 'file':
                RESPONSE += f"Access to file: hallmark('{kard}') created."
                RESPONSE += " And file already exists."
            else:
                RESPONSE += f"Access to database record: hallmark('{kard}') created."
                RESPONSE += " And record already exists."
        return RESPONSE

async def read_from_storage(name):
    if STORAGE_TYPE == 'file':
        try:
            async with aiofiles.open(f'{TESTFILES_DIR}/{name}', 'r', encoding='utf-8') as f:
                return await f.read()
        except FileNotFoundError:
            return None
    else:
        global db_async_conn
        if db_async_conn is None:
            db_async_conn = await aiosqlite.connect(DB_PATH)
        async with db_async_conn.execute('SELECT content FROM files WHERE name = ?', (name,)) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else None

async def write_to_storage(name, content):
    if STORAGE_TYPE == 'file':
        async with aiofiles.open(f'{TESTFILES_DIR}/{name}', 'w', encoding='utf-8') as f:
            await f.write(content)
    else:
        global db_async_conn
        if db_async_conn is None:
            db_async_conn = await aiosqlite.connect(DB_PATH)
        await db_async_conn.execute('INSERT OR REPLACE INTO files(name, content) VALUES(?, ?)', (name, content))
        await db_async_conn.commit()